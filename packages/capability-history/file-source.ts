import { constants, lstatSync, openSync, closeSync, fstatSync, readFileSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { ArtifactRead, ArtifactSource, ArtifactState } from "./model";
import { assertPrivateAuthorityIsolation, type PrivateAuthorityIsolation } from "./private-authority";

export interface PrivateFileArtifactSourceOptions {
  readonly isolation: PrivateAuthorityIsolation;
  readonly root: string;
  /** Authority-private mapping. Protocol callers know artifact ids, never paths. */
  readonly artifacts: Readonly<Record<string, string>>;
  readonly now?: () => Date;
}

function revision(stat: ReturnType<typeof fstatSync>): string {
  return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}`;
}

export function createPrivateFileArtifactSource(options: PrivateFileArtifactSourceOptions): ArtifactSource {
  assertPrivateAuthorityIsolation(options.isolation);
  const root = realpathSync(resolve(options.root));
  if (!options.isolation.protectedPaths.some((path) => {
    const nested = relative(path, root);
    return nested === "" || (!nested.startsWith(`..${sep}`) && nested !== ".." && !isAbsolute(nested));
  })) {
    throw new Error("artifact root is not covered by the private authority proof");
  }
  const now = options.now ?? (() => new Date());

  const read = (artifactId: string, includeBytes: boolean, maxBytes: number): ArtifactRead | ArtifactState | null => {
    const relativeName = options.artifacts[artifactId];
    if (!relativeName) return null;
    if (isAbsolute(relativeName) || relativeName.split(/[\\/]/).includes("..")) throw new Error("authority artifact mapping escaped its root");
    const target = resolve(root, relativeName);
    const fromRoot = relative(root, target);
    if (!fromRoot || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) throw new Error("authority artifact mapping escaped its root");

    let cursor = root;
    for (const component of fromRoot.split(sep)) {
      cursor = resolve(cursor, component);
      const entry = lstatSync(cursor, { bigint: true });
      if (entry.isSymbolicLink()) throw new Error("authority artifact path contains a symlink");
    }
    if (realpathSync(target) !== target) throw new Error("authority artifact path changed during resolution");

    const fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1) throw new Error("authority artifact must be a regular, unlinked file");
      if (before.uid !== options.isolation.brokerUid || (before.mode & 0o077) !== 0) throw new Error("authority artifact permissions are no longer private");
      if (includeBytes && before.size > maxBytes) throw new Error("authority artifact exceeds its configured byte limit");
      const bytes = readFileSync(fd);
      const after = fstatSync(fd);
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
        throw new Error("authority artifact changed while it was read");
      }
      const state = {
        revision: revision(after),
        digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
        observedAt: now().toISOString(),
      };
      return includeBytes ? { ...state, bytes } : state;
    } finally {
      closeSync(fd);
    }
  };

  return {
    async read(artifactId, limits) { return read(artifactId, true, limits.maxBytes) as ArtifactRead | null; },
    async attest(artifactId) { return read(artifactId, false, 0) as ArtifactState | null; },
  };
}
