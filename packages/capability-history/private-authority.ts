import { lstatSync, realpathSync, statSync } from "node:fs";
import { dirname, parse, resolve, sep } from "node:path";

const verifiedProofs = new WeakSet<object>();

export interface PrivateAuthorityIsolation {
  readonly brokerUid: number;
  readonly workerUid: number;
  readonly protectedPaths: readonly string[];
}

export interface VerifyPrivateAuthorityIsolationOptions {
  /** UID of the untrusted worker or worker pool. It must differ from this process. */
  readonly workerUid: number;
  /** Broker-owned source roots and state files. No symlink, hardlink, group, or world access is accepted. */
  readonly protectedPaths: readonly string[];
}

/**
 * Produces an unforgeable in-process proof only after checking an independent
 * OS authority. A boolean "private mode" can never produce this value.
 */
export function verifyPrivateAuthorityIsolation(options: VerifyPrivateAuthorityIsolationOptions): PrivateAuthorityIsolation {
  if (!process.getuid) throw new Error("private capability authority requires a Unix process uid");
  const brokerUid = process.getuid();
  if (brokerUid === options.workerUid) throw new Error("private capability authority must run under a distinct OS uid from its worker");
  if (options.protectedPaths.length === 0) throw new Error("private capability authority requires protected source and state paths");

  const protectedPaths = options.protectedPaths.map((path) => {
    const absolute = resolve(path);
    const entry = lstatSync(absolute, { bigint: true });
    if (entry.isSymbolicLink() || realpathSync(absolute) !== absolute) throw new Error(`protected authority path must not contain a symlink: ${absolute}`);
    if (Number(entry.uid) !== brokerUid) throw new Error(`protected authority path is not owned by broker uid ${brokerUid}: ${absolute}`);
    if ((Number(entry.mode) & 0o077) !== 0) throw new Error(`protected authority path grants group or world permissions: ${absolute}`);
    if (entry.isFile() && entry.nlink !== 1n) throw new Error(`protected authority state must not be hard-linked: ${absolute}`);

    // A writable ancestor could replace the protected entry. Sticky directories
    // are safe for a broker-owned child; ordinary group/world writable ones are not.
    let ancestor = dirname(absolute);
    const filesystemRoot = parse(absolute).root;
    while (true) {
      const parent = statSync(ancestor);
      const writableByOthers = (parent.mode & 0o022) !== 0;
      const sticky = (parent.mode & 0o1000) !== 0;
      if (writableByOthers && !sticky) throw new Error(`protected authority path has a replaceable ancestor: ${ancestor}`);
      if (ancestor === filesystemRoot) break;
      ancestor = dirname(ancestor);
    }
    let component = parse(absolute).root;
    for (const name of absolute.slice(component.length).split(sep)) {
      if (!name) continue;
      component = resolve(component, name);
      if (lstatSync(component).isSymbolicLink()) throw new Error(`protected authority path contains a symlink component: ${component}`);
    }
    return absolute;
  });

  const proof = Object.freeze({ brokerUid, workerUid: options.workerUid, protectedPaths });
  verifiedProofs.add(proof);
  return proof;
}

export function assertPrivateAuthorityIsolation(proof: PrivateAuthorityIsolation): void {
  if (!verifiedProofs.has(proof)) throw new Error("private mode requires a locally verified independent authority proof");
  if (!process.getuid || process.getuid() !== proof.brokerUid) throw new Error("private authority proof belongs to another process identity");
  // Recheck ownership and permissions at server start; a stale proof is not authority.
  for (const path of proof.protectedPaths) {
    const entry = lstatSync(path, { bigint: true });
    if (entry.isSymbolicLink() || Number(entry.uid) !== proof.brokerUid || (Number(entry.mode) & 0o077) !== 0) {
      throw new Error(`private authority isolation changed after verification: ${path}`);
    }
    if (entry.isFile() && entry.nlink !== 1n) throw new Error(`private authority state became hard-linked: ${path}`);
  }
}
