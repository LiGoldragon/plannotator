import { describe, expect, test } from "bun:test";
import { chmodSync, linkSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyPrivateAuthorityIsolation } from "./private-authority";
import { createPrivateFileArtifactSource } from "./file-source";
import { CapabilityHistoryBroker } from "./broker";
import { startCapabilityHistoryUnixServer } from "./unix-server";

describe("private authority isolation", () => {
  test("rejects a same-UID worker and group-readable authority material", () => {
    const root = join(tmpdir(), `capability-authority-${process.pid}-${Date.now()}`);
    mkdirSync(root, { mode: 0o700 });
    const state = join(root, "state");
    writeFileSync(state, "synthetic", { mode: 0o600 });
    try {
      expect(() => verifyPrivateAuthorityIsolation({ workerUid: process.getuid!(), protectedPaths: [root, state] }))
        .toThrow(/distinct OS uid/);
      chmodSync(state, 0o640);
      expect(() => verifyPrivateAuthorityIsolation({ workerUid: process.getuid!() + 1, protectedPaths: [root, state] }))
        .toThrow(/group or world permissions/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects symlink and hardlink artifact mappings and keeps private serving fail-closed", async () => {
    const root = join(tmpdir(), `capability-source-${process.pid}-${Date.now()}`);
    mkdirSync(root, { mode: 0o700 });
    const real = join(root, "real");
    writeFileSync(real, "synthetic", { mode: 0o600 });
    linkSync(real, join(root, "hard"));
    symlinkSync(real, join(root, "symbolic"));
    try {
      const isolation = verifyPrivateAuthorityIsolation({ workerUid: process.getuid!() + 1, protectedPaths: [root] });
      const source = createPrivateFileArtifactSource({ isolation, root, artifacts: { hard: "hard", symbolic: "symbolic" } });
      await expect(source.read("hard", { maxBytes: 1024 })).rejects.toThrow(/unlinked file/);
      await expect(source.read("symbolic", { maxBytes: 1024 })).rejects.toThrow(/symlink/);

      const broker = new CapabilityHistoryBroker({ source });
      await expect(startCapabilityHistoryUnixServer({
        mode: "private",
        isolation,
        socketPath: join(root, "broker.sock"),
        broker,
        principal: { identity: "gateway", audience: "desktop" },
      })).rejects.toThrow(/peer credentials/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
