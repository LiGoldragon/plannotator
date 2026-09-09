import { describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyPrivateAuthorityIsolation } from "./private-authority";

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
});
