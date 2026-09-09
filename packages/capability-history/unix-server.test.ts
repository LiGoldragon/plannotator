import { afterEach, describe, expect, test } from "bun:test";
import { request } from "node:http";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CapabilityHistoryBroker } from "./broker";
import { startCapabilityHistoryUnixServer, type CapabilityHistoryUnixServer } from "./unix-server";

let running: CapabilityHistoryUnixServer | undefined;
afterEach(async () => {
  await running?.close();
  running = undefined;
});

function get(socketPath: string, path: string, authorization?: string): Promise<{ status: number; body: Uint8Array; contentType?: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath, path, headers: authorization ? { authorization } : {} }, (res) => {
      const chunks: Uint8Array[] = [];
      res.on("data", (chunk: Uint8Array) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode!, body: Buffer.concat(chunks), contentType: res.headers["content-type"] }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("Unix capability transport", () => {
  test("serves only artifact-id reads with an opaque capability", async () => {
    const socketPath = join(tmpdir(), `capability-history-${process.pid}-${Date.now()}.sock`);
    const bytes = new TextEncoder().encode("synthetic public transcript");
    const broker = new CapabilityHistoryBroker({
      source: { async read(id) { return id === "artifact-1" ? { bytes, revision: "r1", digest: "sha256:synthetic", observedAt: "2026-09-09T12:00:00.000Z" } : null; } },
      now: () => new Date("2026-09-09T12:00:00.000Z"),
      randomBytes: () => new Uint8Array(32).fill(7),
    });
    broker.registerFlow({ id: "flow", createdAt: "2026-09-09T12:00:00.000Z" });
    broker.registerArtifact({ id: "artifact-1", flowId: "flow", kind: "transcript", contentType: "text/plain", expectedRevision: "r1" });
    const token = broker.issue({ issuerIdentity: "authority", subjectIdentity: "gateway", audience: "desktop", anchorFlowId: "flow", scopes: ["artifact:read"], artifactKinds: ["transcript"], pastDepth: 0, futureDepth: 0, expiresAt: "2026-09-09T13:00:00.000Z" });

    running = await startCapabilityHistoryUnixServer({
      mode: "synthetic",
      socketPath,
      broker,
      principal: { identity: "gateway", audience: "desktop" },
    });
    const denied = await get(socketPath, "/v1/artifacts/artifact-1");
    expect(denied.status).toBe(401);
    const response = await get(socketPath, "/v1/artifacts/artifact-1", `Capability ${token}`);
    expect(response).toEqual({ status: 200, body: bytes, contentType: "text/plain" });
    const noPaths = await get(socketPath, "/v1/artifacts/by-path?path=/tmp/private", `Capability ${token}`);
    expect(noPaths.status).toBe(404);
    rmSync(socketPath, { force: true });
  });
});
