import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { FIXTURE_V1_LOCAL } from "@plannotator/core/guide-format-fixtures";
import { CapabilityHistoryBroker, CapabilityHistoryError } from "./broker";
import type { ArtifactRead, ArtifactSource } from "./model";

const GUIDE_BYTES = new TextEncoder().encode(JSON.stringify(FIXTURE_V1_LOCAL));

class WitnessSource implements ArtifactSource {
  calls: string[] = [];
  revision = "guide-r1";

  async read(artifactId: string): Promise<ArtifactRead | null> {
    this.calls.push(`read:${artifactId}`);
    if (artifactId !== "guide-public-fixture") return null;
    return {
      bytes: GUIDE_BYTES,
      revision: this.revision,
      digest: `sha256:${createHash("sha256").update(GUIDE_BYTES).digest("hex")}`,
      observedAt: "2026-09-09T12:00:00.000Z",
    };
  }

  async attest(artifactId: string) {
    this.calls.push(`attest:${artifactId}`);
    if (artifactId !== "guide-public-fixture") return null;
    return {
      revision: this.revision,
      digest: `sha256:${createHash("sha256").update(GUIDE_BYTES).digest("hex")}`,
      observedAt: "2026-09-09T12:00:00.000Z",
    };
  }
}

function setup() {
  const source = new WitnessSource();
  let nonce = 0;
  const broker = new CapabilityHistoryBroker({
    source,
    now: () => new Date("2026-09-09T12:00:00.000Z"),
    randomBytes: () => new Uint8Array(32).fill(++nonce),
  });
  broker.registerFlow({ id: "past", createdAt: "2026-09-09T10:00:00.000Z" });
  broker.registerFlow({ id: "present", predecessorId: "past", relation: "succession", createdAt: "2026-09-09T11:00:00.000Z" });
  broker.registerFlow({ id: "future", predecessorId: "present", relation: "succession", createdAt: "2026-09-09T13:00:00.000Z" });
  broker.registerArtifact({
    id: "guide-public-fixture",
    flowId: "past",
    kind: "transcript",
    contentType: "application/json",
    expectedRevision: "guide-r1",
  });
  const token = broker.issue({
    issuerIdentity: "authority",
    subjectIdentity: "terra-present",
    audience: "desktop-gateway",
    anchorFlowId: "present",
    scopes: ["artifact:read", "lineage:read", "child:issue"],
    artifactKinds: ["transcript", "cache", "log", "prompt"],
    pastDepth: 1,
    futureDepth: 1,
    expiresAt: "2026-09-09T14:00:00.000Z",
  });
  return { broker, source, token };
}

describe("CapabilityHistoryBroker", () => {
  test("authorizes before touching the source and preserves guide bytes", async () => {
    const { broker, source, token } = setup();

    await expect(broker.readArtifact("not-a-token", { identity: "terra-present", audience: "desktop-gateway" }, "guide-public-fixture"))
      .rejects.toMatchObject({ code: "invalid_capability" });
    await expect(broker.readArtifact(token, { identity: "terra-present", audience: "other" }, "guide-public-fixture"))
      .rejects.toMatchObject({ code: "audience_mismatch" });
    expect(source.calls).toEqual([]);

    const read = await broker.readArtifact(token, { identity: "terra-present", audience: "desktop-gateway" }, "guide-public-fixture");
    expect(read.bytes).toEqual(GUIDE_BYTES);
    expect(JSON.parse(new TextDecoder().decode(read.bytes))).toEqual(FIXTURE_V1_LOCAL);
    expect(read.attestation.fresh).toBe(true);
    expect(source.calls).toEqual(["read:guide-public-fixture"]);
  });

  test("maps only the authorized past, present, and future and attests current state", async () => {
    const { broker, source, token } = setup();
    const history = await broker.reconstruct(token, { identity: "terra-present", audience: "desktop-gateway" }, { attest: true });

    expect(history.nodes.map((node) => node.id)).toEqual(["past", "present", "future"]);
    expect(history.ascii).toBe("past\n`- present [current]\n   `- future");
    expect(history.artifacts).toEqual([
      expect.objectContaining({ artifactId: "guide-public-fixture", flowId: "past", fresh: true, revision: "guide-r1" }),
    ]);
    expect(source.calls).toEqual(["attest:guide-public-fixture"]);
  });

  test("a future child receives a narrower capability and parent revocation reaches it", async () => {
    const { broker, source, token } = setup();
    const child = broker.inheritToChild(token, { identity: "terra-present", audience: "desktop-gateway" }, {
      childFlowId: "future",
      subjectIdentity: "terra-future",
      audience: "future-gateway",
      scopes: ["artifact:read"],
      artifactKinds: ["transcript"],
      pastDepth: 2,
      futureDepth: 0,
      expiresAt: "2026-09-09T13:00:00.000Z",
    });

    const read = await broker.readArtifact(child, { identity: "terra-future", audience: "future-gateway" }, "guide-public-fixture");
    expect(read.bytes).toEqual(GUIDE_BYTES);
    broker.revoke(token);
    await expect(broker.readArtifact(child, { identity: "terra-future", audience: "future-gateway" }, "guide-public-fixture"))
      .rejects.toMatchObject({ code: "revoked" });
    expect(source.calls).toEqual(["read:guide-public-fixture"]);
  });

  test("refuses child authority that is broader than its parent", () => {
    const { broker, token } = setup();
    expect(() => broker.inheritToChild(token, { identity: "terra-present", audience: "desktop-gateway" }, {
      childFlowId: "future",
      subjectIdentity: "terra-future",
      audience: "future-gateway",
      scopes: ["artifact:read", "lineage:read", "child:issue"],
      artifactKinds: ["transcript"],
      pastDepth: 3,
      futureDepth: 0,
      expiresAt: "2026-09-09T13:00:00.000Z",
    })).toThrow(CapabilityHistoryError);
  });
});
