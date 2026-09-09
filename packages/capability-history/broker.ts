import { createHash, timingSafeEqual } from "node:crypto";
import type {
  ArtifactAttestation,
  ArtifactDescriptor,
  ArtifactKind,
  ArtifactRead,
  ArtifactSource,
  AuthorizedHistory,
  CapabilityScope,
  FlowNode,
  InheritCapability,
  IssueCapability,
  Principal,
} from "./model";

export type CapabilityHistoryErrorCode =
  | "invalid_capability"
  | "identity_mismatch"
  | "audience_mismatch"
  | "expired"
  | "revoked"
  | "scope_denied"
  | "resource_denied"
  | "not_found"
  | "invalid_lineage"
  | "not_attenuated"
  | "stale_source";

export class CapabilityHistoryError extends Error {
  constructor(readonly code: CapabilityHistoryErrorCode, message: string) {
    super(message);
    this.name = "CapabilityHistoryError";
  }
}

interface CapabilityRecord {
  readonly id: string;
  readonly parentId?: string;
  readonly issuerIdentity: string;
  readonly subjectIdentity: string;
  readonly audience: string;
  readonly anchorFlowId: string;
  readonly scopes: ReadonlySet<CapabilityScope>;
  readonly artifactKinds: ReadonlySet<ArtifactKind>;
  readonly artifactIds?: ReadonlySet<string>;
  readonly pastDepth: number;
  readonly futureDepth: number;
  readonly expiresAtMs: number;
  revoked: boolean;
}

export interface CapabilityHistoryBrokerOptions {
  readonly source: ArtifactSource;
  readonly now?: () => Date;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly maxArtifactBytes?: number;
}

function defaultRandomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function tokenDigest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function opaqueToken(bytes: Uint8Array): string {
  return `chv1.${Buffer.from(bytes).toString("base64url")}`;
}

function finiteDepth(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new CapabilityHistoryError("not_attenuated", `${field} must be a non-negative integer`);
  return value;
}

function expiryMs(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new CapabilityHistoryError("not_attenuated", "expiresAt must be an ISO timestamp");
  return parsed;
}

function subset<T>(child: ReadonlySet<T>, parent: ReadonlySet<T>): boolean {
  for (const item of child) if (!parent.has(item)) return false;
  return true;
}

export class CapabilityHistoryBroker {
  private readonly source: ArtifactSource;
  private readonly now: () => Date;
  private readonly randomBytes: (size: number) => Uint8Array;
  private readonly maxArtifactBytes: number;
  private readonly capabilities = new Map<string, CapabilityRecord>();
  private readonly flows = new Map<string, FlowNode>();
  private readonly artifacts = new Map<string, ArtifactDescriptor>();

  constructor(options: CapabilityHistoryBrokerOptions) {
    this.source = options.source;
    this.now = options.now ?? (() => new Date());
    this.randomBytes = options.randomBytes ?? defaultRandomBytes;
    this.maxArtifactBytes = options.maxArtifactBytes ?? 8 * 1024 * 1024;
    if (!Number.isSafeInteger(this.maxArtifactBytes) || this.maxArtifactBytes < 1) throw new Error("maxArtifactBytes must be a positive integer");
  }

  registerFlow(node: FlowNode): void {
    if (!node.id || this.flows.has(node.id)) throw new CapabilityHistoryError("invalid_lineage", `flow already exists or has no id: ${node.id}`);
    if (node.predecessorId) {
      if (!this.flows.has(node.predecessorId)) throw new CapabilityHistoryError("invalid_lineage", "predecessor must be registered first");
      if (!node.relation) throw new CapabilityHistoryError("invalid_lineage", "a child flow requires its relation");
    } else if (node.relation) {
      throw new CapabilityHistoryError("invalid_lineage", "a root flow cannot declare a relation");
    }
    this.flows.set(node.id, Object.freeze({ ...node }));
  }

  registerArtifact(descriptor: ArtifactDescriptor): void {
    if (!this.flows.has(descriptor.flowId)) throw new CapabilityHistoryError("invalid_lineage", "artifact flow is unknown");
    if (!descriptor.id || this.artifacts.has(descriptor.id)) throw new CapabilityHistoryError("invalid_lineage", "artifact id must be unique");
    this.artifacts.set(descriptor.id, Object.freeze({ ...descriptor }));
  }

  issue(input: IssueCapability): string {
    if (!this.flows.has(input.anchorFlowId)) throw new CapabilityHistoryError("invalid_lineage", "capability anchor flow is unknown");
    return this.storeCapability({
      ...input,
      scopes: new Set(input.scopes),
      artifactKinds: new Set(input.artifactKinds),
      artifactIds: input.artifactIds ? new Set(input.artifactIds) : undefined,
      pastDepth: finiteDepth(input.pastDepth, "pastDepth"),
      futureDepth: finiteDepth(input.futureDepth, "futureDepth"),
      expiresAtMs: expiryMs(input.expiresAt),
      revoked: false,
    });
  }

  inheritToChild(token: string, principal: Principal, input: InheritCapability): string {
    const parent = this.authorize(token, principal, "child:issue");
    const childNode = this.flows.get(input.childFlowId);
    if (!childNode || childNode.predecessorId !== parent.anchorFlowId) {
      throw new CapabilityHistoryError("invalid_lineage", "capability may pass only to a registered direct child");
    }
    if (input.subjectIdentity !== parent.subjectIdentity || input.audience !== parent.audience) {
      throw new CapabilityHistoryError("not_attenuated", "child identity and audience must remain bound to the parent gateway");
    }
    const scopes = new Set(input.scopes);
    const kinds = new Set(input.artifactKinds);
    const artifactIds = input.artifactIds ? new Set(input.artifactIds) : undefined;
    const childExpiry = expiryMs(input.expiresAt);
    if (!subset(scopes, parent.scopes) || !subset(kinds, parent.artifactKinds)) {
      throw new CapabilityHistoryError("not_attenuated", "child scope and artifact kinds must be subsets of the parent");
    }
    if (parent.artifactIds && (!artifactIds || !subset(artifactIds, parent.artifactIds))) {
      throw new CapabilityHistoryError("not_attenuated", "child artifact resources must be a subset of the parent");
    }
    const pastDepth = finiteDepth(input.pastDepth, "pastDepth");
    const futureDepth = finiteDepth(input.futureDepth, "futureDepth");
    // Moving the anchor one edge forward makes one additional ancestor reachable.
    if (pastDepth > parent.pastDepth + 1 || futureDepth > Math.max(0, parent.futureDepth - 1) || childExpiry > parent.expiresAtMs) {
      throw new CapabilityHistoryError("not_attenuated", "child lineage depth and expiry must not exceed inherited authority");
    }
    return this.storeCapability({
      id: "",
      parentId: parent.id,
      issuerIdentity: parent.subjectIdentity,
      subjectIdentity: input.subjectIdentity,
      audience: input.audience,
      anchorFlowId: input.childFlowId,
      scopes,
      artifactKinds: kinds,
      artifactIds,
      pastDepth,
      futureDepth,
      expiresAtMs: childExpiry,
      revoked: false,
    });
  }

  revoke(token: string): void {
    const record = this.lookup(token);
    record.revoked = true;
  }

  async readArtifact(token: string, principal: Principal, artifactId: string): Promise<ArtifactRead & { readonly contentType: string; readonly attestation: ArtifactAttestation }> {
    const capability = this.authorize(token, principal, "artifact:read");
    const descriptor = this.authorizeArtifact(capability, artifactId);
    const read = await this.source.read(artifactId, { maxBytes: this.maxArtifactBytes });
    if (!read) throw new CapabilityHistoryError("not_found", "authorized artifact is absent from its source");
    if (read.bytes.byteLength > this.maxArtifactBytes) throw new CapabilityHistoryError("resource_denied", "artifact source exceeded its byte limit");
    const fresh = read.revision === descriptor.expectedRevision;
    if (!fresh) throw new CapabilityHistoryError("stale_source", "artifact source revision differs from the registered revision");
    return {
      ...read,
      contentType: descriptor.contentType,
      attestation: { artifactId, flowId: descriptor.flowId, revision: read.revision, digest: read.digest, observedAt: read.observedAt, fresh },
    };
  }

  async reconstruct(token: string, principal: Principal, options: { readonly attest?: boolean } = {}): Promise<AuthorizedHistory> {
    const capability = this.authorize(token, principal, "lineage:read");
    const nodes = this.authorizedNodes(capability);
    const nodeIds = new Set(nodes.map((node) => node.id));
    const descriptors = [...this.artifacts.values()].filter((artifact) => nodeIds.has(artifact.flowId) && this.artifactAllowed(capability, artifact));
    const attestations: ArtifactAttestation[] = [];
    if (options.attest) {
      for (const descriptor of descriptors) {
        const state = this.source.attest
          ? await this.source.attest(descriptor.id)
          : await this.source.read(descriptor.id, { maxBytes: this.maxArtifactBytes });
        if (!state) continue;
        attestations.push({
          artifactId: descriptor.id,
          flowId: descriptor.flowId,
          revision: state.revision,
          digest: state.digest,
          observedAt: state.observedAt,
          fresh: state.revision === descriptor.expectedRevision,
        });
      }
    }
    return { currentFlowId: capability.anchorFlowId, nodes, artifacts: attestations, ascii: this.ascii(nodes, capability.anchorFlowId) };
  }

  private storeCapability(input: Omit<CapabilityRecord, "id"> & { readonly id?: string }): string {
    let token = "";
    let id = "";
    do {
      token = opaqueToken(this.randomBytes(32));
      id = tokenDigest(token);
    } while (this.capabilities.has(id));
    this.capabilities.set(id, { ...input, id });
    return token;
  }

  private lookup(token: string): CapabilityRecord {
    if (!token.startsWith("chv1.")) throw new CapabilityHistoryError("invalid_capability", "capability is malformed or unknown");
    const candidate = tokenDigest(token);
    let found: CapabilityRecord | undefined;
    // Equal work for all retained records; tokens themselves are never stored.
    for (const [digest, record] of this.capabilities) {
      if (timingSafeEqual(Buffer.from(digest, "hex"), Buffer.from(candidate, "hex"))) found = record;
    }
    if (!found) throw new CapabilityHistoryError("invalid_capability", "capability is malformed or unknown");
    return found;
  }

  private authorize(token: string, principal: Principal, scope: CapabilityScope): CapabilityRecord {
    const record = this.lookup(token);
    if (record.subjectIdentity !== principal.identity) throw new CapabilityHistoryError("identity_mismatch", "capability identity does not match the trusted peer");
    if (record.audience !== principal.audience) throw new CapabilityHistoryError("audience_mismatch", "capability audience does not match this broker socket");
    if (this.now().getTime() >= record.expiresAtMs) throw new CapabilityHistoryError("expired", "capability expired");
    let cursor: CapabilityRecord | undefined = record;
    while (cursor) {
      if (cursor.revoked) throw new CapabilityHistoryError("revoked", "capability or an ancestor was revoked");
      cursor = cursor.parentId ? this.capabilities.get(cursor.parentId) : undefined;
    }
    if (!record.scopes.has(scope)) throw new CapabilityHistoryError("scope_denied", `capability lacks ${scope}`);
    return record;
  }

  private authorizeArtifact(capability: CapabilityRecord, artifactId: string): ArtifactDescriptor {
    const descriptor = this.artifacts.get(artifactId);
    // Do not distinguish an unknown artifact from one outside the capability.
    if (!descriptor || !this.artifactAllowed(capability, descriptor)) {
      throw new CapabilityHistoryError("resource_denied", "artifact is outside capability authority");
    }
    return descriptor;
  }

  private artifactAllowed(capability: CapabilityRecord, descriptor: ArtifactDescriptor): boolean {
    return capability.artifactKinds.has(descriptor.kind)
      && (!capability.artifactIds || capability.artifactIds.has(descriptor.id))
      && this.relativePosition(capability.anchorFlowId, descriptor.flowId, capability.pastDepth, capability.futureDepth) !== undefined;
  }

  private authorizedNodes(capability: CapabilityRecord): Array<FlowNode & { position: "past" | "present" | "future" }> {
    const result: Array<FlowNode & { position: "past" | "present" | "future"; distance: number }> = [];
    for (const node of this.flows.values()) {
      const relative = this.relativePosition(capability.anchorFlowId, node.id, capability.pastDepth, capability.futureDepth);
      if (relative) result.push({ ...node, ...relative });
    }
    result.sort((a, b) => {
      const rank = { past: 0, present: 1, future: 2 } as const;
      return rank[a.position] - rank[b.position] || (a.position === "past" ? b.distance - a.distance : a.distance - b.distance) || a.id.localeCompare(b.id);
    });
    return result.map(({ distance: _distance, ...node }) => node);
  }

  private relativePosition(anchorId: string, candidateId: string, pastDepth: number, futureDepth: number): { position: "past" | "present" | "future"; distance: number } | undefined {
    if (anchorId === candidateId) return { position: "present", distance: 0 };
    let distance = 0;
    let cursor = this.flows.get(anchorId);
    while (cursor?.predecessorId && distance < pastDepth) {
      distance += 1;
      if (cursor.predecessorId === candidateId) return { position: "past", distance };
      cursor = this.flows.get(cursor.predecessorId);
    }
    distance = 0;
    cursor = this.flows.get(candidateId);
    while (cursor?.predecessorId && distance < futureDepth) {
      distance += 1;
      if (cursor.predecessorId === anchorId) return { position: "future", distance };
      cursor = this.flows.get(cursor.predecessorId);
    }
    return undefined;
  }

  private ascii(nodes: readonly (FlowNode & { readonly position: "past" | "present" | "future" })[], current: string): string {
    const ids = new Set(nodes.map((node) => node.id));
    const children = new Map<string, string[]>();
    for (const node of nodes) {
      if (node.predecessorId && ids.has(node.predecessorId)) {
        const list = children.get(node.predecessorId) ?? [];
        list.push(node.id);
        children.set(node.predecessorId, list);
      }
    }
    const roots = nodes.filter((node) => !node.predecessorId || !ids.has(node.predecessorId)).map((node) => node.id);
    const lines: string[] = [];
    const draw = (id: string, prefix: string, branch: string) => {
      lines.push(`${prefix}${branch}${id}${id === current ? " [current]" : ""}`);
      const next = (children.get(id) ?? []).sort();
      next.forEach((child, index) => draw(child, `${prefix}${branch ? "   " : ""}`, index === next.length - 1 ? "`- " : "+- "));
    };
    roots.sort().forEach((root) => draw(root, "", ""));
    return lines.join("\n");
  }
}
