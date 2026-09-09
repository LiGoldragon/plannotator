export type ArtifactKind = "transcript" | "cache" | "log" | "prompt";
export type CapabilityScope = "artifact:read" | "lineage:read" | "child:issue";
export type FlowRelation = "delegation" | "succession";

export interface Principal {
  readonly identity: string;
  readonly audience: string;
}

export interface FlowNode {
  readonly id: string;
  readonly predecessorId?: string;
  readonly relation?: FlowRelation;
  readonly createdAt: string;
}

export interface ArtifactDescriptor {
  readonly id: string;
  readonly flowId: string;
  readonly kind: ArtifactKind;
  readonly contentType: string;
  readonly expectedRevision: string;
}

export interface ArtifactState {
  readonly revision: string;
  readonly digest: string;
  readonly observedAt: string;
}

export interface ArtifactRead extends ArtifactState {
  readonly bytes: Uint8Array;
}

/** Implemented inside the broker authority. It must never be sent to a worker. */
export interface ArtifactSource {
  /** Implementations must enforce maxBytes before allocating or reading content. */
  read(artifactId: string, limits: { readonly maxBytes: number }): Promise<ArtifactRead | null>;
  attest?(artifactId: string): Promise<ArtifactState | null>;
}

export interface IssueCapability {
  readonly issuerIdentity: string;
  readonly subjectIdentity: string;
  readonly audience: string;
  readonly anchorFlowId: string;
  readonly scopes: readonly CapabilityScope[];
  readonly artifactKinds: readonly ArtifactKind[];
  readonly artifactIds?: readonly string[];
  readonly pastDepth: number;
  readonly futureDepth: number;
  readonly expiresAt: string;
}

export interface InheritCapability {
  readonly childFlowId: string;
  readonly subjectIdentity: string;
  readonly audience: string;
  readonly scopes: readonly CapabilityScope[];
  readonly artifactKinds: readonly ArtifactKind[];
  readonly artifactIds?: readonly string[];
  readonly pastDepth: number;
  readonly futureDepth: number;
  readonly expiresAt: string;
}

export interface ArtifactAttestation extends ArtifactState {
  readonly artifactId: string;
  readonly flowId: string;
  readonly fresh: boolean;
}

export interface AuthorizedHistory {
  readonly currentFlowId: string;
  readonly nodes: readonly (FlowNode & { readonly position: "past" | "present" | "future" })[];
  readonly artifacts: readonly ArtifactAttestation[];
  readonly ascii: string;
}
