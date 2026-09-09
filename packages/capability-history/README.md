# Capability history

`@plannotator/capability-history` lets an authority expose selected transcript,
cache, log, and prompt artifacts through opaque, attenuable capabilities. Tokens
are stored only as SHA-256 digests. Every token is bound to a gateway identity,
audience, lineage anchor, scope, artifact kind or exact artifact id, expiry, and
revocation ancestry.

The synthetic server is an end-to-end development witness. It listens on an
explicit Unix socket and exposes only:

```text
GET /v1/artifacts/{opaqueArtifactId}
Authorization: Capability chv1.<opaque-token>

GET /v1/lineage/current?attest=1
Authorization: Capability chv1.<opaque-token>
```

`ArtifactSource` belongs inside the authority process. Authorization completes
before `read` or `attest` is called. A source read returns the observed revision
and digest so the broker can reject stale state rather than trusting a timestamp
from a requested map.

Private file authority requires a broker process running under a different UID
from workers, broker-owned source and state paths with no group/world access,
and regular single-link files reached without symlinks. Private Unix serving is
currently fail-closed because Node/Bun does not expose Linux `SO_PEERCRED` on
accepted HTTP sockets. The fixed principal option is therefore available only
in explicit `synthetic` mode. A future private transport must supply witnessed
OS peer credentials before this gate can open.

Capability records are intentionally in memory: restarting the broker revokes
every issued token. The reusable package never discovers home directories,
transcripts, caches, or prompts; the external authority registers opaque ids and
provides their bytes.
