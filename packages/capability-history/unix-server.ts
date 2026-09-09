import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { CapabilityHistoryBroker } from "./broker";
import { CapabilityHistoryError } from "./broker";
import type { Principal } from "./model";
import { assertPrivateAuthorityIsolation, type PrivateAuthorityIsolation } from "./private-authority";

export interface CapabilityHistoryUnixServer {
  readonly socketPath: string;
  close(): Promise<void>;
}

type ServerMode =
  | { readonly mode: "synthetic" }
  | { readonly mode: "private"; readonly isolation: PrivateAuthorityIsolation };

export type StartCapabilityHistoryUnixServerOptions = ServerMode & {
  readonly socketPath: string;
  readonly broker: CapabilityHistoryBroker;
  /** Identity bound to this broker socket by its authority; no request header can replace it. */
  readonly principal: Principal;
  readonly maxHeaderBytes?: number;
};

function capabilityToken(req: IncomingMessage): string | null {
  const value = req.headers.authorization;
  if (!value || Array.isArray(value)) return null;
  const match = /^Capability (chv1\.[A-Za-z0-9_-]{43})$/.exec(value);
  return match?.[1] ?? null;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const encoded = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "content-type": "application/json", "content-length": encoded.byteLength, "cache-control": "no-store" });
  res.end(encoded);
}

function errorStatus(error: CapabilityHistoryError): number {
  if (error.code === "invalid_capability") return 401;
  if (error.code === "not_found") return 404;
  if (error.code === "stale_source") return 409;
  return 403;
}

async function handle(options: StartCapabilityHistoryUnixServerOptions, req: IncomingMessage, res: ServerResponse): Promise<void> {
  res.setHeader("cache-control", "no-store");
  if (req.method !== "GET") return json(res, 405, { error: "method_not_allowed" });
  if (req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined) return json(res, 413, { error: "request_body_denied" });
  if ((req.url?.length ?? 0) > 2048) return json(res, 414, { error: "uri_too_long" });
  const token = capabilityToken(req);
  if (!token) return json(res, 401, { error: "invalid_capability" });
  const url = new URL(req.url ?? "/", "http://broker.invalid");
  const artifactMatch = /^\/v1\/artifacts\/([^/]+)$/.exec(url.pathname);
  try {
    if (artifactMatch) {
      const artifactId = decodeURIComponent(artifactMatch[1]);
      const read = await options.broker.readArtifact(token, options.principal, artifactId);
      res.writeHead(200, {
        "content-type": read.contentType,
        "content-length": read.bytes.byteLength,
        etag: `\"${read.digest}\"`,
        "x-capability-revision": read.revision,
      });
      return res.end(read.bytes);
    }
    if (url.pathname === "/v1/lineage/current") {
      const history = await options.broker.reconstruct(token, options.principal, { attest: url.searchParams.get("attest") === "1" });
      return json(res, 200, history);
    }
    return json(res, 404, { error: "not_found" });
  } catch (error) {
    if (error instanceof CapabilityHistoryError) return json(res, errorStatus(error), { error: error.code });
    return json(res, 500, { error: "authority_failure" });
  }
}

export async function startCapabilityHistoryUnixServer(options: StartCapabilityHistoryUnixServerOptions): Promise<CapabilityHistoryUnixServer> {
  if (!options.socketPath.startsWith("/")) throw new Error("broker socket path must be absolute");
  if (options.mode === "private") {
    assertPrivateAuthorityIsolation(options.isolation);
    throw new Error("private Unix serving is disabled until the runtime supplies verified OS peer credentials");
  }
  const server: Server = createServer({ maxHeaderSize: options.maxHeaderBytes ?? 8 * 1024 }, (req, res) => {
    void handle(options, req, res);
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  server.keepAliveTimeout = 1_000;
  server.maxRequestsPerSocket = 100;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return {
    socketPath: options.socketPath,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    }),
  };
}
