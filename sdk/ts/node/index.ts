// revkit API client for Node: Connect, gRPC-web or gRPC over TLS, trusting a
// CA file or a self-signed rk-daemon certificate pinned by its SHA-256
// fingerprint, with a bearer token (docs/security.md).
//
//   import { nodeTransport } from "@revkit/api/node";
//   const rk = createRevkit(await nodeTransport({ baseUrl: "https://host:50052", token, fingerprint }));
//
// Defaults come from RK_TOKEN (or RK_TOKEN_FILE), RK_TLS_CA and
// RK_TLS_FINGERPRINT, as in the Python SDK.
import { createConnectTransport, createGrpcTransport, createGrpcWebTransport } from "@connectrpc/connect-node";
import type { Transport } from "@connectrpc/connect";
import { readFileSync } from "node:fs";
import { connect as tlsConnect, type PeerCertificate } from "node:tls";

import { credentialsInterceptor } from "../src/index";

export interface NodeTransportOptions {
  /** https://host:port (HTTP gateway) or, with protocol "grpc", the gRPC port. */
  baseUrl: string;
  protocol?: "connect" | "grpc-web" | "grpc";
  useBinaryFormat?: boolean;
  token?: string;
  /** PEM file with the CA (or the self-signed certificate) to trust. */
  ca?: string;
  /** Pin the server's certificate by SHA-256 ("AB:CD:..."); it is then the only root. */
  fingerprint?: string;
}

function normalize(f: string): string {
  return f.replace(/^sha256:/i, "").replace(/[: ]/g, "").toUpperCase();
}

function toPem(cert: PeerCertificate): string {
  const b64 = cert.raw.toString("base64").replace(/(.{64})/g, "$1\n");
  return `-----BEGIN CERTIFICATE-----\n${b64.trim()}\n-----END CERTIFICATE-----\n`;
}

/** The certificate the TLS server at host:port presents, unverified (to pin it). */
export function fetchCertificate(host: string, port: number): Promise<PeerCertificate> {
  return new Promise((resolve, reject) => {
    const s = tlsConnect({ host, port, rejectUnauthorized: false, ALPNProtocols: ["h2", "http/1.1"], servername: /^[\d.:]+$/.test(host) ? undefined : host }, () => {
      const c = s.getPeerCertificate(false);
      s.end();
      resolve(c);
    });
    s.setTimeout(5000, () => s.destroy(new Error(`TLS to ${host}:${port} timed out`)));
    s.on("error", reject);
  });
}

/** A transport for Node with credentials and TLS options. */
export async function nodeTransport(o: NodeTransportOptions): Promise<Transport> {
  const token = o.token ?? process.env.RK_TOKEN ?? (process.env.RK_TOKEN_FILE ? readFileSync(process.env.RK_TOKEN_FILE, "utf8").split("\n")[0].trim() : undefined);
  const fingerprint = o.fingerprint ?? process.env.RK_TLS_FINGERPRINT;
  const caFile = o.ca ?? process.env.RK_TLS_CA;
  const url = new URL(o.baseUrl);
  const nodeOptions: Record<string, unknown> = {};
  if (url.protocol === "https:") {
    if (fingerprint) {
      const cert = await fetchCertificate(url.hostname, Number(url.port || 443));
      if (normalize(cert.fingerprint256) !== normalize(fingerprint))
        throw new Error(`${url.host} presents certificate ${cert.fingerprint256}, not the pinned ${fingerprint}`);
      // The pinned certificate is the only root; its names don't matter.
      nodeOptions.ca = toPem(cert);
      nodeOptions.checkServerIdentity = () => undefined;
    } else if (caFile) {
      nodeOptions.ca = readFileSync(caFile, "utf8");
    }
  }
  const interceptors = [credentialsInterceptor({ token })];
  const protocol = o.protocol ?? "connect";
  if (protocol === "grpc") return createGrpcTransport({ baseUrl: o.baseUrl, interceptors, nodeOptions });
  if (protocol === "grpc-web") return createGrpcWebTransport({ baseUrl: o.baseUrl, httpVersion: "1.1", interceptors, nodeOptions });
  return createConnectTransport({ baseUrl: o.baseUrl, httpVersion: "1.1", useBinaryFormat: o.useBinaryFormat, interceptors, nodeOptions });
}
