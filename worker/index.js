import { Buffer } from "node:buffer";

import { createApiHandler } from "../server/api.js";

const SECURITY_HEADERS = Object.freeze({
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src blob:; font-src 'self'; connect-src 'self'; form-action 'self' https://github.com; frame-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Origin-Agent-Cluster": "?1",
  "X-Permitted-Cross-Domain-Policies": "none",
});

let cachedEnv = null;
let cachedApiHandler = null;

function getApiHandler(env) {
  if (!cachedApiHandler || cachedEnv !== env) {
    cachedEnv = env;
    cachedApiHandler = createApiHandler({ env });
  }
  return cachedApiHandler;
}

function isApiRequest(url) {
  return url.pathname === "/api" || url.pathname.startsWith("/api/");
}

export async function toNodeRequest(request) {
  const url = new URL(request.url);
  const headers = {};

  for (const [name, value] of request.headers) {
    headers[name.toLowerCase()] = value;
  }
  headers.host ||= url.host;
  headers["x-forwarded-proto"] ||= url.protocol.slice(0, -1);

  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  return {
    method: request.method,
    url: request.url,
    headers,
    body: hasBody ? Buffer.from(await request.arrayBuffer()) : undefined,
    socket: { encrypted: url.protocol === "https:" },
  };
}

export class NodeResponseAdapter {
  constructor() {
    this.statusCode = 200;
    this.headers = new Map();
    this.chunks = [];
  }

  setHeader(name, value) {
    const normalizedName = String(name).toLowerCase();
    const normalizedValue = Array.isArray(value)
      ? value.map((item) => String(item))
      : [String(value)];
    const current = this.headers.get(normalizedName);

    if (normalizedName === "set-cookie" && current) {
      current.values.push(...normalizedValue);
      return;
    }
    this.headers.set(normalizedName, {
      name: String(name),
      values: normalizedValue,
    });
  }

  end(chunk) {
    if (chunk !== undefined && chunk !== null) {
      this.chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
  }

  toResponse() {
    const headers = new Headers();
    for (const { name, values } of this.headers.values()) {
      if (name.toLowerCase() === "set-cookie") {
        for (const value of values) {
          headers.append(name, value);
        }
      } else if (values.length > 0) {
        headers.set(name, values.join(", "));
      }
    }

    const canHaveBody =
      this.statusCode !== 204 &&
      this.statusCode !== 205 &&
      this.statusCode !== 304;
    const body =
      canHaveBody && this.chunks.length > 0
        ? Buffer.concat(this.chunks)
        : null;

    return new Response(body, {
      status: this.statusCode,
      headers,
    });
  }
}

export function applySecurityHeaders(response, url = null) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) {
      headers.set(name, value);
    }
  }
  if (url?.protocol === "https:" && !headers.has("Strict-Transport-Security")) {
    headers.set(
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains; preload",
    );
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function handleApiRequest(request, env) {
  const nodeRequest = await toNodeRequest(request);
  const nodeResponse = new NodeResponseAdapter();
  await getApiHandler(env)(nodeRequest, nodeResponse);
  return nodeResponse.toResponse();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      const response = isApiRequest(url)
        ? await handleApiRequest(request, env)
        : await env.ASSETS.fetch(request);
      return applySecurityHeaders(response, url);
    } catch (error) {
      console.error("[worker] Request failed", error);
      const response = new Response(
        JSON.stringify({
          error: {
            code: "internal_error",
            message: "An unexpected server error occurred.",
          },
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json; charset=utf-8" },
        },
      );
      return applySecurityHeaders(response, url);
    }
  },
};
