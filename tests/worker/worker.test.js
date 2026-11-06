import { describe, expect, it, vi } from "vitest";
import worker, {
  NodeResponseAdapter,
  toNodeRequest,
} from "../../worker/index.js";

function createEnv() {
  return {
    ASSETS: {
      fetch: vi.fn(async () => {
        return new Response("<!doctype html><title>Doriya</title>", {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }),
    },
  };
}

describe("Cloudflare Worker entry", () => {
  it("serves static assets through the assets binding", async () => {
    const env = createEnv();
    const response = await worker.fetch(
      new Request("https://2fa.example.com/"),
      env,
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Doriya");
    expect(env.ASSETS.fetch).toHaveBeenCalledOnce();
    expect(response.headers.get("Content-Security-Policy")).toContain(
      "frame-ancestors 'none'",
    );
    expect(response.headers.get("Strict-Transport-Security")).toContain(
      "max-age=63072000",
    );
  });

  it("routes API requests through the existing backend handler", async () => {
    const env = createEnv();
    const response = await worker.fetch(
      new Request("https://2fa.example.com/api/auth/session"),
      env,
    );
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(payload).toMatchObject({
      configured: false,
      authenticated: false,
    });
    expect(response.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(env.ASSETS.fetch).not.toHaveBeenCalled();
  });

  it("returns a JSON 404 for unknown API routes", async () => {
    const env = createEnv();
    const response = await worker.fetch(
      new Request("https://2fa.example.com/api/not-a-route"),
      env,
    );

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "not_found" },
    });
  });
});

describe("Node request and response adapters", () => {
  it("normalizes request headers and body for the backend", async () => {
    const request = new Request("https://2fa.example.com/api/github/vault", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    });
    const nodeRequest = await toNodeRequest(request);

    expect(nodeRequest.method).toBe("PUT");
    expect(nodeRequest.url).toBe("https://2fa.example.com/api/github/vault");
    expect(nodeRequest.headers.host).toBe("2fa.example.com");
    expect(nodeRequest.headers["x-forwarded-proto"]).toBe("https");
    expect(nodeRequest.body.toString("utf8")).toBe('{"hello":"world"}');
  });

  it("preserves multiple Set-Cookie headers in a Fetch response", async () => {
    const adapter = new NodeResponseAdapter();
    adapter.statusCode = 302;
    adapter.setHeader("Location", "/");
    adapter.setHeader("Set-Cookie", ["one=1; Path=/", "two=2; Path=/"]);
    adapter.end();

    const response = adapter.toResponse();
    const cookies = response.headers
      .get("set-cookie")
      .split(/,\s*(?=[^;,]+=)/);

    expect(response.status).toBe(302);
    expect(cookies).toHaveLength(2);
    expect(cookies[0]).toContain("one=1");
    expect(cookies[1]).toContain("two=2");
  });
});
