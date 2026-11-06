import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApiHandler } from "../../server/api.js";
import { createSession, encryptSession } from "../../server/session.js";

const NOW = 1_700_000_000_000;
const SESSION_SECRET = "test-session-secret-with-plenty-of-entropy";
const ACCESS_TOKEN = "ghu_test_access_token";
const REFRESH_TOKEN = "ghr_test_refresh_token";
const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const env = {
  GITHUB_APP_ID: "12345",
  GITHUB_APP_CLIENT_ID: "client-id",
  GITHUB_APP_CLIENT_SECRET: "client-secret",
  GITHUB_APP_PRIVATE_KEY: privateKey,
  GITHUB_APP_SLUG: "doriya-vault",
  SESSION_SECRET,
  APP_ORIGIN: "https://vault.example",
};

const user = {
  id: 101,
  login: "octocat",
  name: "Octo Cat",
  avatarUrl: "https://example.test/avatar.png",
};

let server;
let baseUrl;
let fakeFetch;

function sessionCookie({
  expiresAt = NOW + 60 * 60 * 1000,
  refreshToken = null,
  refreshTokenExpiresAt = null,
  accessToken = ACCESS_TOKEN,
} = {}) {
  const session = createSession({
    user,
    token: {
      accessToken,
      refreshToken,
      expiresAt,
      refreshTokenExpiresAt,
      scope: "",
      tokenType: "bearer",
    },
    now: NOW,
  });
  return `doriya_session=${encryptSession(session, SESSION_SECRET)}`;
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function request(path, { method = "GET", cookie, body } = {}) {
  const headers = { Accept: "application/json" };
  if (cookie) {
    headers.Cookie = cookie;
  }
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { response, text, json };
}

function cookiePair(setCookieHeader) {
  return setCookieHeader.split(";")[0];
}

beforeAll(async () => {
  const handler = createApiHandler({
    env,
    now: () => NOW,
    fetchImpl: (...args) => fakeFetch(...args),
  });
  server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

beforeEach(() => {
  fakeFetch = async () => {
    throw new Error("Unexpected GitHub request in test.");
  };
});

describe("configuration and auth endpoints", () => {
  it("returns clear JSON when unconfigured without crashing", async () => {
    const unconfigured = createApiHandler({ env: {}, now: () => NOW });
    const isolated = createServer(unconfigured);
    await new Promise((resolve) => isolated.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${isolated.address().port}`;

    try {
      const sessionResponse = await fetch(`${origin}/api/auth/session`);
      expect(sessionResponse.status).toBe(200);
      expect(await sessionResponse.json()).toEqual({
        configured: false,
        authenticated: false,
      });

      const loginResponse = await fetch(`${origin}/api/auth/login`, {
        redirect: "manual",
      });
      expect(loginResponse.status).toBe(503);
      expect(loginResponse.headers.get("cache-control")).toContain("no-store");
      expect(await loginResponse.json()).toMatchObject({
        error: { code: "not_configured" },
      });
    } finally {
      await new Promise((resolve, reject) =>
        isolated.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  it("starts OAuth with state, PKCE and a secure HttpOnly cookie", async () => {
    const { response } = await request("/api/auth/login?returnTo=%2Fsettings");
    const location = new URL(response.headers.get("location"));
    const cookies = response.headers.getSetCookie();
    const stateCookie = cookies.find((value) =>
      value.startsWith("doriya_oauth_state="),
    );

    expect(response.status).toBe(302);
    expect(location.origin).toBe("https://github.com");
    expect(location.searchParams.get("state")).toBeTruthy();
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(stateCookie).toContain("HttpOnly");
    expect(stateCookie).toContain("SameSite=Lax");
    expect(stateCookie).toContain("Path=/");
    expect(stateCookie).toContain("Secure");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("rejects external returnTo values", async () => {
    const { response, json } = await request(
      "/api/auth/login?returnTo=https%3A%2F%2Fevil.example",
    );

    expect(response.status).toBe(400);
    expect(json.error.code).toBe("invalid_return_to");
  });

  it("completes the OAuth callback and emits both clear and session cookies", async () => {
    fakeFetch = async (url) => {
      if (url === "https://github.com/login/oauth/access_token") {
        return jsonResponse({
          access_token: ACCESS_TOKEN,
          refresh_token: REFRESH_TOKEN,
          expires_in: 28800,
          refresh_token_expires_in: 15897600,
          token_type: "bearer",
          scope: "",
        });
      }
      if (url === "https://api.github.com/user") {
        return jsonResponse({
          id: user.id,
          login: user.login,
          name: user.name,
          avatar_url: user.avatarUrl,
        });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const login = await request("/api/auth/login?returnTo=%2Fvault");
    const stateCookie = login.response.headers
      .getSetCookie()
      .find((value) => value.startsWith("doriya_oauth_state="));
    const state = new URL(login.response.headers.get("location")).searchParams.get(
      "state",
    );

    const callback = await request(
      `/api/auth/callback?code=test-code&state=${encodeURIComponent(state)}`,
      { cookie: cookiePair(stateCookie) },
    );
    const cookies = callback.response.headers.getSetCookie();

    expect(callback.response.status).toBe(302);
    expect(callback.response.headers.get("location")).toBe("/vault");
    expect(cookies).toHaveLength(2);
    expect(
      cookies.some(
        (value) =>
          value.startsWith("doriya_oauth_state=") &&
          value.includes("Max-Age=0"),
      ),
    ).toBe(true);
    expect(
      cookies.some(
        (value) =>
          value.startsWith("doriya_session=") &&
          value.includes("HttpOnly") &&
          value.includes("Secure"),
      ),
    ).toBe(true);
  });

  it("returns the user without ever returning tokens", async () => {
    const result = await request("/api/auth/session", {
      cookie: sessionCookie(),
    });

    expect(result.response.status).toBe(200);
    expect(result.json).toEqual({
      configured: true,
      authenticated: true,
      user,
    });
    expect(result.text).not.toContain(ACCESS_TOKEN);
    expect(result.text).not.toContain("refreshToken");
    expect(result.text).not.toContain("accessToken");
  });

  it("returns 401 and clears the cookie when an unrefreshable session expired", async () => {
    const result = await request("/api/auth/session", {
      cookie: sessionCookie({ expiresAt: NOW - 1 }),
    });

    expect(result.response.status).toBe(401);
    expect(result.json.error.code).toBe("reauth_required");
    expect(result.response.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("refreshes a near-expiry token and replaces the session cookie", async () => {
    let refreshCalls = 0;
    fakeFetch = async (url, options) => {
      if (
        url === "https://github.com/login/oauth/access_token" &&
        options.method === "POST"
      ) {
        refreshCalls += 1;
        return jsonResponse({
          access_token: "ghu_refreshed",
          refresh_token: "ghr_refreshed",
          expires_in: 28800,
          refresh_token_expires_in: 15897600,
          token_type: "bearer",
          scope: "",
        });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const result = await request("/api/auth/session", {
      cookie: sessionCookie({
        expiresAt: NOW + 30_000,
        refreshToken: REFRESH_TOKEN,
        refreshTokenExpiresAt: NOW + 86_400_000,
      }),
    });

    expect(result.response.status).toBe(200);
    expect(result.json.authenticated).toBe(true);
    expect(refreshCalls).toBe(1);
    expect(result.response.headers.get("set-cookie")).toContain(
      "doriya_session=",
    );
    expect(result.text).not.toContain("ghu_refreshed");
  });
});

describe("GitHub installations, repositories and vault", () => {
  it("starts installation and validates its state on setup", async () => {
    fakeFetch = async (url) => {
      if (url.startsWith("https://api.github.com/user/installations?")) {
        return jsonResponse({
          total_count: 1,
          installations: [{ id: 123, account: { login: "octocat" } }],
        });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const install = await request("/api/github/install", {
      method: "POST",
      cookie: sessionCookie(),
    });
    const location = new URL(install.response.headers.get("location"));
    const installCookie = install.response.headers
      .getSetCookie()
      .find((value) => value.startsWith("doriya_install_state="));
    const session = sessionCookie();

    expect(install.response.status).toBe(302);
    expect(location.origin).toBe("https://github.com");
    expect(location.pathname).toBe(
      "/apps/doriya-vault/installations/new",
    );
    expect(installCookie).toContain("HttpOnly");

    const setup = await request(
      `/api/github/setup?installation_id=123&state=${encodeURIComponent(
        location.searchParams.get("state"),
      )}`,
      {
        cookie: `${session}; ${cookiePair(installCookie)}`,
      },
    );
    const setupCookies = setup.response.headers.getSetCookie();

    expect(setup.response.status).toBe(302);
    expect(setup.response.headers.get("location")).toBe("/?github=installed");
    expect(
      setupCookies.some(
        (value) =>
          value.startsWith("doriya_install_state=") &&
          value.includes("Max-Age=0"),
      ),
    ).toBe(true);
  });

  it("redirects an anonymous setup request through login", async () => {
    const result = await request(
      "/api/github/setup?installation_id=123&state=test-state",
    );
    const location = new URL(
      result.response.headers.get("location"),
      "https://vault.example",
    );

    expect(result.response.status).toBe(302);
    expect(location.pathname).toBe("/api/auth/login");
    expect(location.searchParams.get("returnTo")).toBe(
      "/api/github/setup?installation_id=123&state=test-state",
    );
  });

  it("lists simplified user installations", async () => {
    fakeFetch = async (url) => {
      if (url.startsWith("https://api.github.com/user/installations?")) {
        return jsonResponse({
          total_count: 1,
          installations: [
            {
              id: 123,
              account: {
                id: 9,
                login: "octocat",
                type: "User",
                avatar_url: "https://example.test/avatar.png",
              },
              repository_selection: "selected",
            },
          ],
        });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const result = await request("/api/github/installations", {
      cookie: sessionCookie(),
    });

    expect(result.response.status).toBe(200);
    expect(result.json).toEqual({
      installations: [
        {
          id: 123,
          account: {
            id: 9,
            login: "octocat",
            type: "User",
            avatarUrl: "https://example.test/avatar.png",
          },
          repositorySelection: "selected",
        },
      ],
    });
  });

  it("lists only repositories returned for the user's installation", async () => {
    fakeFetch = async (url) => {
      if (url.startsWith("https://api.github.com/user/installations?")) {
        return jsonResponse({
          total_count: 1,
          installations: [{ id: 123 }],
        });
      }
      if (
        url.startsWith(
          "https://api.github.com/user/installations/123/repositories?",
        )
      ) {
        return jsonResponse({
          total_count: 1,
          repositories: [
            {
              id: 55,
              name: "private-vault",
              full_name: "octocat/private-vault",
              private: true,
              default_branch: "main",
              html_url: "https://github.com/octocat/private-vault",
              owner: { id: 9, login: "octocat", type: "User" },
            },
            {
              id: 56,
              name: "public-repo",
              full_name: "octocat/public-repo",
              private: false,
              default_branch: "main",
              html_url: "https://github.com/octocat/public-repo",
              owner: { id: 9, login: "octocat", type: "User" },
            },
          ],
        });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const result = await request(
      "/api/github/repositories?installationId=123",
      { cookie: sessionCookie() },
    );

    expect(result.response.status).toBe(200);
    expect(result.json.repositories).toHaveLength(1);
    expect(result.json.repositories[0]).toMatchObject({
      fullName: "octocat/private-vault",
      private: true,
    });
  });

  it("round-trips vault read and optimistic writes", async () => {
    const written = [];
    fakeFetch = async (url, options = {}) => {
      if (
        url.startsWith(
          "https://api.github.com/user/installations/123/repositories?",
        )
      ) {
        return jsonResponse({
          total_count: 1,
          repositories: [
            { full_name: "octocat/private-vault", private: true },
          ],
        });
      }
      if (
        url ===
          "https://api.github.com/app/installations/123/access_tokens" &&
        options.method === "POST"
      ) {
        return jsonResponse({
          token: "ghs_installation_token",
          expires_at: new Date(NOW + 60 * 60 * 1000).toISOString(),
        });
      }
      if (
        url ===
          "https://api.github.com/repos/octocat/private-vault/contents/.doriya/vault.json" &&
        options.method === "GET"
      ) {
        return jsonResponse({
          type: "file",
          encoding: "base64",
          sha: "a".repeat(40),
          content: Buffer.from('{"encrypted":true}').toString("base64"),
          html_url:
            "https://github.com/octocat/private-vault/blob/main/.doriya/vault.json",
        });
      }
      if (
        url ===
          "https://api.github.com/repos/octocat/private-vault/contents/.doriya/vault.json" &&
        options.method === "PUT"
      ) {
        written.push(JSON.parse(options.body));
        return jsonResponse({
          content: {
            sha: "b".repeat(40),
            html_url:
              "https://github.com/octocat/private-vault/blob/main/.doriya/vault.json",
          },
        });
      }
      throw new Error(`Unexpected URL: ${url} ${options.method || "GET"}`);
    };

    const read = await request(
      "/api/github/vault?installationId=123&repository=octocat%2Fprivate-vault",
      { cookie: sessionCookie() },
    );
    expect(read.response.status).toBe(200);
    expect(read.json).toEqual({
      exists: true,
      sha: "a".repeat(40),
      content: '{"encrypted":true}',
      htmlUrl:
        "https://github.com/octocat/private-vault/blob/main/.doriya/vault.json",
    });

    const write = await request("/api/github/vault", {
      method: "PUT",
      cookie: sessionCookie(),
      body: {
        installationId: 123,
        repository: "octocat/private-vault",
        content: '{"encrypted":"next"}',
        sha: "a".repeat(40),
      },
    });
    expect(write.response.status).toBe(200);
    expect(write.json.sha).toBe("b".repeat(40));
    expect(written).toEqual([
      {
        message: "Update Doriya vault",
        content: Buffer.from('{"encrypted":"next"}').toString("base64"),
        sha: "a".repeat(40),
      },
    ]);
    expect(fakeFetch).toBeTypeOf("function");
  });

  it("maps missing vault files to exists:false", async () => {
    fakeFetch = async (url, options = {}) => {
      if (
        url.startsWith(
          "https://api.github.com/user/installations/123/repositories?",
        )
      ) {
        return jsonResponse({
          total_count: 1,
          repositories: [
            { full_name: "octocat/private-vault", private: true },
          ],
        });
      }
      if (
        url ===
          "https://api.github.com/app/installations/123/access_tokens" &&
        options.method === "POST"
      ) {
        return jsonResponse({
          token: "ghs_installation_token",
          expires_at: new Date(NOW + 60 * 60 * 1000).toISOString(),
        });
      }
      if (
        url ===
        "https://api.github.com/repos/octocat/private-vault/contents/.doriya/vault.json"
      ) {
        return jsonResponse({ message: "Not Found" }, 404);
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const result = await request(
      "/api/github/vault?installationId=123&repository=octocat%2Fprivate-vault",
      { cookie: sessionCookie() },
    );

    expect(result.response.status).toBe(200);
    expect(result.json).toEqual({
      exists: false,
      sha: null,
      content: null,
      htmlUrl: null,
    });
  });

  it("returns a conflict when an optimistic vault write loses a race", async () => {
    fakeFetch = async (url, options = {}) => {
      if (
        url.startsWith(
          "https://api.github.com/user/installations/123/repositories?",
        )
      ) {
        return jsonResponse({
          total_count: 1,
          repositories: [
            { full_name: "octocat/private-vault", private: true },
          ],
        });
      }
      if (
        url ===
          "https://api.github.com/app/installations/123/access_tokens" &&
        options.method === "POST"
      ) {
        return jsonResponse({
          token: "ghs_installation_token",
          expires_at: new Date(NOW + 60 * 60 * 1000).toISOString(),
        });
      }
      if (
        url ===
          "https://api.github.com/repos/octocat/private-vault/contents/.doriya/vault.json" &&
        options.method === "PUT"
      ) {
        return jsonResponse({ message: "sha does not match" }, 409);
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const result = await request("/api/github/vault", {
      method: "PUT",
      cookie: sessionCookie(),
      body: {
        installationId: 123,
        repository: "octocat/private-vault",
        content: '{"encrypted":"next"}',
        sha: "a".repeat(40),
      },
    });

    expect(result.response.status).toBe(409);
    expect(result.json.error.code).toBe("vault_conflict");
  });
});
