import { describe, expect, it } from "vitest";
import {
  buildAuthorizeUrl,
  createInstallAttempt,
  createOAuthAttempt,
  sanitizeReturnTo,
  validateInstallAttempt,
  validateOAuthAttempt,
} from "../../server/oauth.js";

describe("OAuth return paths", () => {
  it("allows only site-relative paths", () => {
    expect(sanitizeReturnTo("/")).toBe("/");
    expect(sanitizeReturnTo("/settings?tab=vault#key")).toBe(
      "/settings?tab=vault#key",
    );
    expect(sanitizeReturnTo(undefined)).toBe("/");
  });

  it.each([
    "https://evil.example/",
    "//evil.example/path",
    "/\\evil.example/path",
    "/%5Cevil.example/path",
    "/%2F%2Fevil.example/path",
    "javascript:alert(1)",
    "/path\nSet-Cookie: bad=true",
    "",
  ])("rejects unsafe return value %s", (value) => {
    expect(sanitizeReturnTo(value, null)).toBeNull();
  });

  it("accepts an empty query as the default", () => {
    expect(sanitizeReturnTo("", "/fallback")).toBe("/fallback");
  });
});

describe("OAuth state and PKCE", () => {
  it("creates and validates a state-bound PKCE attempt", () => {
    const now = 1_700_000_000_000;
    const attempt = createOAuthAttempt({
      returnTo: "/?github=connected",
      redirectUri: "https://vault.example/api/auth/callback",
      now,
    });

    expect(attempt.cookie.verifier.length).toBe(43);
    expect(attempt.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      validateOAuthAttempt(
        attempt.cookie,
        attempt.cookie.state,
        now + 1_000,
      ).returnTo,
    ).toBe("/?github=connected");
  });

  it("rejects wrong and expired state", () => {
    const now = 1_700_000_000_000;
    const attempt = createOAuthAttempt({
      returnTo: "/",
      redirectUri: "https://vault.example/api/auth/callback",
      now,
    });

    expect(() =>
      validateOAuthAttempt(attempt.cookie, "wrong-state", now),
    ).toThrow(expect.objectContaining({ code: "invalid_state" }));
    expect(() =>
      validateOAuthAttempt(
        attempt.cookie,
        attempt.cookie.state,
        attempt.cookie.expiresAt,
      ),
    ).toThrow(expect.objectContaining({ code: "invalid_state" }));
  });

  it("builds a GitHub authorize URL with S256", () => {
    const value = buildAuthorizeUrl({
      clientId: "client-id",
      redirectUri: "https://vault.example/api/auth/callback",
      state: "state",
      codeChallenge: "challenge",
    });
    const url = new URL(value);

    expect(url.origin).toBe("https://github.com");
    expect(url.pathname).toBe("/login/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe("client-id");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toBe("state");
  });
});

describe("installation state", () => {
  it("binds installation state to the signed-in user", () => {
    const now = 1_700_000_000_000;
    const attempt = createInstallAttempt({ userId: 123, now });

    expect(
      validateInstallAttempt(attempt.cookie, attempt.cookie.state, 123, now),
    ).toEqual(attempt.cookie);
    expect(() =>
      validateInstallAttempt(attempt.cookie, attempt.cookie.state, 456, now),
    ).toThrow(expect.objectContaining({ code: "invalid_install_state" }));
  });
});
