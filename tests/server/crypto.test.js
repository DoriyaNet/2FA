import { describe, expect, it } from "vitest";
import {
  createPkceChallenge,
  decryptJson,
  encryptJson,
  generatePkceVerifier,
  safeStringEqual,
} from "../../server/crypto.js";
import {
  clearCookie,
  serializeCookie,
} from "../../server/cookies.js";

const SECRET = "test-session-secret-that-is-long-enough";

describe("encrypted cookie payloads", () => {
  it("round-trips JSON with AES-256-GCM", () => {
    const payload = {
      userId: 42,
      accessToken: "github-token",
      nested: { enabled: true },
    };
    const encrypted = encryptJson(payload, SECRET, "session-test");

    expect(encrypted).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(encrypted).not.toContain("github-token");
    expect(decryptJson(encrypted, SECRET, "session-test")).toEqual(payload);
  });

  it("rejects ciphertext modification", () => {
    const encrypted = encryptJson({ ok: true }, SECRET, "session-test");
    const last = encrypted.at(-1);
    const tampered = `${encrypted.slice(0, -1)}${last === "A" ? "B" : "A"}`;

    expect(() =>
      decryptJson(tampered, SECRET, "session-test"),
    ).toThrow();
  });

  it("rejects a different secret or purpose", () => {
    const encrypted = encryptJson({ ok: true }, SECRET, "session-test");

    expect(() =>
      decryptJson(encrypted, `${SECRET}-different`, "session-test"),
    ).toThrow();
    expect(() =>
      decryptJson(encrypted, SECRET, "another-purpose"),
    ).toThrow();
  });

  it("uses a fresh IV for each payload", () => {
    const first = encryptJson({ value: 1 }, SECRET, "session-test");
    const second = encryptJson({ value: 1 }, SECRET, "session-test");

    expect(first).not.toBe(second);
  });
});

describe("PKCE", () => {
  it("matches the RFC 7636 S256 example", () => {
    expect(
      createPkceChallenge(
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      ),
    ).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("generates verifier-safe random strings", () => {
    const first = generatePkceVerifier();
    const second = generatePkceVerifier();

    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second).not.toBe(first);
    expect(safeStringEqual(first, first)).toBe(true);
    expect(safeStringEqual(first, second)).toBe(false);
  });
});

describe("cookie serialization", () => {
  it("sets the required security attributes", () => {
    const cookie = serializeCookie("doriya_session", "value", {
      maxAge: 600,
      secure: true,
    });

    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=600");
    expect(cookie).toContain("Secure");
  });

  it("clears cookies with Max-Age=0", () => {
    expect(clearCookie("doriya_session", { secure: false })).toContain(
      "Max-Age=0",
    );
  });
});
