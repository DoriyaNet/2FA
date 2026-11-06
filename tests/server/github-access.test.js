import { generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createAppJwt,
  installationIsAccessible,
  normalizeInstallationId,
  normalizeOAuthToken,
  normalizeRepositoryFullName,
  repositoryIsAccessible,
  simplifyInstallation,
  simplifyRepository,
} from "../../server/github.js";

describe("installation and repository validation", () => {
  it("normalizes valid installation IDs only", () => {
    expect(normalizeInstallationId("123")).toBe(123);
    expect(normalizeInstallationId(456)).toBe(456);
    expect(normalizeInstallationId("0")).toBeNull();
    expect(normalizeInstallationId("-1")).toBeNull();
    expect(normalizeInstallationId("1e3")).toBeNull();
    expect(normalizeInstallationId("abc")).toBeNull();
  });

  it("validates owner/name repository paths", () => {
    expect(normalizeRepositoryFullName("octocat/hello-world")).toBe(
      "octocat/hello-world",
    );
    expect(normalizeRepositoryFullName("octocat/.github")).toBe(
      "octocat/.github",
    );
    expect(normalizeRepositoryFullName("octocat/../secret")).toBeNull();
    expect(normalizeRepositoryFullName("octocat/name/extra")).toBeNull();
    expect(normalizeRepositoryFullName("../name")).toBeNull();
  });

  it("checks both installation and repository grants", () => {
    const installations = [{ id: 123 }, { id: 456 }];
    const repositories = [
      { full_name: "OctoCat/Hello-World", private: true },
    ];

    expect(installationIsAccessible(installations, 123)).toBe(true);
    expect(installationIsAccessible(installations, 999)).toBe(false);
    expect(repositoryIsAccessible(repositories, "octocat/hello-world")).toBe(
      true,
    );
    expect(repositoryIsAccessible(repositories, "octocat/not-allowed")).toBe(
      false,
    );
    expect(
      repositoryIsAccessible(
        [{ full_name: "octocat/public", private: false }],
        "octocat/public",
      ),
    ).toBe(false);
  });

  it("simplifies GitHub payloads without leaking unrelated fields", () => {
    expect(
      simplifyInstallation({
        id: 123,
        token: "must-not-leak",
        repository_selection: "selected",
        account: {
          id: 9,
          login: "octocat",
          type: "User",
          avatar_url: "https://example.test/avatar",
          email: "private@example.test",
        },
      }),
    ).toEqual({
      id: 123,
      account: {
        id: 9,
        login: "octocat",
        type: "User",
        avatarUrl: "https://example.test/avatar",
      },
      repositorySelection: "selected",
    });

    expect(
      simplifyRepository({
        id: 55,
        name: "vault",
        full_name: "octocat/vault",
        private: true,
        default_branch: "main",
        html_url: "https://github.com/octocat/vault",
        owner: { id: 9, login: "octocat", type: "User" },
        permissions: { admin: true },
      }),
    ).toEqual({
      id: 55,
      name: "vault",
      fullName: "octocat/vault",
      private: true,
      defaultBranch: "main",
      htmlUrl: "https://github.com/octocat/vault",
      owner: {
        id: 9,
        login: "octocat",
        type: "User",
        avatarUrl: null,
      },
    });
  });
});

describe("GitHub App JWT", () => {
  it("creates a verifiable RS256 JWT", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const now = 1_700_000_000_000;
    const token = createAppJwt({ appId: "12345", privateKey, now });
    const [header, payload, signature] = token.split(".");

    expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({
      alg: "RS256",
      typ: "JWT",
    });
    expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toEqual({
      iat: Math.floor(now / 1000) - 60,
      exp: Math.floor(now / 1000) + 480,
      iss: "12345",
    });
    expect(
      verify(
        "RSA-SHA256",
        Buffer.from(`${header}.${payload}`),
        publicKey,
        Buffer.from(signature, "base64url"),
      ),
    ).toBe(true);
  });
});

describe("OAuth token normalization", () => {
  it("stores expiries without changing GitHub token values", () => {
    expect(
      normalizeOAuthToken(
        {
          access_token: "ghu_access",
          refresh_token: "ghr_refresh",
          expires_in: 28800,
          refresh_token_expires_in: 15897600,
          scope: "",
          token_type: "bearer",
        },
        1_000,
      ),
    ).toEqual({
      accessToken: "ghu_access",
      refreshToken: "ghr_refresh",
      expiresAt: 28_801_000,
      refreshTokenExpiresAt: 15_897_601_000,
      scope: "",
      tokenType: "bearer",
    });
  });
});
