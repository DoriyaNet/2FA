import { describe, expect, it } from "vitest";
import { readConfig } from "../../server/config.js";

const completeEnv = {
  GITHUB_APP_ID: "12345",
  GITHUB_APP_CLIENT_ID: "client-id",
  GITHUB_APP_CLIENT_SECRET: "client-secret",
  GITHUB_APP_PRIVATE_KEY: "test-key",
  GITHUB_APP_SLUG: "doriya-vault",
  SESSION_SECRET: "a".repeat(32),
  APP_ORIGIN: "https://vault.example",
};

describe("server configuration", () => {
  it("accepts a complete configuration with a 32-byte session secret", () => {
    const config = readConfig(completeEnv);
    expect(config.configured).toBe(true);
    expect(config.configErrors).toEqual([]);
  });

  it("rejects a short session secret without exposing its value", () => {
    const secret = "short-secret";
    const config = readConfig({ ...completeEnv, SESSION_SECRET: secret });

    expect(config.configured).toBe(false);
    expect(config.configErrors.join(" ")).toContain("SESSION_SECRET");
    expect(config.configErrors.join(" ")).not.toContain(secret);
  });

  it("rejects non-http app origins", () => {
    const config = readConfig({
      ...completeEnv,
      APP_ORIGIN: "javascript:alert(1)",
    });

    expect(config.configured).toBe(false);
    expect(config.configErrors).toContain(
      "APP_ORIGIN must be a valid absolute http(s) URL.",
    );
  });
});
