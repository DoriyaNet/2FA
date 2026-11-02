import { describe, expect, it } from "vitest";
import {
  buildOtpauthUri,
  generateTOTP,
  normalizeBase32,
  parseTotpInput,
  TotpInputError,
} from "../src/totp.js";

const SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SHA256_SECRET =
  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SHA512_SECRET =
  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

describe("Base32 handling", () => {
  it("normalizes lowercase, whitespace, hyphens and padding", () => {
    expect(normalizeBase32("jbsw y3dp-ehpk3pxp====")).toBe("JBSWY3DPEHPK3PXP");
  });

  it("rejects non-Base32 characters", () => {
    expect(() => normalizeBase32("NOT_A_SECRET")).toThrow(TotpInputError);
  });
});

describe("TOTP generation", () => {
  const vectors = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ];

  it.each(vectors)("matches RFC 6238 at %i seconds", async (timestamp, expected) => {
    const code = await generateTOTP(
      {
        secret: SHA1_SECRET,
        algorithm: "SHA-1",
        digits: 6,
        period: 30,
      },
      timestamp * 1000,
    );
    expect(code).toBe(expected);
  });

  it("supports eight-digit codes", async () => {
    const code = await generateTOTP(
      {
        secret: SHA1_SECRET,
        algorithm: "SHA-1",
        digits: 8,
        period: 30,
      },
      59 * 1000,
    );
    expect(code).toBe("94287082");
  });

  it("matches RFC 6238 SHA-256 and SHA-512 vectors", async () => {
    const sha256 = await generateTOTP(
      {
        secret: SHA256_SECRET,
        algorithm: "SHA-256",
        digits: 8,
        period: 30,
      },
      59 * 1000,
    );
    const sha512 = await generateTOTP(
      {
        secret: SHA512_SECRET,
        algorithm: "SHA-512",
        digits: 8,
        period: 30,
      },
      59 * 1000,
    );
    expect(sha256).toBe("46119246");
    expect(sha512).toBe("90693936");
  });
});

describe("otpauth parsing", () => {
  const uri =
    "otpauth://totp/Example%20Co:hello%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=60";

  it("extracts account metadata and parameters", () => {
    expect(parseTotpInput(uri)).toEqual({
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Example Co",
      account: "hello@example.com",
      algorithm: "SHA-256",
      digits: 8,
      period: 60,
    });
  });

  it("round-trips a generated URI", () => {
    const source = {
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Doriya",
      account: "demo@doriya.dev",
      algorithm: "SHA-1",
      digits: 6,
      period: 30,
    };
    expect(parseTotpInput(buildOtpauthUri(source))).toEqual(source);
  });

  it("rejects unsupported token types", () => {
    expect(() =>
      parseTotpInput("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=1"),
    ).toThrow("仅支持 TOTP");
  });
});
