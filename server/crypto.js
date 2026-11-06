import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const ENVELOPE_VERSION = "v1";
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_COOKIE_BYTES = 16 * 1024;

export function base64urlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

export function base64urlDecode(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }
  return Buffer.from(value, "base64url");
}

export function deriveSessionKey(secret) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("SESSION_SECRET is required.");
  }

  return Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.from(secret, "utf8"),
      Buffer.from("doriya2fa:cookie:v1", "utf8"),
      Buffer.from("aes-256-gcm", "utf8"),
      32,
    ),
  );
}

export function encryptJson(value, secret, purpose) {
  const key = deriveSessionKey(secret);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(purpose, "utf8"));

  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [
    ENVELOPE_VERSION,
    base64urlEncode(iv),
    base64urlEncode(tag),
    base64urlEncode(ciphertext),
  ].join(".");
}

export function decryptJson(value, secret, purpose) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") > MAX_COOKIE_BYTES
  ) {
    throw new Error("Invalid encrypted cookie.");
  }

  const parts = value.split(".");
  if (parts.length !== 4 || parts[0] !== ENVELOPE_VERSION) {
    throw new Error("Invalid encrypted cookie.");
  }

  const iv = base64urlDecode(parts[1]);
  const tag = base64urlDecode(parts[2]);
  const ciphertext = base64urlDecode(parts[3]);
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error("Invalid encrypted cookie.");
  }

  const key = deriveSessionKey(secret);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(purpose, "utf8"));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return JSON.parse(plaintext.toString("utf8"));
}

export function randomToken(byteLength = 32) {
  return randomBytes(byteLength).toString("base64url");
}

export function generatePkceVerifier() {
  return randomToken(32);
}

export function createPkceChallenge(verifier) {
  if (
    typeof verifier !== "string" ||
    verifier.length < 43 ||
    verifier.length > 128 ||
    !/^[A-Za-z0-9._~-]+$/.test(verifier)
  ) {
    throw new Error("PKCE verifier must be 43-128 unreserved characters.");
  }

  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function safeStringEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }

  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}
