import { beforeAll, describe, expect, it } from "vitest";
import {
  createVaultAccount,
  createVaultDocument,
  decryptVault,
  encryptVault,
  parseVaultEnvelope,
  serializeVaultEnvelope,
  validatePassphrase,
  validateVaultDocument,
} from "../src/vault-crypto.js";

const PASSPHRASE = "correct horse battery staple";
const FAKE_SECRET = "JBSWY3DPEHPK3PXP";
const AAD = "doriya-vault:v1";

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (character) =>
    character.charCodeAt(0),
  );
}

async function encryptWithAad(envelope, passphrase, document, additionalData) {
  const salt = base64ToBytes(envelope.kdf.salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: envelope.kdf.iterations,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const data = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(additionalData),
      tagLength: 128,
    },
    key,
    new TextEncoder().encode(JSON.stringify(document)),
  );

  return {
    format: "doriya-vault",
    version: 1,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations: envelope.kdf.iterations,
      salt: envelope.kdf.salt,
    },
    cipher: {
      name: "AES-256-GCM",
      iv: bytesToBase64(iv),
      data: bytesToBase64(new Uint8Array(data)),
    },
  };
}

describe("vault document and account validation", () => {
  it("creates a normalized account with required metadata", () => {
    const rawSecret = ` ${FAKE_SECRET.toLowerCase().match(/.{1,4}/g).join("-")} `;
    const account = createVaultAccount(
      {
        issuer: "  GitHub  ",
        account: "  developer@example.invalid  ",
        secret: rawSecret,
        algorithm: "sha256",
        digits: "8",
        period: "60",
      },
      { id: "fixed-account-id" },
    );

    expect(account).toEqual({
      id: "fixed-account-id",
      issuer: "GitHub",
      account: "developer@example.invalid",
      secret: FAKE_SECRET,
      algorithm: "SHA-256",
      digits: 8,
      period: 60,
      createdAt: expect.stringMatching(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      ),
      updatedAt: expect.stringMatching(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      ),
    });
    expect(account.createdAt).toBe(account.updatedAt);
  });

  it("generates UUID account ids by default", () => {
    const account = createVaultAccount({
      issuer: "Example",
      account: "user@example.invalid",
      secret: FAKE_SECRET,
    });

    expect(account.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("rejects invalid Base32, algorithms, digits and periods", () => {
    const valid = {
      issuer: "Example",
      account: "user@example.invalid",
      secret: FAKE_SECRET,
      algorithm: "SHA-1",
      digits: 6,
      period: 30,
    };

    expect(() =>
      createVaultAccount({ ...valid, secret: "NOT_A_BASE32_SECRET" }),
    ).toThrow(/Base32/);
    expect(() =>
      createVaultAccount({ ...valid, algorithm: "MD5" }),
    ).toThrow(/SHA-1/);
    expect(() => createVaultAccount({ ...valid, digits: 7 })).toThrow(/6 位或 8 位/);
    expect(() => createVaultAccount({ ...valid, period: 10 })).toThrow(/15、30 或 60/);
  });

  it("rejects duplicate account ids and unknown fields", () => {
    const first = createVaultAccount(
      {
        issuer: "Example",
        account: "first@example.invalid",
        secret: FAKE_SECRET,
      },
      { id: "duplicate-id" },
    );
    const second = {
      ...first,
      account: "second@example.invalid",
    };

    expect(() => createVaultDocument([first, second])).toThrow(/id 必须唯一/);
    expect(() =>
      createVaultDocument([{ ...first, notes: "must be encrypted" }]),
    ).toThrow(/未知字段/);
  });

  it("rejects non-canonical secrets and malformed timestamps", () => {
    const account = createVaultAccount({
      issuer: "Example",
      account: "user@example.invalid",
      secret: FAKE_SECRET,
    });
    const document = createVaultDocument([account]);

    expect(() =>
      validateVaultDocument({
        ...document,
        accounts: [{ ...account, secret: account.secret.toLowerCase() }],
      }),
    ).toThrow(/规范化/);
    expect(() =>
      validateVaultDocument({
        ...document,
        accounts: [{ ...account, createdAt: "yesterday" }],
      }),
    ).toThrow(/ISO 8601/);
  });

  it("rejects prototype-polluting document shapes", () => {
    const document = createVaultDocument([]);
    const malicious = JSON.parse(
      `${JSON.stringify(document).slice(0, -1)},"__proto__":{"polluted":true}}`,
    );

    expect(() => validateVaultDocument(malicious)).toThrow(/未知字段/);
    expect({}.polluted).toBeUndefined();
  });
});

describe("vault encryption", () => {
  let document;
  let envelope;

  beforeAll(async () => {
    const github = createVaultAccount({
      issuer: "GitHub",
      account: "developer@example.invalid",
      secret: FAKE_SECRET,
      algorithm: "SHA-1",
      digits: 6,
      period: 30,
    });
    const backup = createVaultAccount({
      issuer: "Example Backup",
      account: "backup@example.invalid",
      secret: FAKE_SECRET.split("").reverse().join(""),
      algorithm: "SHA-512",
      digits: 8,
      period: 60,
    });

    document = createVaultDocument([github, backup]);
    envelope = await encryptVault(document, PASSPHRASE);
  });

  it("round-trips a vault using the default 600000 PBKDF2 iterations", async () => {
    expect(envelope.kdf.iterations).toBe(600_000);
    const decrypted = await decryptVault(envelope, PASSPHRASE);
    expect(decrypted).toEqual(document);
  });

  it("keeps all vault metadata encrypted inside the ciphertext", () => {
    const serialized = serializeVaultEnvelope(envelope);
    const parsed = JSON.parse(serialized);

    expect(Object.keys(parsed)).toEqual([
      "format",
      "version",
      "kdf",
      "cipher",
    ]);
    expect(serialized).not.toContain("GitHub");
    expect(serialized).not.toContain("developer@example.invalid");
    expect(serialized).not.toContain(FAKE_SECRET);
    expect(parseVaultEnvelope(serialized)).toEqual(envelope);
  });

  it("uses fresh salt and IV values for every encryption", async () => {
    const secondEnvelope = await encryptVault(document, PASSPHRASE);

    expect(secondEnvelope.kdf.salt).not.toBe(envelope.kdf.salt);
    expect(secondEnvelope.cipher.iv).not.toBe(envelope.cipher.iv);
    expect(base64ToBytes(envelope.kdf.salt)).toHaveLength(16);
    expect(base64ToBytes(envelope.cipher.iv)).toHaveLength(12);
  });

  it("rejects a wrong passphrase", async () => {
    await expect(
      decryptVault(envelope, "this is the wrong password"),
    ).rejects.toThrow(/密码错误/);
  });

  it("rejects modified ciphertext", async () => {
    const tampered = structuredClone(envelope);
    const ciphertext = base64ToBytes(tampered.cipher.data);
    ciphertext[ciphertext.length - 1] ^= 0x01;
    tampered.cipher.data = bytesToBase64(ciphertext);

    await expect(decryptVault(tampered, PASSPHRASE)).rejects.toThrow(
      /密码错误或保险库数据已损坏/,
    );
  });

  it("rejects ciphertext authenticated with different AAD", async () => {
    const tampered = await encryptWithAad(
      envelope,
      PASSPHRASE,
      document,
      "doriya-vault:v2",
    );

    await expect(decryptVault(tampered, PASSPHRASE)).rejects.toThrow(
      /密码错误或保险库数据已损坏/,
    );
  });

  it("enforces PBKDF2 iteration bounds", async () => {
    await expect(
      encryptVault(document, PASSPHRASE, { iterations: 99_999 }),
    ).rejects.toThrow(/100000/);
    await expect(
      encryptVault(document, PASSPHRASE, { iterations: 10_000_001 }),
    ).rejects.toThrow(/10000000/);
  });
});

describe("vault envelope validation", () => {
  let envelope;

  beforeAll(async () => {
    const account = createVaultAccount({
      issuer: "Example",
      account: "user@example.invalid",
      secret: FAKE_SECRET,
    });
    envelope = await encryptVault(createVaultDocument([account]), PASSPHRASE);
  });

  it("rejects malformed JSON and unknown fields", () => {
    expect(() => parseVaultEnvelope("not-json")).toThrow(/JSON/);
    expect(() =>
      parseVaultEnvelope(
        JSON.stringify({ ...envelope, issuer: "leaked plaintext" }),
      ),
    ).toThrow(/未知字段/);
  });

  it("rejects unsupported formats, versions and KDF settings", () => {
    expect(() =>
      parseVaultEnvelope(JSON.stringify({ ...envelope, format: "other" })),
    ).toThrow(/格式/);
    expect(() =>
      parseVaultEnvelope(JSON.stringify({ ...envelope, version: 2 })),
    ).toThrow(/版本/);
    expect(() =>
      parseVaultEnvelope(
        JSON.stringify({
          ...envelope,
          kdf: { ...envelope.kdf, name: "PBKDF2-SHA1" },
        }),
      ),
    ).toThrow(/KDF/);
    expect(() =>
      parseVaultEnvelope(
        JSON.stringify({
          ...envelope,
          kdf: { ...envelope.kdf, iterations: 100_000 - 1 },
        }),
      ),
    ).toThrow(/100000/);
  });

  it("rejects invalid salt, IV and cipher settings", () => {
    expect(() =>
      parseVaultEnvelope(
        JSON.stringify({
          ...envelope,
          kdf: { ...envelope.kdf, salt: "AA==" },
        }),
      ),
    ).toThrow(/长度/);
    expect(() =>
      parseVaultEnvelope(
        JSON.stringify({
          ...envelope,
          cipher: { ...envelope.cipher, iv: "not base64" },
        }),
      ),
    ).toThrow(/Base64/);
    expect(() =>
      parseVaultEnvelope(
        JSON.stringify({
          ...envelope,
          cipher: { ...envelope.cipher, name: "AES-256-CBC" },
        }),
      ),
    ).toThrow(/加密算法/);
  });

  it("serializes in a stable, readable format", () => {
    const serialized = serializeVaultEnvelope(envelope);
    expect(serialized).toContain("\n  \"format\": \"doriya-vault\",");
    expect(serializeVaultEnvelope(parseVaultEnvelope(serialized))).toBe(
      serialized,
    );
  });
});

describe("passphrase validation", () => {
  it("requires at least twelve Unicode characters", () => {
    expect(validatePassphrase("12345678901")).toMatch(/12/);
    expect(validatePassphrase("🔐".repeat(11))).toMatch(/12/);
    expect(validatePassphrase("🔐".repeat(12))).toBe(true);
    expect(validatePassphrase("十二个字符的安全测试密码")).toBe(true);
  });

  it("rejects non-string passphrases without throwing", () => {
    expect(validatePassphrase(null)).toBe("密码必须是字符串。");
  });
});
