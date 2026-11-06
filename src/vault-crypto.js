import { normalizeBase32 } from "./totp.js";

const VAULT_FORMAT = "doriya-vault";
const VAULT_VERSION = 1;
const VAULT_AAD = "doriya-vault:v1";
const KDF_NAME = "PBKDF2-SHA256";
const CIPHER_NAME = "AES-256-GCM";
const DEFAULT_ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 10_000_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const SUPPORTED_ALGORITHMS = new Set(["SHA-1", "SHA-256", "SHA-512"]);
const SUPPORTED_DIGITS = new Set([6, 8]);
const SUPPORTED_PERIODS = new Set([15, 30, 60]);

const DOCUMENT_KEYS = ["version", "createdAt", "updatedAt", "accounts"];
const ACCOUNT_KEYS = [
  "id",
  "issuer",
  "account",
  "secret",
  "algorithm",
  "digits",
  "period",
  "createdAt",
  "updatedAt",
];
const ACCOUNT_CONFIG_KEYS = [
  "issuer",
  "account",
  "secret",
  "algorithm",
  "digits",
  "period",
];
const ENVELOPE_KEYS = ["format", "version", "kdf", "cipher"];
const KDF_KEYS = ["name", "iterations", "salt"];
const CIPHER_KEYS = ["name", "iv", "data"];

class VaultCryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = "VaultCryptoError";
  }
}

function fail(message) {
  throw new VaultCryptoError(message);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label}必须是对象。`);
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(`${label}结构无效。`);
  }
}

function assertExactKeys(object, expectedKeys, label) {
  const actualKeys = Reflect.ownKeys(object);
  if (
    actualKeys.some((key) => typeof key !== "string") ||
    actualKeys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !actualKeys.includes(key))
  ) {
    fail(`${label}包含缺失或未知字段。`);
  }

  const descriptors = Object.getOwnPropertyDescriptors(object);
  for (const key of expectedKeys) {
    if (!descriptors[key] || !hasOwn(descriptors[key], "value")) {
      fail(`${label}结构无效。`);
    }
  }
}

function assertAllowedKeys(object, allowedKeys, label) {
  const allowed = new Set(allowedKeys);
  const actualKeys = Reflect.ownKeys(object);
  if (
    actualKeys.some((key) => typeof key !== "string") ||
    actualKeys.some((key) => !allowed.has(key))
  ) {
    fail(`${label}包含未知字段。`);
  }

  const descriptors = Object.getOwnPropertyDescriptors(object);
  for (const key of actualKeys) {
    if (!descriptors[key] || !hasOwn(descriptors[key], "value")) {
      fail(`${label}结构无效。`);
    }
  }
}

function assertStrictArray(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label}必须是数组。`);
  }

  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") continue;
    if (
      typeof key !== "string" ||
      !/^(0|[1-9]\d*)$/.test(key) ||
      Number(key) >= value.length
    ) {
      fail(`${label}结构无效。`);
    }
  }

  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !hasOwn(descriptor, "value")) {
      fail(`${label}结构无效。`);
    }
  }
}

function getWebCrypto() {
  if (
    !globalThis.crypto?.subtle ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    fail("当前环境不支持 Web Crypto，请通过安全上下文访问。");
  }
  return globalThis.crypto;
}

function nowIso() {
  return new Date().toISOString();
}

function assertIsoTimestamp(value, label) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) {
    fail(`${label}必须是 ISO 8601 时间字符串。`);
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) {
    fail(`${label}不是有效的时间。`);
  }
  return value;
}

function compareTimestamps(start, end, label) {
  if (Date.parse(end) < Date.parse(start)) {
    fail(`${label}不能早于创建时间。`);
  }
}

function normalizeAlgorithm(value) {
  if (typeof value !== "string") {
    fail("算法必须是 SHA-1、SHA-256 或 SHA-512。");
  }

  const normalized = value
    .trim()
    .toUpperCase()
    .replace(/^SHA-?(1|256|512)$/, "SHA-$1");

  if (!SUPPORTED_ALGORITHMS.has(normalized)) {
    fail("仅支持 SHA-1、SHA-256 与 SHA-512 算法。");
  }
  return normalized;
}

function normalizeDigits(value) {
  const digits = Number(value);
  if (!SUPPORTED_DIGITS.has(digits)) {
    fail("验证码位数仅支持 6 位或 8 位。");
  }
  return digits;
}

function normalizePeriod(value) {
  const period = Number(value);
  if (!SUPPORTED_PERIODS.has(period)) {
    fail("刷新周期仅支持 15、30 或 60 秒。");
  }
  return period;
}

function normalizeLabel(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    fail(`${label}必须是非空文本。`);
  }
  return value.trim();
}

function normalizeSecret(value, { canonical = false } = {}) {
  let normalized;
  try {
    normalized = normalizeBase32(value);
  } catch (error) {
    throw new VaultCryptoError(
      error instanceof Error && error.message
        ? error.message
        : "账户密钥不是有效的 Base32 字符串。",
    );
  }

  if (canonical && value !== normalized) {
    fail("账户密钥必须使用规范化后的 Base32 字符串。");
  }
  return normalized;
}

function normalizeAccountId(value) {
  if (
    typeof value !== "string" ||
    !value ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail("账户 id 必须是非空字符串。");
  }
  return value;
}

function createRandomId() {
  const webCrypto = getWebCrypto();
  if (typeof webCrypto.randomUUID === "function") {
    return webCrypto.randomUUID();
  }

  const bytes = webCrypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

function normalizeAccount(account, { canonical = false } = {}) {
  assertPlainObject(account, "账户记录");
  assertExactKeys(account, ACCOUNT_KEYS, "账户记录");

  const id = normalizeAccountId(account.id);
  const issuer = normalizeLabel(account.issuer, "发行方");
  const accountName = normalizeLabel(account.account, "账户名称");
  if (canonical) {
    if (issuer !== account.issuer) {
      fail("发行方名称不能包含首尾空白。");
    }
    if (accountName !== account.account) {
      fail("账户名称不能包含首尾空白。");
    }
  }

  const secret = normalizeSecret(account.secret, { canonical });
  const algorithm = normalizeAlgorithm(account.algorithm);
  if (canonical && algorithm !== account.algorithm) {
    fail("算法必须使用规范化的 SHA-1、SHA-256 或 SHA-512 名称。");
  }

  const digits = normalizeDigits(account.digits);
  if (canonical && account.digits !== digits) {
    fail("验证码位数必须是数值 6 或 8。");
  }

  const period = normalizePeriod(account.period);
  if (canonical && account.period !== period) {
    fail("刷新周期必须是数值 15、30 或 60。");
  }

  const createdAt = assertIsoTimestamp(account.createdAt, "账户创建时间");
  const updatedAt = assertIsoTimestamp(account.updatedAt, "账户更新时间");
  compareTimestamps(createdAt, updatedAt, "账户更新时间");

  return {
    id,
    issuer,
    account: accountName,
    secret,
    algorithm,
    digits,
    period,
    createdAt,
    updatedAt,
  };
}

function assertUniqueIds(accounts) {
  const ids = new Set();
  for (const account of accounts) {
    if (ids.has(account.id)) {
      fail("账户 id 必须唯一。");
    }
    ids.add(account.id);
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(offset, offset + chunkSize),
    );
  }

  try {
    return btoa(binary);
  } catch {
    fail("无法编码加密数据。");
  }
}

function base64ToBytes(value, label, expectedLength) {
  if (
    typeof value !== "string" ||
    !value ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    fail(`${label}不是有效的 Base64 数据。`);
  }

  let binary;
  try {
    binary = atob(value);
  } catch {
    fail(`${label}不是有效的 Base64 数据。`);
  }

  const bytes = Uint8Array.from(binary, (character) =>
    character.charCodeAt(0),
  );
  if (bytesToBase64(bytes) !== value) {
    fail(`${label}不是规范的 Base64 数据。`);
  }
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    fail(`${label}长度无效。`);
  }
  return bytes;
}

function normalizeIterations(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_ITERATIONS ||
    value > MAX_ITERATIONS
  ) {
    fail(
      `PBKDF2 迭代次数必须是 ${MIN_ITERATIONS} 到 ${MAX_ITERATIONS} 之间的整数。`,
    );
  }
  return value;
}

function validateEnvelope(envelope) {
  assertPlainObject(envelope, "保险库 envelope");
  assertExactKeys(envelope, ENVELOPE_KEYS, "保险库 envelope");

  if (envelope.format !== VAULT_FORMAT) {
    fail("保险库格式不受支持。");
  }
  if (envelope.version !== VAULT_VERSION) {
    fail("保险库版本不受支持。");
  }

  const kdf = envelope.kdf;
  assertPlainObject(kdf, "KDF 配置");
  assertExactKeys(kdf, KDF_KEYS, "KDF 配置");
  if (kdf.name !== KDF_NAME) {
    fail("KDF 算法不受支持。");
  }
  const iterations = normalizeIterations(kdf.iterations);
  const salt = base64ToBytes(kdf.salt, "KDF salt", SALT_BYTES);

  const cipher = envelope.cipher;
  assertPlainObject(cipher, "加密配置");
  assertExactKeys(cipher, CIPHER_KEYS, "加密配置");
  if (cipher.name !== CIPHER_NAME) {
    fail("加密算法不受支持。");
  }
  const iv = base64ToBytes(cipher.iv, "AES-GCM IV", IV_BYTES);
  const data = base64ToBytes(cipher.data, "密文");
  if (data.length < GCM_TAG_BYTES) {
    fail("密文长度无效。");
  }

  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    kdf: {
      name: KDF_NAME,
      iterations,
      salt: kdf.salt,
    },
    cipher: {
      name: CIPHER_NAME,
      iv: cipher.iv,
      data: cipher.data,
    },
    salt,
    iv,
    data,
  };
}

function validateOptions(options) {
  assertPlainObject(options, "加密选项");
  assertAllowedKeys(options, ["iterations"], "加密选项");
  return hasOwn(options, "iterations")
    ? normalizeIterations(options.iterations)
    : DEFAULT_ITERATIONS;
}

function requireValidPassphrase(passphrase) {
  const result = validatePassphrase(passphrase);
  if (result !== true) {
    throw new VaultCryptoError(result);
  }
  return passphrase;
}

async function deriveVaultKey(webCrypto, passphrase, salt, iterations) {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const keyMaterial = await webCrypto.subtle.importKey(
    "raw",
    passphraseBytes,
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return webCrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function gcmAlgorithm(iv) {
  return {
    name: "AES-GCM",
    iv,
    additionalData: new TextEncoder().encode(VAULT_AAD),
    tagLength: 128,
  };
}

function decodePlaintext(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("解密后的保险库内容不是有效的 UTF-8 文本。");
  }
}

export function createVaultDocument(accounts = []) {
  assertStrictArray(accounts, "账户列表");
  const timestamp = nowIso();
  const normalizedAccounts = accounts.map((account, index) => {
    try {
      return normalizeAccount(account, { canonical: true });
    } catch (error) {
      if (error instanceof VaultCryptoError) {
        throw new VaultCryptoError(
          `第 ${index + 1} 个账户：${error.message}`,
        );
      }
      throw error;
    }
  });
  assertUniqueIds(normalizedAccounts);

  return {
    version: VAULT_VERSION,
    createdAt: timestamp,
    updatedAt: timestamp,
    accounts: normalizedAccounts,
  };
}

export function createVaultAccount(config, overrides = {}) {
  assertPlainObject(config, "账户配置");
  assertAllowedKeys(config, ACCOUNT_CONFIG_KEYS, "账户配置");
  assertPlainObject(overrides, "账户覆盖项");
  assertAllowedKeys(overrides, ACCOUNT_KEYS, "账户覆盖项");

  const pick = (key) => {
    if (hasOwn(overrides, key)) return overrides[key];
    if (hasOwn(config, key)) return config[key];
    return undefined;
  };

  const timestamp = nowIso();
  const algorithm = pick("algorithm");
  const digits = pick("digits");
  const period = pick("period");
  const record = {
    id: hasOwn(overrides, "id") ? overrides.id : createRandomId(),
    issuer: pick("issuer"),
    account: pick("account"),
    secret: pick("secret"),
    algorithm: algorithm === undefined ? "SHA-1" : algorithm,
    digits: digits === undefined ? 6 : digits,
    period: period === undefined ? 30 : period,
    createdAt: hasOwn(overrides, "createdAt")
      ? overrides.createdAt
      : timestamp,
    updatedAt: hasOwn(overrides, "updatedAt")
      ? overrides.updatedAt
      : timestamp,
  };

  return normalizeAccount(record);
}

export function validateVaultDocument(document) {
  assertPlainObject(document, "保险库文档");
  assertExactKeys(document, DOCUMENT_KEYS, "保险库文档");

  if (document.version !== VAULT_VERSION) {
    fail("保险库文档版本不受支持。");
  }
  const createdAt = assertIsoTimestamp(
    document.createdAt,
    "保险库创建时间",
  );
  const updatedAt = assertIsoTimestamp(
    document.updatedAt,
    "保险库更新时间",
  );
  compareTimestamps(createdAt, updatedAt, "保险库更新时间");

  assertStrictArray(document.accounts, "账户列表");
  const accounts = document.accounts.map((account, index) => {
    try {
      return normalizeAccount(account, { canonical: true });
    } catch (error) {
      if (error instanceof VaultCryptoError) {
        throw new VaultCryptoError(
          `第 ${index + 1} 个账户：${error.message}`,
        );
      }
      throw error;
    }
  });
  assertUniqueIds(accounts);

  return {
    version: VAULT_VERSION,
    createdAt,
    updatedAt,
    accounts,
  };
}

export async function encryptVault(document, passphrase, options = {}) {
  const documentToEncrypt = validateVaultDocument(document);
  const validPassphrase = requireValidPassphrase(passphrase);
  const iterations = validateOptions(options);
  const webCrypto = getWebCrypto();
  const salt = webCrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));

  let encrypted;
  try {
    const key = await deriveVaultKey(
      webCrypto,
      validPassphrase,
      salt,
      iterations,
    );
    const plaintext = new TextEncoder().encode(
      JSON.stringify(documentToEncrypt),
    );
    encrypted = new Uint8Array(
      await webCrypto.subtle.encrypt(gcmAlgorithm(iv), key, plaintext),
    );
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError("加密失败，请重试。");
  }

  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    kdf: {
      name: KDF_NAME,
      iterations,
      salt: bytesToBase64(salt),
    },
    cipher: {
      name: CIPHER_NAME,
      iv: bytesToBase64(iv),
      data: bytesToBase64(encrypted),
    },
  };
}

export async function decryptVault(envelope, passphrase) {
  const parsedEnvelope = validateEnvelope(envelope);
  const validPassphrase = requireValidPassphrase(passphrase);
  const webCrypto = getWebCrypto();

  let decrypted;
  try {
    const key = await deriveVaultKey(
      webCrypto,
      validPassphrase,
      parsedEnvelope.salt,
      parsedEnvelope.kdf.iterations,
    );
    decrypted = new Uint8Array(
      await webCrypto.subtle.decrypt(
        gcmAlgorithm(parsedEnvelope.iv),
        key,
        parsedEnvelope.data,
      ),
    );
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    if (error?.name === "OperationError") {
      fail("解密失败：密码错误或保险库数据已损坏。");
    }
    fail("解密失败：当前环境无法完成安全解密。");
  }

  let parsedDocument;
  try {
    parsedDocument = JSON.parse(decodePlaintext(decrypted));
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError("解密后的保险库内容不是有效的 JSON。");
  }

  return validateVaultDocument(parsedDocument);
}

export function serializeVaultEnvelope(envelope) {
  const validated = validateEnvelope(envelope);
  const serializable = {
    format: validated.format,
    version: validated.version,
    kdf: validated.kdf,
    cipher: validated.cipher,
  };
  return JSON.stringify(serializable, null, 2);
}

export function parseVaultEnvelope(text) {
  if (typeof text !== "string" || !text.trim()) {
    fail("保险库数据必须是非空 JSON 文本。");
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail("保险库数据不是有效的 JSON。");
  }

  const validated = validateEnvelope(parsed);
  return {
    format: validated.format,
    version: validated.version,
    kdf: validated.kdf,
    cipher: validated.cipher,
  };
}

export function validatePassphrase(passphrase) {
  if (typeof passphrase !== "string") {
    return "密码必须是字符串。";
  }
  if (Array.from(passphrase).length < 12) {
    return "密码至少需要 12 个 Unicode 字符。";
  }
  return true;
}
