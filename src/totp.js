const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SUPPORTED_ALGORITHMS = new Set(["SHA-1", "SHA-256", "SHA-512"]);
const SUPPORTED_DIGITS = new Set([6, 8]);
const SUPPORTED_PERIODS = new Set([15, 30, 60]);

export class TotpInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "TotpInputError";
  }
}

export function normalizeBase32(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new TotpInputError("请输入验证器密钥。");
  }

  const normalized = value
    .trim()
    .replace(/[\s-]/g, "")
    .replace(/=+$/g, "")
    .toUpperCase();

  if (!normalized) {
    throw new TotpInputError("请输入验证器密钥。");
  }

  if (!/^[A-Z2-7]+$/.test(normalized)) {
    throw new TotpInputError("密钥格式无效，只能包含 Base32 字符 A-Z 与 2-7。");
  }

  return normalized;
}

export function base32Decode(value) {
  const normalized = normalizeBase32(value);
  const bytes = [];
  let buffer = 0;
  let bitCount = 0;

  for (const character of normalized) {
    const index = BASE32_ALPHABET.indexOf(character);
    buffer = (buffer << 5) | index;
    bitCount += 5;

    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((buffer >>> bitCount) & 0xff);
      buffer &= bitCount === 0 ? 0 : (1 << bitCount) - 1;
    }
  }

  if (bytes.length === 0) {
    throw new TotpInputError("密钥过短，无法生成验证码。");
  }

  return new Uint8Array(bytes);
}

export function normalizeAlgorithm(value = "SHA-1") {
  const normalized = String(value)
    .trim()
    .toUpperCase()
    .replace(/^SHA-?(1|256|512)$/, "SHA-$1");

  if (!SUPPORTED_ALGORITHMS.has(normalized)) {
    throw new TotpInputError("仅支持 SHA-1、SHA-256 与 SHA-512 算法。");
  }

  return normalized;
}

function normalizeDigits(value = 6) {
  const digits = Number(value);
  if (!SUPPORTED_DIGITS.has(digits)) {
    throw new TotpInputError("验证码位数仅支持 6 位或 8 位。");
  }
  return digits;
}

function normalizePeriod(value = 30) {
  const period = Number(value);
  if (!SUPPORTED_PERIODS.has(period)) {
    throw new TotpInputError("刷新周期仅支持 15、30 或 60 秒。");
  }
  return period;
}

function decodeUriPart(value, fallback = "") {
  if (!value) return fallback;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function parseTotpInput(rawValue, defaults = {}) {
  const raw = String(rawValue ?? "").trim();
  if (!raw) {
    throw new TotpInputError("请输入验证器密钥或 otpauth:// 链接。");
  }

  if (/^otpauth:\/\//i.test(raw)) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      throw new TotpInputError("otpauth 链接格式无效。");
    }

    if (url.hostname.toLowerCase() !== "totp") {
      throw new TotpInputError("目前仅支持 TOTP 类型的 otpauth 链接。");
    }

    const params = url.searchParams;
    const label = decodeUriPart(url.pathname.replace(/^\//, ""));
    const parsedIssuer = params.get("issuer")?.trim() || "";
    let issuer = parsedIssuer;
    let account = label;

    if (label.includes(":")) {
      const separatorIndex = label.indexOf(":");
      const labelIssuer = label.slice(0, separatorIndex).trim();
      account = label.slice(separatorIndex + 1).trim();
      issuer ||= labelIssuer;
    }

    if (issuer && account.startsWith(`${issuer}:`)) {
      account = account.slice(issuer.length + 1).trim();
    }

    return {
      secret: normalizeBase32(params.get("secret") || ""),
      issuer: issuer || "验证器账户",
      account: account || "未命名账户",
      algorithm: normalizeAlgorithm(params.get("algorithm") || "SHA-1"),
      digits: normalizeDigits(params.get("digits") || 6),
      period: normalizePeriod(params.get("period") || 30),
    };
  }

  return {
    secret: normalizeBase32(raw),
    issuer: defaults.issuer?.trim() || "自定义账户",
    account: defaults.account?.trim() || "Base32 secret",
    algorithm: normalizeAlgorithm(defaults.algorithm || "SHA-1"),
    digits: normalizeDigits(defaults.digits ?? 6),
    period: normalizePeriod(defaults.period ?? 30),
  };
}

export async function generateTOTP(config, timestamp = Date.now()) {
  if (!globalThis.crypto?.subtle) {
    throw new TotpInputError("当前环境不支持 Web Crypto，请通过 HTTPS 访问。");
  }

  const algorithm = normalizeAlgorithm(config.algorithm);
  const digits = normalizeDigits(config.digits);
  const period = normalizePeriod(config.period);
  const keyBytes = base32Decode(config.secret);
  const counter = Math.floor(timestamp / 1000 / period);
  const counterBuffer = new ArrayBuffer(8);
  new DataView(counterBuffer).setBigUint64(0, BigInt(counter), false);

  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await globalThis.crypto.subtle.sign("HMAC", key, counterBuffer),
  );
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  const code = (binary >>> 0) % 10 ** digits;

  return String(code).padStart(digits, "0");
}

export function buildOtpauthUri(config) {
  const issuer = config.issuer || "Doriya 2FA";
  const account = config.account || "Account";
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret: normalizeBase32(config.secret),
    issuer,
    algorithm: normalizeAlgorithm(config.algorithm).replace("-", ""),
    digits: String(normalizeDigits(config.digits)),
    period: String(normalizePeriod(config.period)),
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}
