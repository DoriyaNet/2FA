import { Buffer } from "node:buffer";

import { ApiError } from "./errors.js";

export const REQUIRED_ENV_NAMES = Object.freeze([
  "GITHUB_APP_ID",
  "GITHUB_APP_CLIENT_ID",
  "GITHUB_APP_CLIENT_SECRET",
  "GITHUB_APP_PRIVATE_KEY",
  "GITHUB_APP_SLUG",
  "SESSION_SECRET",
]);

export function normalizePrivateKey(value) {
  if (typeof value !== "string") {
    return "";
  }

  let key = value.trim();
  if (
    key.length >= 2 &&
    ((key.startsWith('"') && key.endsWith('"')) ||
      (key.startsWith("'") && key.endsWith("'")))
  ) {
    key = key.slice(1, -1);
  }

  return key.replace(/\\n/g, "\n").trim();
}

function normalizeAppOrigin(value) {
  if (!value) {
    return { appOrigin: null, error: null };
  }

  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("unsupported protocol");
    }
    return { appOrigin: url.origin, error: null };
  } catch {
    return {
      appOrigin: null,
      error: "APP_ORIGIN must be a valid absolute http(s) URL.",
    };
  }
}

export function readConfig(env = process.env) {
  const values = {};
  for (const name of REQUIRED_ENV_NAMES) {
    values[name] = typeof env[name] === "string" ? env[name].trim() : "";
  }

  const missing = REQUIRED_ENV_NAMES.filter((name) => !values[name]);
  const appOriginValue =
    typeof env.APP_ORIGIN === "string" ? env.APP_ORIGIN.trim() : "";
  const origin = normalizeAppOrigin(appOriginValue);
  const privateKey = normalizePrivateKey(values.GITHUB_APP_PRIVATE_KEY);
  const configErrors = [];
  if (origin.error) {
    configErrors.push(origin.error);
  }
  if (values.SESSION_SECRET && Buffer.byteLength(values.SESSION_SECRET, "utf8") < 32) {
    configErrors.push("SESSION_SECRET must contain at least 32 bytes.");
  }

  return {
    appId: values.GITHUB_APP_ID,
    clientId: values.GITHUB_APP_CLIENT_ID,
    clientSecret: values.GITHUB_APP_CLIENT_SECRET,
    privateKey,
    slug: values.GITHUB_APP_SLUG,
    sessionSecret: values.SESSION_SECRET,
    appOrigin: origin.appOrigin,
    missing,
    configErrors,
    configured: missing.length === 0 && configErrors.length === 0,
    isProduction:
      env.NODE_ENV === "production" ||
      env.VERCEL_ENV === "production" ||
      env.VERCEL_ENV === "preview" ||
      origin.appOrigin?.startsWith("https://") === true,
  };
}

export function assertConfigured(config) {
  if (config.missing.length > 0 || config.configErrors.length > 0) {
    const details = [];
    if (config.missing.length > 0) {
      details.push(`missing ${config.missing.join(", ")}`);
    }
    details.push(...config.configErrors);
    throw new ApiError(
      503,
      "not_configured",
      `GitHub App backend is not configured (${details.join("; ")}).`,
    );
  }
}

export function getRequestOrigin(req, config) {
  if (config.appOrigin) {
    return config.appOrigin;
  }

  const forwardedHost = firstHeaderValue(req.headers["x-forwarded-host"]);
  const host = forwardedHost || req.headers.host;
  if (!host) {
    throw new ApiError(400, "invalid_host", "The request Host header is missing.");
  }

  const forwardedProto = firstHeaderValue(req.headers["x-forwarded-proto"]);
  const proto = forwardedProto || (req.socket?.encrypted ? "https" : "http");
  if (proto !== "http" && proto !== "https") {
    throw new ApiError(400, "invalid_host", "The request protocol is invalid.");
  }

  try {
    return new URL(`${proto}://${host}`).origin;
  } catch {
    throw new ApiError(400, "invalid_host", "The request Host header is invalid.");
  }
}

export function getOAuthRedirectUri(req, config) {
  return `${getRequestOrigin(req, config)}/api/auth/callback`;
}

function firstHeaderValue(value) {
  if (Array.isArray(value)) {
    value = value[0];
  }
  return typeof value === "string" ? value.split(",")[0].trim() : "";
}
