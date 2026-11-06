import { ApiError } from "./errors.js";
import {
  createPkceChallenge,
  generatePkceVerifier,
  randomToken,
  safeStringEqual,
} from "./crypto.js";

const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const INSTALL_STATE_TTL_SECONDS = 10 * 60;
const MAX_RETURN_TO_LENGTH = 2048;
const INTERNAL_BASE_URL = "https://doriya.invalid";

export function sanitizeReturnTo(value, fallback = "/") {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  if (
    typeof value !== "string" ||
    value.length > MAX_RETURN_TO_LENGTH ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    return null;
  }

  try {
    const parsed = new URL(value, INTERNAL_BASE_URL);
    if (parsed.origin !== INTERNAL_BASE_URL) {
      return null;
    }

    const decodedPath = decodeURIComponent(parsed.pathname);
    if (
      decodedPath.startsWith("//") ||
      decodedPath.includes("\\") ||
      /[\u0000-\u001f\u007f]/.test(decodedPath)
    ) {
      return null;
    }

    const normalized = `${parsed.pathname}${parsed.search}${parsed.hash}`;
    if (!normalized.startsWith("/") || normalized.startsWith("//")) {
      return null;
    }
    return normalized;
  } catch {
    return null;
  }
}

export function createOAuthAttempt({
  returnTo = "/",
  redirectUri,
  now = Date.now(),
} = {}) {
  const safeReturnTo = sanitizeReturnTo(returnTo);
  if (!safeReturnTo) {
    throw new ApiError(
      400,
      "invalid_return_to",
      "returnTo must be a site-relative path.",
    );
  }
  if (typeof redirectUri !== "string" || redirectUri.length === 0) {
    throw new ApiError(
      500,
      "invalid_configuration",
      "OAuth redirect URI is missing.",
    );
  }

  const state = randomToken(32);
  const verifier = generatePkceVerifier();
  return {
    cookie: {
      version: 1,
      state,
      verifier,
      returnTo: safeReturnTo,
      redirectUri,
      expiresAt: now + OAUTH_STATE_TTL_SECONDS * 1000,
    },
    challenge: createPkceChallenge(verifier),
    maxAge: OAUTH_STATE_TTL_SECONDS,
  };
}

export function validateOAuthAttempt(attempt, state, now = Date.now()) {
  if (
    !attempt ||
    attempt.version !== 1 ||
    typeof attempt.state !== "string" ||
    typeof attempt.verifier !== "string" ||
    typeof attempt.redirectUri !== "string" ||
    !Number.isFinite(attempt.expiresAt) ||
    attempt.expiresAt <= now
  ) {
    throw new ApiError(
      400,
      "invalid_state",
      "The OAuth state is missing or expired. Please sign in again.",
    );
  }
  if (!safeStringEqual(attempt.state, state)) {
    throw new ApiError(
      400,
      "invalid_state",
      "The OAuth state does not match. Please sign in again.",
    );
  }

  const returnTo = sanitizeReturnTo(attempt.returnTo, null);
  if (!returnTo) {
    throw new ApiError(
      400,
      "invalid_return_to",
      "The saved return path is invalid.",
    );
  }
  return { ...attempt, returnTo };
}

export function buildAuthorizeUrl({
  clientId,
  redirectUri,
  state,
  codeChallenge,
}) {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export function createInstallAttempt({ userId, now = Date.now() }) {
  if (!Number.isSafeInteger(Number(userId)) || Number(userId) <= 0) {
    throw new ApiError(401, "not_authenticated", "A valid session is required.");
  }

  return {
    cookie: {
      version: 1,
      state: randomToken(32),
      userId: Number(userId),
      expiresAt: now + INSTALL_STATE_TTL_SECONDS * 1000,
    },
    maxAge: INSTALL_STATE_TTL_SECONDS,
  };
}

export function validateInstallAttempt(attempt, state, userId, now = Date.now()) {
  if (
    !attempt ||
    attempt.version !== 1 ||
    typeof attempt.state !== "string" ||
    !Number.isFinite(attempt.expiresAt) ||
    attempt.expiresAt <= now
  ) {
    throw new ApiError(
      400,
      "invalid_install_state",
      "The GitHub App installation state is missing or expired.",
    );
  }
  if (!safeStringEqual(attempt.state, state)) {
    throw new ApiError(
      400,
      "invalid_install_state",
      "The GitHub App installation state does not match.",
    );
  }
  if (attempt.userId !== Number(userId)) {
    throw new ApiError(
      403,
      "invalid_install_state",
      "This installation request belongs to a different user.",
    );
  }
  return attempt;
}

export function buildInstallUrl(slug, state) {
  return `https://github.com/apps/${encodeURIComponent(
    slug,
  )}/installations/new?state=${encodeURIComponent(state)}`;
}
