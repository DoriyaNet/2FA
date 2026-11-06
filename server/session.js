import { ApiError } from "./errors.js";
import { encryptJson } from "./crypto.js";

export const SESSION_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
export const SESSION_REFRESH_WINDOW_MS = 60 * 1000;

export function createSession({ user, token, now = Date.now() }) {
  if (
    !user ||
    !Number.isSafeInteger(user.id) ||
    user.id <= 0 ||
    typeof user.login !== "string"
  ) {
    throw new ApiError(502, "invalid_user", "GitHub user data is invalid.");
  }
  if (!token || typeof token.accessToken !== "string") {
    throw new ApiError(502, "invalid_token", "GitHub token data is invalid.");
  }

  return {
    version: 1,
    user: {
      id: user.id,
      login: user.login,
      name: user.name ?? null,
      avatarUrl: user.avatarUrl ?? null,
    },
    accessToken: token.accessToken,
    refreshToken: token.refreshToken ?? null,
    expiresAt: token.expiresAt ?? null,
    refreshTokenExpiresAt: token.refreshTokenExpiresAt ?? null,
    scope: token.scope ?? null,
    createdAt: now,
  };
}

export function sessionCookieMaxAge(session, now = Date.now()) {
  const refreshExpiry = session.refreshTokenExpiresAt;
  let expiry;
  if (session.refreshToken) {
    if (!Number.isFinite(refreshExpiry)) {
      return SESSION_COOKIE_MAX_AGE_SECONDS;
    }
    expiry =
      refreshExpiry > now ? refreshExpiry : session.expiresAt;
  } else if (!Number.isFinite(session.expiresAt)) {
    return SESSION_COOKIE_MAX_AGE_SECONDS;
  } else {
    expiry = session.expiresAt;
  }
  if (!Number.isFinite(expiry) || expiry <= now) {
    return 1;
  }

  return Math.max(
    1,
    Math.min(
      SESSION_COOKIE_MAX_AGE_SECONDS,
      Math.floor((expiry - now) / 1000),
    ),
  );
}

export function isSessionValid(session, now = Date.now()) {
  return Boolean(
    session &&
      session.version === 1 &&
      session.user &&
      typeof session.user.id === "number" &&
      typeof session.user.login === "string" &&
      typeof session.accessToken === "string" &&
      session.accessToken.length > 0 &&
      (!Number.isFinite(session.expiresAt) || session.expiresAt > now),
  );
}

export function shouldRefreshSession(session, now = Date.now()) {
  return Boolean(
    Number.isFinite(session?.expiresAt) &&
      session.expiresAt <= now + SESSION_REFRESH_WINDOW_MS,
  );
}

export function mergeRefreshedToken(session, token, now = Date.now()) {
  return {
    ...session,
    accessToken: token.accessToken,
    refreshToken: token.refreshToken || session.refreshToken || null,
    expiresAt: token.expiresAt ?? null,
    refreshTokenExpiresAt:
      token.refreshTokenExpiresAt ?? session.refreshTokenExpiresAt ?? null,
    scope: token.scope ?? session.scope ?? null,
    createdAt: now,
  };
}

export function encryptSession(session, secret) {
  return encryptJson(session, secret, "doriya2fa:session:v1");
}
