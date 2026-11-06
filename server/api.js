import { Buffer } from "node:buffer";

import { ApiError, GitHubHttpError, GitHubNetworkError, GitHubOAuthError } from "./errors.js";
import { assertConfigured, getOAuthRedirectUri, readConfig } from "./config.js";
import {
  COOKIE_NAMES,
  clearCookie,
  parseCookies,
  serializeCookie,
} from "./cookies.js";
import { decryptJson, encryptJson } from "./crypto.js";
import {
  InstallationTokenService,
  assertUserCanAccessInstallation,
  assertUserCanAccessRepository,
  exchangeOAuthCode,
  fetchGitHubUser,
  listInstallationRepositories,
  listUserInstallations,
  normalizeInstallationId,
  normalizeRepositoryFullName,
  readVaultFile,
  refreshOAuthToken,
  simplifyInstallation,
  simplifyRepository,
  writeVaultFile,
} from "./github.js";
import {
  buildAuthorizeUrl,
  buildInstallUrl,
  createInstallAttempt,
  createOAuthAttempt,
  sanitizeReturnTo,
  validateInstallAttempt,
  validateOAuthAttempt,
} from "./oauth.js";
import {
  createSession,
  encryptSession,
  isSessionValid,
  mergeRefreshedToken,
  sessionCookieMaxAge,
  shouldRefreshSession,
} from "./session.js";

const MAX_JSON_BODY_BYTES = 768 * 1024;
const MAX_VAULT_BYTES = 512 * 1024;

export function createApiHandler({
  env = process.env,
  fetchImpl = globalThis.fetch,
  now = Date.now,
  logger = console,
} = {}) {
  const config = readConfig(env);
  const installationTokens = new InstallationTokenService({
    appId: config.appId,
    privateKey: config.privateKey,
    fetchImpl,
    now,
  });

  return async function apiHandler(req, res) {
    const context = createResponseContext(res, config, logger);
    let pathname = "/";

    try {
      const url = requestUrl(req);
      pathname = normalizePathname(url.pathname);
      await route({
        req,
        res,
        url,
        pathname,
        context,
        config,
        fetchImpl,
        now,
        installationTokens,
      });
    } catch (error) {
      sendError({
        context,
        error,
        logger,
        method: req.method,
        pathname,
      });
    }
  };
}

async function route({
  req,
  url,
  pathname,
  context,
  config,
  fetchImpl,
  now,
  installationTokens,
}) {
  if (pathname === "/api/auth/login") {
    assertMethod(req, ["GET"]);
    assertConfigured(config);
    await handleLogin({ req, url, context, config, now });
    return;
  }

  if (pathname === "/api/auth/callback") {
    assertMethod(req, ["GET"]);
    assertConfigured(config);
    await handleCallback({ req, url, context, config, fetchImpl, now });
    return;
  }

  if (pathname === "/api/auth/session") {
    assertMethod(req, ["GET"]);
    await handleSession({ req, context, config, fetchImpl, now });
    return;
  }

  if (pathname === "/api/auth/logout") {
    assertMethod(req, ["POST"]);
    context.clearCookie(COOKIE_NAMES.session);
    context.json(200, { ok: true });
    return;
  }

  if (pathname === "/api/github/installations") {
    assertMethod(req, ["GET"]);
    assertConfigured(config);
    const session = await requireSession({
      req,
      context,
      config,
      fetchImpl,
      now,
    });
    const installations = await listUserInstallations(session.accessToken, {
      fetchImpl,
    });
    context.json(200, {
      installations: installations.map(simplifyInstallation),
    });
    return;
  }

  if (pathname === "/api/github/install") {
    assertMethod(req, ["POST"]);
    assertConfigured(config);
    const session = await requireSession({
      req,
      context,
      config,
      fetchImpl,
      now,
    });
    const attempt = createInstallAttempt({
      userId: session.user.id,
      now: now(),
    });
    context.setCookie(
      COOKIE_NAMES.installState,
      encryptJson(
        attempt.cookie,
        config.sessionSecret,
        "doriya2fa:install-state:v1",
      ),
      { maxAge: attempt.maxAge },
    );
    context.redirect(302, buildInstallUrl(config.slug, attempt.cookie.state));
    return;
  }

  if (pathname === "/api/github/setup") {
    assertMethod(req, ["GET"]);
    assertConfigured(config);
    await handleSetup({ req, url, context, config, fetchImpl, now });
    return;
  }

  if (pathname === "/api/github/repositories") {
    assertMethod(req, ["GET"]);
    assertConfigured(config);
    const session = await requireSession({
      req,
      context,
      config,
      fetchImpl,
      now,
    });
    const installationId = requireInstallationId(
      url.searchParams.get("installationId"),
    );
    await assertUserCanAccessInstallation(
      session.accessToken,
      installationId,
      { fetchImpl },
    );
    const repositories = await listInstallationRepositories(
      session.accessToken,
      installationId,
      { fetchImpl },
    );
    context.json(200, {
      repositories: repositories
        .map(simplifyRepository)
        .filter((repository) => repository.private === true),
    });
    return;
  }

  if (pathname === "/api/github/vault") {
    assertConfigured(config);
    if (req.method === "GET") {
      await handleGetVault({
        req,
        url,
        context,
        config,
        fetchImpl,
        now,
        installationTokens,
      });
      return;
    }
    if (req.method === "PUT") {
      await handlePutVault({
        req,
        url,
        context,
        config,
        fetchImpl,
        now,
        installationTokens,
      });
      return;
    }
    throw new ApiError(
      405,
      "method_not_allowed",
      "Use GET or PUT for this endpoint.",
    );
  }

  throw new ApiError(404, "not_found", "API route not found.");
}

async function handleLogin({ req, url, context, config, now }) {
  const returnToParam = url.searchParams.get("returnTo");
  const returnTo =
    returnToParam === null ? "/" : sanitizeReturnTo(returnToParam, null);
  if (!returnTo) {
    throw new ApiError(
      400,
      "invalid_return_to",
      "returnTo must be a site-relative path.",
    );
  }

  const redirectUri = getOAuthRedirectUri(req, config);
  const attempt = createOAuthAttempt({
    returnTo,
    redirectUri,
    now: now(),
  });
  context.setCookie(
    COOKIE_NAMES.oauthState,
    encryptJson(
      attempt.cookie,
      config.sessionSecret,
      "doriya2fa:oauth-state:v1",
    ),
    { maxAge: attempt.maxAge },
  );
  context.redirect(
    302,
    buildAuthorizeUrl({
      clientId: config.clientId,
      redirectUri,
      state: attempt.cookie.state,
      codeChallenge: attempt.challenge,
    }),
  );
}

async function handleCallback({
  req,
  url,
  context,
  config,
  fetchImpl,
  now,
}) {
  const cookies = parseCookies(req.headers.cookie);
  const encryptedAttempt = cookies[COOKIE_NAMES.oauthState];
  if (encryptedAttempt) {
    context.clearCookie(COOKIE_NAMES.oauthState);
  }
  if (!encryptedAttempt) {
    throw new ApiError(
      400,
      "invalid_state",
      "The OAuth state cookie is missing. Please sign in again.",
    );
  }

  let cookieAttempt;
  try {
    cookieAttempt = decryptJson(
      encryptedAttempt,
      config.sessionSecret,
      "doriya2fa:oauth-state:v1",
    );
  } catch {
    throw new ApiError(
      400,
      "invalid_state",
      "The OAuth state cookie is invalid. Please sign in again.",
    );
  }

  const attempt = validateOAuthAttempt(
    cookieAttempt,
    url.searchParams.get("state"),
    now(),
  );

  if (url.searchParams.has("error")) {
    throw new ApiError(
      401,
      "oauth_denied",
      "GitHub authorization was cancelled or denied.",
    );
  }
  const code = url.searchParams.get("code");
  if (!code) {
    throw new ApiError(400, "missing_code", "GitHub did not return an OAuth code.");
  }

  let token;
  try {
    token = await exchangeOAuthCode({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      code,
      redirectUri: attempt.redirectUri,
      codeVerifier: attempt.verifier,
      fetchImpl,
      now: now(),
    });
  } catch (error) {
    if (error instanceof GitHubOAuthError) {
      throw new ApiError(
        401,
        "oauth_failed",
        `GitHub sign-in failed: ${error.message}`,
      );
    }
    throw error;
  }

  const user = await fetchGitHubUser(token.accessToken, { fetchImpl });
  const session = createSession({ user, token, now: now() });
  setSessionCookie(context, config, session, now());
  context.redirect(302, attempt.returnTo);
}

async function handleSession({ req, context, config, fetchImpl, now }) {
  if (!config.configured) {
    context.json(200, { configured: false, authenticated: false });
    return;
  }

  const session = await requireSession({
    req,
    context,
    config,
    fetchImpl,
    now,
    optional: true,
  });

  if (!session) {
    context.json(200, { configured: true, authenticated: false });
    return;
  }
  context.json(200, {
    configured: true,
    authenticated: true,
    user: session.user,
  });
}

async function handleSetup({ req, url, context, config, fetchImpl, now }) {
  let session = null;
  try {
    session = await requireSession({
      req,
      context,
      config,
      fetchImpl,
      now,
      optional: true,
    });
  } catch (error) {
    if (!(error instanceof ApiError && error.code === "reauth_required")) {
      throw error;
    }
  }

  if (!session) {
    const returnTo = sanitizeReturnTo(
      `${url.pathname}${url.search}`,
      null,
    );
    if (!returnTo) {
      throw new ApiError(400, "invalid_return_to", "Invalid setup return path.");
    }
    context.redirect(
      302,
      `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`,
    );
    return;
  }

  const state = url.searchParams.get("state");
  const installationId = requireInstallationId(
    url.searchParams.get("installation_id"),
  );
  const cookies = parseCookies(req.headers.cookie);
  const encryptedAttempt = cookies[COOKIE_NAMES.installState];
  if (encryptedAttempt) {
    context.clearCookie(COOKIE_NAMES.installState);
  }
  if (!encryptedAttempt) {
    throw new ApiError(
      400,
      "invalid_install_state",
      "The GitHub App installation state cookie is missing.",
    );
  }

  let cookieAttempt;
  try {
    cookieAttempt = decryptJson(
      encryptedAttempt,
      config.sessionSecret,
      "doriya2fa:install-state:v1",
    );
  } catch {
    throw new ApiError(
      400,
      "invalid_install_state",
      "The GitHub App installation state cookie is invalid.",
    );
  }
  validateInstallAttempt(
    cookieAttempt,
    state,
    session.user.id,
    now(),
  );

  await assertUserCanAccessInstallation(
    session.accessToken,
    installationId,
    { fetchImpl },
  );
  context.redirect(302, "/?github=installed");
}

async function handleGetVault({
  req,
  url,
  context,
  config,
  fetchImpl,
  now,
  installationTokens,
}) {
  const session = await requireSession({
    req,
    context,
    config,
    fetchImpl,
    now,
  });
  const installationId = requireInstallationId(
    url.searchParams.get("installationId"),
  );
  const repository = requireRepository(url.searchParams.get("repository"));
  await assertUserCanAccessRepository(
    session.accessToken,
    installationId,
    repository,
    { fetchImpl },
  );

  const installationToken = await installationTokens.get(installationId);
  const vault = await readVaultFile({
    installationToken,
    repository,
    fetchImpl,
  });
  if (
    vault.content !== null &&
    Buffer.byteLength(vault.content, "utf8") > MAX_VAULT_BYTES
  ) {
    throw new ApiError(
      413,
      "vault_too_large",
      "The vault file exceeds the 512 KB limit.",
    );
  }
  context.json(200, vault);
}

async function handlePutVault({
  req,
  url,
  context,
  config,
  fetchImpl,
  now,
  installationTokens,
}) {
  const session = await requireSession({
    req,
    context,
    config,
    fetchImpl,
    now,
  });
  const body = await readJsonBody(req);
  const installationId = requireInstallationId(
    body.installationId ?? url.searchParams.get("installationId"),
  );
  const repository = requireRepository(
    body.repository ?? url.searchParams.get("repository"),
  );
  if (typeof body.content !== "string") {
    throw new ApiError(400, "invalid_content", "content must be a string.");
  }
  if (Buffer.byteLength(body.content, "utf8") > MAX_VAULT_BYTES) {
    throw new ApiError(
      413,
      "vault_too_large",
      "The vault file exceeds the 512 KB limit.",
    );
  }
  if (
    body.sha !== undefined &&
    body.sha !== null &&
    (typeof body.sha !== "string" ||
      !/^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(body.sha))
  ) {
    throw new ApiError(400, "invalid_sha", "sha must be a full Git object SHA.");
  }

  await assertUserCanAccessRepository(
    session.accessToken,
    installationId,
    repository,
    { fetchImpl },
  );
  const installationToken = await installationTokens.get(installationId);

  let vault;
  try {
    vault = await writeVaultFile({
      installationToken,
      repository,
      content: body.content,
      sha: body.sha ?? null,
      fetchImpl,
    });
  } catch (error) {
    if (error instanceof GitHubHttpError) {
      if (error.status === 409 || error.status === 422) {
        throw new ApiError(
          409,
          "vault_conflict",
          "The vault changed on GitHub. Fetch the latest SHA and try again.",
        );
      }
      if (error.status === 404) {
        throw new ApiError(
          404,
          "repository_not_found",
          "The repository or .doriya path could not be found.",
        );
      }
      if (error.status === 403) {
        throw new ApiError(
          403,
          "vault_forbidden",
          "The GitHub App cannot write to this repository.",
        );
      }
    }
    throw error;
  }

  context.json(200, vault);
}

async function requireSession({
  req,
  context,
  config,
  fetchImpl,
  now,
  optional = false,
}) {
  const cookies = parseCookies(req.headers.cookie);
  const encryptedSession = cookies[COOKIE_NAMES.session];
  if (!encryptedSession) {
    if (optional) {
      return null;
    }
    throw new ApiError(401, "not_authenticated", "GitHub sign-in is required.");
  }

  let session;
  try {
    session = decryptJson(
      encryptedSession,
      config.sessionSecret,
      "doriya2fa:session:v1",
    );
  } catch {
    context.clearCookie(COOKIE_NAMES.session);
    if (optional) {
      return null;
    }
    throw new ApiError(
      401,
      "reauth_required",
      "The session cookie is invalid. Please sign in again.",
    );
  }

  const currentTime = now();
  const accessExpired =
    Number.isFinite(session?.expiresAt) && session.expiresAt <= currentTime;
  const refreshAvailable =
    typeof session?.refreshToken === "string" &&
    session.refreshToken.length > 0 &&
    (!Number.isFinite(session.refreshTokenExpiresAt) ||
      session.refreshTokenExpiresAt > currentTime);

  if (shouldRefreshSession(session, currentTime) && refreshAvailable) {
    try {
      const token = await refreshOAuthToken({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        refreshToken: session.refreshToken,
        fetchImpl,
        now: currentTime,
      });
      session = mergeRefreshedToken(session, token, currentTime);
      setSessionCookie(context, config, session, currentTime);
    } catch (error) {
      if (accessExpired) {
        context.clearCookie(COOKIE_NAMES.session);
        if (optional) {
          return null;
        }
        throw new ApiError(
          401,
          "reauth_required",
          "The GitHub session expired and could not be refreshed. Please sign in again.",
        );
      }
      if (
        error instanceof GitHubOAuthError &&
        (error.status === 400 || error.status === 401)
      ) {
        context.warn?.(
          "GitHub token refresh was rejected before access token expiry.",
          error.code,
        );
      } else {
        throw error;
      }
    }
  }

  if (!isSessionValid(session, now())) {
    context.clearCookie(COOKIE_NAMES.session);
    throw new ApiError(
      401,
      "reauth_required",
      "The GitHub session expired. Please sign in again.",
    );
  }
  return session;
}

function setSessionCookie(context, config, session, currentTime) {
  context.setCookie(
    COOKIE_NAMES.session,
    encryptSession(session, config.sessionSecret),
    { maxAge: sessionCookieMaxAge(session, currentTime) },
  );
}

function createResponseContext(res, config, logger) {
  const cookies = [];
  let sent = false;

  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("X-Content-Type-Options", "nosniff");

  function commitCookies() {
    if (cookies.length > 0) {
      res.setHeader("Set-Cookie", cookies);
    }
  }

  return {
    setCookie(name, value, options = {}) {
      cookies.push(
        serializeCookie(name, value, {
          ...options,
          secure: config.isProduction,
        }),
      );
    },
    clearCookie(name) {
      cookies.push(
        clearCookie(name, {
          secure: config.isProduction,
        }),
      );
    },
    json(status, payload) {
      if (sent) {
        return;
      }
      sent = true;
      commitCookies();
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(payload));
    },
    redirect(status, location) {
      if (sent) {
        return;
      }
      sent = true;
      commitCookies();
      res.statusCode = status;
      res.setHeader("Location", location);
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end();
    },
    get sent() {
      return sent;
    },
    warn(message, detail) {
      logger?.warn?.(`[github-api] ${message}`, detail || "");
    },
  };
}

function sendError({ context, error, logger, method, pathname }) {
  if (context.sent) {
    return;
  }

  const mapped = mapError(error);
  if (mapped.code === "reauth_required") {
    context.clearCookie(COOKIE_NAMES.session);
  }
  if (mapped.status >= 500 && !(error instanceof ApiError)) {
    logger?.error?.(
      `[github-api] ${method || "?"} ${pathname} failed:`,
      error,
    );
  }
  context.json(mapped.status, {
    error: {
      code: mapped.code,
      message: mapped.message,
    },
  });
}

function mapError(error) {
  if (error instanceof ApiError) {
    return error;
  }
  if (error instanceof GitHubHttpError) {
    if (error.status === 401 && error.authKind === "user") {
      return new ApiError(
        401,
        "reauth_required",
        "GitHub no longer accepts this session. Please sign in again.",
      );
    }
    if (error.status === 403) {
      return new ApiError(
        403,
        "github_forbidden",
        "GitHub denied access to the requested resource.",
      );
    }
    if (error.status === 404) {
      return new ApiError(
        404,
        "github_not_found",
        "The requested GitHub resource was not found.",
      );
    }
    return new ApiError(
      502,
      "github_api_error",
      `GitHub API request failed (HTTP ${error.status}).`,
    );
  }
  if (error instanceof GitHubNetworkError) {
    return new ApiError(
      502,
      "github_unavailable",
      "GitHub could not be reached. Please try again.",
    );
  }
  if (error instanceof GitHubOAuthError) {
    return new ApiError(
      401,
      "oauth_failed",
      `GitHub OAuth failed: ${error.message}`,
    );
  }
  return new ApiError(
    500,
    "internal_error",
    "An unexpected server error occurred.",
  );
}

async function readJsonBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) {
      return parseJsonBuffer(req.body);
    }
    if (typeof req.body === "string") {
      if (Buffer.byteLength(req.body, "utf8") > MAX_JSON_BODY_BYTES) {
        throw bodyTooLarge();
      }
      return parseJsonBuffer(Buffer.from(req.body, "utf8"));
    }
    if (typeof req.body === "object") {
      return req.body;
    }
  }

  const contentLength = Number(req.headers["content-length"]);
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BODY_BYTES) {
    throw bodyTooLarge();
  }

  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of req) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > MAX_JSON_BODY_BYTES) {
        throw bodyTooLarge();
      }
      chunks.push(buffer);
    }
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(400, "invalid_body", "Could not read the request body.");
  }

  if (chunks.length === 0) {
    throw new ApiError(400, "invalid_body", "A JSON request body is required.");
  }
  return parseJsonBuffer(Buffer.concat(chunks));
}

function parseJsonBuffer(buffer) {
  if (buffer.length > MAX_JSON_BODY_BYTES) {
    throw bodyTooLarge();
  }
  if (buffer.length === 0) {
    throw new ApiError(400, "invalid_body", "A JSON request body is required.");
  }

  let value;
  try {
    value = JSON.parse(buffer.toString("utf8"));
  } catch {
    throw new ApiError(400, "invalid_json", "The request body is not valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, "invalid_body", "The JSON body must be an object.");
  }
  return value;
}

function bodyTooLarge() {
  return new ApiError(
    413,
    "body_too_large",
    "The request body exceeds the 768 KB limit.",
  );
}

function requireInstallationId(value) {
  const id = normalizeInstallationId(value);
  if (id === null) {
    throw new ApiError(
      400,
      "invalid_installation_id",
      "installationId must be a positive integer.",
    );
  }
  return id;
}

function requireRepository(value) {
  const repository = normalizeRepositoryFullName(value);
  if (!repository) {
    throw new ApiError(
      400,
      "invalid_repository",
      "repository must use the owner/name format.",
    );
  }
  return repository;
}

function assertMethod(req, allowed) {
  if (!allowed.includes(req.method)) {
    throw new ApiError(
      405,
      "method_not_allowed",
      `Use ${allowed.join(" or ")} for this endpoint.`,
    );
  }
}

function requestUrl(req) {
  try {
    return new URL(req.url || "/", "http://localhost");
  } catch {
    throw new ApiError(400, "invalid_url", "The request URL is invalid.");
  }
}

function normalizePathname(pathname) {
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname;
}

