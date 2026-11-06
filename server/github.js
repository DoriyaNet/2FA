import { createPrivateKey, sign } from "node:crypto";
import { ApiError, GitHubHttpError, GitHubNetworkError, GitHubOAuthError } from "./errors.js";
import { base64urlEncode } from "./crypto.js";

const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const USER_AGENT = "Doriya-2FA/1.0";
const API_VERSION = "2022-11-28";
const PER_PAGE = 100;
const MAX_PAGES = 100;
const INSTALLATION_TOKEN_EARLY_REFRESH_MS = 60 * 1000;
const DEFAULT_INSTALLATION_TOKEN_TTL_MS = 55 * 60 * 1000;

function requestHeaders({ token, tokenKind, accept, hasBody }) {
  const headers = {
    Accept: accept || "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": API_VERSION,
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
}

async function requestJson(
  url,
  {
    fetchImpl = globalThis.fetch,
    token,
    tokenKind = "user",
    method = "GET",
    body,
    accept,
  } = {},
) {
  if (typeof fetchImpl !== "function") {
    throw new ApiError(
      500,
      "fetch_unavailable",
      "The runtime does not provide fetch.",
    );
  }

  let response;
  try {
    response = await fetchImpl(url, {
      method,
      headers: requestHeaders({
        token,
        tokenKind,
        accept,
        hasBody: body !== undefined,
      }),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    throw new GitHubNetworkError("Could not reach GitHub.", { cause: error });
  }

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const message =
      typeof data?.message === "string"
        ? data.message
        : `GitHub returned HTTP ${response.status}.`;
    throw new GitHubHttpError(response.status, message, {
      authKind: tokenKind,
      requestId: response.headers.get("x-github-request-id"),
      githubCode: Array.isArray(data?.errors)
        ? data.errors.find((entry) => typeof entry?.code === "string")?.code
        : null,
    });
  }

  return data;
}

function withQuery(path, values = {}) {
  const url = new URL(path, GITHUB_API_BASE);
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function listPages(path, arrayKey, options = {}) {
  const items = [];
  let totalCount = null;

  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const data = await requestJson(
      withQuery(path, { per_page: PER_PAGE, page }),
      options,
    );
    const pageItems = Array.isArray(data?.[arrayKey]) ? data[arrayKey] : [];
    items.push(...pageItems);

    if (Number.isFinite(data?.total_count)) {
      totalCount = data.total_count;
    }
    if (
      pageItems.length < PER_PAGE ||
      (totalCount !== null && items.length >= totalCount)
    ) {
      return items;
    }
  }

  throw new GitHubHttpError(
    502,
    `GitHub pagination exceeded ${MAX_PAGES} pages.`,
    { authKind: options.tokenKind },
  );
}

function simplifyAccount(account) {
  if (!account || typeof account !== "object") {
    return null;
  }
  return {
    id: Number(account.id) || null,
    login: typeof account.login === "string" ? account.login : "",
    type: typeof account.type === "string" ? account.type : null,
    avatarUrl: typeof account.avatar_url === "string" ? account.avatar_url : null,
  };
}

export function simplifyInstallation(installation) {
  return {
    id: Number(installation?.id) || null,
    account: simplifyAccount(installation?.account),
    repositorySelection:
      typeof installation?.repository_selection === "string"
        ? installation.repository_selection
        : null,
  };
}

export function simplifyRepository(repository) {
  return {
    id: Number(repository?.id) || null,
    name: typeof repository?.name === "string" ? repository.name : "",
    fullName:
      typeof repository?.full_name === "string" ? repository.full_name : "",
    private: repository?.private === true,
    defaultBranch:
      typeof repository?.default_branch === "string"
        ? repository.default_branch
        : null,
    htmlUrl: typeof repository?.html_url === "string" ? repository.html_url : null,
    owner: simplifyAccount(repository?.owner),
  };
}

export function normalizeInstallationId(value) {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  }
  if (typeof value === "string" && /^[1-9]\d*$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

export function normalizeRepositoryFullName(value) {
  if (typeof value !== "string") {
    return null;
  }

  const parts = value.split("/");
  if (parts.length !== 2) {
    return null;
  }
  const [owner, name] = parts;
  if (
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner) ||
    !/^[A-Za-z0-9._-]{1,100}$/.test(name) ||
    name === "." ||
    name === ".."
  ) {
    return null;
  }
  return `${owner}/${name}`;
}

export function installationIsAccessible(installations, installationId) {
  const id = normalizeInstallationId(installationId);
  return (
    id !== null &&
    Array.isArray(installations) &&
    installations.some((installation) => Number(installation?.id) === id)
  );
}

export function repositoryIsAccessible(repositories, fullName) {
  const normalized = normalizeRepositoryFullName(fullName);
  if (!normalized || !Array.isArray(repositories)) {
    return false;
  }
  const expected = normalized.toLowerCase();
  return repositories.some(
    (repository) =>
      repository?.private === true &&
      typeof repository?.full_name === "string" &&
      repository.full_name.toLowerCase() === expected,
  );
}

export async function listUserInstallations(accessToken, options = {}) {
  return listPages("/user/installations", "installations", {
    ...options,
    token: accessToken,
    tokenKind: "user",
  });
}

export async function listInstallationRepositories(
  accessToken,
  installationId,
  options = {},
) {
  const id = normalizeInstallationId(installationId);
  if (id === null) {
    throw new ApiError(400, "invalid_installation_id", "installationId is invalid.");
  }

  return listPages(
    `/user/installations/${id}/repositories`,
    "repositories",
    {
      ...options,
      token: accessToken,
      tokenKind: "user",
    },
  );
}

export async function assertUserCanAccessInstallation(
  accessToken,
  installationId,
  options = {},
) {
  const id = normalizeInstallationId(installationId);
  if (id === null) {
    throw new ApiError(400, "invalid_installation_id", "installationId is invalid.");
  }

  let installations;
  try {
    installations = await listUserInstallations(accessToken, options);
  } catch (error) {
    if (error instanceof GitHubHttpError && error.status === 404) {
      throw new ApiError(
        403,
        "installation_forbidden",
        "This GitHub App installation is not accessible to the signed-in user.",
      );
    }
    throw error;
  }

  if (!installationIsAccessible(installations, id)) {
    throw new ApiError(
      403,
      "installation_forbidden",
      "This GitHub App installation is not accessible to the signed-in user.",
    );
  }
  return id;
}

export async function assertUserCanAccessRepository(
  accessToken,
  installationId,
  repository,
  options = {},
) {
  const id = normalizeInstallationId(installationId);
  if (id === null) {
    throw new ApiError(400, "invalid_installation_id", "installationId is invalid.");
  }
  const fullName = normalizeRepositoryFullName(repository);
  if (!fullName) {
    throw new ApiError(
      400,
      "invalid_repository",
      "repository must use the owner/name format.",
    );
  }

  let repositories;
  try {
    repositories = await listInstallationRepositories(accessToken, id, options);
  } catch (error) {
    if (error instanceof GitHubHttpError && error.status === 404) {
      throw new ApiError(
        403,
        "repository_forbidden",
        "The repository is not accessible to the signed-in user.",
      );
    }
    throw error;
  }

  if (!repositoryIsAccessible(repositories, fullName)) {
    throw new ApiError(
      403,
      "repository_forbidden",
      "The repository is not accessible to the signed-in user.",
    );
  }
  return fullName;
}

async function requestOAuthToken(payload, fetchImpl) {
  let response;
  try {
    const body = new URLSearchParams();
    for (const [key, value] of Object.entries(payload)) {
      body.set(key, String(value));
    }
    response = await fetchImpl(GITHUB_OAUTH_TOKEN_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT,
      },
      body: body.toString(),
    });
  } catch (error) {
    throw new GitHubNetworkError("Could not reach GitHub OAuth.", {
      cause: error,
    });
  }

  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!response.ok || data?.error) {
    throw new GitHubOAuthError(
      data?.error || "oauth_http_error",
      data?.error_description || `GitHub OAuth returned HTTP ${response.status}.`,
      response.status,
    );
  }
  return data;
}

export function normalizeOAuthToken(data, now = Date.now()) {
  if (!data || typeof data.access_token !== "string" || !data.access_token) {
    throw new GitHubOAuthError(
      "invalid_token_response",
      "GitHub did not return an access token.",
    );
  }

  const expiresIn = Number(data.expires_in);
  const refreshExpiresIn = Number(data.refresh_token_expires_in);
  return {
    accessToken: data.access_token,
    refreshToken:
      typeof data.refresh_token === "string" && data.refresh_token
        ? data.refresh_token
        : null,
    expiresAt:
      Number.isFinite(expiresIn) && expiresIn > 0
        ? now + expiresIn * 1000
        : null,
    refreshTokenExpiresAt:
      Number.isFinite(refreshExpiresIn) && refreshExpiresIn > 0
        ? now + refreshExpiresIn * 1000
        : null,
    scope: typeof data.scope === "string" ? data.scope : null,
    tokenType: typeof data.token_type === "string" ? data.token_type : "bearer",
  };
}

export async function exchangeOAuthCode({
  clientId,
  clientSecret,
  code,
  redirectUri,
  codeVerifier,
  fetchImpl = globalThis.fetch,
  now = Date.now(),
}) {
  const data = await requestOAuthToken(
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    },
    fetchImpl,
  );
  return normalizeOAuthToken(data, now);
}

export async function refreshOAuthToken({
  clientId,
  clientSecret,
  refreshToken,
  fetchImpl = globalThis.fetch,
  now = Date.now(),
}) {
  const data = await requestOAuthToken(
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    },
    fetchImpl,
  );
  return normalizeOAuthToken(data, now);
}

export async function fetchGitHubUser(accessToken, options = {}) {
  const user = await requestJson(`${GITHUB_API_BASE}/user`, {
    ...options,
    token: accessToken,
    tokenKind: "user",
  });
  if (
    !user ||
    !Number.isSafeInteger(Number(user.id)) ||
    Number(user.id) <= 0 ||
    typeof user.login !== "string"
  ) {
    throw new GitHubHttpError(502, "GitHub returned an invalid user payload.", {
      authKind: "user",
    });
  }

  return {
    id: Number(user.id),
    login: user.login,
    name: typeof user.name === "string" ? user.name : null,
    avatarUrl:
      typeof user.avatar_url === "string" ? user.avatar_url : null,
  };
}

export function createAppJwt({ appId, privateKey, now = Date.now() }) {
  let key;
  try {
    key = createPrivateKey(privateKey);
  } catch {
    throw new ApiError(
      503,
      "invalid_configuration",
      "GITHUB_APP_PRIVATE_KEY is not a valid RSA private key.",
    );
  }

  const issuedAt = Math.floor(now / 1000) - 60;
  const header = base64urlEncode(
    JSON.stringify({ alg: "RS256", typ: "JWT" }),
  );
  const payload = base64urlEncode(
    JSON.stringify({
      iat: issuedAt,
      exp: issuedAt + 540,
      iss: String(appId),
    }),
  );
  const unsigned = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(unsigned), key);
  return `${unsigned}.${signature.toString("base64url")}`;
}

export class InstallationTokenService {
  constructor({
    appId,
    privateKey,
    fetchImpl = globalThis.fetch,
    now = Date.now,
  }) {
    this.appId = appId;
    this.privateKey = privateKey;
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.cache = new Map();
    this.inflight = new Map();
    this.jwt = null;
    this.jwtExpiresAt = 0;
  }

  getJwt(now = this.now()) {
    if (this.jwt && now < this.jwtExpiresAt) {
      return this.jwt;
    }
    this.jwt = createAppJwt({
      appId: this.appId,
      privateKey: this.privateKey,
      now,
    });
    this.jwtExpiresAt = now + 8 * 60 * 1000;
    return this.jwt;
  }

  async get(installationId) {
    const id = normalizeInstallationId(installationId);
    if (id === null) {
      throw new ApiError(
        400,
        "invalid_installation_id",
        "installationId is invalid.",
      );
    }

    const now = this.now();
    const cached = this.cache.get(id);
    if (cached && cached.expiresAt - INSTALLATION_TOKEN_EARLY_REFRESH_MS > now) {
      return cached.token;
    }
    if (this.inflight.has(id)) {
      return this.inflight.get(id);
    }

    const promise = this.fetchToken(id, now).finally(() => {
      this.inflight.delete(id);
    });
    this.inflight.set(id, promise);
    return promise;
  }

  async fetchToken(id, now) {
    let data;
    try {
      data = await requestJson(
        `${GITHUB_API_BASE}/app/installations/${id}/access_tokens`,
        {
          fetchImpl: this.fetchImpl,
          token: this.getJwt(now),
          tokenKind: "app",
          method: "POST",
        },
      );
    } catch (error) {
      if (error instanceof GitHubHttpError) {
        if (error.status === 401) {
          this.jwt = null;
          this.jwtExpiresAt = 0;
          throw new ApiError(
            503,
            "invalid_configuration",
            "GitHub rejected the App JWT. Check GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY.",
          );
        }
        if (error.status === 404) {
          throw new ApiError(
            404,
            "installation_not_found",
            "The GitHub App installation could not be found.",
          );
        }
      }
      throw error;
    }

    if (typeof data?.token !== "string" || !data.token) {
      throw new GitHubHttpError(
        502,
        "GitHub did not return an installation token.",
        { authKind: "app" },
      );
    }

    const parsedExpiry = Date.parse(data.expires_at);
    const expiresAt = Number.isFinite(parsedExpiry)
      ? parsedExpiry
      : now + DEFAULT_INSTALLATION_TOKEN_TTL_MS;
    this.cache.set(id, { token: data.token, expiresAt });
    return data.token;
  }
}

function vaultContentsUrl(repository) {
  const [owner, name] = repository.split("/");
  return `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(
    name,
  )}/contents/.doriya/vault.json`;
}

export async function readVaultFile({
  installationToken,
  repository,
  fetchImpl = globalThis.fetch,
}) {
  let data;
  try {
    data = await requestJson(vaultContentsUrl(repository), {
      fetchImpl,
      token: installationToken,
      tokenKind: "installation",
    });
  } catch (error) {
    if (error instanceof GitHubHttpError && error.status === 404) {
      return {
        exists: false,
        sha: null,
        content: null,
        htmlUrl: null,
      };
    }
    throw error;
  }

  if (
    data?.type !== "file" ||
    data?.encoding !== "base64" ||
    typeof data?.content !== "string"
  ) {
    throw new GitHubHttpError(
      502,
      "The vault path is not a readable file.",
      { authKind: "installation" },
    );
  }

  return {
    exists: true,
    sha: typeof data.sha === "string" ? data.sha : null,
    content: Buffer.from(data.content, "base64").toString("utf8"),
    htmlUrl: typeof data.html_url === "string" ? data.html_url : null,
  };
}

export async function writeVaultFile({
  installationToken,
  repository,
  content,
  sha = null,
  fetchImpl = globalThis.fetch,
}) {
  const body = {
    message: "Update Doriya vault",
    content: Buffer.from(content, "utf8").toString("base64"),
  };
  if (sha) {
    body.sha = sha;
  }

  const data = await requestJson(vaultContentsUrl(repository), {
    fetchImpl,
    token: installationToken,
    tokenKind: "installation",
    method: "PUT",
    body,
  });

  return {
    exists: true,
    sha:
      typeof data?.content?.sha === "string" ? data.content.sha : null,
    content,
    htmlUrl:
      typeof data?.content?.html_url === "string"
        ? data.content.html_url
        : null,
  };
}
