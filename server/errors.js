export class ApiError extends Error {
  constructor(status, code, message, options = {}) {
    super(message, options);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export class GitHubHttpError extends Error {
  constructor(status, message, options = {}) {
    super(message);
    this.name = "GitHubHttpError";
    this.status = status;
    this.authKind = options.authKind ?? "unknown";
    this.requestId = options.requestId ?? null;
    this.githubCode = options.githubCode ?? null;
  }
}

export class GitHubOAuthError extends Error {
  constructor(code, description, status = 400) {
    super(description || code || "GitHub OAuth request failed.");
    this.name = "GitHubOAuthError";
    this.code = code || "oauth_error";
    this.status = status;
  }
}

export class GitHubNetworkError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "GitHubNetworkError";
  }
}
