# GitHub App Backend

All routes below are served from `/api` by both Vercel and the Vite dev
middleware. API responses use `Cache-Control: no-store`.

## GitHub App configuration

- OAuth callback URL: `https://YOUR_ORIGIN/api/auth/callback`
- Setup URL: `https://YOUR_ORIGIN/api/github/setup`
- Repository permissions: Contents read/write, Metadata read-only

The Setup URL must point at the backend setup route so the installation state
cookie can be checked before returning to the site.

## Authentication

### `GET /api/auth/login?returnTo=/optional/path`

Creates an encrypted, short-lived OAuth state/PKCE cookie and redirects to
GitHub with `302`.

`returnTo` must be a site-relative path. External, protocol-relative, path
traversal via backslashes, and control-character values return
`400 invalid_return_to`.

### `GET /api/auth/callback?code=...&state=...`

Validates state and PKCE, exchanges the code for a user access token, loads
`GET /user`, sets the encrypted session cookie, and redirects to the saved
site-relative path with `302`.

### `GET /api/auth/session`

```json
{
  "configured": true,
  "authenticated": true,
  "user": {
    "id": 123,
    "login": "octocat",
    "name": "Octo Cat",
    "avatarUrl": "https://..."
  }
}
```

No access or refresh token is returned. If an access token is expired, has no
refresh token, and cannot be refreshed, the endpoint returns `401` with
`error.code = "reauth_required"`.

### `POST /api/auth/logout`

Clears the session cookie.

```json
{ "ok": true }
```

## Installations and repositories

### `GET /api/github/installations`

```json
{
  "installations": [
    {
      "id": 123,
      "account": {
        "id": 456,
        "login": "octocat",
        "type": "User",
        "avatarUrl": "https://..."
      },
      "repositorySelection": "selected"
    }
  ]
}
```

### `POST /api/github/install`

Sets an encrypted installation-state cookie and redirects to the GitHub App
installation page with `302`.

### `GET /api/github/setup?installation_id=123&state=...`

If unauthenticated, redirects through `/api/auth/login` and then returns to the
setup request. Otherwise validates the installation state cookie, verifies
that the current user can access the installation, and redirects to
`/?github=installed`.

### `GET /api/github/repositories?installationId=123`

```json
{
  "repositories": [
    {
      "id": 789,
      "name": "vault",
      "fullName": "octocat/vault",
      "private": true,
      "defaultBranch": "main",
      "htmlUrl": "https://github.com/octocat/vault",
      "owner": {
        "id": 456,
        "login": "octocat",
        "type": "User",
        "avatarUrl": "https://..."
      }
    }
  ]
}
```

Only private repositories returned for that installation by the signed-in
user's token are included. Public repositories are filtered out and are also
rejected by vault access checks.

## Vault

The fixed file path is `.doriya/vault.json`. `content` is treated as an opaque
frontend-generated encrypted JSON string.

### `GET /api/github/vault?installationId=123&repository=octocat/vault`

```json
{
  "exists": true,
  "sha": "full-git-object-sha",
  "content": "{\"cipher\":\"...\"}",
  "htmlUrl": "https://github.com/octocat/vault/blob/main/.doriya/vault.json"
}
```

When the file does not exist:

```json
{
  "exists": false,
  "sha": null,
  "content": null,
  "htmlUrl": null
}
```

### `PUT /api/github/vault`

Request:

```json
{
  "installationId": 123,
  "repository": "octocat/vault",
  "content": "{\"cipher\":\"...\"}",
  "sha": "current-full-git-object-sha"
}
```

`sha` is optional for creation and should be the current file SHA for updates.
The maximum content size is 512 KiB. The commit message is always
`Update Doriya vault`.

Success uses the same shape as `GET`. A stale or missing update SHA returns
`409` with `error.code = "vault_conflict"`.

## Errors

Errors use this shape:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Human-readable explanation."
  }
}
```

Unconfigured backends return `503 not_configured`, except
`/api/auth/session`, which returns `200 { "configured": false, ... }`.
