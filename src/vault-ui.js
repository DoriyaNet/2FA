import {
  createVaultAccount,
  createVaultDocument,
  decryptVault,
  encryptVault,
  parseVaultEnvelope,
  serializeVaultEnvelope,
  validatePassphrase,
  validateVaultDocument,
} from "./vault-crypto.js";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

class VaultApiError extends Error {
  constructor(message, { status = 0, code = "request_failed" } = {}) {
    super(message);
    this.name = "VaultApiError";
    this.status = status;
    this.code = code;
  }
}

const ERROR_MESSAGES = {
  not_authenticated: "GitHub 登录已失效，请重新登录。",
  reauth_required: "GitHub 会话已过期，请重新登录。",
  not_configured: "这个站点还没有配置 GitHub App。",
  oauth_denied: "GitHub 授权已取消。",
  oauth_failed: "GitHub 登录失败，请稍后重试。",
  installation_forbidden: "当前 GitHub 账户无权使用这个 installation。",
  repository_forbidden: "当前 installation 无权访问这个仓库。",
  vault_conflict: "仓库中的保险库已被其他设备更新，请先刷新再保存。",
  vault_forbidden: "GitHub 拒绝了写入请求，请检查 App 的 Contents 权限。",
  repository_not_found: "找不到这个仓库或保险库文件。",
  github_forbidden: "GitHub 拒绝了请求，请重新检查 App 权限。",
  github_not_found: "GitHub 上找不到请求的资源。",
  github_unavailable: "暂时无法连接 GitHub，请稍后重试。",
};

function formatError(error) {
  if (error?.code && ERROR_MESSAGES[error.code]) {
    return ERROR_MESSAGES[error.code];
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return "操作失败，请稍后重试。";
}

async function apiRequest(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  const options = {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  };

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new VaultApiError("网络连接失败，请检查网络后重试。", {
      code: "network_error",
    });
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    throw new VaultApiError(
      payload?.error?.message || `请求失败（HTTP ${response.status}）。`,
      {
        status: response.status,
        code: payload?.error?.code || "request_failed",
      },
    );
  }

  return payload || {};
}

function toIsoNow() {
  return new Date().toISOString();
}

function withUpdatedTimestamp(document) {
  return validateVaultDocument({
    ...document,
    updatedAt: toIsoNow(),
  });
}

function accountInitial(account) {
  return account.issuer.trim().charAt(0).toUpperCase() || "2";
}

function vaultConfigFromAccount(account) {
  return {
    source: "vault",
    vaultAccountId: account.id,
    issuer: account.issuer,
    account: account.account,
    secret: account.secret,
    algorithm: account.algorithm,
    digits: account.digits,
    period: account.period,
  };
}

function removeQueryParameter(name) {
  const url = new URL(window.location.href);
  if (!url.searchParams.has(name)) return;
  url.searchParams.delete(name);
  const next = `${url.pathname}${url.search}${url.hash}`;
  window.history.replaceState(window.history.state, "", next);
}

function submitInstallForm() {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = "/api/github/install";
  form.hidden = true;
  document.body.append(form);
  form.submit();
}

export function initVaultUI({
  loadConfig,
  getActiveConfig,
  showToast,
  onVaultLocked = () => {},
  onVaultAccountRemoved = () => {},
} = {}) {
  if (
    typeof loadConfig !== "function" ||
    typeof getActiveConfig !== "function" ||
    typeof showToast !== "function"
  ) {
    throw new TypeError("Vault UI requires loadConfig, getActiveConfig and showToast.");
  }

  const elements = {
    dialog: $("#vault-dialog"),
    close: $("#vault-close"),
    notice: $("#vault-notice"),
    noticeMark: $("#vault-notice-mark"),
    noticeMessage: $("#vault-notice-message"),
    dialogRepo: $("#vault-dialog-repo"),
    cloudState: $("#cloud-state"),
    cloudStateLabel: $("#cloud-state-label"),
    boardState: $("#vault-board-state"),
    boardStateLabel: $("#vault-board-state-label"),
    boardTitle: $("#vault-board-title"),
    boardDescription: $("#vault-board-description"),
    primaryButton: $("#vault-primary-button"),
    loginButton: $("#vault-login-button"),
    loginHint: $("#vault-login-hint"),
    configPill: $("#vault-config-pill"),
    installButton: $("#vault-install-button"),
    refreshInstallations: $("#vault-refresh-installations"),
    sessionUser: $("#vault-session-user"),
    repoForm: $("#vault-repo-form"),
    installationSelect: $("#vault-installation-select"),
    repositorySelect: $("#vault-repository-select"),
    repoOpen: $("#vault-repo-open"),
    repoError: $("#vault-repo-error"),
    manageInstallations: $("#vault-manage-installations"),
    selectedRepoName: $("#vault-selected-repo-name"),
    changeRepo: $("#vault-change-repo"),
    unlockKicker: $("#vault-unlock-kicker"),
    unlockTitle: $("#vault-unlock-title"),
    unlockDescription: $("#vault-unlock-description"),
    passphraseForm: $("#vault-passphrase-form"),
    passphrase: $("#vault-passphrase"),
    passphraseConfirm: $("#vault-passphrase-confirm"),
    confirmLabel: $("#vault-confirm-label"),
    passwordNote: $("#vault-password-note"),
    passwordToggle: $("#vault-password-toggle"),
    passphraseError: $("#vault-passphrase-error"),
    unlockButton: $("#vault-unlock-button"),
    accountCount: $("#vault-account-count"),
    accountList: $("#vault-account-list"),
    accountsEmpty: $("#vault-accounts-empty"),
    selectedAccount: $("#vault-selected-account"),
    addAccount: $("#vault-add-account"),
    accountForm: $("#vault-account-form"),
    accountIssuer: $("#vault-account-issuer"),
    accountName: $("#vault-account-name"),
    accountSecret: $("#vault-account-secret"),
    accountAlgorithm: $("#vault-account-algorithm"),
    accountDigits: $("#vault-account-digits"),
    accountPeriod: $("#vault-account-period"),
    accountError: $("#vault-account-error"),
    accountSave: $("#vault-account-save"),
    useActive: $("#vault-use-active"),
    syncButton: $("#vault-sync-button"),
    lockButton: $("#vault-lock-button"),
    logoutButton: $("#vault-logout-button"),
    footNote: $("#vault-dialog-foot-note"),
  };

  let session = { configured: false, authenticated: false, user: null };
  let installations = [];
  let repositories = [];
  let selectedRepo = null;
  let vaultState = {
    envelope: null,
    sha: null,
    htmlUrl: null,
  };
  let vaultDocument = null;
  let vaultPassphrase = null;
  let unlockMode = "unlock";
  let selectedAccountId = null;
  let activeVaultAccountId = null;
  let currentView = "loading";
  let repoRequestId = 0;
  let prefillActiveOnUnlock = false;
  let lastFocusedElement = null;

  function setNotice(message = "", isError = false) {
    elements.notice.hidden = !message;
    elements.notice.classList.toggle("is-error", isError);
    elements.noticeMark.textContent = isError ? "!" : "✓";
    elements.noticeMessage.textContent = message;
  }

  function setView(view) {
    currentView = view;
    $$("[data-vault-view]", elements.dialog).forEach((section) => {
      section.hidden = section.dataset.vaultView !== view;
    });
    elements.dialog.setAttribute("aria-busy", view === "loading" ? "true" : "false");
    elements.dialog.scrollTop = 0;
  }

  function setButtonBusy(button, busy) {
    button.disabled = busy;
    if (busy) {
      button.setAttribute("aria-busy", "true");
    } else {
      button.removeAttribute("aria-busy");
    }
  }

  function updateConnectionSurface() {
    let label = "本地就绪";
    let stateLabel = "本地模式";
    let title = "连接你的 GitHub 保险库";
    let description =
      "授权一个 GitHub App installation，选择任意私有仓库。无需把仓库地址或访问令牌交给前端。";
    let primary = "打开 GitHub 保险库";

    if (!session.configured) {
      stateLabel = "等待配置";
      title = "GitHub App 尚未配置";
      description =
        "站点仍然可以本地生成验证码。部署者配置 GitHub App 凭据后，云保险库会自动启用。";
    } else if (!session.authenticated) {
      stateLabel = "未连接";
      label = "本地就绪";
    } else if (vaultDocument) {
      label = "云保险库已解锁";
      stateLabel = "已解锁";
      title = selectedRepo?.repository || "GitHub 保险库已连接";
      description =
        "当前保险库只在浏览器内存中解密。提交到 GitHub 的只有重新加密后的 envelope。";
      primary = "管理 GitHub 保险库";
    } else {
      label = `@${session.user?.login || "GitHub"} 已连接`;
      stateLabel = "已连接";
      title = selectedRepo?.repository || "选择一个私有仓库";
      description = "GitHub 身份已确认。选择 installation 与私有仓库后，再输入独立的保险库密码。";
      primary = selectedRepo ? "解锁 GitHub 保险库" : "选择保险库仓库";
    }

    elements.cloudState.classList.toggle("is-connected", session.authenticated);
    elements.cloudStateLabel.textContent = label;
    elements.boardState.classList.toggle("is-connected", session.authenticated);
    elements.boardStateLabel.textContent = stateLabel;
    elements.boardTitle.textContent = title;
    elements.boardDescription.textContent = description;
    $("span", elements.primaryButton).textContent = primary;
    elements.dialogRepo.textContent = selectedRepo?.repository || "NOT CONNECTED";
  }

  function updateSessionUser() {
    if (!session.user) return;
    const mark = $(".vault-account-chip-mark", elements.sessionUser);
    const strong = $("strong", elements.sessionUser);
    const small = $("small", elements.sessionUser);
    if (mark) mark.textContent = session.user.login?.charAt(0).toUpperCase() || "GH";
    if (strong) strong.textContent = session.user.name || session.user.login;
    if (small) small.textContent = `@${session.user.login}`;
  }

  async function loadSession() {
    const data = await apiRequest("/api/auth/session");
    session = {
      configured: data.configured === true,
      authenticated: data.authenticated === true,
      user:
        data.user && typeof data.user === "object"
          ? {
              id: Number(data.user.id) || null,
              login:
                typeof data.user.login === "string" ? data.user.login : "GitHub",
              name:
                typeof data.user.name === "string" ? data.user.name : null,
              avatarUrl:
                typeof data.user.avatarUrl === "string"
                  ? data.user.avatarUrl
                  : null,
            }
          : null,
    };
    updateConnectionSurface();
  }

  async function loadInstallations() {
    const data = await apiRequest("/api/github/installations");
    installations = Array.isArray(data.installations)
      ? data.installations.filter(
          (installation) =>
            Number.isSafeInteger(Number(installation?.id)) &&
            Number(installation.id) > 0,
        )
      : [];
    return installations;
  }

  function fillInstallationSelect(preferredId) {
    elements.installationSelect.replaceChildren();
    installations.forEach((installation) => {
      const option = document.createElement("option");
      option.value = String(installation.id);
      const login = installation.account?.login || `installation-${installation.id}`;
      const selection =
        installation.repositorySelection === "all"
          ? "全部仓库"
          : "已选仓库";
      option.textContent = `${login} · ${selection}`;
      elements.installationSelect.append(option);
    });

    const targetId = String(preferredId || selectedRepo?.installationId || "");
    if (
      targetId &&
      [...elements.installationSelect.options].some(
        (option) => option.value === targetId,
      )
    ) {
      elements.installationSelect.value = targetId;
    }
  }

  async function loadRepositories(installationId) {
    const requestId = ++repoRequestId;
    repositories = [];
    elements.repositorySelect.replaceChildren();
    const loadingOption = document.createElement("option");
    loadingOption.value = "";
    loadingOption.textContent = "正在读取仓库…";
    elements.repositorySelect.append(loadingOption);
    elements.repositorySelect.disabled = true;
    elements.repoOpen.disabled = true;
    elements.repoError.textContent = "";

    if (!installationId) return;

    try {
      const query = new URLSearchParams({
        installationId,
      });
      const data = await apiRequest(
        `/api/github/repositories?${query.toString()}`,
      );
      if (requestId !== repoRequestId) return;

      repositories = Array.isArray(data.repositories)
        ? data.repositories.filter(
            (repository) =>
              repository?.private === true &&
              typeof repository.fullName === "string" &&
              repository.fullName.includes("/"),
          )
        : [];

      elements.repositorySelect.replaceChildren();
      if (repositories.length === 0) {
        const emptyOption = document.createElement("option");
        emptyOption.value = "";
        emptyOption.textContent = "没有可用的私有仓库";
        elements.repositorySelect.append(emptyOption);
        elements.repoError.textContent =
          "这个 installation 没有向 Doriya 暴露私有仓库。请检查 GitHub App 的仓库选择。";
        return;
      }

      repositories.forEach((repository) => {
        const option = document.createElement("option");
        option.value = repository.fullName;
        option.textContent = repository.fullName;
        option.dataset.defaultBranch = repository.defaultBranch || "";
        option.dataset.htmlUrl = repository.htmlUrl || "";
        elements.repositorySelect.append(option);
      });

      if (
        selectedRepo?.installationId === Number(installationId) &&
        repositories.some(
          (repository) => repository.fullName === selectedRepo.repository,
        )
      ) {
        elements.repositorySelect.value = selectedRepo.repository;
      }
      elements.repositorySelect.disabled = false;
      elements.repoOpen.disabled = false;
    } catch (error) {
      if (requestId !== repoRequestId) return;
      elements.repositorySelect.replaceChildren();
      const errorOption = document.createElement("option");
      errorOption.value = "";
      errorOption.textContent = "仓库读取失败";
      elements.repositorySelect.append(errorOption);
      elements.repoError.textContent = formatError(error);
    }
  }

  function setUnlockMode(mode) {
    unlockMode = mode;
    const creating = mode === "create";
    elements.unlockKicker.textContent = creating
      ? "CREATE ENCRYPTED VAULT"
      : "UNLOCK ENCRYPTED VAULT";
    elements.unlockTitle.textContent = creating ? "创建保险库" : "解锁保险库";
    elements.unlockDescription.textContent = creating
      ? "为这个仓库设置独立的保险库密码。密码不会离开浏览器，也无法由服务器找回。"
      : "输入保险库密码。密码只在这个标签页内用于派生 AES 密钥。";
    elements.passphrase.autocomplete = creating
      ? "new-password"
      : "current-password";
    elements.confirmLabel.hidden = !creating;
    elements.passphraseConfirm.required = creating;
    elements.passphraseConfirm.value = "";
    elements.passwordNote.textContent = creating
      ? "密码至少 12 个字符。忘记后只能删除 GitHub 中的保险库文件并重新创建。"
      : "密码无法找回；密码与派生密钥不会发送到服务器。";
    $("span", elements.unlockButton).textContent = creating
      ? "创建并解锁"
      : "解锁保险库";
    elements.passphrase.value = "";
    elements.passphrase.type = "password";
    elements.passphraseError.textContent = "";
    elements.footNote.textContent = creating
      ? "创建后会立即写入加密文件"
      : "密码与明文密钥不会发送到服务器";
  }

  function updateSelectedRepoLabels() {
    const label = selectedRepo?.repository || "owner/repository";
    elements.selectedRepoName.textContent = label;
    elements.dialogRepo.textContent = selectedRepo?.repository || "NOT CONNECTED";
  }

  async function loadVaultMetadata() {
    if (!selectedRepo) {
      throw new VaultApiError("请先选择保险库仓库。");
    }
    const query = new URLSearchParams({
      installationId: String(selectedRepo.installationId),
      repository: selectedRepo.repository,
    });
    const data = await apiRequest(`/api/github/vault?${query.toString()}`);

    let envelope = null;
    if (data.exists === true) {
      if (typeof data.content !== "string") {
        throw new VaultApiError("GitHub 返回的保险库内容格式无效。");
      }
      envelope = parseVaultEnvelope(data.content);
    }

    vaultState = {
      envelope,
      sha:
        typeof data.sha === "string" || data.sha === null ? data.sha : null,
      htmlUrl: typeof data.htmlUrl === "string" ? data.htmlUrl : null,
    };
    updateSelectedRepoLabels();
    return { exists: data.exists === true };
  }

  async function openSelectedRepository() {
    const installationId = Number(elements.installationSelect.value);
    const repository = elements.repositorySelect.value;
    if (!Number.isSafeInteger(installationId) || installationId <= 0) {
      elements.repoError.textContent = "请选择一个 GitHub App installation。";
      return;
    }
    const repositoryData = repositories.find(
      (entry) => entry.fullName === repository,
    );
    if (!repositoryData || repositoryData.private !== true) {
      elements.repoError.textContent = "请选择一个私有仓库。";
      return;
    }

    selectedRepo = {
      installationId,
      repository,
      defaultBranch: repositoryData.defaultBranch || null,
      htmlUrl: repositoryData.htmlUrl || null,
    };
    vaultDocument = null;
    vaultPassphrase = null;
    selectedAccountId = null;
    updateSelectedRepoLabels();
    elements.repoError.textContent = "";
    setNotice("正在读取 .doriya/vault.json…");
    setButtonBusy(elements.repoOpen, true);

    try {
      const result = await loadVaultMetadata();
      setNotice("");
      setUnlockMode(result.exists ? "unlock" : "create");
      setView("unlock");
      window.setTimeout(() => elements.passphrase.focus(), 40);
    } catch (error) {
      setNotice(formatError(error), true);
    } finally {
      setButtonBusy(elements.repoOpen, false);
    }
  }

  async function saveEnvelope(content, sha) {
    if (!selectedRepo) {
      throw new VaultApiError("保险库仓库尚未选择。");
    }
    const data = await apiRequest("/api/github/vault", {
      method: "PUT",
      body: {
        installationId: selectedRepo.installationId,
        repository: selectedRepo.repository,
        content,
        sha,
      },
    });

    let nextSha =
      typeof data.sha === "string" || data.sha === null ? data.sha : null;
    if (!nextSha) {
      await loadVaultMetadata();
      nextSha = vaultState.sha;
    }
    if (!nextSha) {
      throw new VaultApiError(
        "GitHub 已接受写入，但没有返回文件 SHA。请关闭后重新打开保险库。",
      );
    }
    return {
      sha: nextSha,
      htmlUrl: typeof data.htmlUrl === "string" ? data.htmlUrl : null,
    };
  }

  async function persistDocument(nextDocument, options = {}) {
    if (!vaultPassphrase) {
      throw new VaultApiError("保险库已锁定，请重新解锁。");
    }
    const validated = validateVaultDocument(nextDocument);
    const envelope = await encryptVault(validated, vaultPassphrase);
    const content = serializeVaultEnvelope(envelope);
    const result = await saveEnvelope(
      content,
      options.create ? null : vaultState.sha,
    );
    vaultState = {
      envelope,
      sha: result.sha,
      htmlUrl: result.htmlUrl || vaultState.htmlUrl,
    };
    return validated;
  }

  async function handlePassphraseSubmit(event) {
    event.preventDefault();
    elements.passphraseError.textContent = "";
    const passphrase = elements.passphrase.value;
    const validation = validatePassphrase(passphrase);
    if (validation !== true) {
      elements.passphraseError.textContent = validation;
      elements.passphrase.focus();
      return;
    }
    if (
      unlockMode === "create" &&
      passphrase !== elements.passphraseConfirm.value
    ) {
      elements.passphraseError.textContent = "两次输入的保险库密码不一致。";
      elements.passphraseConfirm.focus();
      return;
    }

    setButtonBusy(elements.unlockButton, true);
    try {
      let document;
      if (unlockMode === "create") {
        document = createVaultDocument([]);
        vaultPassphrase = passphrase;
        try {
          document = await persistDocument(document, { create: true });
        } catch (error) {
          vaultPassphrase = null;
          throw error;
        }
        showToast("加密保险库已创建并提交到 GitHub");
      } else {
        if (!vaultState.envelope) {
          await loadVaultMetadata();
        }
        if (!vaultState.envelope) {
          setUnlockMode("create");
          throw new VaultApiError("仓库中没有保险库文件，请重新创建。");
        }
        document = await decryptVault(vaultState.envelope, passphrase);
        vaultPassphrase = passphrase;
        showToast("保险库已在本地解锁");
      }

      vaultDocument = validateVaultDocument(document);
      elements.passphrase.value = "";
      elements.passphraseConfirm.value = "";
      elements.passphrase.type = "password";
      selectedAccountId = vaultDocument.accounts[0]?.id || null;
      setNotice("");
      setView("unlocked");
      renderAccounts();
      updateConnectionSurface();

      if (prefillActiveOnUnlock) {
        prefillAccountForm();
      }
      if (prefillActiveOnUnlock || vaultDocument.accounts.length === 0) {
        elements.addAccount.open = true;
      }
      prefillActiveOnUnlock = false;
    } catch (error) {
      elements.passphrase.value = "";
      elements.passphraseError.textContent = formatError(error);
      elements.passphrase.focus();
    } finally {
      setButtonBusy(elements.unlockButton, false);
    }
  }

  function renderSelectedAccount() {
    elements.selectedAccount.replaceChildren();
    const account = vaultDocument?.accounts.find(
      (entry) => entry.id === selectedAccountId,
    );
    if (!account) {
      const empty = document.createElement("div");
      empty.className = "vault-selected-empty";

      const kicker = document.createElement("span");
      kicker.className = "mini-label";
      kicker.textContent = "ACCOUNT DETAIL";
      const title = document.createElement("h3");
      title.textContent = "选择一个账户";
      const copy = document.createElement("p");
      copy.textContent = "选中后会只在本机验证器中载入，不会再次上传密钥。";
      empty.append(kicker, title, copy);
      elements.selectedAccount.append(empty);
      return;
    }

    const head = document.createElement("div");
    head.className = "vault-account-detail-head";
    const titleWrap = document.createElement("div");
    titleWrap.className = "vault-account-detail-title";
    const mark = document.createElement("span");
    mark.textContent = accountInitial(account);
    const copy = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = account.issuer;
    const accountName = document.createElement("p");
    accountName.textContent = account.account;
    copy.append(title, accountName);
    titleWrap.append(mark, copy);
    head.append(titleWrap);

    const meta = document.createElement("div");
    meta.className = "vault-account-detail-meta";
    [
      ["ALGORITHM", account.algorithm],
      ["DIGITS", `${account.digits} DIGITS`],
      ["PERIOD", `${account.period} SEC`],
    ].forEach(([label, value]) => {
      const cell = document.createElement("span");
      cell.textContent = label;
      const strong = document.createElement("strong");
      strong.textContent = value;
      cell.append(strong);
      meta.append(cell);
    });

    const actions = document.createElement("div");
    actions.className = "vault-account-detail-actions";
    const loadButton = document.createElement("button");
    loadButton.type = "button";
    loadButton.className = "button button--dark";
    loadButton.textContent = "载入验证码";
    loadButton.addEventListener("click", () => {
      void loadAccount(account);
    });
    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "text-button";
    removeButton.textContent = "从保险库删除 ↗";
    removeButton.addEventListener("click", () => {
      void removeAccount(account);
    });
    actions.append(loadButton, removeButton);
    elements.selectedAccount.append(head, meta, actions);
  }

  function renderAccounts() {
    const accounts = vaultDocument?.accounts || [];
    elements.accountCount.textContent = String(accounts.length);
    elements.accountsEmpty.hidden = accounts.length > 0;
    elements.accountList.hidden = accounts.length === 0;
    elements.accountList.replaceChildren();

    if (
      selectedAccountId &&
      !accounts.some((account) => account.id === selectedAccountId)
    ) {
      selectedAccountId = null;
    }
    if (!selectedAccountId && accounts.length > 0) {
      selectedAccountId = accounts[0].id;
    }

    accounts.forEach((account) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "vault-account-item";
      button.classList.toggle("is-selected", account.id === selectedAccountId);
      button.setAttribute("aria-pressed", String(account.id === selectedAccountId));

      const mark = document.createElement("span");
      mark.className = "vault-account-item-mark";
      mark.textContent = accountInitial(account);
      const copy = document.createElement("span");
      copy.className = "vault-account-item-copy";
      const title = document.createElement("strong");
      title.textContent = account.issuer;
      const accountName = document.createElement("span");
      accountName.textContent = account.account;
      copy.append(title, accountName);
      const arrow = document.createElement("span");
      arrow.className = "vault-account-item-arrow";
      arrow.textContent = "→";
      button.append(mark, copy, arrow);
      button.addEventListener("click", () => {
        selectedAccountId = account.id;
        renderAccounts();
      });
      elements.accountList.append(button);
    });

    renderSelectedAccount();
    updateConnectionSurface();
  }

  async function loadAccount(account) {
    activeVaultAccountId = account.id;
    try {
      await loadConfig(vaultConfigFromAccount(account));
      elements.dialog.close();
      showToast(`${account.issuer} 已载入，密钥只在内存中`);
    } catch {
      showToast("账户载入失败，请重新选择。", true);
    }
  }

  async function removeAccount(account) {
    const confirmed = window.confirm(
      `从保险库中删除“${account.issuer} / ${account.account}”？此操作会更新 GitHub 文件。`,
    );
    if (!confirmed) return;

    const nextAccounts = vaultDocument.accounts.filter(
      (entry) => entry.id !== account.id,
    );
    setButtonBusy(elements.lockButton, true);
    try {
      const nextDocument = withUpdatedTimestamp({
        ...vaultDocument,
        accounts: nextAccounts,
      });
      vaultDocument = await persistDocument(nextDocument);
      selectedAccountId = vaultDocument.accounts[0]?.id || null;
      if (activeVaultAccountId === account.id) {
        activeVaultAccountId = null;
        onVaultAccountRemoved(account.id);
      }
      renderAccounts();
      showToast("账户已从加密保险库中删除");
    } catch (error) {
      setNotice(formatError(error), true);
    } finally {
      setButtonBusy(elements.lockButton, false);
    }
  }

  function prefillAccountForm(config = getActiveConfig()) {
    if (!config) return;
    elements.accountIssuer.value = config.issuer || "";
    elements.accountName.value = config.account || "";
    elements.accountSecret.value = config.secret || "";
    elements.accountAlgorithm.value = config.algorithm || "SHA-1";
    elements.accountDigits.value = String(config.digits || 6);
    elements.accountPeriod.value = String(config.period || 30);
    elements.accountError.textContent = "";
  }

  function resetAccountForm() {
    elements.accountForm.reset();
    elements.accountAlgorithm.value = "SHA-1";
    elements.accountDigits.value = "6";
    elements.accountPeriod.value = "30";
    elements.accountError.textContent = "";
  }

  async function handleAccountSubmit(event) {
    event.preventDefault();
    elements.accountError.textContent = "";

    if (!vaultDocument || !vaultPassphrase) {
      elements.accountError.textContent = "保险库已经锁定，请重新解锁。";
      return;
    }

    const issuer = elements.accountIssuer.value.trim();
    const accountName = elements.accountName.value.trim();
    const secret = elements.accountSecret.value.trim();
    if (!issuer || !accountName || !secret) {
      elements.accountError.textContent = "请填写发行方、账户名称和 Base32 密钥。";
      return;
    }

    setButtonBusy(elements.accountSave, true);
    try {
      const account = createVaultAccount({
        issuer,
        account: accountName,
        secret,
        algorithm: elements.accountAlgorithm.value,
        digits: Number(elements.accountDigits.value),
        period: Number(elements.accountPeriod.value),
      });
      const duplicate = vaultDocument.accounts.some(
        (entry) =>
          entry.issuer.toLowerCase() === account.issuer.toLowerCase() &&
          entry.account.toLowerCase() === account.account.toLowerCase(),
      );
      if (duplicate) {
        throw new VaultApiError("这个发行方与账户名称已经存在于保险库。");
      }

      const nextDocument = withUpdatedTimestamp({
        ...vaultDocument,
        accounts: [...vaultDocument.accounts, account],
      });
      vaultDocument = await persistDocument(nextDocument);
      selectedAccountId = account.id;
      resetAccountForm();
      elements.addAccount.open = false;
      renderAccounts();
      showToast("账户已加密并提交到 GitHub");
    } catch (error) {
      elements.accountError.textContent = formatError(error);
    } finally {
      setButtonBusy(elements.accountSave, false);
    }
  }

  async function syncFromGitHub() {
    if (!vaultPassphrase) {
      showToast("保险库已锁定。", true);
      return;
    }
    setButtonBusy(elements.syncButton, true);
    try {
      const result = await loadVaultMetadata();
      if (!result.exists || !vaultState.envelope) {
        throw new VaultApiError("远端保险库文件不存在，可能已被删除。");
      }
      const nextDocument = await decryptVault(
        vaultState.envelope,
        vaultPassphrase,
      );
      vaultDocument = nextDocument;
      selectedAccountId = vaultDocument.accounts[0]?.id || null;
      renderAccounts();
      showToast("已从 GitHub 刷新保险库");
    } catch (error) {
      setNotice(formatError(error), true);
    } finally {
      setButtonBusy(elements.syncButton, false);
    }
  }

  function lockVault({ notify = true } = {}) {
    const lockedAccountId = activeVaultAccountId;
    vaultDocument = null;
    vaultPassphrase = null;
    activeVaultAccountId = null;
    selectedAccountId = null;
    elements.passphrase.value = "";
    elements.passphraseConfirm.value = "";
    elements.accountSecret.value = "";
    elements.accountError.textContent = "";
    elements.passphraseError.textContent = "";
    elements.accountList.replaceChildren();
    elements.accountCount.textContent = "0";
    elements.accountsEmpty.hidden = false;
    updateConnectionSurface();
    onVaultLocked(lockedAccountId);
    if (notify) {
      showToast("保险库已锁定，内存中的明文已清除");
    }
    if (selectedRepo) {
      setUnlockMode(vaultState.envelope ? "unlock" : "create");
      setView("unlock");
    } else {
      setView("disconnected");
    }
  }

  async function logoutGitHub() {
    setButtonBusy(elements.logoutButton, true);
    try {
      await apiRequest("/api/auth/logout", { method: "POST" });
    } catch {
      // Clearing the local UI is still safer if the session endpoint fails.
    } finally {
      setButtonBusy(elements.logoutButton, false);
    }
    lockVault({ notify: false });
    session = { configured: session.configured, authenticated: false, user: null };
    installations = [];
    repositories = [];
    selectedRepo = null;
    vaultState = { envelope: null, sha: null, htmlUrl: null };
    updateConnectionSurface();
    setView("disconnected");
    showToast("已清除本站 GitHub 会话");
  }

  async function bootstrapVault() {
    if (vaultDocument) {
      renderAccounts();
      setView("unlocked");
      if (prefillActiveOnUnlock) {
        prefillAccountForm();
        elements.addAccount.open = true;
      }
      prefillActiveOnUnlock = false;
      return;
    }

    setView("loading");
    try {
      await loadSession();
    } catch (error) {
      setView("disconnected");
      setNotice(formatError(error), true);
      return;
    }

    if (!session.configured) {
      elements.loginButton.disabled = true;
      $("span", elements.loginButton).textContent = "等待部署者配置 GitHub App";
      elements.loginHint.textContent =
        "配置 GITHUB_APP_ID、OAuth 凭据、私钥与 SESSION_SECRET 后即可启用。";
      elements.configPill.textContent = "NOT CONFIGURED";
      setView("disconnected");
      return;
    }

    elements.loginButton.disabled = false;
    $("span", elements.loginButton).textContent = "使用 GitHub 登录";
    elements.loginHint.textContent =
      "登录只用于确认身份，不会请求你的 GitHub 密码。";
    elements.configPill.textContent = "GITHUB APP";

    if (!session.authenticated) {
      setView("disconnected");
      return;
    }

    updateSessionUser();
    setView("loading");
    try {
      await loadInstallations();
    } catch (error) {
      setView("disconnected");
      setNotice(formatError(error), true);
      return;
    }

    if (installations.length === 0) {
      setView("installation");
      return;
    }

    fillInstallationSelect();
    setView("repository");
    await loadRepositories(elements.installationSelect.value);
  }

  async function openVault({ prefillActive = false } = {}) {
    lastFocusedElement = document.activeElement;
    prefillActiveOnUnlock = prefillActive;
    if (!elements.dialog.open) {
      elements.dialog.showModal();
    }
    setNotice("");
    await bootstrapVault();
  }

  function closeVault() {
    elements.accountSecret.value = "";
    elements.passphrase.value = "";
    elements.passphraseConfirm.value = "";
    if (elements.dialog.open) {
      elements.dialog.close();
    }
    lastFocusedElement?.focus?.();
  }

  function setupEvents() {
    $$('[data-action="open-vault"]').forEach((button) => {
      button.addEventListener("click", () => {
        void openVault({
          prefillActive:
            button.dataset.vaultPrefill === "active" ||
            (vaultDocument?.accounts.length === 0 &&
              button.classList.contains("vault-save-entry")),
        });
      });
    });

    elements.close.addEventListener("click", closeVault);
    elements.dialog.addEventListener("click", (event) => {
      if (event.target === elements.dialog) closeVault();
    });
    elements.dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      closeVault();
    });

    elements.loginButton.addEventListener("click", () => {
      const returnTo = "/?github=connected#vault";
      window.location.assign(
        `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`,
      );
    });

    elements.installButton.addEventListener("click", submitInstallForm);
    elements.manageInstallations.addEventListener("click", submitInstallForm);
    elements.refreshInstallations.addEventListener("click", () => {
      void bootstrapVault();
    });

    elements.installationSelect.addEventListener("change", () => {
      void loadRepositories(elements.installationSelect.value);
    });
    elements.repoForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void openSelectedRepository();
    });
    elements.changeRepo.addEventListener("click", () => {
      if (installations.length === 0) {
        void bootstrapVault();
        return;
      }
      fillInstallationSelect(selectedRepo?.installationId);
      setView("repository");
      void loadRepositories(elements.installationSelect.value);
    });

    elements.passphraseForm.addEventListener("submit", (event) => {
      void handlePassphraseSubmit(event);
    });
    elements.passwordToggle.addEventListener("click", () => {
      const showing = elements.passphrase.type === "text";
      elements.passphrase.type = showing ? "password" : "text";
      elements.passwordToggle.setAttribute(
        "aria-label",
        showing ? "显示保险库密码" : "隐藏保险库密码",
      );
    });

    elements.accountForm.addEventListener("submit", (event) => {
      void handleAccountSubmit(event);
    });
    elements.useActive.addEventListener("click", () => {
      prefillAccountForm();
      elements.accountIssuer.focus();
    });
    elements.syncButton.addEventListener("click", () => {
      void syncFromGitHub();
    });
    elements.lockButton.addEventListener("click", () => {
      lockVault();
    });
    elements.logoutButton?.addEventListener("click", () => {
      void logoutGitHub();
    });
  }

  async function handleReturnFromGitHub() {
    const url = new URL(window.location.href);
    const returnState = url.searchParams.get("github");
    if (returnState !== "connected" && returnState !== "installed") {
      return;
    }

    removeQueryParameter("github");
    if (!elements.dialog.open) {
      elements.dialog.showModal();
    }
    setNotice(
      returnState === "installed"
        ? "GitHub App 安装状态已更新，正在重新读取可用仓库。"
        : "GitHub 登录成功，正在读取 App installation。",
    );
    await bootstrapVault();

    if (returnState === "installed" && session.authenticated) {
      showToast("GitHub App 安装状态已更新");
    } else if (returnState === "connected") {
      showToast("GitHub 已连接");
    }
    if (currentView !== "loading") setNotice("");
  }

  setupEvents();
  updateConnectionSurface();
  void (async () => {
    try {
      await loadSession();
    } catch {
      // The local generator remains usable when the API is unavailable.
    }
    await handleReturnFromGitHub();
  })();

  return {
    open: openVault,
    lock: lockVault,
    clear() {
      lockVault({ notify: false });
    },
    refreshConnection: bootstrapVault,
  };
}
