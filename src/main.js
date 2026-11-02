import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./styles.css";

import {
  buildOtpauthUri,
  generateTOTP,
  parseTotpInput,
  TotpInputError,
} from "./totp.js";

const DEMO_CONFIG = Object.freeze({
  secret: "JBSWY3DPEHPK3PXP",
  issuer: "Doriya Demo",
  account: "demo@doriya.dev",
  algorithm: "SHA-1",
  digits: 6,
  period: 30,
});

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const elements = {
  form: $("#secret-form"),
  secretInput: $("#secret-input"),
  formError: $("#form-error"),
  generateButton: $("#generate-button"),
  toggleSecret: $("#toggle-secret"),
  pasteSecret: $("#paste-secret"),
  algorithmSelect: $("#algorithm-select"),
  digitsSelect: $("#digits-select"),
  periodSelect: $("#period-select"),
  codeDisplay: $("#copy-code"),
  codeDigits: $("#code-digits"),
  codeGroupA: $("#code-group-a"),
  codeGroupB: $("#code-group-b"),
  secondsRemaining: $("#seconds-remaining"),
  heroCountdown: $("#hero-countdown"),
  signalAlgorithm: $("#signal-algorithm"),
  signalDigits: $("#signal-digits"),
  signalPeriod: $("#signal-period"),
  progressFill: $("#progress-fill"),
  accountAvatar: $("#account-avatar"),
  issuerName: $("#issuer-name"),
  accountName: $("#account-name"),
  configurationLabel: $("#configuration-label"),
  localTime: $("#local-time"),
  footerClock: $("#footer-clock"),
  shareLink: $("#share-link"),
  useDemo: $("#use-demo"),
  qrDialog: $("#qr-dialog"),
  closeQr: $("#close-qr"),
  qrCanvas: $("#qr-canvas"),
  qrDropzone: $("#qr-dropzone"),
  qrFile: $("#qr-file"),
  startCamera: $("#start-camera"),
  stopCamera: $("#stop-camera"),
  cameraShell: $("#camera-shell"),
  cameraVideo: $("#camera-video"),
  copyOtpauth: $("#copy-otpauth"),
  toast: $("#toast"),
  toastMark: $(".toast-mark", $("#toast")),
  toastMessage: $(".toast-message", $("#toast")),
};

let activeConfig = { ...DEMO_CONFIG };
let generatedCode = "";
let renderedCounter = null;
let pendingCounter = null;
let generationId = 0;
let toastTimer;
let cameraStream = null;
let cameraFrame = null;
let cameraActive = false;
let cameraRequestId = 0;
let qrDecoderFunction = null;
let lastCameraScan = 0;
let qrDecoderPromise;
let qrGeneratorPromise;

const timeFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function setFieldError(message = "") {
  elements.formError.textContent = message;
  elements.secretInput.setAttribute("aria-invalid", message ? "true" : "false");
}

function showToast(message, isError = false) {
  window.clearTimeout(toastTimer);
  elements.toastMessage.textContent = message;
  elements.toastMark.textContent = isError ? "!" : "✓";
  elements.toast.classList.toggle("is-error", isError);
  elements.toast.classList.add("is-visible");
  toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, isError ? 4200 : 3200);
}

function fallbackCopy(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.setAttribute("readonly", "");
  textArea.style.position = "fixed";
  textArea.style.top = "-9999px";
  document.body.append(textArea);
  textArea.select();
  const copied = document.execCommand("copy");
  textArea.remove();
  if (!copied) throw new Error("Copy command failed");
}

async function copyText(text, successMessage) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      fallbackCopy(text);
    }
    showToast(successMessage);
    return true;
  } catch {
    try {
      fallbackCopy(text);
      showToast(successMessage);
      return true;
    } catch {
      showToast("复制失败，请检查浏览器剪贴板权限。", true);
      return false;
    }
  }
}

function setSelectValue(select, value) {
  const stringValue = String(value);
  if (![...select.options].some((option) => option.value === stringValue)) {
    select.add(new Option(stringValue, stringValue));
  }
  select.value = stringValue;
}

function updateAccountUi(config) {
  elements.issuerName.textContent = config.issuer;
  elements.accountName.textContent = config.account;
  elements.accountAvatar.textContent = config.issuer.trim().charAt(0).toUpperCase() || "2";
  elements.configurationLabel.textContent =
    `${config.algorithm} · ${config.digits} DIGITS · ${config.period}S`;
  elements.signalAlgorithm.textContent = `HMAC-${config.algorithm.replace("-", "")}`;
  elements.signalDigits.textContent = `${config.digits} DIGITS`;
  elements.signalPeriod.textContent = `${config.period} SEC`;
  setSelectValue(elements.algorithmSelect, config.algorithm);
  setSelectValue(elements.digitsSelect, config.digits);
  setSelectValue(elements.periodSelect, config.period);
}

function renderCode(code) {
  const midpoint = Math.ceil(code.length / 2);
  elements.codeGroupA.textContent = code.slice(0, midpoint);
  elements.codeGroupB.textContent = code.slice(midpoint);
  elements.codeDigits.classList.toggle("is-eight", code.length > 6);
  elements.codeDisplay.setAttribute("aria-label", `复制当前验证码 ${code}`);
  document.title = `${code} · Doriya 2FA`;
}

async function refreshCode(force = false) {
  const now = Date.now();
  const counter = Math.floor(now / 1000 / activeConfig.period);

  if (!force && (counter === renderedCounter || counter === pendingCounter)) {
    return generatedCode;
  }

  pendingCounter = counter;
  const requestId = ++generationId;

  try {
    const code = await generateTOTP(activeConfig, now);
    if (requestId !== generationId) return generatedCode;

    const currentCounter = Math.floor(Date.now() / 1000 / activeConfig.period);
    if (currentCounter !== counter) {
      pendingCounter = null;
      return refreshCode(true);
    }

    generatedCode = code;
    renderedCounter = counter;
    renderCode(code);
    return code;
  } catch (error) {
    if (requestId === generationId) {
      renderedCounter = counter;
      generatedCode = "";
      setFieldError(error.message || "无法生成验证码。");
      elements.codeGroupA.textContent = "— — —";
      elements.codeGroupB.textContent = "— — —";
      elements.codeDigits.classList.remove("is-eight");
      document.title = "Doriya 2FA — 浏览器里的验证码";
    }
    return null;
  } finally {
    if (requestId === generationId) {
      pendingCounter = null;
    }
  }
}

function updateTimers(now = Date.now(), shouldRefresh = true) {
  const periodMs = activeConfig.period * 1000;
  const remainingMs = periodMs - (now % periodMs);
  const seconds = Math.ceil(remainingMs / 1000);
  const progress = Math.min(100, Math.max(0, (remainingMs / periodMs) * 100));
  const time = timeFormatter.format(now);
  const counter = Math.floor(now / periodMs);

  elements.secondsRemaining.textContent = String(seconds);
  elements.heroCountdown.textContent = String(seconds).padStart(2, "0");
  elements.progressFill.style.width = `${progress}%`;
  elements.progressFill.classList.toggle("is-ending", seconds <= 5);
  elements.localTime.textContent = `LOCAL TIME ${time}`;
  elements.footerClock.textContent = `LOCAL ${time}`;

  if (shouldRefresh && counter !== renderedCounter && counter !== pendingCounter) {
    void refreshCode();
  }
}

async function applyConfig(config, { syncInput = true } = {}) {
  activeConfig = { ...config };
  generatedCode = "";
  renderedCounter = null;
  pendingCounter = null;
  generationId += 1;
  setFieldError();
  updateAccountUi(activeConfig);

  if (syncInput) {
    elements.secretInput.value = activeConfig.secret;
    elements.secretInput.type = "password";
    elements.toggleSecret.classList.remove("is-revealing");
    elements.toggleSecret.setAttribute("aria-label", "显示密钥");
  }

  updateTimers(Date.now(), false);
  const code = await refreshCode(true);
  if (elements.qrDialog.open) {
    await renderQrCode();
  }
  return code;
}

function buildShareLink() {
  const url = new URL(window.location.href);
  const params = new URLSearchParams({
    issuer: activeConfig.issuer,
    account: activeConfig.account,
    algorithm: activeConfig.algorithm,
    digits: String(activeConfig.digits),
    period: String(activeConfig.period),
  });
  url.search = "";
  url.hash =
    `#/2fa/${encodeURIComponent(activeConfig.secret)}?${params.toString()}`;
  return url.toString();
}

function configFromLocation() {
  const prefix = "#/2fa/";
  if (!window.location.hash.startsWith(prefix)) return null;

  const payload = window.location.hash.slice(prefix.length);
  if (!payload) return null;

  const queryIndex = payload.indexOf("?");
  const secretPart = queryIndex === -1 ? payload : payload.slice(0, queryIndex);
  const query = queryIndex === -1 ? "" : payload.slice(queryIndex + 1);
  const params = new URLSearchParams(query);
  let secret;

  try {
    secret = decodeURIComponent(secretPart);
  } catch {
    throw new TotpInputError("私密链接中的密钥格式无效。");
  }

  return parseTotpInput(secret, {
    issuer: params.get("issuer") || "共享账户",
    account: params.get("account") || "Private link",
    algorithm: params.get("algorithm") || "SHA-1",
    digits: params.get("digits") || 6,
    period: params.get("period") || 30,
  });
}

async function loadConfigFromLocation({ notify = false } = {}) {
  try {
    const config = configFromLocation();
    if (!config) return false;
    await applyConfig(config, { syncInput: true });
    if (notify) showToast("已从此链接载入账户");
    return true;
  } catch (error) {
    if (notify) showToast(error.message || "无法读取链接中的密钥。", true);
    return false;
  }
}

async function handleSecretSubmit(event) {
  event.preventDefault();
  const rawSecret = elements.secretInput.value.trim();

  if (!rawSecret) {
    setFieldError("请输入验证器密钥或 otpauth:// 链接。");
    elements.secretInput.focus();
    return;
  }

  elements.generateButton.disabled = true;
  const buttonLabel = $("span", elements.generateButton);
  const initialLabel = buttonLabel.textContent;
  buttonLabel.textContent = "正在生成";

  try {
    const config = parseTotpInput(rawSecret, {
      algorithm: elements.algorithmSelect.value,
      digits: elements.digitsSelect.value,
      period: elements.periodSelect.value,
    });
    const code = await applyConfig(config, { syncInput: true });
    if (code) {
      await copyText(code, "验证码已生成并复制");
    }
  } catch (error) {
    setFieldError(
      error instanceof TotpInputError ? error.message : "密钥读取失败，请检查后重试。",
    );
    elements.secretInput.focus();
  } finally {
    elements.generateButton.disabled = false;
    buttonLabel.textContent = initialLabel;
  }
}

function handleAdvancedChange() {
  activeConfig = {
    ...activeConfig,
    algorithm: elements.algorithmSelect.value,
    digits: Number(elements.digitsSelect.value),
    period: Number(elements.periodSelect.value),
  };
  renderedCounter = null;
  pendingCounter = null;
  generationId += 1;
  updateAccountUi(activeConfig);
  void refreshCode(true);
  showToast("验证参数已更新");
}

async function pasteSecret() {
  if (!navigator.clipboard?.readText) {
    showToast("当前浏览器不允许读取剪贴板，请手动粘贴。", true);
    elements.secretInput.focus();
    return;
  }

  try {
    const text = (await navigator.clipboard.readText()).trim();
    if (!text) {
      showToast("剪贴板为空。", true);
      return;
    }
    elements.secretInput.value = text;
    elements.secretInput.type = "password";
    elements.toggleSecret.classList.remove("is-revealing");
    elements.toggleSecret.setAttribute("aria-label", "显示密钥");
    setFieldError();
    elements.secretInput.focus();
    showToast("已从剪贴板读取");
  } catch {
    showToast("无法读取剪贴板，请检查浏览器权限。", true);
  }
}

function toggleSecretVisibility() {
  const isHidden = elements.secretInput.type === "password";
  elements.secretInput.type = isHidden ? "text" : "password";
  elements.toggleSecret.classList.toggle("is-revealing", isHidden);
  elements.toggleSecret.setAttribute("aria-label", isHidden ? "隐藏密钥" : "显示密钥");
}

async function copyCurrentCode() {
  if (!generatedCode) {
    showToast("验证码尚未生成。", true);
    return;
  }
  await copyText(generatedCode, "验证码已复制");
}

async function useDemoConfig() {
  elements.secretInput.value = "";
  elements.secretInput.type = "password";
  elements.toggleSecret.classList.remove("is-revealing");
  await applyConfig({ ...DEMO_CONFIG }, { syncInput: false });
  showToast("已载入示例密钥");
}

async function loadQrGenerator() {
  qrGeneratorPromise ||= import("qrcode").then((module) => module.default);
  return qrGeneratorPromise;
}

async function loadQrDecoder() {
  qrDecoderPromise ||= import("jsqr").then((module) => module.default);
  return qrDecoderPromise;
}

async function renderQrCode() {
  try {
    const QRCode = await loadQrGenerator();
    await QRCode.toCanvas(elements.qrCanvas, buildOtpauthUri(activeConfig), {
      width: 220,
      margin: 0,
      errorCorrectionLevel: "M",
      color: {
        dark: "#0b0b0b",
        light: "#fbfbf7",
      },
    });
  } catch {
    showToast("二维码生成失败。", true);
  }
}

async function openQrDialog() {
  if (!elements.qrDialog.open) {
    elements.qrDialog.showModal();
  }
  elements.qrFile.value = "";
  await renderQrCode();
}

function closeQrDialog() {
  stopCamera();
  elements.qrDialog.close();
}

async function handleQrPayload(payload) {
  try {
    const config = parseTotpInput(payload);
    stopCamera();
    await applyConfig(config, { syncInput: true });
    closeQrDialog();
    showToast("二维码已导入，验证码已更新");
  } catch (error) {
    showToast(error.message || "二维码内容不是有效的 TOTP 配置。", true);
  }
}

function loadImage(file) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    const objectUrl = URL.createObjectURL(file);
    image.onload = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(image);
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error("Image could not be loaded"));
    };
    image.src = objectUrl;
  });
}

async function decodeQrFile(file) {
  if (!file || !file.type.startsWith("image/")) {
    throw new TotpInputError("请选择二维码图片文件。");
  }

  const image = await loadImage(file);
  const maxSide = 1600;
  const scale = Math.min(1, maxSide / Math.max(image.naturalWidth, image.naturalHeight));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(image.naturalWidth * scale));
  canvas.height = Math.max(1, Math.round(image.naturalHeight * scale));
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.drawImage(image, 0, 0, canvas.width, canvas.height);

  const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
  const jsQR = await loadQrDecoder();
  const result = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: "attemptBoth",
  });

  if (!result?.data) {
    throw new TotpInputError("没有识别到二维码，请尝试更清晰、完整的图片。");
  }

  return result.data;
}

async function handleQrFile(file) {
  elements.qrDropzone.setAttribute("aria-busy", "true");
  try {
    const payload = await decodeQrFile(file);
    await handleQrPayload(payload);
  } catch (error) {
    showToast(
      error instanceof TotpInputError ? error.message : "二维码解析失败，请重试。",
      true,
    );
  } finally {
    elements.qrDropzone.removeAttribute("aria-busy");
    elements.qrFile.value = "";
  }
}

function stopCamera() {
  cameraRequestId += 1;
  cameraActive = false;
  if (cameraFrame) {
    cancelAnimationFrame(cameraFrame);
    cameraFrame = null;
  }
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = null;
  }
  elements.cameraVideo.srcObject = null;
  elements.cameraShell.hidden = true;
  elements.startCamera.disabled = false;
  elements.startCamera.removeAttribute("aria-busy");
}

function scanCameraFrame(timestamp) {
  if (!cameraActive) return;

  const video = elements.cameraVideo;
  if (
    timestamp - lastCameraScan >= 180 &&
    video.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA &&
    video.videoWidth > 0 &&
    video.videoHeight > 0
  ) {
    lastCameraScan = timestamp;
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(video, 0, 0);
    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);

    try {
      const result = qrDecoderFunction(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });

      if (result?.data) {
        cameraActive = false;
        stopCamera();
        void handleQrPayload(result.data);
        return;
      }
    } catch {
      // A transient frame decode error should not stop the camera loop.
    }
  }

  cameraFrame = requestAnimationFrame(scanCameraFrame);
}

async function startCamera() {
  if (!navigator.mediaDevices?.getUserMedia) {
    showToast("当前浏览器或访问环境不支持摄像头。", true);
    return;
  }

  const requestId = ++cameraRequestId;
  elements.startCamera.disabled = true;
  elements.startCamera.setAttribute("aria-busy", "true");
  elements.cameraShell.hidden = false;

  try {
    const jsQR = await loadQrDecoder();
    if (requestId !== cameraRequestId) return;
    qrDecoderFunction = jsQR;
    const stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: "environment" },
        width: { ideal: 1280 },
        height: { ideal: 1280 },
      },
      audio: false,
    });
    if (requestId !== cameraRequestId) {
      stream.getTracks().forEach((track) => track.stop());
      return;
    }
    cameraStream = stream;
    elements.cameraVideo.srcObject = cameraStream;
    await elements.cameraVideo.play();
    if (requestId !== cameraRequestId) {
      stopCamera();
      return;
    }
    cameraActive = true;
    lastCameraScan = 0;
    elements.startCamera.removeAttribute("aria-busy");
    cameraFrame = requestAnimationFrame(scanCameraFrame);
  } catch {
    if (requestId === cameraRequestId) {
      stopCamera();
      showToast("无法打开摄像头，请检查权限后重试。", true);
    }
  }
}

async function handleShareLink() {
  const link = buildShareLink();
  await copyText(link, "私密链接已复制 · 密钥只位于 # 片段中");
}

function setupQrEvents() {
  $$('[data-action="open-qr"]').forEach((button) => {
    button.addEventListener("click", () => {
      void openQrDialog();
    });
  });

  elements.closeQr.addEventListener("click", closeQrDialog);
  elements.qrDialog.addEventListener("close", stopCamera);
  elements.qrDialog.addEventListener("click", (event) => {
    if (event.target === elements.qrDialog) closeQrDialog();
  });

  elements.qrDropzone.addEventListener("click", () => elements.qrFile.click());
  elements.qrDropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      elements.qrFile.click();
    }
  });
  elements.qrFile.addEventListener("change", () => {
    if (elements.qrFile.files?.[0]) void handleQrFile(elements.qrFile.files[0]);
  });

  for (const eventName of ["dragenter", "dragover"]) {
    elements.qrDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.qrDropzone.classList.add("is-dragging");
    });
  }
  for (const eventName of ["dragleave", "drop"]) {
    elements.qrDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.qrDropzone.classList.remove("is-dragging");
    });
  }
  elements.qrDropzone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) void handleQrFile(file);
  });

  elements.startCamera.addEventListener("click", () => {
    void startCamera();
  });
  elements.stopCamera.addEventListener("click", stopCamera);
  elements.copyOtpauth.addEventListener("click", () => {
    void copyText(buildOtpauthUri(activeConfig), "otpauth 链接已复制 · 请妥善保管");
  });
}

function setupNavigationHighlight() {
  const links = $$(".main-nav a");
  const byId = new Map(
    links.map((link) => [link.getAttribute("href").slice(1), link]),
  );
  const sections = ["generator", "how-it-works", "privacy"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      links.forEach((link) => link.classList.remove("is-active"));
      byId.get(visible.target.id)?.classList.add("is-active");
    },
    { rootMargin: "-18% 0px -58% 0px", threshold: [0, 0.15, 0.5] },
  );

  sections.forEach((section) => observer.observe(section));
}

function setupEventListeners() {
  elements.form.addEventListener("submit", handleSecretSubmit);
  elements.secretInput.addEventListener("input", () => setFieldError());
  elements.toggleSecret.addEventListener("click", toggleSecretVisibility);
  elements.pasteSecret.addEventListener("click", () => {
    void pasteSecret();
  });
  elements.codeDisplay.addEventListener("click", () => {
    void copyCurrentCode();
  });
  elements.shareLink.addEventListener("click", () => {
    void handleShareLink();
  });
  elements.useDemo.addEventListener("click", () => {
    void useDemoConfig();
  });
  [
    elements.algorithmSelect,
    elements.digitsSelect,
    elements.periodSelect,
  ].forEach((select) => select.addEventListener("change", handleAdvancedChange));

  window.addEventListener("hashchange", () => {
    if (window.location.hash.startsWith("#/2fa/")) {
      void loadConfigFromLocation({ notify: true });
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      renderedCounter = null;
      updateTimers();
    }
  });

  setupQrEvents();
  setupNavigationHighlight();
}

async function initialize() {
  $("#footer-year").textContent = String(new Date().getFullYear());
  setupEventListeners();

  const loadedFromLink = await loadConfigFromLocation();
  if (!loadedFromLink) {
    await applyConfig({ ...DEMO_CONFIG }, { syncInput: false });
  }

  updateTimers();
  window.setInterval(updateTimers, 250);
}

void initialize();
