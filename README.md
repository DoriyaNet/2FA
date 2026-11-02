# Doriya 2FA

一个完全在浏览器本地运行的在线 TOTP 验证器。视觉上采用黑白灰、酸绿色与硬边框的锐利工具风格。

## 功能

- Base32 密钥与完整 `otpauth://` 链接导入
- SHA-1 / SHA-256 / SHA-512
- 6 位 / 8 位验证码，15 / 30 / 60 秒周期
- 实时刷新倒计时和进度反馈
- 一键生成并复制验证码
- 上传二维码图片或调用摄像头导入
- 生成 `otpauth://` 二维码，方便添加到其他验证器
- 私密分享链接，密钥只写入 URL 的 `#` 片段
- 桌面与移动端响应式布局

## 本地运行

```bash
npm install
npm run dev
```

生产构建和验证：

```bash
npm test
npm run build
npm run preview
```

## 隐私模型

- 验证码通过浏览器原生 Web Crypto API 计算。
- 没有后端接口、分析脚本、Cookie 或 `localStorage`。
- 二维码图片只在本地 Canvas 中解码。
- 分享链接把密钥放在 `#` 后，浏览器不会把片段发送给服务器。
- 分享链接和二维码都包含密钥，只应发送给信任的人。
- 摄像头扫描需要 HTTPS 或 `localhost`，并且由用户主动授权。

这是一个便捷工具，不替代密码管理器中的长期验证器备份。

## 技术栈

- Vite + 原生 JavaScript
- Web Crypto API（HMAC-TOTP / RFC 6238）
- `qrcode` 与 `jsQR`
- 自托管 Geist / Geist Mono 字体

项目附带 `vercel.json`，可直接部署到 Vercel。静态文件也可以在任意静态托管平台运行。
