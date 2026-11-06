# Doriya 2FA

一个类似 2fa.run 的在线 TOTP 验证器。界面采用黑白灰、酸绿色、硬边框的锐利工具风格；本地模式可以即开即用，云同步则通过 GitHub App 把浏览器加密后的保险库写入用户自己的私有仓库。

## 功能

- Base32 密钥与完整 `otpauth://` 链接导入
- SHA-1 / SHA-256 / SHA-512
- 6 位 / 8 位验证码，15 / 30 / 60 秒周期
- 实时倒计时、验证码复制和二维码导出
- 二维码图片导入与摄像头扫描
- GitHub App 登录、installation 授权和私有仓库选择
- 客户端 PBKDF2 + AES-256-GCM 加密保险库
- 多设备从 GitHub 读取密文并在浏览器内解密
- GitHub Contents API `sha` 乐观并发控制
- 桌面与移动端响应式布局

## 架构

```text
浏览器
  ├─ TOTP 生成、二维码解析、保险库加解密
  └─ /api/*
       └─ Doriya 后端
            ├─ GitHub OAuth 与 GitHub App installation token
            └─ GitHub Contents API
                 └─ 用户私有仓库 /.doriya/vault.json
```

Doriya 不保存保险库副本，也没有数据库。后端只负责 OAuth 会话、权限复核，以及把前端生成的密文转发到 GitHub。仓库中的 `.doriya/vault.json` 不包含 Base32 明文密钥或保险库密码。

## 安全模型

### 浏览器端

- TOTP 使用 Web Crypto API 在浏览器内计算。
- 保险库使用 PBKDF2-HMAC-SHA256，默认 600,000 次迭代，16 字节随机 salt。
- 文档使用 AES-256-GCM 加密，12 字节随机 IV、128 位认证标签，AAD 为 `doriya-vault:v1`。
- 每次写入都会重新加密并生成新的 salt 与 IV。
- 密码、Base32 密钥和明文账户只在解锁后的当前页面内存中。
- 不使用 `localStorage` 或 `sessionStorage` 保存保险库密钥。
- 保险库密码不会被提交给 Doriya 后端，也无法找回。

### 服务端与 GitHub

- GitHub App 私钥只存放在服务端环境变量中。
- GitHub 用户 access token / refresh token 只保存在加密的 HttpOnly Cookie 中，不返回给前端。
- OAuth 使用 `state` 与 PKCE；installation 流程使用独立的加密状态 Cookie。
- 后端同时复核 installation 与仓库授权，并拒绝公开仓库。
- installation token 只缓存在服务端进程内存中。
- GitHub 仓库只保存加密 envelope；GitHub 和 Doriya 后端按设计都看不到明文。

### 边界与限制

- 这是**应用层的客户端加密与后端零明文存储**，不是可独立验证的零知识证明。
- 托管网站的前端代码由部署者提供。只要部署者修改页面脚本，就能在密码或明文进入加密函数前读取它们。需要更强保证时，请自行部署、固定版本并审计实际加载的 JS。
- 浏览器内存、浏览器扩展、XSS、恶意依赖或被入侵的设备仍可能读取已解锁的明文。
- GitHub 仍可见仓库、提交时间和密文大小等元数据；仓库 Git 历史也会保留旧密文。
- 保险库密码离线可被猜测。请使用高强度、唯一的密码。
- 明文分享链接与二维码会暴露密钥；通过云保险库载入的账户不会生成明文分享链接。
- 本项目不替代密码管理器中的长期验证器备份。

## 创建 GitHub App

以下步骤需要在 GitHub 上手动完成；仓库代码本身不能替你创建带凭据的 GitHub App。

1. 打开 GitHub 的 **Settings → Developer settings → GitHub Apps → New GitHub App**。
2. 填写应用名称和**正式站点首页 URL**。
3. 在 **Identifying and authorizing users** 中填写：
   - Callback URL：`https://YOUR_DOMAIN/api/auth/callback`
   - 不需要额外 OAuth scope。
4. 在 **Post installation** 中填写：
   - Setup URL：`https://YOUR_DOMAIN/api/github/setup`
   - 如需响应 installation 更新，启用 Redirect on update。
5. 在 **Repository permissions** 中只授予：
   - Contents：Read and write
   - Metadata：Read-only（GitHub 会作为基础权限要求）
6. 关闭不需要的 Webhook。若要让其他用户安装，把安装范围设为任意账户；仅个人使用则限制为你的账户。
7. 创建后记录 **App ID**、**Client ID** 和 **App slug**，生成 **Client secret**，并下载 **Private key**。

本地开发时，Callback URL 和 Setup URL 可以分别改为：

```text
http://localhost:5173/api/auth/callback
http://localhost:5173/api/github/setup
```

正式域名变化后，必须同步更新 GitHub App 配置与 `APP_ORIGIN`。

## 环境变量

复制 `.env.example` 为 `.env`，再填入 GitHub App 凭据：

| 变量 | 说明 |
| --- | --- |
| `GITHUB_APP_ID` | GitHub App 的 App ID |
| `GITHUB_APP_CLIENT_ID` | OAuth Client ID |
| `GITHUB_APP_CLIENT_SECRET` | OAuth Client secret |
| `GITHUB_APP_PRIVATE_KEY` | 下载的 PEM 私钥，可保留多行或使用字面量 `\n` |
| `GITHUB_APP_SLUG` | GitHub App URL 中的 slug |
| `SESSION_SECRET` | 至少 32 字节的随机会话密钥 |
| `APP_ORIGIN` | 站点的规范 origin，例如 `https://2fa.example.com` |

生成会话密钥：

```bash
openssl rand -base64 48
```

不要把这些值放进任何 `VITE_*` 变量。Vite 的 `VITE_*` 内容会被打包到公开前端代码中。

## 本地运行

```bash
npm install
copy .env.example .env
npm run dev
```

打开 `http://localhost:5173`。没有填写 GitHub App 环境变量时，本地 TOTP、二维码和分享链接仍可使用，云保险库会显示“等待配置”。

验证与预览：

```bash
npm test
npm run build
npm run preview
```

开发服务器和预览服务器都挂载了同一个 API middleware。纯静态托管只能使用本地验证器功能；云端保险库需要 Node 服务端或 Vercel Functions。

## 部署到 Vercel

1. 把仓库导入 Vercel，Framework Preset 选择 Vite。
2. Build Command 使用 `npm run build`，Output Directory 使用 `dist`。
3. 在 Vercel 项目的 Environment Variables 中填写上面的全部变量；Production 和 Preview 要分别评估是否使用不同的 GitHub App。
4. 把 `APP_ORIGIN` 设置为正式域名，例如 `https://2fa.example.com`。
5. 确认 GitHub App 的 Callback URL 和 Setup URL 指向同一个正式域名。
6. 部署后完成一次真实 GitHub 登录、安装、私有仓库选择和保存测试。

`api/[...path].js` 是 Vercel Functions 入口，`vercel.json` 提供 CSP、HSTS、COOP、CORP 等安全响应头。环境变量修改后需要重新部署。

如果没有真实 GitHub App 凭据，只能验证本地 TOTP 和模拟 API；不要把“未配置”状态当作 GitHub 授权已通过。

## 使用流程

1. 点击“GitHub 保险库”并使用 GitHub 登录。
2. 安装 GitHub App，只选择准备存放密文的私有仓库。
3. 回到站点，选择 installation 与私有仓库。
4. 首次使用时创建一个独立的保险库密码。
5. 在本地验证器载入账户后，点击“保存到 GitHub 私有仓库”，或手动添加账户。
6. 其他设备重复登录与仓库选择，然后输入同一个保险库密码解密。

“锁定并清除内存”会丢弃当前页面中的密码、明文和派生密钥；“断开 GitHub”会清除本站的登录会话，不会退出你的 GitHub 账户。“保存到 GitHub”会创建或更新 `.doriya/vault.json`，文件冲突时会提示先刷新。

## 保险库文件

固定路径：

```text
.doriya/vault.json
```

文件只包含四类顶层字段：

```json
{
  "format": "doriya-vault",
  "version": 1,
  "kdf": {
    "name": "PBKDF2-SHA256",
    "iterations": 600000,
    "salt": "base64"
  },
  "cipher": {
    "name": "AES-256-GCM",
    "iv": "base64",
    "data": "base64"
  }
}
```

账户名称、发行方、算法、周期和 Base32 密钥都在 `cipher.data` 的加密 JSON 中。单个保险库上限为 512 KiB。

## API

后端路由与环境变量约束见 `server/API.md`。主要接口：

- `GET /api/auth/login`、`GET /api/auth/callback`
- `GET /api/auth/session`、`POST /api/auth/logout`
- `GET /api/github/installations`
- `POST /api/github/install`、`GET /api/github/setup`
- `GET /api/github/repositories`
- `GET /api/github/vault`、`PUT /api/github/vault`

## 技术栈

- Vite + 原生 JavaScript
- Web Crypto API（RFC 6238 TOTP、PBKDF2、AES-GCM）
- `qrcode` 与 `jsQR`
- 自托管 Geist / Geist Mono 字体
- Vercel Functions + GitHub App / GitHub Contents API
