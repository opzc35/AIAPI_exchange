# AIAPI_exchange

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/opzc35/AIAPI_exchange)

支持OpenAI API和Anthropic API调用，有用户系统和管理员系统，每个用户都可以上传自己的AI渠道，并且设置其定价，其他用户可以调用所有上传的渠道。只能由管理员添加额度来调用。

## Cloudflare MVP

这个仓库现在提供了一个可直接部署到 Cloudflare Workers 的 MVP 版本，包含：

- 用户注册 / 登录
- 第一个注册用户自动成为管理员
- 管理员为用户增减额度
- 用户上传 OpenAI / Anthropic 渠道并配置单价
- 其他用户通过统一代理接口调用渠道
- 使用 D1 存储用户、会话、渠道和调用日志

## 项目结构

- `src/worker.js`: Worker 服务端和单页前端
- `schema.sql`: D1 初始化 SQL
- `wrangler.toml`: Cloudflare 部署配置
- `.dev.vars.example`: Deploy to Cloudflare / 本地开发时需要填写的密钥示例

## 本地检查

```bash
npm run check
```

## 一键部署到 Cloudflare

Cloudflare 官方现在支持 `Deploy to Cloudflare` 按钮，适用于 Workers 项目。这个项目已经补齐了按钮部署需要的基本条件：

- `wrangler.toml` 中声明了 D1 绑定，Cloudflare 在按钮部署流程里可以自动创建并回填资源
- `.dev.vars.example` 提供了 `APP_SECRET` 示例，部署时会提示你填写密钥
- `package.json` 里补了 Cloudflare 绑定说明，方便在部署向导里理解每个绑定的用途

要让上面的按钮真正可点可用，你只需要把 README 里的占位地址替换成你公开仓库的真实地址，例如：

```md
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/<your-org>/<your-repo>)
```

说明：

- 这个按钮只适用于 Workers 项目，不适用于 Pages 项目
- 公开给别人一键部署时，源仓库需要是公开的 GitHub 或 GitLab 仓库
- 如果只是你自己部署，也可以直接用下面的“控制台手动部署”或 “Wrangler CLI 部署”

## 手动部署教程（Cloudflare 控制台）

适合不想用命令行、直接在 Cloudflare 后台导入仓库的人。

1. 先把当前仓库推送到 GitHub 或 GitLab
2. 登录 Cloudflare 控制台，进入 `Workers & Pages`
3. 点击 `Create application`
4. 选择 `Import a repository`
5. 授权 Cloudflare 访问你的 GitHub / GitLab 仓库
6. 选择这个项目仓库
7. 在构建配置页面确认项目根目录就是仓库根目录
8. 确认 Worker 名称与 `wrangler.toml` 里的 `name = "aiapi-exchange"` 一致，避免构建失败
9. 在资源 / 绑定配置里确认 D1 数据库已创建并绑定到 `DB`
10. 在环境变量或 Secrets 中设置 `APP_SECRET`
11. 点击 `Save and Deploy`

部署完成后，Cloudflare 会分配一个 `*.workers.dev` 地址，你打开后就可以使用这个系统。

## 手动部署教程（Wrangler CLI）

1. 安装 Wrangler

```bash
npm install -g wrangler
```

2. 登录 Cloudflare

```bash
wrangler login
```

3. 创建 D1 数据库

```bash
wrangler d1 create aiapi-exchange
```

4. 把返回的 `database_id` 填入 `wrangler.toml`

5. 初始化表结构

```bash
wrangler d1 execute aiapi-exchange --file=schema.sql
```

6. 设置应用密钥

```bash
wrangler secret put APP_SECRET
```

7. 部署

```bash
wrangler deploy
```

## 说明

- 渠道 API Key 会先用 `APP_SECRET` 做 AES-GCM 加密后再写入 D1。
- 当前为 MVP，密码使用 SHA-256 存储，适合快速上线验证，不适合直接作为高安全生产实现。
- 若要进一步产品化，建议补上更强密码哈希、权限细分、充值审计、渠道停用、速率限制和更完整的 OpenAI / Anthropic API 兼容层。
- Cloudflare 官方关于 Deploy to Cloudflare 按钮的文档：<https://developers.cloudflare.com/workers/platform/deploy-buttons/>
- Cloudflare 官方关于控制台导入 Git 仓库部署 Workers 的文档：<https://developers.cloudflare.com/workers/get-started/dashboard/>
