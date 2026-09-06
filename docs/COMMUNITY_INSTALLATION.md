# Community 安装与运行说明

本页补充根目录 [README](../README.md) 的全新本地安装流程。
安装入口只启动 Community，不依赖未随源码包提供的私有启动脚本。

## 前置检查

确认 Python、Node.js、npm 与 Docker Compose v2 可用。
数据库初始化使用后端锁定依赖中的 psycopg 驱动，无需安装 PowerShell 或 PostgreSQL 客户端。Python 支持 3.11–3.14；首次配置读取权威版本范围并检查解释器。
`backend/requirements.lock` 是带 hash 的锁定依赖，包含开发验证依赖，首次下载可能较大。
前端使用 `npm ci`；不要为解决安装失败删除锁文件或关闭 hash 校验。

## 配置与目录

- `community.env.example` 是无凭据模板；`scripts/community.py configure` 生成 `.env`。
- `DEPLOYMENT_PROFILE=oss`、`AUTO_CREATE_TABLES=false` 是安装入口的强制要求。
- `DATABASE_URL` 指向独立 PostgreSQL；默认数据库名为 `truthward_community`。
- `QUEUE_MODE=inline` 是单实例安装路径，不需要另起 worker。
- `COMMUNITY_SKILL_MANIFEST_DIR` 默认 `community-skills`；不得放入不可信代码。
- `.tmp/artifacts`、`.tmp/runner-artifacts`、`.tmp/replay-repository` 保存本地运行文件。
- 模型和 Connector 凭据由管理员在运行环境中配置；启动模板不含真实 Provider 配置。

运行命令应在源码根目录执行。启动器固定后端工作目录，确保 `.env`、Manifest 和
`schemas/contracts/` 不受调用位置影响。现有 `.env` 永不自动覆盖。

初始化完成后运行 `python scripts/community.py doctor`。该入口只读检查 `.env`、
Community profile、必需源码目录、Node/npm、迁移 checksum 和数据库 ledger；Docker
Compose 只在使用包内 Compose 时需要，因此 Docker 不可用会显示为 optional
`unavailable`。`doctor --json` 输出 `truthward.community-doctor.v1`，任一 required
检查未通过时退出非零。报告不包含 DSN、密码或 Token，也不会创建目录、修改配置、
应用迁移或修复数据库。

## 真实浏览器执行

功能测试的真实 Playwright 路径需要包内 `tools/playwright/semantic_action_runner.mjs`、
已安装的 `frontend/node_modules` 和锁定版本的 Chromium。运行根目录不能只保留 Python 文件。
在源码根目录安装浏览器：

Linux：

```bash
PLAYWRIGHT_BROWSERS_PATH="$PWD/.ms-playwright" npm exec --prefix frontend -- playwright install chromium
```

Linux 还需满足 Playwright 提示的浏览器原生库依赖。运行用户必须能够读取该目录；
执行器不会用系统中的任意浏览器替代锁定版本，也不会在执行期间隐式下载浏览器。

真实调用需在创建计划 API 的 `domainConfig.functional` 中显式设置
`actualExecution=true`、受控测试目标 `targetUrl` 和结构化 `semanticAction`。
工作流的测试计划表单提供“元素可见”“元素文本匹配”模板，可配置目标 URL、
元素角色/名称或 CSS 选择器以及预期文本，保存计划后通过既有执行控制启动。
其他高级动作继续使用 API；只修改名称等字段时，页面保留已有 domainConfig。
缺少真实配置时的模拟执行不能作为业务测试通过证据。
验收必须核对 task 的 `executionMode=actual`、`actualExecution=true`、
`runnerMetadata.namedToolExecuted=true`、`pinnedChromium=true`，以及实际 report、
screenshot、trace 等产物。回归展示扩展只处理执行后的既有推荐，不启动 Playwright。

完整计划、可运行脚本、本地演示目标和界面操作步骤见
[真实浏览器示例](../examples/community-browser/README.md#简体中文)。示例必须在 API
所在机器上执行；`127.0.0.1` 指向执行器所在机器。缺少模型配置不妨碍固定浏览器断言，
但真实模型业务调用必须单独验收，见[模型验证记录](COMMUNITY_PROVIDER_VERIFICATION.md#简体中文)。

## Windows 兼容说明

README 的主安装流程以 Linux / Bash 为准。Windows 使用相同源码包，但完整 Windows
安装链尚未验收。安装受支持的 Python、Node.js 与 Docker Desktop（含 Compose v2），
在源码根目录用 Windows PowerShell 创建并激活虚拟环境：

```powershell
python -m venv backend/.venv
.\backend\.venv\Scripts\Activate.ps1
```

激活后，继续执行 README 中的 `python`、`npm` 和 `docker compose` 命令。
新开终端时重新激活虚拟环境；不要直接复制 Bash 的 `source` 或环境变量赋值语法。
需要真实浏览器执行时，使用：

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $PWD '.ms-playwright'
npm exec --prefix frontend -- playwright install chromium
```

## 数据库初始化与升级边界

`python scripts/community.py init-db` 只用于独立空数据库，复用
`scripts/apply_migrations.py`、`DB_SCHEMA.sql` 和包内编号 SQL 迁移。
因此保留 canonical PostgreSQL 的约束、触发器与 checksum 账本，不以 ORM 自动建表替代。
共用数据库结构不等于开放全部业务入口；后端只注册 Community composition。

Python 先验证 `scripts/migrations/MANIFEST.sha256` 与全部编号 SQL，再连接数据库。
同一连接上的数据库锁覆盖空库检查、历史 checksum 核对和迁移执行；每个迁移及其
账本记录在同一事务提交。SQL 失败时当前事务回滚，已完成迁移保留。
`init-db` 会拒绝已有表、视图、序列或用户定义类型/函数的 public schema。
旧 `scripts/apply-migrations.ps1` 仅为 Windows 兼容入口，使用同一 Python 实现；
Linux 安装和运行无需调用它。维护者预演编号迁移可用
`python scripts/apply_migrations.py`，连接从环境变量或 `.env` 读取，不从示例配置推断。

可使用自行安装的 PostgreSQL 16：先创建独立数据库，再配置 `.env` 中的连接。
初始化账号需要在该数据库创建表、类型、函数、触发器和 pgcrypto 扩展的权限。
不要使用生产业务数据库，也不要直接对旧数据库运行首次安装步骤。

初始化中途失败时，保留错误与 migration ledger，不自动重放或删除数据库。
检查原因后可在另一个新建的隔离空数据库重新验证；不要把重建数据库当作升级策略。
`init-db` 不提供版本升级、降级、数据搬迁或跨已提交迁移的整库回滚。旧版本升级需要对应版本说明、
数据库及制品备份和隔离环境预演；迁移 checksum 不匹配必须停止，不得改账本绕过。

## 停止、备份与公网部署

Compose 只管理本地 PostgreSQL/Redis，数据保存在命名卷中。`stop` 不删除卷；
不要为清理容器删除数据库卷。保留 `.env` 中生成的凭据，已有数据库不会随新配置自动改密码。

至少备份数据库、`.env`、artifact/replay 目录与使用的源码版本，并验证恢复。
备份包含敏感信息，应加密保存并限制访问。首次安装流程不操作已有服务器实例。

默认 API 与前端只绑定 loopback。公网部署需要单独配置 TLS、反向代理、静态前端、
防火墙、允许来源、运行身份与备份；不要直接暴露数据库、Redis 或开发前端。
开放访问前应完成首次管理员创建。启动后的只读检查包括
`/api/v1/health`、`/api/v1/readiness` 和未认证 `/api/v1/auth/me` 返回 401。

## 故障排查

| 现象 | 检查方向 |
| --- | --- |
| configure 拒绝覆盖 | 已有 `.env` 被保留；首次安装使用新目录，已有实例按原配置启动 |
| init-db 提示非空 | 当前连接并非新数据库；不要删表或覆盖账本 |
| 缺少 psycopg | 在激活的 Python 环境重新按锁文件安装后端依赖 |
| SQLSTATE 或 checksum 错误 | 保留账本与报错标识；确认源码包及数据库状态，不修改历史 SQL 或账本来绕过 |
| 连接失败 | 检查依赖健康、端口和 `.env`；不要公开完整 DSN 或密码 |
| doctor 返回 blocked | 按 `blockedChecks` 修复配置、依赖或迁移状态；doctor 不会自动修改实例 |
| Python 不支持 | 使用 3.11–3.14，不绕过版本检查 |
| 登录 401 | 使用自己创建的用户名/邮箱；演示 bearer 被拒绝，Token 过期需重新登录 |
| 多个接口 422 | 核对版本和完整 `schemas/contracts/`，不要关闭响应校验 |
| Provider/执行器不可用 | 配置实际依赖后再运行；安装成功不代表外部能力已验证 |
| 审计“未记录” | 展开现有事件详情；不能恢复历史未持久化字段 |

## 验证范围

首次安装验收必须针对同一候选源码包，在空数据库、独立目录与显式资源限制下执行：
配置生成、锁定依赖安装、canonical migrations、API 启动、首次管理员、登录、项目/环境
创建、授权读取、重启持久性和前端 OSS 构建。不得借用已有部署的源码、配置或数据库。

首次安装通过本身不代表真实模型、浏览器/扫描器、SCM 外部写入或全平台验收通过。
证据应记录实际系统、Python 版本、archive hash 和未执行范围，不把未运行标为成功。

本次候选包已在 Linux / Python 3.12 上验证独立锁定依赖安装、空 PostgreSQL 16、
原生依赖与 Compose 两条路径、真实 HTTP 首次管理员/项目/计划/执行 API、令牌撤销、
重启持久性以及 Vite 页面和 API 代理。后续 Skill 候选包补验了真实 Playwright 功能
执行、实际工具产物、本地扩展解析、绑定启停、跨项目拒绝及构建后的浏览器 UI。
精确源码包与结果见 [Skill 验收记录](COMMUNITY_SKILL_ENABLEMENT.md#验收)。
后续 2026-09-05 候选包已补验本地 Ollama 0.11.10 / `qwen2.5:0.5b` 的真实业务调用、
持久化 live ModelInvocation、官方固定 Chromium 新装与 P21 Semgrep Docker 沙箱。
Windows 全流程、托管/外部模型 Provider、其他扫描器与真实 SCM 写入仍未验证。

2026-09-05 的原生 Python 迁移增量已在 Ubuntu / Python 3.12 / PostgreSQL 16.15
隔离环境通过：PATH 中无 `pwsh`、`psql` 时完成空库初始化；64 条账本与旧入口一致，
并逐项核对列、约束、索引、触发器、函数和枚举。SQL 失败与账本原子回滚、历史 checksum
冲突前置拒绝、非空库保护、并发锁、重复执行、API 健康/认证及重启持久性均已验证。
该迁移记录仅覆盖迁移和启动增量；本地 Ollama 模型的后续补验证据见
[模型验证记录](COMMUNITY_PROVIDER_VERIFICATION.md#简体中文)。
