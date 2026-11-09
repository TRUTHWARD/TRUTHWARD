# 贡献指南 / Contributing to TRUTHWARD

感谢你改进 TRUTHWARD Community。我们欢迎可复现的软件缺陷修复、测试、文档、
兼容性改进和边界清晰的小型功能建议。

Thank you for improving TRUTHWARD Community. Reproducible bug fixes, tests,
documentation, compatibility improvements, and narrowly scoped feature proposals are
welcome.

## 适用范围 / Scope

本指南同时面向公开 Community 仓库和正在审查的下一版 OSS 源码候选。正式 Community
源码归档是可运行的源码发行物，不保证包含私有 monorepo 的全部维护者测试、发行脚本或
治理材料。文档只能把实际包含在相应 checkout 中的命令描述为可运行命令。

This guide applies to the public Community repository and to a next-release OSS source
candidate under review. A formal Community source archive is a runnable source
distribution; it does not promise every maintainer-only test, release script, or governance
artifact from the private source-of-record repository. Documentation must describe a command
as runnable only when that command is present in the corresponding checkout.

开始前请阅读：

- [README](README.md)
- [Community 功能分层](docs/OSS_FUNCTIONAL_LAYERING.md)
- [社区行为准则](CODE_OF_CONDUCT.md)
- [安全策略](SECURITY.md)
- [支持与问题分流](SUPPORT.md)

Before starting, read the same documents above. Security vulnerabilities must use the
private process in `SECURITY.md`, not a public Issue or Pull Request.

## 许可证边界 / License boundary

正式 Community 源码归档中随附的文件适用归档内的
[Apache License 2.0](release/oss/LICENSE)。私有 source-of-record 仓库默认仍受其自身
许可证约束；运行 OSS profile、文件出现在候选列表或提交 Pull Request 都不会自行改变
许可证。每次公开源码发行仍须冻结精确 commit、路径范围和归档证据。

Files included in a formal Community source archive are governed by the
[Apache License 2.0](release/oss/LICENSE) shipped in that archive. The private
source-of-record repository remains governed by its own license by default. Running the OSS
profile, listing a path as a candidate, or opening a Pull Request does not itself change a
license. Every public source release still requires an exact commit, reviewed path scope,
and archive evidence.

只提交你有权提供的原创内容或许可证兼容内容。不要复制来源不明的代码、测试数据、图片、
字体、模型文件或客户材料。

Submit only original material or material you have the right to provide under compatible
terms. Do not copy code, datasets, images, fonts, model files, or customer material of
uncertain provenance.

## 先讨论再修改 / Discuss before changing

- 使用和配置问题、功能构想：使用 [GitHub Discussions](https://github.com/TRUTHWARD/TRUTHWARD/discussions)。
- 可复现缺陷：使用 [GitHub Issues](https://github.com/TRUTHWARD/TRUTHWARD/issues/new)。
- 安全漏洞：按 [SECURITY.md](SECURITY.md) 私密报告。
- 行为问题：按 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) 报告。

较大改动请先说明用户问题、Community/Enterprise 边界、预期接口和验证方式，避免实现方向
已经偏离后再投入大量工作。

For a larger change, first describe the user problem, Community/Enterprise boundary,
expected interface, and validation approach. This keeps implementation work aligned before
it becomes expensive to revise.

## 获取源码与本地运行 / Get and run the source

按照 [README 快速开始](README.md#quick-start)使用全新空数据库启动 Community。
中文安装、备份和故障排查见
[Community 安装说明](docs/COMMUNITY_INSTALLATION.md)。不要为解决安装失败而删除锁文件、
关闭 hash 校验、覆盖现有 `.env` 或删除已有数据库。

Follow the [README quick start](README.md#quick-start) with a fresh empty database. The
[Community installation guide](docs/COMMUNITY_INSTALLATION.md) covers installation,
backups, and troubleshooting. Do not resolve installation failures by deleting lockfiles,
disabling hash checks, overwriting an existing `.env`, or deleting an existing database.

不得提交 `.env`、Token、Provider key、数据库、备份、客户数据、浏览器 trace、本地报告或
其他运行产物。

Never commit `.env`, tokens, Provider keys, databases, backups, customer data, browser
traces, local reports, or other runtime artifacts.

## 修改边界 / Change boundaries

- 保持 `Controller → Service → Agent → Service-managed Skill Invocation → Tool/Connector`
  的职责边界；Agent 不直接执行 Skill、Tool 或 Connector。
- 不新增 `replay-service`、`skill-service`、`integration-service` 或
  `visual-grounding-service`。
- 前端显隐不是授权；后端 capability、scope 和 route composition 才是权威边界。
- Community 不得静态依赖 Enterprise 实现，也不得展示无法执行的 mutation。
- 未运行、缺少依赖、部分结果和模拟结果必须如实标注，不能伪造成 pass 或 external actual。
- 改动 API、Schema、持久化或安全边界时，同步实现、测试和用户文档；不适用项要明确说明。

- Preserve the documented layer ownership; Agents do not directly execute Skills, Tools,
  or Connectors.
- Do not add prohibited service boundaries or make the OSS composition import Enterprise
  implementations.
- Frontend visibility is not authorization. Backend capability, scope, and route
  composition remain authoritative.
- Report unavailable, partial, simulated, and unexecuted results honestly.
- Keep implementation, tests, and user documentation aligned when changing an API,
  Schema, persistence, or security boundary.

## 验证 / Validation

只承诺当前 checkout 实际提供的入口。Community 源码归档至少可以执行：

```bash
python -m compileall -q backend/src
npm --prefix frontend ci
npm --prefix frontend run build:oss
```

安装完成后运行只读检查：

```bash
python scripts/community.py doctor
```

真实浏览器流程见[可运行示例](examples/community-browser/README.md)，公开质量样例、truth
set 和参考结果见[公开质量基准说明](examples/public_quality_benchmark/README.md)。基础安装通过
不代表模型、浏览器、扫描器或外部 SCM 已验证。

The commands above are the minimum portable checks exposed by the Community source
distribution. After installation, run the read-only `doctor` command. Use the linked browser
example for a real local flow and inspect the public quality sample, truth set, and reference
result. A successful base installation does not validate models, browsers, scanners, or
external SCM systems.

完整 source-of-record checkout 可能另外包含 `scripts/run-tests.ps1`、静态检查、
PR-equivalent 和发行聚合入口；这些属于维护者验证面，只有文件实际存在时才可执行，且不能
冒充 Community 归档已经提供的命令。

维护者必须明确区分真实证据与模拟证据，并如实记录 external actual、local actual、
contract-only、skip 和 failure。完整仓库存在对应入口时，可用以下命令做隔离的 portable
贡献者检查；该命令不属于 Community 运行源码包承诺：

```powershell
.\scripts\test-clean-contributor.ps1 -Suite Portable -IncludeWorkingTree
Push-Location frontend
npm run lint
npm run test
npm run build
Pop-Location
```

A full source-of-record checkout may additionally contain maintainer test, static,
PR-equivalent, and release-aggregate entrypoints. Run them when present, but do not present
them as commands shipped in the Community archive.

## Pull Request

Pull Request 至少说明：

- 问题、目标和变更范围；
- Community/Enterprise、API、Schema、迁移、安全和兼容性影响；
- 实际运行的命令及退出状态；
- 真实、模拟、local actual 或 external actual 等证据类别；
- 未运行、失败、跳过和仍需人工验证的项目；
- 不含 Secret 或个人/客户数据的最小复现和错误摘要。

A Pull Request should state the problem and scope, product-boundary impact, commands and
exit status, evidence class, every unrun or unresolved item, and a secret-safe minimal
reproduction. Keep the change focused; unrelated generated artifacts or formatting churn
make review harder.

## 最小问题复现 / Minimal bug report

请提供 commit 或版本、操作系统、Python/Node/浏览器或工具版本、执行命令、期望结果、
实际结果、最小输入，以及脱敏后的日志或 Artifact 引用。无法公开的数据请不要上传；改用
最小合成样例。

Include the commit or version, operating system, Python/Node/browser or tool versions,
command, expected result, actual result, minimal input, and a redacted log or Artifact
reference. Do not upload data that cannot be shared publicly; replace it with a minimal
synthetic example.
