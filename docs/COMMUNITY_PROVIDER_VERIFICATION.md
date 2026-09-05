# Community Provider verification / 模型验证记录

## English

**Verified for the current runtime candidate: local Ollama 0.11.10 with `qwen2.5:0.5b`.**

On 2026-09-05, an isolated Ubuntu 24.04 environment installed the exact clean source
bundle for commit `701bd58112eb7baa3f3ddf383a281dacd2905982` (bundle SHA-256
`1855fad016ecb181e122c6ea37c1da825d305f137012dbf42119d963155832df`).
The Ollama container was pinned to image digest
`sha256:a5409cb903d30f9cd67e9f430dd336ddc9274e16fd78f75b675c42065991b4fd`
and exposed on loopback only. The model required no credential.

| Check | Result |
| --- | --- |
| Project/environment-scoped model configuration | Passed |
| Live Provider health probe | Passed |
| Actual Community business execution | Passed |
| Persisted live ModelInvocation linked to the Execution | Passed; 2 of 2 invocations completed live |
| Agent run bound to the selected model | Passed |
| Real browser tool in the same business execution | Passed with the pinned Playwright Chromium |
| Hosted/external Provider combinations | Not run |

This verifies one local Provider/model combination and the Community Service/model-gateway
business path. It does not establish model quality thresholds, hosted Provider compatibility,
external network reliability, cost behavior, or production capacity. OpenAI-compatible,
Anthropic, Gemini, and other hosted endpoints remain unverified until each exact configuration
completes the same live business-call acceptance.

For another Provider, configure its model ID, base URL and runtime credential reference in
an isolated deployment. Create a scoped model binding, run its connection check, then run a
Community business execution through the existing Service/model gateway. Verify a persisted
live ModelInvocation linked to that execution, including status, model identity and scope.
A stub response, fallback, missing invocation or Provider failure does not qualify.

The acceptance report must identify the exact source commit/archive, date, Provider, model,
workflow, live-call result and limitations. Do not publish credentials, credential references,
raw Provider responses, or private configuration files with the report.

## 简体中文

**当前运行候选版本已验证：本地 Ollama 0.11.10 与 `qwen2.5:0.5b`。**

2026-09-05，在 Ubuntu 24.04 隔离环境中安装并验证了 commit
`701bd58112eb7baa3f3ddf383a281dacd2905982` 的精确 clean source bundle
（bundle SHA-256：`1855fad016ecb181e122c6ea37c1da825d305f137012dbf42119d963155832df`）。
Ollama 容器固定到镜像 digest
`sha256:a5409cb903d30f9cd67e9f430dd336ddc9274e16fd78f75b675c42065991b4fd`，
仅监听 loopback；该本地模型无需凭据。

| 检查项 | 结果 |
| --- | --- |
| 项目/环境作用域模型配置 | 通过 |
| Provider 真实在线健康检查 | 通过 |
| Community 真实业务执行 | 通过 |
| 与 Execution 关联的持久化 live ModelInvocation | 通过，2/2 次调用均为 live completed |
| Agent run 绑定到所选模型 | 通过 |
| 同一业务执行中的真实浏览器工具 | 通过，使用固定版本 Playwright Chromium |
| 托管/外部 Provider 组合 | 未运行 |

这次结果验证了一个本地 Provider/模型组合以及 Community 的
Service/model-gateway 业务路径，不代表模型质量阈值、托管 Provider 兼容性、
外部网络可靠性、成本表现或生产容量已经验证。OpenAI-compatible、Anthropic、
Gemini 等托管端点仍需分别通过同样的真实业务调用验收。

验证其他 Provider 时，需要在隔离部署中配置模型 ID、Base URL 和运行时凭据引用，
创建作用域内模型绑定，先做连接检查，再通过既有 Service/model-gateway 执行
Community 业务任务。需要核对持久化的 live ModelInvocation 与 Execution 关联、
调用状态、模型身份及作用域。stub、fallback、缺失调用和 Provider 失败均不能算通过。

验收报告需要记录精确源码 commit/archive、日期、Provider、模型、业务路径、
真实调用结果与限制。报告不得包含凭据、凭据引用、Provider 原始响应或私有配置文件。
