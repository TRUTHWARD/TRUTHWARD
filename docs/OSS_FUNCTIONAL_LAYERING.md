# OSS functional layering

Status: Community core v1 implemented; Basic remains a separate commercial edition.

机器可读权威分别是 `release/oss/feature_layers.json` 和
`release/oss/manifest.json`。本文件描述产品分层；Apache-2.0 是否适用于某个
文件，仍由精确源码导出、owner/path 冻结和发布证据决定。

## 版本关系

`community`、`basic`、`pro`、`enterprise` 是不同 edition。历史 Basic 版本继续
保持项目级只读能力；Community OSS 不继承 Basic allowlist，而由独立
`COMMUNITY_CAPABILITIES`、独立 API composition 和 OSS 前端 composition 约束。

## Community core v1

当前可用闭环为：

```text
bootstrap 本地管理员 / 登录
→ 创建项目、环境和成员
→ 配置项目/环境模型、Community SCM、受信任本地 Skill
→ 创建测试计划
→ 启动受限本地执行
→ 查看 Finding、Workflow、WorkItem、Audit 与只读分析投影
```

已实现的核心包括：

- 可撤销数据库 Token、本地用户与固定 Community 角色；
- project/environment 作用域授权，以及项目和成员管理；
- 项目/环境多模型配置与 PRIMARY、CHALLENGER、JUDGE、LOCAL_FALLBACK 绑定；
- 受信任本地目录中的低风险 data-only Skill Manifest 注册、Binding 与 Invocation 观测；
- GitHub、GitLab、Mock SCM 的项目范围 Binding 和 Safe Projection；
- 测试计划、受限执行、Finding/Workflow 投影和 WorkItem 流转；
- candidate path、change set、impact、selective replay plan、audit 和 observability 等已纳入 composition 的只读投影。

Requirement Intake、Test Assets、Gate/PR Admission、完整 Coverage/Replay/Evidence、
Agent/Queue、Correction/Knowledge/Lesson/Improvement 当前没有进入 Community v1；
前端隐藏，后端 composition 也不注册相应路由。

## 三层边界

| Layer | License target | Product rule |
| --- | --- | --- |
| `oss_core` | Apache-2.0 source export | 自托管 Community 闭环及其安全基础。 |
| `oss_conditional` | Apache-2.0 source export | 依赖已配置或已有上游数据后才显示。 |
| `enterprise` | Proprietary | 跨组织、高风险治理和商业管理扩展。 |

安全不是 Enterprise 附加项。认证、ScopeAuthorization、脱敏、Secret ref、
Guardrail、幂等、fail-closed 和审计安全投影属于 Community core 的必要边界。

## Skill 边界

Community 开放可替换 Skill 模块，但只接受受信任本地目录中的 JSON Manifest：

- low risk、data-only、无 Tool/Connector、无外部写；
- 无脚本、命令、二进制、远程 URL、任意上传或软链接；
- 不得写数据库、Memory、Gate、Approval 或 canonical Finding；
- Binding 必须匹配授权 project/environment 和 Extension Point contract。

固定回归展示扩展允许按 `community-presentation-enable.v1` 显式启用/停用，后端
重验精确适配器、配置、版本/hash、Scope、Capability、Kill Switch 和并发状态。
它只分组展示已有建议，不替换权威计算；其他 Skill 不适用此受限政策。
实施与验收状态见 [Community Skill 启用契约](COMMUNITY_SKILL_ENABLEMENT.md)。

私有 Registry、Dataset Evaluation、Shadow、Approval-backed Activation、自动回滚
和 controlled autonomy 属于 Enterprise 治理扩展。

## 项目选择器

```text
zero projects  -> onboarding，不显示空选择器
one project    -> 静态项目范围
multiple       -> 显示项目选择器
```

项目控件只选择已授权范围，从不授予成员关系。

## 物理与许可边界

Community 运行入口固定为 `agentic_qa.apps.oss_api_gateway:app`，只组合
`COMMUNITY_OSS_ROUTERS`。full 入口可组合 Enterprise 扩展，但 Community 不得
静态导入 Enterprise 页面或请求实现。

私有仓库默认专有。candidate/approved path 本身不改变仓库许可；只有从精确
commit 生成、通过 Secret/专有路径/依赖/clean build/SBOM 门禁并获得 owner
授权的独立源码导出包适用 Apache-2.0。二进制和容器不在当前授权内。
