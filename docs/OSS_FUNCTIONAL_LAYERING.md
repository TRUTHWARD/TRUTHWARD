# OSS functional layering

Status: Community core v1 implemented; Basic remains a separate commercial edition.

机器可读权威分别是 `release/oss/feature_layers.json` 和
`release/oss/manifest.json`。本文件描述产品分层；Apache-2.0 是否适用于某个
文件，仍由精确源码导出、owner/path 冻结和发布证据决定。

## 版本关系

`community`、`basic`、`pro`、`enterprise` 是不同 edition。历史 Basic 版本继续
保持项目级只读能力；Community OSS 不继承 Basic allowlist，而由独立
`COMMUNITY_CAPABILITIES`、独立 API composition 和 OSS 前端 composition 约束。

## 产品形态与核心主线

谛序的产品形态是测试平台：项目/环境、测试计划、执行、结果、Finding 和后续处理
共同组成基础流程。执行证据与失败归因是贯穿这条流程的核心主线和差异化能力，不是
脱离测试平台单独存在的产品，也不替代计划、执行和结果管理。

Community core v1 开放这条主线的可运行基础，包括受限执行、失败信息、Artifact、
Finding、WorkItem、Trace 和审计投影。完整平台中的自动 Triage、Gate、受管 Replay
与发布决策继续受各 edition 的 capability 和 composition 约束；未注册到 Community
composition 的能力不得因总体产品定位而被表述为 Community 已开放。

## Community core v1

当前可用闭环为：

```text
bootstrap 本地管理员 / 登录
→ 创建项目、环境和成员
→ 配置项目/环境模型、Community Connector、受信任本地 Skill
→ 粘贴、上传、OCR 或导入需求并在需求库中选择
→ 创建测试计划
→ 创建并完成项目范围的本地探索性测试会话
→ 启动受限本地执行
→ 查看 Finding、Workflow、WorkItem、Audit 与只读分析投影
```

已实现的核心包括：

- 可撤销数据库 Token、本地用户与固定 Community 角色；
- project/environment 作用域授权，以及项目和成员管理；
- 项目/环境多模型配置与 PRIMARY、CHALLENGER、JUDGE、LOCAL_FALLBACK 绑定；
- 受信任本地目录中的低风险 data-only Skill Manifest 注册、Binding 与 Invocation 观测；Community
  Invocation 观测包含服务端脱敏的输入/输出/策略结构摘要、解析来源与证据引用，不包含高权限快照；
- GitHub、GitLab、Mock SCM，以及 Mock/Lark/ZenTao 只读需求文档 Connector 的项目范围 Binding 和 Safe Projection；
- 项目/环境范围的需求接入与需求库：文本粘贴、txt/md/json/csv/PDF/DOCX 上传、图片或扫描 PDF OCR、公共 HTTPS 链接、受控文档 Connector、Draft/Preview/Batch 和需求选择；
- 测试计划、受限执行、Finding/Workflow 投影和 WorkItem 流转；
- 项目/环境范围的本地探索会话：章程、范围、时间盒、笔记、证据引用、受限图片证据、规范化缺陷候选、结束和报告；图片仅允许单个 PNG/JPEG/WebP（最大 8 MiB），经真实格式/像素校验和服务端解码重编码后进入 Artifact Storage，并由鉴权预览接口读取；member 只能维护自己创建的会话，owner/admin 可维护项目内会话，viewer 只读；不提供其他文件、脚本、命令、可执行二进制或任意上传，不提供外部写回、Gate、Approval、Memory 或自动化外部操作；
- candidate path、change set、impact、selective replay plan、audit 和 observability 等已纳入 composition 的只读投影；Community 额外提供受 `coverage.materialize` 保护的项目级分析物化入口，只生成同项目需求 Change Set、observed/unfrozen/non-authoritative Graph、Coverage/Proof、关闭 AI 的确定性 Impact 和不执行的 Selective Replay Plan；`graph.candidate.observe` 仅在该生命周期内基于持久化语义执行事实生成只读 Candidate 观察，通用 Candidate 创建/Promotion/模型增强接口仍不开放；
  observability UI 可下钻 Trace 计数、脱敏元数据、结构化日志上下文与护栏证据，不展示原始模型或 Agent payload。

Candidate 查询路由和通用创建路由继续物理分离。为复用确定性转换与
append-only provenance，Candidate Service 是共享源码边界；OSS composition
不注册通用创建路由，Community capability ceiling 也不授予
`graph.candidate.create`。因此源码可见不等于运行时授权，受限观察只能从
`coverage.materialize` 生命周期进入。

Test Assets、Gate/PR Admission、完整 Coverage/Replay/Evidence、
Agent/Queue、Correction/Knowledge/Lesson/Improvement 当前没有进入 Community v1；
前端隐藏，后端 composition 也不注册相应路由。

Community 的需求数据必须绑定授权 project；environment 存在时必须属于该 project。
外部链接只读取受限公共 HTTPS 文本资源，文档 Connector 只能使用项目范围 Binding 和
运行时 credential ref。二进制原文留在 StorageAdapter 后，API/Audit/Trace 只返回脱敏
引用。Community 不组合 Approval，因此 high-risk 需求在入口被明确拒绝；低/中风险可
进入现有需求流水线。审批中心不在 OSS UI 中出现。测试计划 `sourceRef` 是来源追溯，
从需求流程生成时自动带入；`status` 由后端生命周期推进，普通更新不可选择或改写。

Community 分析物化由服务端派生完整 scope 并执行幂等/陈旧校验。owner/admin 可以手动刷新；
member 只能在其已授权执行结束后由生命周期触发，viewer 只读。它不组合或创建 Approval、
Gate、Memory、CI，不调用模型、不提升 canonical Graph、不创建新的 Execution/Task/retry，
也不执行 Selective Replay 或任何外部写；partial/unknown 一律保持保守并要求复核。

## 三层边界

| Layer | License target | Product rule |
| --- | --- | --- |
| `oss_core` | Apache-2.0 source export | 自托管 Community 闭环及其安全基础。 |
| `oss_conditional` | Apache-2.0 source export | 依赖已配置或已有上游数据后才显示。 |
| `enterprise` | Proprietary | 跨组织、高风险治理和商业管理扩展。 |

安全不是 Enterprise 附加项。认证、ScopeAuthorization、脱敏、Secret ref、
Guardrail、幂等、fail-closed 和审计安全投影属于 Community core 的必要边界。

## 性能能力边界

Community OSS 纳入不改变产品治理语义的基础性能能力：请求大小/超时上限、
Execution/Finding 可选 keyset cursor 读取、P0 复合索引、显式数据库连接预算、
聚合延迟桶，以及现有大 Gate/Replay 快照的 Artifact Storage 外置。Community
默认仍为单实例 `QUEUE_MODE=inline`，因此不把多 worker 能力伪装成已开放能力。

完整版默认启用 Redis/Celery，并将 control、execution、analysis、maintenance
分队列；普通 Execution 按 `options.parallelism` 分批 fan-out，最后只由一个
Service reducer 执行 OBSERVE→ANALYZE→NORMALIZE。完整版还默认启用 Redis
共享 Skill tenant/project/binding 并发配额和仅标记 `purge_eligible` 的保留扫描。
扫描绝不自动 purge，legal hold 与 pending legal-hold Approval 优先。

机器可读逐项边界见 `release/oss/feature_layers.json` 的
`runtime_operations.features`：`ossIncluded=true` 才是 Community 功能；源码被
导出但配置关闭不等于 Community 已启用。固定 large/soak 性能基线仍待部署服务器
对精确 clean commit 验证，不能从本地契约测试推导为通过。

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
