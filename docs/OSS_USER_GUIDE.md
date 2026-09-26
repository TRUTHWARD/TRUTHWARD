# Community OSS 使用指南

> 适用范围：后端 `DEPLOYMENT_PROFILE=oss`，前端 `VITE_PRODUCT_PROFILE=oss`。

Community OSS 是可自托管核心版。实际权限以后端 `/api/v1/auth/me` 返回的
effective capabilities 和项目成员关系为准；前端是否显示按钮不构成授权。

Community 保留项目、环境、计划、执行、结果和问题跟进组成的基本测试流程，并提供
执行记录、失败信息、Artifact、Finding、WorkItem、Trace 和审计投影等证据基础。
完整平台在同一数据链上继续提供受治理的自动归因、Gate、Replay 和发布决策；这些能力
未进入当前 Community composition 时，本指南不会把它们描述为 Community 已开放功能。

## 1. 启动

首次安装遵循根目录 [快速开始](../README.md#快速开始)，使用包内
`community.env.example`、`compose.community.yml` 和 `scripts/community.py`。
数据库初始化仅接受空库，不覆盖已有配置或数据。详细前置条件与故障排查见
[安装与运行说明](COMMUNITY_INSTALLATION.md)。

OSS 后端使用 `agentic_qa.apps.oss_api_gateway:app`。`user-token`、`admin-token`
等演示 bearer 一律返回 401；不要把 full profile 的演示身份用于 OSS。

## 2. 首次管理员与登录

数据库中没有 Community 用户时，登录页提供首次管理员 bootstrap。创建完成后使用本地
用户名和密码登录。前端只使用登录后保存的 Community Token，忽略演示 Token 配置。
旧版账号与 Community 共用用户名/邮箱唯一性约束；出现重复身份提示时应更换用户名或邮箱，不必重置数据库。
Token 只在创建时返回，数据库保存不可逆 hash；登出或撤销后
立即失效。

部署到公网前必须更换数据库密码、Secret key、允许来源，并通过 TLS 终止访问。
API、日志、Trace 和 Audit 不应包含明文密码、bearer Token、credential ref 或
Provider 原始响应。

## 3. 项目、环境与成员

Community 管理员可以创建、更新和归档项目/环境，并给本地用户分配固定项目
角色。所有 project/environment 请求都由 `ScopeAuthorizationService` 重新校验；
environment 必须属于 project，跨项目或猜测 ID 的访问会 fail closed。

顶部项目范围规则：

- 零项目：显示 onboarding；
- 一个项目：显示静态项目名；
- 多个项目：显示项目选择器。

选择器只切换已有授权范围，不创建成员关系。

## 4. 多模型配置

模型可以配置在项目默认范围，或覆盖到某个 environment。可将多个配置绑定到
PRIMARY、CHALLENGER、JUDGE、LOCAL_FALLBACK。解析顺序是 environment 精确绑定
优先，再回退到项目默认绑定。

密钥只接受运行时 credential/env ref，不通过 API 回显。列表只返回
`apiKeyConfigured` 等安全状态。如果引用不存在、环境不匹配或 Provider 不可用，
系统返回真实 unavailable，不伪造成功。

当前运行候选版本已使用本地 Ollama 0.11.10 与 `qwen2.5:0.5b` 完成真实业务调用验收，
并核对了与 Execution 关联的 live ModelInvocation。托管/外部 Provider 尚未验证；
连接检查和真实业务调用仍需分别记录，见[模型验证记录](COMMUNITY_PROVIDER_VERIFICATION.md#简体中文)。

### 第一次真实浏览器测试

在工作流的测试计划管理中选择项目与环境后，可以按“场景集合”维护浏览器测试：
一个计划可包含多个场景，每个场景又可按顺序包含跳转、填写、点击、元素可见和元素文本匹配等动作。
“元素可见”用于确认页面上出现了目标元素；“元素文本匹配”还会校验该元素的文本内容。

从需求工作流生成测试资产时，平台会同时保存结构化浏览器场景候选。候选默认不能直接执行；
用户需要补齐目标 URL、定位信息或参数引用，并逐个确认场景。启动执行时可以只勾选本次要运行的场景，
后端会把所选场景及动作冻结到对应执行任务中。未确认、来源已变化、信息不完整或包含明文敏感值的候选会拒绝执行。

项目环境配置了 `base_url` 时，编辑器会给出 URL 建议；既有执行中成功使用过的定位信息会作为历史提示展示，
但不会自动覆盖当前配置。需求或生成计划发生变化后，既有场景会标记为来源已变化，需要接受新来源并重新确认。
页面展示后端记录的任务状态、真实/模拟执行模式和失败信息；进入执行详情检查产物。
高级 API 配置在仅更新计划名称等字段时会保留，选择新的浏览器场景配置才替换对应动作。
完整本地演示页面和脚本见[真实浏览器示例](../examples/community-browser/README.md#简体中文)。

## 5. 可替换 Skill

Community 支持可信本地注册；首个可显式启用的扩展是回归推荐展示：

1. 把 JSON Manifest 放入配置的受信任 `community-skills` 目录；
2. 在 Skill 页面注册 Manifest；
3. 选择 `PREPARE.regression_scope`、`regression-scope-local` 1.1.0，按 project 或 environment 建立 draft Binding；
4. 点击“启用绑定”，由后端验证配置、权限、版本/hash、停止开关及展示契约；
5. 进入一次 Execution，点击“生成回归展示”，查看分组结果和实际解析的 Skill/Invocation；
6. 在 Invocation 页面核对 Binding、冻结版本、ReasonCode 和 evidence refs；
7. 不再使用时点击“停用绑定”；后续解析使用原有默认政策，历史 Invocation 不改写。

示例通过 `compatibility.communityProfile` 配置按 domain/priority 分组，以及是否显示
case ID。它只展示 Service 已选择的回归用例，不改变用例选择、风险或执行任务。
修改 Manifest 必须注册新版本，同一作用域切换版本前先停用旧 Binding。其他扩展点或
适配器不因“低风险”声明而自动获得启用权限。详细字段见 [本地 Skill](../community-skills/README.md)。

允许的 Skill 必须是 low-risk、data-only，且 `allowedTools`、
`allowedConnectors` 为空。平台拒绝软链接、目录穿越、远程 URL、脚本、命令、
二进制、任意上传、外部写、数据库/Memory/Gate 权限和中高风险 Manifest。

Community 不开放私有 Skill Registry、任意代码执行、Evaluation、Shadow、Approval
激活、自动回滚或 controlled autonomy；上述展示扩展使用独立的受限显式启用政策。

## 6. Connector

Community Connector allowlist 为 GitHub、GitLab 和 Mock SCM。Binding 必须属于
当前授权 project，可选 environment。API 和 Audit 只暴露 binding identity、类型、
scope、配置/权限 hash、configured 布尔值和 redaction policy version；不返回原始
配置或 credential ref。

真实 Secret 只在 Connector 调用期间以内存形式注入。当前 Community v1 只开放
SCM 配置和纳入 composition 的只读分析，不开放 PR Admission/Enforce 管理面。

## 7. 基本测试闭环

推荐顺序：

1. 创建测试计划；
2. 启动受限本地执行，必要时取消；
3. 查看 Workflow Run 和 Execution，核对任务状态、失败信息及真实 Artifact；
4. 查看标准化 Finding 及其已有证据引用，不把原始日志或模拟结果当作业务结论；
5. 创建 WorkItem，并执行认领、完成或取消等授权流转；
6. 通过 Trace 和审计投影复核已记录的调用与状态；
7. 查看 candidate path、change set、impact 和 selective replay plan；owner/admin 可在这些页面按需刷新受限分析链。

Change Set、Impact 和 Selective Replay 的结果页仍是只读投影。数据为空或陈旧时，页面通过
服务端 `coverage-readiness` 投影列出当前项目已有的需求版本、测试计划、执行、执行图和覆盖
快照数量，并逐项说明缺失或陈旧的后端事实。owner/admin 可使用“生成/刷新分析”创建受限分析链；
member 仅能由其已获授权的执行生命周期自动触发，viewer 只能查看。该链只生成同项目需求
Change Set、observed 非权威图、Coverage/Proof、关闭 AI 的确定性 Impact 和不执行的 Selective
Replay Plan；不会启动测试、审批、Gate、Memory、CI、模型调用或外部写，也不会把图提升为 canonical。
空列表、过期结果与页面故障保持明确区分。

需求变更集的“变更字段”是字段名，不是需求正文，也不是测试数。新增条目会显示新增需求文本；
删除和修改条目分别显示变更前文本、变更前后文本。正文通过单独的只读预览接口从冻结需求版本读取，
同时要求 `change.read` 和 `requirements.read`，并核对项目范围与条目内容哈希；无法核对时明确显示
“内容不可用”。旧版按列表序号生成的 `requirement-N` 在跨版本修改时仅表示位置匹配，需人工核对身份。
已纳入需求库投影的来源需求版本可跳转到相应版本筛选视图。

选择性回放计划中的后端 `status=fallback` 表示证据不足时采用保守选择策略，不表示已经执行回退。
Community 页面只展示计划和只读执行交接信息；过期或陈旧的计划需要刷新分析数据，页面不会执行测试。

当前 v1 已开放 Requirement Intake；没有开放完整 Test Assets、Gate/PR Admission、完整
Coverage/Replay/Evidence 页面，也不在 Community 工作流中启用自动 Triage/Healing。
当前失败分析以执行状态、失败信息、Artifact、Finding 和可追溯记录为基础；不要通过
直接 URL 或修改 DOM 绕过 composition，也不要把完整产品的自动归因能力误写为 OSS
当前能力。

## 8. 可见和隐藏模块

默认可见：Workspace、Workflow、Exploratory 本地会话闭环、Tasks、Findings、Audit、
Candidate Paths、Change Sets、Impact、Selective Replay Plans、Observability、
Execution、Skill Invocation/Binding、Project/Environment/Model/Connector 设置。

Exploratory 支持在授权项目/环境内创建会话、记录笔记、添加证据引用或上传受限图片证据、把缺陷候选经
`RawFindingRecord -> NORMALIZE -> Finding` 形成项目内 Finding，以及结束会话和查看报告。
图片只接受单个 PNG、JPEG 或 WebP，最大 8 MiB；服务端会校验真实格式和像素、拒绝动画，
并解码重编码以移除 EXIF/内嵌元数据。上传前仍需确认图片可见内容不含不应存储的密钥或个人
敏感信息；预览必须登录并再次通过项目 scope 校验。笔记与 Bug candidate 从已经管理的证据中
勾选关联，不能在缺陷表单内绕过证据入口。member 只能维护自己创建的会话，owner/admin 可维护
项目内会话，viewer 只读。该闭环不支持其他文件、脚本、命令、可执行二进制或任意上传，也不支持
外部缺陷同步、Gate/CI 写回、Approval、Memory 或自动化外部操作。页面默认显示人类可读追溯卡片；
原始 JSON 只放在折叠的技术详情中。

默认隐藏且后端未组合：Enterprise IAM、Gate Policy、PR Admission/Enforce、受管
Replay Repository、Agent/Queue、Correction、Knowledge、Lessons、Improvement、
高级交互治理、跨项目可视化和 controlled autonomy。

## 9. 健康与故障判断

部署后只读检查：

- `/api/v1/health` 正常；
- 未认证访问 `/api/v1/auth/me` 返回 401；
- bootstrap/login 后返回 `edition=community`、`deploymentProfile=oss`；
- effective capabilities 不超出 manifest 的 Community allowlist；
- Enterprise 路由不出现在 OSS OpenAPI；
- 零/一/多个项目时顶部控件行为符合规则。

常见状态：401 表示需要登录或 Token 已撤销；403 表示 capability/角色不足；404
也可能是跨 scope 的 fail-closed；409 表示状态或幂等冲突；413/429/504 分别是
载荷、速率或超时边界。Mutation 不应由前端自动重放。

## 10. 发布边界

根私有仓库仍适用专有许可证。Apache-2.0 只适用于 owner/path 冻结、同一精确
commit/archive 扫描和 clean build 全部通过的独立源码导出。当前授权是 source-only，
不包括 wheel、容器或预构建前端。

具体授权以下载文件包随附的许可证与来源清单为准。首次安装验收不代表所有外部
Provider/Runner 或完整生产发布矩阵已通过。
