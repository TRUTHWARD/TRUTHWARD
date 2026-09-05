# Community OSS 使用指南

> 适用范围：后端 `DEPLOYMENT_PROFILE=oss`，前端 `VITE_PRODUCT_PROFILE=oss`。

Community OSS 是可自托管核心版。实际权限以后端 `/api/v1/auth/me` 返回的
effective capabilities 和项目成员关系为准；前端是否显示按钮不构成授权。

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

在工作流的测试计划管理中选择项目与环境，选择“元素可见”或“元素文本匹配”，
填写目标 URL、元素角色/名称或 CSS 选择器，保存计划，再在执行控制中启动功能执行。
页面展示后端记录的任务状态、真实/模拟执行模式和失败信息；进入执行详情检查产物。
高级 API 配置在仅更新计划名称等字段时会保留，选择新的浏览器模板才替换对应动作。
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
3. 查看 Workflow Run、Execution、Finding 和审计投影；
4. 创建 WorkItem，并执行认领、完成或取消等授权流转；
5. 有现成数据时查看 candidate path、change set、impact 和 selective replay plan。

当前 v1 没有开放 Requirement Intake、Test Assets、Gate/PR Admission、完整
Coverage/Replay/Evidence 页面；不要通过直接 URL 或修改 DOM 绕过 composition。

## 8. 可见和隐藏模块

默认可见：Workspace、Workflow、Exploratory 只读投影、Tasks、Findings、Audit、
Candidate Paths、Change Sets、Impact、Selective Replay Plans、Observability、
Execution、Skill Invocation/Binding、Project/Environment/Model/Connector 设置。

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
