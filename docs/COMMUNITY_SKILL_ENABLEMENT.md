# Community Skill 受限启用与实际调用

分类：implemented contract change；功能、真实工具、界面与一个本地真实模型组合已验证；
托管/外部 Provider 仍为 not_run。

## 本次授权范围

首版仅开放 `PREPARE.regression_scope` 的回归计划展示扩展。Manifest 选择平台编译的
`community.regression_projection.v1`，以 `compatibility.communityProfile` 配置
`groupBy=domain|priority` 与 `includeCaseIds=true|false`。适配器只对 Service 已计算的
recommendedRegressionSuite 做分组计数及 ID 展示，不改变任何 case、风险、执行选择、
Finding、Gate 或 evidence。它没有模型、Tool、Connector、数据库或外部写权限。

## 启用政策

本次新增政策是 `community-presentation-enable.v1`，不是 Enterprise 治理的 edition
旁路。仅以上精确扩展点、适配器与严格配置契约可申请；必须可信本地注册、low risk、
空 Tool/Connector、无写权限且无需 Approval。其他适配器/扩展点/风险/能力变更仍走
现有完整治理链，在 Community 中不可启用。不会伪造 Approval、Evaluation 或 Shadow。
这种展示变换不替换 Service 的权威计算，固定夹具验证和完整性检查是其启用证据；
该例外不适用于任意运行时实现替换。

Binding 先创建为 draft。后端以 capability、ScopeAuthorization、Manifest/hash、严格
配置、运行时 contract、Kill Switch、乐观状态 token 与事务 scope lock 重新校验后，
由显式生命周期请求启用/停用。同一作用域与扩展点已有 active Binding 时拒绝新启用，
须先明确停用旧 Binding。重放相同操作必须幂等，过期状态不得覆盖新状态。
停用不受 Kill Switch 阻碍；无有效 Binding 时保留扩展点既有默认解析政策。

## 业务入口和观测

使用受权 `POST /executions/{id}/regression-plan` 生成非权威回归展示，不创建执行或
测试任务。Service 通过 `SkillService.invoke_extension()` 调用，冻结版本/hash/profile，
校验权威内容未变，返回分组结果及 Invocation ref。不开放直接 Skill 执行接口。
启用、停用复用 Guardrail、Trace、Audit；Invocation 保留 input/output/resolution。
这些证据不升级 Overall Audit Exposure Closure。

Invocation 列表在计数/分页前按授权项目过滤，详情从持久化 Execution→TestPlan 或
无 Execution 时的 Binding 推导作用域，均复用 ScopeAuthorizationService。
Community 无法读取无权访问或缺少权威作用域的 Invocation；不能用 snapshot 中的项目 ID 授权。

## 验收

本地先做严格配置、作用域、生命周期、并发 token、结果不变性和静态检查。部署服务器
使用精确源码包、独立数据库/临时目录、资源限制运行 API/UI 验收，再分别验证真实
Provider 调用、真实工具产物及指定本地 Skill 的实际调用与结果。缺失必须记录为
not_run/unavailable/failed，不能用模拟替代。README 在实际验收后更新。

2026-09-04 验收结果：

| 范围 | 结果 |
| --- | --- |
| 本地配置/结果完整性/作用域/生命周期/契约 | 55 tests、19 subtests passed |
| 静态检查、文档检查与前端类型检查 | passed |
| 精确 review archive 与服务器文件逐项比对 | 527 files passed |
| 独立 PostgreSQL 16 正式迁移、真实 HTTP 身份与 Binding 操作 | passed |
| 环境级 Binding 的真实业务解析 | passed；冻结 Manifest 与 Invocation 可观测 |
| Playwright 1.61.1 / Chromium 149.0.7827.55 | actual execution passed；report、screenshot、trace、DOM、accessibility、HAR、video 已产生 |
| 浏览器 UI 创建草稿、项目级启用、生成展示、停用 | passed；无 page error |
| 幂等冲突、过期状态、同 scope active 冲突、未授权 Invocation 列表/详情 | 按预期拒绝或返回空集合 |
| 停用后默认解析、选中用例与历史 Invocation 保留 | passed |
| 真实模型 Provider | not_run：未配置可用 Provider 与凭据 |

运行证据绑定到临时验证 commit `c4477606b55f842b69304b00f81590768a18a78b`，
archive SHA-256 `29fa1fa854dc8064727154332db3628b02df4fc3f8d05d8bd99282d47613a584`。
环境为 Linux、Python 3.12.3、Node.js 22.23.2、独立数据库/Redis/制品目录。
API/UI、构建和验收进程均使用显式 CPU、内存与任务数上限。源码为不可公开发行的
review candidate；依赖锁文件及 hash 校验未关闭，下载使用可用镜像源。
README、截图及最终状态文档在运行验收后更新，不纳入此前 runtime archive 的 hash。

可复现探针保留在仓库 `tests/integration/community_skill_actual_probe.py` 和
`tests/integration/community_skill_ui_probe.mjs`；前者要求新的隔离空数据库，后者
读取该实例权限为 0600 的私有登录状态。私有状态不作为公开证据或源码导出。
这次未切换线上服务，也未执行 Windows 全流程、其他扫描器或真实 SCM 写入验收。

2026-09-05 补验使用 commit `701bd58112eb7baa3f3ddf383a281dacd2905982`
的精确 clean bundle，在新的隔离数据库中再次通过 Manifest 注册、Binding 显式启停、
真实 Playwright、业务调用、Invocation 观测与越权拒绝；P21 固定 Semgrep Docker 沙箱
也通过。随后，本地 Ollama 0.11.10 / `qwen2.5:0.5b` 通过 live 健康检查并参与同一
Community 业务路径，2/2 次持久化 ModelInvocation 均为 live completed，且绑定到
所选模型和 Agent run。该结果只验证这个本地 Provider/模型组合；托管/外部 Provider、
语义质量阈值和生产容量仍未验证。安全证据摘要见
`reports/community-runtime-20260905/validation-summary.json`。

实施状态以 IMPLEMENTATION_STATUS.md 为锚点；最终文档提交仍需完整 P0 与精确发布证据。
