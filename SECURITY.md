# 安全策略

## 支持范围

当前尚未提供长期安全支持版本或响应时限承诺。维护者以尽力而为的方式处理
最新 Community 源码发行和默认分支中可以复现的安全问题；历史版本不承诺
安全修复。

| 版本 | 安全支持状态 |
| --- | --- |
| 最新 Community 源码发行 | 尽力而为 |
| 默认分支 | 尽力而为 |
| 更早的发行或 commit | 不承诺支持 |

该范围不表示 production-ready、高可用或商业支持承诺。

## 私密报告漏洞

不要在公开 Issue、Pull Request、讨论区、日志附件或测试 fixture 中披露：

- 可利用的漏洞细节；
- token、密码、cookie、API key、credentialRef 对应的明文；
- 真实个人信息或客户数据；
- 尚未修复的外部目标信息。

请使用 GitHub 的
[Private vulnerability reporting](https://github.com/TRUTHWARD/TRUTHWARD/security/advisories/new)
向维护者提交私密报告。该渠道用于在公开披露前讨论、复现和修复漏洞。

如果私密入口不可用，可以提交一条**不包含漏洞细节或敏感信息**的普通 Issue，
只说明“私密安全报告入口不可用”，等待维护者恢复私密渠道。当前没有经过确认的
公共安全邮箱，不会从 Git 提交身份推断或公布个人邮箱。

## 报告内容

请提供：

```text
受影响 commit / 版本
影响面与风险等级建议
最小复现步骤
期望与实际安全边界
是否涉及跨 workspace / project / environment
是否涉及 Guardrail / Approval / Trace / Replay / NORMALIZE / Gate
secret-safe 日志、hash 或 artifact ref
建议的临时缓解措施
```

使用合成数据与 canary secret。不要上传真实 token、PII、客户文档、数据库
dump 或可攻击第三方的自动化脚本。

## 响应流程

维护者收到私密报告后将尽力：

1. 确认接收并分配受限跟踪引用；
2. 复现并确定影响范围；
3. 对高风险修复使用现有 approval-backed review flow；
4. 增加回归测试、secret scan 与必要的审计证据；
5. 在修复可发布后协调披露时间；
6. 不通过 Skill、Tool 或 Connector 绕过 Service-owned 决策边界。

当前没有首次响应或修复时限承诺。修复准备完成前，请报告者与维护者协调披露，
不要提前公开可利用细节。

## 安全测试

贡献者可以运行：

```powershell
.\scripts\run-backend-quality.ps1
Push-Location frontend
npm audit --audit-level=low
Pop-Location
```

完整 dependency audit、Gitleaks 与 release 阻断由：

```powershell
.\scripts\run-release-acceptance.ps1 `
  -PostgresAdminDatabaseUrl "postgresql://USER:PASSWORD@localhost:5432/postgres" `
  -RedisUrl "redis://localhost:6379/0"
```

外部实际扫描只能针对明确授权的受控目标。不得扫描第三方系统，也不得把
safe fixture、模拟结果或 missing-dependency skip 描述为真实外部安全验证。
