# Real browser example / 真实浏览器示例

[English](#english) | [简体中文](#简体中文)

## English

Run this example on the **same Linux machine as the Community API**, after completing
the [installation](../../README.md#quick-start), administrator setup, and
[Chromium installation](../../docs/COMMUNITY_INSTALLATION.md#真实浏览器执行).
Activate the backend Python environment from the source root.

```bash
python examples/community-browser/run_example.py
```

Enter your existing Community username and password at the prompts. The account needs
permission to create projects, environments, plans, and executions. The script creates
a new example project each time and retains its records. It starts a temporary local
page, creates a real functional test, verifies that the Submit button is visible, and
checks persisted task and artifact records through the API. This fixed assertion does
not require a live model. The workflow may call a configured model through its gateway;
a successful browser result alone does not verify your AI provider.

Use `--api http://127.0.0.1:18091/api/v1` for a different local API port.
Automation may supply an existing token through the `TRUTHWARD_TOKEN` environment
variable; the script does not revoke a supplied token. Interactive login is logged out
after the run. Credentials are never written to the result file.

A successful run exits with code 0 and writes `.tmp/community-browser-result.json`:

- `status` is `passed`, with every `checks` field true.
- The task reports actual execution by Playwright using pinned Chromium.
- Persisted artifacts include a report, screenshot, and trace.
- Project, environment, plan, execution, task, and artifact IDs locate the records in the UI.

Open the workspace, select the new **Browser example** project, and inspect its execution
and task artifacts. A green API health check or a simulated task is insufficient.
If the script fails, use the saved IDs to inspect the existing records before retrying.
The temporary target stops when the script exits; start a fresh example for another run.

### Use the template through the API or UI

Keep a local target running in another terminal:

```bash
python examples/community-browser/target.py --port 8765
```

The complete [plan.json](plan.json) uses the existing `domainConfig.functional` contract.
For an API request, replace `projectId` and `environmentId` with your authorized IDs and
set `environment` to that environment's key. Keep `actualExecution=true` and the supplied
structured visibility assertion. POST the plan to `/api/v1/test-plans`, then create an
execution using the returned `planId` with only functional execution enabled.
Stop the target with Ctrl+C after the execution finishes.

In the UI, open **Workflow → Test plan management**, select your project and environment,
choose **Element is visible**, enter `http://127.0.0.1:8765`, role `button`, and name
`Submit`. Select low risk for this local visibility check and save the plan. In
**Execution control**, select that plan and start its functional execution. Open
**View execution details and artifacts** to inspect the result. The **Element text matches**
template can additionally check that the button text equals `Submit`.

## 简体中文

完成[基础安装](../../README.md#快速开始)、首次管理员创建和
[Chromium 安装](../../docs/COMMUNITY_INSTALLATION.md#真实浏览器执行)后，在 **Community API
所在的同一台 Linux 机器**上运行。先进入源码根目录并激活后端 Python 虚拟环境：

```bash
python examples/community-browser/run_example.py
```

按提示输入已有 Community 用户名和密码。账号需要创建项目、环境、计划和执行的权限。
脚本每次创建一个新的示例项目并保留记录，启动临时本地页面，创建真实功能测试，
检查 Submit 按钮可见，并通过 API 核对持久化任务和产物。本固定断言不要求真实模型。
工作流仍可能通过网关调用已配置的模型；浏览器运行成功本身不代表 AI Provider 已验收。

API 使用其他本机端口时添加 `--api http://127.0.0.1:18091/api/v1`。
自动化可通过环境变量 `TRUTHWARD_TOKEN` 提供已有 Token；脚本不会撤销传入的 Token。
交互登录创建的会话会在结束时登出，凭据不会写入结果文件。

成功时退出码为 0，并生成 `.tmp/community-browser-result.json`：

- `status=passed`，所有 `checks` 均为 true。
- 任务明确记录由 Playwright 使用锁定 Chromium 真实执行。
- 持久化产物包含 report、screenshot 和 trace。
- 返回项目、环境、计划、执行、任务与产物 ID，便于在界面中定位。

打开工作台，选择新建的 **Browser example** 项目，查看执行详情与任务产物。
健康检查成功或模拟任务成功都不能替代这些证据。失败时先用保存的 ID 检查既有记录，
再决定是否重试。脚本结束会关闭临时目标；重新运行测试时创建新的示例。

### 通过 API 或 UI 使用模板

在另一个终端保持演示目标运行：

```bash
python examples/community-browser/target.py --port 8765
```

完整的 [plan.json](plan.json) 使用现有 `domainConfig.functional` 契约。
使用 API 时，将 `projectId`、`environmentId` 替换为有权访问的实际 ID，`environment`
填写对应环境的 key。保留 `actualExecution=true` 与结构化可见性断言。
向 `/api/v1/test-plans` 提交计划，再用返回的 `planId` 创建只启用 functional 的执行。
执行完成后按 Ctrl+C 关闭目标页面服务。

使用 UI 时，打开 **工作流 → 测试计划管理**，选择项目与环境，选择“元素可见”，
填写目标 `http://127.0.0.1:8765`、角色 `button`、名称 `Submit`。对此本地可见性检查
选择低风险并保存计划。在“执行控制”中选择该计划，启动功能测试，点击
“查看执行详情与产物”核对结果。“元素文本匹配”模板还可检查按钮文本是否等于 `Submit`。
