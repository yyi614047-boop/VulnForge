# 本地构建、文件工具与容器脚本执行

> 高级功能仍可通过 Python API 使用；精简后的 CLI 不再提供这些命令。

这批工具已接入主 LangGraph 流程，主入口仍为 `python -m app.lab.cli`。
Planner 按知识卡生成带引用、参数引用和输入哈希的计划，Executor 消费对应步骤。
支持执行已有脚本，也支持通过 `author` 生成复现脚本、执行并根据独立验证结果有限修复。

## 模型生成与修复脚本

```powershell
# 先在进程环境配置 OPENAI_API_KEY、PLANNER_MODEL；兼容服务可另设 OPENAI_BASE_URL。
```

知识卡仍需声明脚本 ID、source、service、环境变量及独立验证断言；source 可以尚不存在。
模型只生成 `scripts` 中的 Python 内容，不改变初始化脚本、Docker 环境、目标或成功判据。
首次生成之后默认最多修复两次。语法或脚本 ID 校验失败会反馈给模型，尚未执行容器。
执行失败或独立证据不匹配时，将失败步骤、日志和断言结果反馈给模型；模型服务故障和
环境部署错误直接停止，不伪装成可修复的脚本错误。

每次执行使用独立知识快照和新 Docker 项目；先清理上一轮，清理失败不继续。
重新执行初始化，再运行新脚本，避免沿用上一次遗留状态。原知识库保持不变。
脚本输出“成功”或退出码为零均不足以通过，必须由既有独立 Verifier 确认。
报告保存候选代码、生成理由、内容哈希、每轮执行报告路径和最终接受的知识快照。
提示词也保存在本次 workspace 中。`--keep` 不适用于 author。

没有模型凭据时可检查真实 Docker 修复链路：

```powershell
.\.venv\Scripts\python.exe -m examples.authoring_smoke
```

此示例明确使用固定模型响应：第一轮只打印文本，第二轮调用目标接口。
它验证执行与修复编排，不代表真实模型生成效果。真实模型调用会发送知识卡、引用资料
和失败诊断到配置的模型服务。生成代码的运行边界仍是现有 Docker 实验环境，未增加网络隔离。

## 工具与接口

主 CLI 的 `run` 现在会在计划校验通过后、部署前自动调用 `ensure_docker_engine`。
引擎已运行时直接继续；未运行时，Windows 尝试启动 Docker Desktop，macOS 使用
`open -g -a Docker`，Linux 使用 `systemctl --no-ask-password start docker`。
工具持续检查真实服务端版本，启动进程本身不算就绪。默认等待预算为 120 秒，
可用 `--engine-timeout 180` 调整（1–300 秒）。不切换 Docker context，不提权，
远程 endpoint 不触发本机启动。权限不足或启动超时时返回结构化诊断，停止部署。

```powershell
# 独立调用启动工具
.\.venv\Scripts\python.exe -m app.lab.cli engine
# 只检查，不启动
.\.venv\Scripts\python.exe -m app.lab.cli engine --check-only
```

工具注册接口为 `DockerEngine().registry()`，参数为 `start` 和 `timeout`。
输出含 `ready`、`status`、`start_attempted` 以及错误诊断；调用方必须检查 `ready`。
主 CLI 自动启用；直接使用 `Pipeline` 的调用方需传入 `docker_engine=DockerEngine()`。
运行报告将启动结果保存在 `engine` 字段。系统权限仍由运行 Agent 的用户决定。

| 工具 | 接口 | 功能 |
| --- | --- | --- |
| inspect_workspace / read_document | WorkspaceFiles.registry() | 项目内文件列表、按行读取、内容哈希 |
| write_artifact | 可写 WorkspaceFiles.registry() | 保存文本、Python 语法检查、覆盖前哈希检查、旧版本留存 |
| validate_environment | DockerLab.registry() | 校验 Compose、构建和挂载输入，返回文件清单 |
| build_image | DockerLab.registry() | 构建 Compose 中声明了 build 的服务 |
| run_in_container | DockerLab.registry() | 挂载已保存的 Python 脚本，在临时容器执行，返回退出码、stdout、stderr、超时和清理结果 |
| collect_file_evidence | DockerLab.registry() | 在目标服务里独立读取普通文件，返回内容、路径、服务和哈希 |

DockerLab 的脚本工具从当前项目的 `artifacts/` 读取脚本，不能通过该接口指定任意宿主机路径。
文件工具的根目录由调用方固定。覆盖产物需要提供当前 `expected_hash`；旧内容存入 `.versions/`。


最后一条把候选脚本写入默认 `.labs/artifacts/`，不会自动将其加入知识库或执行。
如需读取这个候选文件，使用 `read candidate.py --knowledge .labs/artifacts`。

## 环境支持

新增 Compose `build` 支持：本地 `context`、`dockerfile`、`args`、`target`。不支持远程构建上下文、宿主机网络、特权配置等额外字段。
构建上下文必须在环境文档所在目录内，Dockerfile 必须在对应 context 内。
新增 `volumes` 支持：长格式的只读 bind mount，source 必须位于环境目录内。暂不支持宿主机可写挂载和 named volume。

```yaml
services:
  web:
    build:
      context: ./server
      dockerfile: Dockerfile
    volumes:
      - type: bind
        source: ./settings.txt
        target: /etc/lab-settings.txt
        read_only: true
```

输入文件有数量/大小上限（1000 个文件、合计 32 MiB），并被复制到 `.labs/<项目名>/inputs/`。
构建与运行使用这个快照，通过 Compose `--project-directory` 解析相对路径。
`.dockerignore` 会随 context 复制，但当前文件清单会保守地包含 context 内所有文件；不要把虚拟环境、大缓存和凭据放进构建目录。
外部镜像标签或构建期间联网下载的内容不会由本地哈希固定，严格复现仍应使用 digest 和固定依赖版本。

## 知识卡新增字段

- `initialization`：启动服务后、HTTP 就绪断言前执行的初始化 Python 脚本。
- `scripts`：健康检查之后执行的复现脚本。
- `verification_requests`：脚本执行后独立发送的 GET 请求及断言。
- `file_evidence`：目标容器服务、绝对文件路径和期望内容。

脚本指定 `id`、知识库内相对 `source`、Compose `service`、可选 `args` 和 `environment`。
脚本环境需要 Python，相关依赖由 runner 镜像或其 Dockerfile 安装。
每个脚本用 `docker compose run --rm --no-deps` 启动临时容器，脚本只读挂载，entrypoint 固定为 Python。
它通过 Compose 网络访问目标服务；例如 runner 内访问 `http://web:8000`，不能用宿主机的 `127.0.0.1:28082`。
它不是在目标服务容器内原地修改文件；如需改变目标状态，应调用目标接口，再由独立工具检查。

当前初始化、构建和脚本步骤均不自动重试。脚本超时会尝试强制删除临时容器，删除失败会保留诊断并在最终清理再试。
脚本退出码 0 只说明执行结束；知识卡必须为脚本提供独立 HTTP 或目标文件断言。
目标文件读取工具目前也要求目标镜像有 Python，只读取普通文件且最多保留 64 KiB；不能读取设备、FIFO，内容截断时不会把缺失标记直接当作确定失败。
stdout/stderr 在报告中最多各保留 64 KiB，但 subprocess 内部仍会先捕获输出；这不是无界输出任务的资源限制方案。

## 完整演示

示例位于 `examples/script_lab/knowledge/`。它是合成状态变化测试，不是真实 CVE：

1. 构建 Python HTTP 服务镜像，挂载只读配置。
2. runner 脚本调用初始化接口和触发接口。
3. Verifier 独立请求 `/proof` 并读取目标 `/tmp/lab-proof.txt`。
4. 保存报告，删除本次容器和网络；保留本地镜像和产物。

```powershell
.\.venv\Scripts\python.exe -m app.lab.cli plan DEMO-SCRIPT-LAB --knowledge examples/script_lab/knowledge --workspace .labs/script-example
.\.venv\Scripts\python.exe -m app.lab.cli run DEMO-SCRIPT-LAB --knowledge examples/script_lab/knowledge --workspace .labs/script-example --timeout 300 --report reports/script-run-001.json
```

需要 Docker Engine 运行且能够拉取基础镜像。已存在的报告不会被覆盖，下次运行换一个报告名。
手动清理示例：

```powershell
docker compose --project-name <项目名> --project-directory .labs/script-example/<项目名>/inputs --file .labs/script-example/<项目名>/compose.json down
```

这套功能仍是受限本地实验工具，不提供任意宿主机终端、任意目标扫描或通用环境自修复。
