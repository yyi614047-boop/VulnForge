# 代码阅读指南

本文按一次实验从输入到输出的顺序介绍项目，适合第一次阅读代码时使用。主入口是 `app/lab`。

## 1. 了解项目和实验输入

先阅读 [README](../README.md)，了解项目目标、运行条件和 CLI 命令。然后打开 [示例知识卡](../examples/script_lab/knowledge/DEMO-SCRIPT-LAB.yaml)，关注：

- 实验环境如何定义，使用哪些服务、配置和脚本。
- 复现步骤是什么，以什么顺序执行。
- 哪些 HTTP 或文件断言用于判断实验结果。

示例是合成场景，不是真实 CVE。

## 2. 从命令行入口开始

阅读 [app/lab/cli.py](../app/lab/cli.py)，找到 `main()` 中的参数定义和 `plan`、`run` 分支。跟踪命令行参数如何传给后续组件，先不必逐个研究所有子命令。

可以先生成示例计划，边看输出边追踪代码：

```powershell
.\.venv\Scripts\python.exe -m app.lab.cli plan DEMO-SCRIPT-LAB --knowledge examples/script_lab/knowledge
```

这个命令生成计划；完整的 `run` 命令会使用 Docker 创建实验环境。

## 3. 理解主流程

阅读 [app/lab/pipeline.py](../app/lab/pipeline.py)，配合 [架构说明](architecture.md) 了解研究、规划、部署、复现、验证和清理之间的流转。重点检查：

- 各阶段的输入、输出和执行条件。
- 失败后如何记录状态，以及清理如何执行。
- LangGraph 和顺序执行模式如何复用节点。

## 4. 看知识卡和计划

先看 [app/lab/knowledge.py](../app/lab/knowledge.py)，理解知识卡和相关环境文件的加载；再看 [app/lab/planning.py](../app/lab/planning.py)，理解结构化计划和校验规则。

阅读时可以对照示例知识卡，确认计划中的步骤、参数和成功判据来自哪里，以及模型生成计划时受到哪些限制。

## 5. 跟踪执行、验证和清理

阅读 [app/lab/step_executor.py](../app/lab/step_executor.py) 和 [app/tools/docker_lab.py](../app/tools/docker_lab.py)，跟踪计划步骤如何调用工具。重点检查步骤依赖、重试、失败处理、报告写入、独立证据验证和资源清理。

运行实验后，可以打开生成的 JSON 报告，把报告中的步骤和证据与代码、知识卡对应起来。

## 6. 理解检索和上下文隔离

- [app/rag/index.py](../app/rag/index.py)：文档分块、索引和检索。
- [app/rag/researcher.py](../app/rag/researcher.py)：使用检索结果进行研究和引用校验。
- [app/agent_context.py](../app/agent_context.py)：节点的共享状态读写边界，以及模型调用上下文隔离。

上下文隔离的具体范围和限制见 [实现报告](agent-context-isolation.md)；它是应用层隔离，不是进程级安全沙箱。

## 7. 按需阅读扩展功能和测试

主流程看完后，再按需要阅读 `app/lab/authoring.py`、`environment_authoring.py`、`recovery.py`、`comparison.py` 和 `batch.py`，分别了解生成、环境生成、恢复、版本对照和批处理。

结合 [tests](../tests) 中的对应测试理解边界，建议先看 `test_structured_planning.py`、`test_step_executor.py` 和 `test_agent_context.py`。运行完整测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

测试通过说明现有测试覆盖的行为符合预期，不等同于真实漏洞和真实模型效果都已验证。
