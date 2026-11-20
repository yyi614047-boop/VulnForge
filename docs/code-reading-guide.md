# 代码阅读指南

本文按一次实验从输入到输出的顺序介绍项目。主入口是 `app/lab/cli.py`，
默认完整运行逻辑在 `app/lab/vulhub_run.py`。

## 1. 了解项目和实验输入

先阅读 [README](../README.md)，再看 `knowledge/vulhub/` 中一个环境目录：
`docker-compose.yml` 描述服务，Markdown 记录原始部署和复现资料；
独立的 YAML evaluation card 用于评估实验结果。

## 2. 从命令行入口开始

阅读 [app/lab/cli.py](../app/lab/cli.py)，跟踪 `search`、`research`、
`plan` 和 `run` 分支。主流程不需要构建索引，也不依赖 Embedding。

## 3. 理解主运行逻辑

阅读 [app/lab/vulhub_run.py](../app/lab/vulhub_run.py)：

- `plan()`：读取本地 Compose/Markdown，生成有来源引用的操作计划。
- `prepare()`：复制环境快照，校验 Compose，映射本地回环端口。
- `agent_loop()`：模型根据观察选择下一步有限工具动作。
- `check()`：独立评估器根据 evaluation card 检查复现证据。
- `_run()`：串联部署、执行、评估、日志收集和清理。

## 4. 看信任边界和计划约束

阅读 `app/lab/knowledge.py`、`app/lab/documented_card.py`、
`app/lab/document_evidence.py`，理解可信卡片与原始文档证据的区别。
模型输出由 Pydantic schema 和业务校验约束，原始文档不能直接变成可信执行配置。

## 5. 跟踪工具和审计证据

阅读 `app/tools/vulhub_sources.py`、`app/tools/docker_lab.py`、
`app/tools/files.py`、`app/tools/registry.py` 和 `app/trace.py`。
再看生成的 JSON 报告及其 trace，核对每个动作、证据和清理结果。

## 6. 阅读卡片式 Pipeline

`app/lab/pipeline.py` 是另一个显式分阶段的执行 API，配合
`app/lab/planning.py` 和 `app/lab/step_executor.py` 阅读。
它与 CLI 的 source-driven loop 不同，但同样使用结构化状态和有界工具执行。

## 7. 检索实验与扩展模块

`app/rag/` 是独立实验代码，不属于主 CLI 的运行依赖。只有研究 BM25、
Embedding、混合检索或案例检索时才需要阅读它。扩展能力可按需阅读
`authoring.py`、`environment_authoring.py`、`recovery.py`、
`comparison.py` 和 `batch.py`。

运行测试：

```powershell
python -m pytest -q
```

测试通过只说明现有测试覆盖的行为符合预期，不等于真实模型效果或真实 CVE
环境均已验证。
