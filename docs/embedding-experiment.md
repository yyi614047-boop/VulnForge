# Experimental retrieval benchmark (not part of the main runtime)

This document describes an isolated experiment for comparing BM25 and embedding-based retrieval. The production CLI and card-based Pipeline do not build or query these indexes. The experiment is optional and must be invoked through its dedicated script/module.

# 本地 embedding 仿真实验

本轮实验验证文档分块、真实模型向量生成、SQLite 入库、查询向量化、BM25 与向量检索融合及评测。默认使用 `BAAI/bge-small-zh-v1.5`，CPU 运行，不需要 API Key、GPU、Docker 或生成模型。尚未接入 reranker。本实验不执行漏洞复现容器，也不评测生成回答。

## 首次安装和运行

在项目根目录的 PowerShell 终端执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_embedding_experiment.ps1 -Setup
```

脚本安装 `sentence-transformers` 及其 PyTorch、Transformers 等依赖，下载模型到 `.cache/embedding-models`，验证模型可以生成向量，然后运行实验。首次需要访问所配置的 Python 包源和 Hugging Face。下载量以实际依赖解析和模型文件为准；无需下载生成式大语言模型。

如果终端继承了 `PIP_NO_INDEX=1`，pip 不会访问包索引。请在允许联网安装的终端运行，或按环境规定准备离线 wheel 包。脚本不会修改代理、包源或系统网络设置。离线模型目录可通过 `-Model 'F:\models\bge-small-zh-v1.5'` 指定；目录应含完整的 Sentence Transformers 模型和 tokenizer 文件。

## 后续重复实验

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_embedding_experiment.ps1
```

后续运行使用 `local_files_only=True`，不再自动下载。脚本在运行期间设置本地模型配置，结束后恢复原有环境变量。该实验不再通过主 CLI 的 `--dense` 参数启动，项目不会自动读取 `.env`。

每轮使用独立的 `.labs/embedding-experiments/<run-id>/` 目录，包含 BM25 和混合检索两个 SQLite 索引及评测查询副本。文档中的长代码块可能超过模型输入上限，适配器按 token 窗口编码并平均归一化，避免直接截掉尾部。BGE 查询加中文检索指令，文档不加。

## 结果

JSON 报告写入 `reports/embedding/<run-id>.json`，记录模型、包版本、建库情况、缓存检查、耗时、逐条查询结果，以及 BM25/混合检索的 Recall@5、MRR、拒答准确率和差值。

默认数据是 `knowledge` 和 `examples/retrieval_cases.json`，只有四个合成查询，用来验证流程。资料主要是英文，中文小模型不一定优于 BM25。相似度阈值沿用现有的 0.25，尚未针对该模型校准；无答案查询可能被错误召回。报告如实记录结果，不把分数提升作为流程成功的必要条件。

自定义数据示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_embedding_experiment.ps1 -Knowledge knowledge -Cases examples/retrieval_cases.json
```

`Cases` 是 JSON 数组，每条包含 `query` 和 `expected_sources`（相对于知识库的文件路径列表，无答案问题为 `[]`）。扩大语料和标注后再评价真实检索效果。
