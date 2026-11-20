# Agent 上下文隔离实现报告

日期：2026-10-24

## 实现结果

在现有 Shared State 上增加了应用层上下文边界。节点只收到声明允许读取的字段，只有声明允许写入的字段才能作为更新返回；模型调用记录按运行和 Agent 分开管理。共享计划、研究结果、执行证据仍通过显式交接传递。

核心实现位于 `app/agent_context.py`：

- `state_boundary(reads=..., writes=...)`：调用节点前裁剪输入并深拷贝，返回后校验写入字段并深拷贝。节点修改嵌套对象不会反向修改共享状态，节点保留的返回对象也不会与合并后的状态共享引用。
- `isolated_run`：通过 ContextVar 创建独立运行标识和私有上下文容器，正常返回或异常退出时恢复调用前的上下文。
- `agent_session`：独立调用组件时创建运行作用域；在已有工作流内调用时沿用当前作用域。
- `invoke_agent`：按 `run_id + agent_id` 保存最近 16 次成功模型调用的输入和输出。历史不会自动拼接到其他 Agent 的 prompt，也不会自动写入 Shared State。
- `current_agent_context()`：仅在模型调用期间提供当前 Agent 的上下文深拷贝，没有通过公共 API 查询其他 Agent 上下文的入口。

## 接入范围

主流程 `app/lab/pipeline.py` 的研究、规划、部署、复现、验证和清理节点全部接入字段边界，顺序执行和 LangGraph 使用同一组包装后的节点。

| 主流程节点 | 可读取的共享字段 | 可写入的共享字段 |
| --- | --- | --- |
| researcher | identifier | bundle、status、error |
| planner | status、bundle | plan、status、error |
| deployer | status、plan、bundle | status、engine、error |
| reproducer | 无 | status |
| verifier | 无 | status |
| cleanup | identifier、status、error、engine、bundle、plan | report、status |

复现和验证节点仍由受信任的执行器提供执行状态和证据；这里的“无”表示不读取图的共享输入字段，不表示执行器没有内部状态。

以下模型组件已使用私有调用上下文：Researcher、StructuredPlanner、Case Assistant、脚本生成、环境生成、恢复决策和 Web Research。现有 prompt 和结果校验保持原有业务含义。

`Pipeline.run()` 增加实例运行锁：同一实例同时运行会立即报错，要求使用独立实例。每次运行重置临时运行状态，结束后释放执行器引用和锁，异常路径也执行释放。

## 验证

新增 `tests/test_agent_context.py`，包含 9 项测试（含参数化）：

1. 节点不能读取未授权字段，嵌套输入和输出不共享可变引用。
2. 未声明的共享状态写入被拒绝。
3. 同运行内不同 Agent 历史隔离，跨运行历史重新初始化，上下文快照不能修改原记录。
4. 并行独立调用的运行标识隔离，异常后恢复上下文。
5. 主流程 Planner 不接收无关报告字段，不能通过修改 bundle 影响原始状态。
6. Planner 修复重试保留本 Agent 历史，下次独立调用不继承历史。
7. 同一 Pipeline 实例拒绝重叠运行，失败后仍可再次运行。
8. 顺序执行模式下研究和规划共用运行标识、历史隔离，连续两次任务使用不同标识。
9. LangGraph 模式下验证同样的行为。

测试命令：`.\.venv\Scripts\python.exe -m pytest -q`。

最终完整测试结果：**173 passed in 28.87s**，无失败、无跳过。新增隔离测试单独运行结果为 **9 passed**。

端到端测试使用固定模型响应和模拟 Docker 执行器，覆盖实际图编排、报告生成及清理逻辑；未调用真实模型或启动真实 Docker 实验。

## 边界和后续扩展

- 这是应用层的数据传递与模型上下文隔离，不是进程级安全沙箱。可信 Python 组件仍能访问自身对象或模块内部；外部注入的模型客户端若自行保存对话记忆，本层不会清除其内部记忆。
- 白名单按共享状态顶层字段定义；允许的 `bundle` 等结构内部仍按现有业务契约完整交接，不提供逐字段保密分级。
- 既有作者/研究报告可能按原设计保存 prompt、工具记录和反馈。私有内存隔离不等于磁盘报告的访问权限隔离。
- 私有记录只在内存中保留，没有新增持久化恢复、自动摘要或 token 预算管理；16 次记录上限不是字节上限。异常调用不追加成功记录。
- 同一运行内的相同 `agent_id` 表示同一个逻辑 Agent；本实现不提供同一 Agent 的并行分支历史合并。
- 使用 `Pipeline.run()` 才具备完整的运行作用域和实例并发保护。直接调用底层 `graph().invoke()` 仍有节点字段边界，但不具备该入口的整次运行管理。
- 主 CLI 和高级扩展统一使用 `app/lab/pipeline.py`；旧版 `LabWorkflow` 已移除。

为新节点接入时必须声明 `state_boundary` 的读写字段；为新模型 Agent 接入时应使用 `agent_session` 和唯一的逻辑 Agent 标识调用 `invoke_agent`。
