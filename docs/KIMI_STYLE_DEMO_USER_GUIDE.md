# Kimi-Style Demo 使用说明书（用户版 + 开发版）

## 1. 文档目的

本文档用于说明当前 Demo 的真实能力、使用步骤、已实现与未实现项，以及 API 失败时的表现。

## 2. 快速开始

1. 启动服务

```bash
python main.py --port 8001
```

2. 打开页面

- 首页即 Studio：`http://localhost:8001/`
- 也可直接访问：`http://localhost:8001/studio`

3. 运行流程

- 把左侧模块拖拽到中间画布
- 或点击“装载默认流程”
- 点击“运行”

## 3. 你会看到什么（Kimi 风格）

1. 顶部进度：`当前进度 x/y`
2. 右侧思考大纲：每一步的状态（等待/执行中/完成/失败）
3. 实时时间线：
- step_started
- step_progress（思考输出）
- tool_finished（工具调用）
- step_finished
- run_finished / run_failed

## 4. 关键行为说明（诚实声明）

### 已实现

1. 只执行你放到画布里的步骤（不再固定全量跑 4 步）
2. 执行顺序会按层级自动重排：先分析层（语义意图分析 / 多维关联检测），再决策层（风险研判 / 响应处置）
3. 实时显示 AI 思考过程和工具调用
4. 严格 LLM 模式：当检测到 LLM 失败时，流程会显式失败并中止
5. 右侧展示数据库最近报告（来自 `/api/reports`）
6. 支持执行模式切换：`serial`（串行）与 `cluster`（并行集群）
7. LLM 日志语义已修正：
  - 先显示“输出接收完成，正在解析结构化结果”
  - 仅在 JSON 解析成功后显示“结构化解析成功”
8. 依赖自动补齐：如果选择了 `response` 但未选择 `risk`，系统会自动插入 `risk` 再执行 `response`
9. 知识库检索（RAG-MVP）：检测阶段会命中本地知识条目并展示证据
10. 风险双轨评分：展示 `rule_score` 与 `llm_score` 及分差预警
11. 环境健康面板：展示 build/signature/model/probe 延迟
12. 运行回放：支持慢速/快速回放上次执行事件

### 未实现

1. 条件分支连线（if/else）
2. 节点参数面板（每节点独立配置）
3. 中途暂停/恢复
4. 多用户协作编辑

## 5. API 失败时会怎样

当前 Studio 使用 `strict_llm=true`：

- 如果出现 API Key 无效、鉴权失败、流式失败回退等信号
- 后端会发出 `llm_failed` 和 `run_failed`
- 前端会明确显示失败状态，不会悄悄继续当作“成功分析”

## 6. 对外接口（供二次开发）

### 流式运行接口

- `POST /api/v2/runs/stream`

请求体示例：

```json
{
  "subject": "紧急验证",
  "sender": "security@example.com",
  "body": "请点击链接验证账户",
  "selected_steps": ["semantic", "risk"],
  "strict_llm": true,
  "execution_mode": "cluster"
}
```

执行模式说明：

- `serial`：按步骤顺序串行执行
- `cluster`：语义分析与多维检测并行执行，然后进入风险融合阶段

### 知识库检索接口（MVP）

- `GET /api/kb/entries?limit=50`：查看知识库条目
- `GET /api/kb/search?q=关键词&limit=5`：关键词检索知识库

### 事件示例

- `run_started`
- `step_started`
- `step_progress`
- `tool_finished`
- `step_finished`
- `llm_failed`
- `run_finished`
- `run_failed`

## 7. 演示建议

1. 先跑默认四步流程，确认全链路可见
2. 再只放两个模块（如 semantic + risk），验证“只跑所选步骤”
3. 如出现 `llm_failed`，请检查 `.env` 中 API 配置

## 8. 故障排查

1. 页面打不开：确认服务是否运行在 8001
2. 一直失败：检查 API Key、base_url、model 是否有效
3. 数据库列表空：先至少运行一次分析

## 9. 面向后续用户的说明

这是一个“过程可视化优先”的 Demo，不是完整生产版。若用于生产，请补齐：

1. 异步任务队列与重试
2. 运行审计与权限控制
3. 更完整的回归测试与基准评测
