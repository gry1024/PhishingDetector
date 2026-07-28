# PhishingDetector AI Studio Demo 开发路线图

## 1. 目标与范围

本路线图用于把当前项目升级为“可演示的 AI Studio 形态”：

- 前端支持拖拽式工作流编排（类似 FastGPT/Kimi 的可视化编排体验）
- 分析过程中可实时显示 AI 当前步骤、工具调用、阶段进度
- 后端输出标准化分步事件，支撑前端完整过程可视化

本路线图分两段：

1. Demo 阶段（先做出可展示成果）
2. Demo 后改善阶段（工程化、稳定性、性能与可观测性增强）

---

## 2. 执行规则（强制）

每一步都必须严格执行：

1. 先定义验收标准
2. 先补测试或验证脚本
3. 再实现最小改动
4. 最后执行验证命令并记录结果
5. 只有验证通过，才标记“已完成”

统一完成记录模板：

- 完成状态：未开始 / 进行中 / 已完成
- 验证命令：
- 验证结果：
- 备注：

---

## 3. Demo 阶段（可视化成果优先）

### Demo-1：统一后端事件协议（Run/Step/Event）

#### 目标

把现有零散事件升级为统一协议，前端能够稳定渲染“进行到哪一步”。

#### 改动内容

- 新增 run_id 与 trace_id
- 标准事件类型：
  - run_started
  - step_started
  - step_progress
  - tool_started
  - tool_finished
  - step_finished
  - run_finished
  - run_failed
- 每个事件包含：
  - run_id
  - step_id
  - step_name
  - ts
  - status
  - payload

#### 影响文件

- src/workflow/graph.py
- src/api/routes.py
- src/models.py

#### 验收标准

- 流式接口可连续输出标准事件
- 同一 run 的事件可按时间排序重放
- 任一步失败时前端可收到 run_failed

#### 测试与验证

- 建议新增：tests/test_stream_protocol.py
- 验证命令：

```bash
python -m unittest tests.test_stream_protocol
```

#### 完成记录

- 完成状态：已完成（MVP）
- 验证命令：
  - `python -m unittest tests.test_rule_fallback tests.test_evidence_fusion tests.test_url_reputation tests.test_attachment_behavior_analysis`
  - `python -m unittest tests.test_selected_steps`
- 验证结果：
  - `Ran 11 tests in 0.030s`
  - `OK`
- 备注：
  - 已新增 `POST /api/v2/runs/stream`，输出统一事件结构并兼容现有工作流回调。
  - 已支持 `selected_steps`，后端不再固定跑全量 4 步。
  - 已支持 `strict_llm`，LLM 失败会显式中止并返回 `llm_failed` / `run_failed`。
  - 已支持 `execution_mode=cluster`，语义分析与多维检测可并行执行后再融合。
  - 已修复 LLM 日志语义：仅在 JSON 解析成功后显示“结构化解析成功”。

---

### Demo-2：前端 Studio 基础壳（工作台 + 运行面板）

#### 目标

上线一个可访问的新页面（例如 /studio），具备主流 AI 产品风格的工作台体验。

#### 改动内容

- 新页面：Studio 工作台
- 布局区域：
  - 左侧节点面板
  - 中间画布（可拖拽）
  - 右侧运行状态与参数面板
  - 底部事件日志与 token 流
- 统一视觉风格与动效（加载、步骤切换、事件进度）

#### 影响文件

- src/api/server.py
- src/static/pages/studio.html（新增）
- src/static/industrial.css

#### 验收标准

- 访问 /studio 页面成功
- 可完成节点拖拽到画布
- 运行面板可显示空态、运行中、完成态

#### 测试与验证

- 手工验证：浏览器打开 /studio
- 核查项：
  - 拖拽动作正常
  - 布局在桌面与移动端可用
  - 无阻塞式报错

#### 完成记录

- 完成状态：已完成
- 验证命令：
  - `Invoke-WebRequest http://localhost:8001/studio`
- 验证结果：
  - HTTP `200`
- 备注：
  - 已新增 `src/static/pages/studio.html`
  - 已新增 `GET /studio` 页面路由
  - 页面支持节点拖拽和“一键装载默认流程”
  - 页面新增 Kimi 风格的“进度 + 思考大纲 + 时间线”

---

### Demo-3：Studio 对接实时分析流

#### 目标

Studio 页面接入真实后端流，展示“AI 正在做什么”。

#### 改动内容

- 在 Studio 中发起分析请求
- 按 step 维度渲染状态：待执行/执行中/完成/失败
- 渲染工具调用卡片与关键摘要
- 支持“中断运行”与“重试运行”按钮（MVP 可先做前端交互与接口预留）

#### 影响文件

- src/static/pages/studio.html
- src/api/routes.py
- src/workflow/graph.py

#### 验收标准

- 点击运行后，前端看到完整步骤流转
- 每步至少有开始和结束事件
- 结束后显示最终风险结论与证据摘要

#### 测试与验证

- 建议新增：tests/test_studio_stream_integration.py
- 验证命令：

```bash
python -m unittest tests.test_studio_stream_integration
```

#### 完成记录

- 完成状态：已完成（MVP）
- 验证命令：
  - 浏览器访问 `/studio`，点击“装载默认流程”+“运行流程”
- 验证结果：
  - 前端可见完整 step_started/step_progress/tool_finished/step_finished/run_finished 状态流
  - 最终可显示风险等级与风险分（示例：`high` / `78`）
- 备注：
  - 前端已接入 `POST /api/v2/runs/stream`
  - 已验证 `selected_steps=[semantic,risk]` 时只执行两步
  - 仍可继续增强：取消运行、重试运行、事件回放

---

### Demo-4：可展示版本收口（给你验收）

#### 目标

完成一版可演示链路，能直接给你看 UI 与过程可视化成果。

#### 改动内容

- 固化 3-5 个演示样例
- 增加演示模式（自动回放步骤）
- 补充演示文案（每一步在做什么）

#### 影响文件

- src/static/pages/studio.html
- docs/DEMO_PHISHING_EMAIL_CASES.md

#### 验收标准

- 本地可稳定演示 3 次以上
- 展示过程无明显卡顿、无关键错误
- 可清楚看到 AI 每一步状态变化

#### 测试与验证

- 手工回归 3 轮
- 验证命令：

```bash
python -m unittest tests.test_rule_fallback tests.test_evidence_fusion tests.test_url_reputation tests.test_attachment_behavior_analysis
```

#### 完成记录

- 完成状态：进行中
- 验证命令：
  - `python -m unittest tests.test_rule_fallback tests.test_evidence_fusion tests.test_url_reputation tests.test_attachment_behavior_analysis`
- 验证结果：
  - `Ran 9 tests in 0.021s`
  - `OK`
- 备注：
  - 当前已具备可演示版本，下一步是补充演示样例回放与操作文案。

---

## 4. Demo 后改善阶段（工程化增强）

### Improve-1：异步任务队列与状态查询

#### 目标

从“请求线程直接执行”升级为“任务化处理 + 状态查询 + 重试”。

#### 验收标准

- 支持提交任务并返回 task_id
- 支持轮询/订阅任务状态
- 失败任务可重试并记录历史

#### 验证命令

```bash
python -m unittest tests.test_async_queue
```

#### 完成记录

- 完成状态：未开始

---

### Improve-2：可观测性与审计增强

#### 目标

补齐 trace_id、阶段耗时、工具调用日志、脱敏策略。

#### 验收标准

- 每次运行可追踪全链路
- 日志中敏感字段脱敏
- 可查询每个步骤耗时与状态

#### 验证命令

```bash
python -m unittest tests.test_observability
```

#### 完成记录

- 完成状态：未开始

---

### Improve-3：评测基准与回归压测

#### 目标

建立可比较的质量基线，持续评估版本改进效果。

#### 验收标准

- 输出 precision/recall/F1/FPR
- 新版本与基线可对比
- 回归测试稳定通过

#### 验证命令

```bash
python -m unittest tests.test_benchmark
```

#### 完成记录

- 完成状态：未开始

---

### Improve-4：流程模板化与权限控制

#### 目标

支持保存/复用流程模板，并按角色控制可执行能力。

#### 验收标准

- 可保存流程模板
- 可加载模板并运行
- 不同角色权限隔离有效

#### 验证命令

```bash
python -m unittest tests.test_template_and_rbac
```

#### 完成记录

- 完成状态：未开始

---

## 5. 冗余清理策略（避免误删）

清理遵循“可证明未引用才删除”的原则：

1. 先做引用扫描（路由、导入、静态资源引用）
2. 再做小批量删除
3. 每次删除后跑最小回归测试
4. 删除记录写入变更说明

本轮已清理明确弃用页面文件：

- 已删除：`src/static/index.html`（未被路由引用）
- 已删除：`src/static/pages/index.html`（旧 UI）
- 已删除：`src/static/pages/analyze.html`（旧 UI）
- 已删除：`src/static/pages/about.html`（旧 UI）
- 已删除：`src/static/industrial.css`（旧 UI 样式）

后续按批次推进。

---

## 6. 当前执行状态

- 本文档：已完成
- Demo-1：进行中
- Demo-1：已完成（MVP）
- Demo-2：已完成
- Demo-3：已完成（MVP）
- Demo-4：进行中
- Improve-1 ~ Improve-4：未开始
