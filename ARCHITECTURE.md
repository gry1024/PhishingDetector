# PhishingDetector 架构说明

本文档基于当前仓库源码整理，目标是让外部协作者在最短时间内理解项目结构、调用链路与扩展边界。

约束说明：
- 仅依据仓库真实代码编写。
- 未能在当前代码中直接证实的内容，统一标注为：待确认。

---

## 1. 目录树（排除 __pycache__、.venv、.git）

```text
PhishingDetector/ # 项目根目录（FastAPI + 多 Agent 钓鱼检测）
├─ .vscode/ # VS Code 工程配置
│  └─ tasks.json # 预定义本地运行/重启任务
├─ docs/ # 产品/研发路线与演示文档
│  ├─ AI_STUDIO_DEMO_ROADMAP.md # Studio 演示路线规划
│  ├─ BACKEND_IMPROVEMENT_ROADMAP.md # 后端改造路线
│  ├─ DEMO_PHISHING_EMAIL_CASES.md # 演示用邮件案例
│  ├─ KIMI_STYLE_DEMO_USER_GUIDE.md # 演示使用说明
│  └─ TEAM_SYNC.md # 团队协作同步记录
├─ scripts/ # 辅助脚本（数据、快速测试、API 推送）
│  ├─ download_datasets.py # 下载示例数据集脚本
│  ├─ push_via_api.py # 通过 API 推送测试请求
│  ├─ quick_test.py # 快速验证脚本
│  └─ run_test.py # main.py --test 入口调用脚本
├─ src/ # 主业务代码
│  ├─ __init__.py # 包初始化
│  ├─ config.py # 全局配置与环境变量读取
│  ├─ database.py # SQLite 数据层（建表、读写、KB 检索）
│  ├─ llm.py # LLM 统一客户端（OpenAI 兼容）
│  ├─ models.py # Pydantic 数据模型与工作流状态
│  ├─ tools.py # Agent 工具注册中心与具体工具实现
│  ├─ agents/ # Orchestrator 与子 Agent
│  │  ├─ __init__.py # 导出部分 Agent 类
│  │  ├─ __init__ - 副本.py # 备份文件（未见主流程引用）
│  │  ├─ base.py # Agent 抽象基类与事件/LLM JSON 解析
│  │  ├─ base - 副本.py # 备份文件（未见主流程引用）
│  │  ├─ orchestrator.py # 主编排 Agent（核心调用链）
│  │  ├─ sender_profiler.py # 发件人画像分析 Agent
│  │  ├─ header_forensics.py # 邮件头取证分析 Agent
│  │  ├─ semantic.py # 语义意图分析 Agent
│  │  ├─ threat_intel.py # 威胁情报关联 Agent
│  │  ├─ detector.py # 多维关联检测 Agent
│  │  ├─ risk.py # 风险研判 Agent
│  │  └─ response.py # 响应处置 Agent
│  ├─ api/ # FastAPI 应用与路由
│  │  ├─ __init__.py # 包初始化
│  │  ├─ server.py # FastAPI app、静态页与首页路由
│  │  └─ routes.py # 业务 API（分析、SSE、数据集、KB、健康）
│  ├─ static/ # 静态资源
│  │  └─ pages/ # 前端页面
│  │     ├─ landing.html # 封面页（入口与能力介绍）
│  │     └─ studio.html # Studio 检测页（SSE 实时渲染）
│  └─ workflow/ # 工作流封装层
│     ├─ __init__.py # 包初始化
│     └─ graph.py # run_analysis 入口与 AGENT_PIPELINE 元数据
├─ tests/ # 自动化测试
│  ├─ __init__.py # 测试包初始化
│  ├─ test_attachment_behavior_analysis.py # 附件/行为异常证据测试
│  ├─ test_cluster_execution_mode.py # cluster 模式并行性测试（待确认是否仍适配当前架构）
│  ├─ test_evidence_fusion.py # 证据融合结构与权重测试
│  ├─ test_health_llm.py # LLM 健康检查 API 测试
│  ├─ test_kb_search.py # 知识库检索命中测试
│  ├─ test_rule_fallback.py # LLM 失败兜底与标记测试
│  ├─ test_selected_steps.py # selected_steps 执行控制测试（待确认是否仍适配当前事件类型）
│  └─ test_url_reputation.py # URL 信誉证据测试
├─ .env # 本地运行环境变量（敏感）
├─ .env.example # 环境变量模板
├─ .gitignore # Git 忽略配置
├─ main.py # 启动入口（init_db + uvicorn）
├─ phishing_detector.db # SQLite 数据库文件
├─ README.md # 项目说明
├─ requirements.txt # Python 依赖清单
└─ TECH.md # 技术方案文档
```

---

## 2. 技术栈与依赖

### 2.1 依赖来源
- 已读取 requirements.txt。
- 未发现 pyproject.toml（待确认是否后续会迁移到 pyproject 管理）。

### 2.2 核心依赖及用途
- fastapi: Web API 框架，承载 REST 与 SSE 接口。
- uvicorn[standard]: ASGI 服务器，运行 FastAPI。
- openai: 通过 OpenAI 兼容协议访问 Minimax/Qwen。
- pydantic: 请求体与内部数据模型校验。
- python-dotenv: 从 .env 加载环境变量。
- pandas: 数据处理工具（当前主流程中未见核心调用，可能用于脚本/离线处理，待确认）。
- datasets: 数据集处理（用于示例数据流与脚本侧，主检测链非强依赖）。
- requests: HTTP 请求工具（当前主流程联网检索主要用 urllib，requests 可能用于脚本或预留，待确认）。

### 2.3 后端与前端技术要点
- 后端：FastAPI + 线程内事件队列 + StreamingResponse 实现 SSE。
- 模型层：Pydantic + 自定义轻量结果类（如 SenderProfilerResult）。
- 存储层：sqlite3 原生驱动，非 ORM。
- 前端：单文件 HTML/CSS/JS，fetch 直连接口并手动解析 SSE 数据流。

---

## 3. 请求生命周期（从 studio.html 点击“运行检测”）

本节按真实函数名串联链路。

### 3.1 前端触发
1) 用户在 studio 页点击按钮
- 文件: src/static/pages/studio.html
- 元素: runBtn，onclick="runFlow()"

2) runFlow() 组装请求并发起
- 函数: runFlow
- 请求: POST /api/v2/runs/stream
- payload 字段: subject, sender, body, prompt, selected_steps, strict_llm, execution_mode

3) runFlow() 读取 SSE 流
- 函数内部通过 resp.body.getReader() + TextDecoder
- 解析协议: 按 \n\n 分块，识别 event: 与 data:
- 分发函数: renderEvent(eventType, payload)

### 3.2 FastAPI 路由与编排入口
1) 路由接收
- 文件: src/api/routes.py
- 函数: analyze_stream_v2(req: AnalyzeRequest)

2) 请求持久化
- 调用: db.save_email(email.model_dump())

3) 启动异步线程执行分析
- 内部函数: run_in_thread
- 主调用: run_analysis(email, callback=callback, selected_steps=selected_steps, execution_mode="serial")

4) run_analysis 进入编排器
- 文件: src/workflow/graph.py
- 函数: run_analysis
- 实例化: orchestrator = OrchestratorAgent()
- 核心调用: orchestrator.analyze(...)

### 3.3 Orchestrator 到各子 Agent 的调用顺序

入口函数：
- 文件: src/agents/orchestrator.py
- 函数: OrchestratorAgent.analyze

Phase 1（策略阶段）
- emit_orchestrator_start
- _phase1_orchestrator_think
  - _quick_observe
  - _generate_hypotheses
  - _counterfactual_analysis
  - _meta_cognitive_reflection
  - 若 LLM 可用: chat_json(...)
  - 否则: _fallback_strategy

Phase 2（子 Agent 调用阶段）
- _ensure_dependencies(selected_steps)
- _ensure_threat_intel_for_suspicious(email, agents_to_call)
- _phase2_call_sub_agents(...)
  - 对每个 agent_key:
    - _call_narrative
    - emit_agent_call
    - agent_instance.analyze(...)
    - 更新 WorkflowState
    - _summarize_result
    - emit_agent_result
    - _post_call_narrative

默认子 Agent 顺序（AGENT_PIPELINE）
1. sender_profiler
2. header_forensics
3. semantic
4. threat_intel
5. detector
6. risk
7. response

说明：
- 若用户自选 selected_steps，顺序会经 _ensure_dependencies 重排并补依赖。
- threat_intel 会被强制纳入（若尚未包含）。

Phase 3（报告聚合）
- _phase3_generate_report
  - _build_evidence_items
  - _final_narrative
  - emit_report
  - callback type="orchestrator_done"

### 3.4 SSE 回推与前端渲染
后端发流
- analyze_stream_v2 中 callback 将内部事件映射为统一 v2 事件对象（_v2_event）
- StreamingResponse 逐条输出：
  - event: <event_name>
  - data: <json_payload>

前端消费
- runFlow > renderEvent
  - orchestrator_thinking: appendNarrative
  - agent_call: createAgentCard + setStatus
  - step_progress: appendAgentLLM / addAgentThinking
  - tool_finished: addAgentTool
  - report: renderReportCard + updateOverviewPanel
  - run_finished/run_failed: 状态收敛与 UI 收尾

---

## 4. 数据层（src/database.py）

### 4.1 建表 SQL（原样摘录）

```sql
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT DEFAULT '',
    sender TEXT DEFAULT '',
    recipients TEXT DEFAULT '',
    body TEXT NOT NULL,
    urls TEXT DEFAULT '[]',
    headers TEXT DEFAULT '{}',
    has_attachment INTEGER DEFAULT 0,
    raw_text TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    timestamp TEXT NOT NULL,
    is_phishing INTEGER NOT NULL,
    risk_score REAL DEFAULT 0,
    risk_level TEXT DEFAULT 'unknown',
    semantic_result TEXT DEFAULT '{}',
    detection_result TEXT DEFAULT '{}',
    risk_result TEXT DEFAULT '{}',
    response_result TEXT DEFAULT '{}',
    workflow_log TEXT DEFAULT '[]',
    FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE INDEX IF NOT EXISTS idx_reports_email ON reports(email_id);
CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON reports(timestamp);
CREATE INDEX IF NOT EXISTS idx_reports_is_phishing ON reports(is_phishing);
CREATE INDEX IF NOT EXISTS idx_reports_risk_level ON reports(risk_level);
CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at);

CREATE TABLE IF NOT EXISTS kb_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    keywords TEXT NOT NULL DEFAULT '[]',
    content TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kb_category ON kb_entries(category);
CREATE INDEX IF NOT EXISTS idx_kb_severity ON kb_entries(severity);
CREATE INDEX IF NOT EXISTS idx_kb_enabled ON kb_entries(enabled);
```

### 4.2 公开函数签名与职责
- get_connection() -> sqlite3.Connection
  - 创建 SQLite 连接并设置 PRAGMA（DELETE journal + NORMAL synchronous）。
- init_db()
  - 初始化三张表与索引，并执行 KB 种子填充。
- save_email(email_data: dict) -> int
  - 写入 emails，返回 email_id。
- save_report(email_id: int, report_data: dict) -> int
  - 写入 reports，返回 report_id。
- get_recent_emails(limit: int = 50) -> list[dict]
  - 按 created_at 倒序返回邮件列表。
- get_recent_reports(limit: int = 50) -> list[dict]
  - 关联 emails 返回报告列表（含 subject/sender/body）。
- get_email_by_id(email_id: int) -> Optional[dict]
  - 根据 id 查询单封邮件。
- get_stats() -> dict
  - 返回 total_emails, total_reports, phishing_detected, safe_emails, avg_risk_score。
- list_kb_entries(limit: int = 100) -> list[dict]
  - 返回知识库条目并解析 keywords JSON。
- search_kb(text: str, limit: int = 5) -> list[dict]
  - 关键词轻量匹配检索并返回带分命中列表。

内部函数（非公开）
- _seed_kb_entries(conn)
  - 在 kb_entries 为空时写入默认种子。

### 4.3 知识库字段与种子来源
kb_entries 字段
- id, title, category, severity, keywords, content, recommendation, enabled, created_at, updated_at

种子来源
- 来自 src/database.py 中常量 KB_SEED_ENTRIES（硬编码 4 条）。
- 不是外部同步源，也不是迁移脚本注入。

### 4.4 search_kb 匹配算法（逐步解释）
函数：search_kb(text: str, limit: int = 5)

1) 预处理
- query_text = (text or "").lower().strip()
- 若为空，直接返回 []。

2) 拉取候选
- SQL 读取 enabled = 1 的全部 kb_entries。

3) 准备评分参数
- severity_bonus = {critical:15, high:10, medium:6, low:3}
- tokens = 使用正则按非字母数字中文分割 query_text，再过滤长度 >= 2。

4) 遍历每条 KB
- 解析 keywords JSON 并 lowercase。
- matched = []
  - 对每个 kw，若 kw in query_text，则加入 matched。
- 兜底 token 匹配：
  - title/content 均 lowercase。
  - token_hits = [tok for tok in tokens if tok in title or tok in content]

5) 过滤规则
- 若 matched 和 token_hits 都为空，则该条目跳过。

6) 打分规则
- 基础分：score = min(len(matched) * 18 + len(token_hits) * 6, 80)
- 严重度加成：score += severity_bonus[severity]
- 封顶：score = min(score, 100)

7) 输出结构
- 每条命中输出：id, title, category, severity, score,
  matched_keywords(去重后最多 8 个), content, recommendation。

8) 排序与截断
- 按 score 倒序排序。
- 返回前 limit 条。

结论：
- 算法是词匹配加权，不是向量语义检索。
- 匹配命中来自两路：keywords 直接命中 + title/content token 命中。

---

## 5. API 清单（src/api/routes.py）

统一前缀：/api

### 5.1 分析相关

1) POST /api/analyze/stream
- 参数: AnalyzeRequest(JSON)
- 行为: 旧流式接口，逐行输出 event/data。
- 返回: StreamingResponse(media_type=application/x-ndjson)
- 事件示例:
```json
event: report
data: {"is_phishing": true, "risk_score": 78, "risk_level": "high"}
```

2) POST /api/v2/runs/stream
- 参数: AnalyzeRequest(JSON)
- 行为: 新统一事件协议（SSE）。
- 返回: StreamingResponse(media_type=text/event-stream)
- 事件示例:
```json
event: run_started
data: {
  "event": "run_started",
  "run_id": "uuid",
  "step_id": null,
  "step_name": null,
  "status": "running",
  "ts": "2026-...",
  "payload": {"email_id": 1, "selected_steps": [], "strict_llm": false, "execution_mode": "orchestrator"}
}
```

3) POST /api/analyze
- 参数: AnalyzeRequest(JSON)
- 行为: 同步分析，等待完成后一次返回。
- 返回示例:
```json
{
  "is_phishing": true,
  "risk_score": 72,
  "risk_level": "high",
  "semantic": {},
  "detection": {},
  "risk": {},
  "response": {},
  "email_id": 11,
  "report_id": 7
}
```

### 5.2 历史与统计

4) GET /api/emails
- 参数: limit(int, 默认 50)
- 返回: 最近邮件记录数组。

5) GET /api/reports
- 参数: limit(int, 默认 50)
- 返回: 最近报告数组（含关联邮件主题与发件人）。

6) GET /api/stats
- 参数: 无
- 返回示例:
```json
{
  "total_emails": 120,
  "total_reports": 120,
  "phishing_detected": 45,
  "safe_emails": 75,
  "avg_risk_score": 38.6
}
```

### 5.3 数据集

7) GET /api/datasets
- 参数: 无
- 返回: 数据集元数据列表（id/name/source/format）。

8) GET /api/datasets/{dataset_id}
- 参数: dataset_id(path), q(query), label(query), limit(query, 默认50)
- 返回示例:
```json
{
  "dataset_id": "test_set",
  "total": 200,
  "limit": 50,
  "items": [
    {"id":"...","subject":"...","sender":"...","body":"...","label":"phishing","intent":"","technique":"","target":""}
  ]
}
```

### 5.4 管线与知识库

9) GET /api/pipeline
- 参数: 无
- 返回: AGENT_PIPELINE 列表。

10) GET /api/kb/entries
- 参数: limit(int, 默认50)
- 返回: kb_entries 列表。

11) GET /api/kb/search
- 参数: q(query, 必填语义上), limit(query, 默认5)
- 返回: search_kb 命中数组。

### 5.5 健康检查

12) GET /api/health/llm
- 参数: probe(bool, 默认 true)
- 返回示例:
```json
{
  "status": "ok|degraded|fail",
  "checked_at": "2026-...",
  "service": {
    "name": "PhishingDetector",
    "build": "orchestrator-v1",
    "signature": {"has_studio_page": true, "has_v2_stream": true, "architecture": "orchestrator"}
  },
  "llm": {
    "provider": "minimax",
    "base_url": "...",
    "model": "...",
    "api_key_present": true,
    "api_key_length": 32,
    "api_key_masked": "sk-***",
    "probe": {"attempted": true, "success": true, "latency_ms": 388, "error_type": "", "error_message": "", "sample_response": "OK"}
  }
}
```

---

## 6. SSE 事件协议（后端推送类型与 payload）

事件对象统一字段（v2）
- event, run_id, step_id, step_name, status, ts, payload

### 6.1 v2 主事件类型

1) run_started
- payload: email_id, selected_steps, strict_llm, execution_mode

2) orchestrator_start
- payload: icon

3) orchestrator_thinking
- payload: message

4) agent_call
- payload: agent_key, agent_name, agent_icon, agent_desc

5) agent_result
- payload: agent_key, agent_name, agent_icon, result_summary

6) step_started
- payload: index, icon

7) step_progress
- payload: channel(thinking/llm_chunk/sub_step), message, agent, sub_step_status

8) tool_finished
- payload: tool, input, output, duration_ms

9) data_flow
- payload: from, to, data
- 备注: 代码中有映射分支，但当前子 Agent 是否实际发出 data_flow 待确认。

10) step_finished
- payload: result

11) report
- payload: 最终完整 report 对象

12) orchestrator_done
- payload: is_phishing, risk_level, risk_score

13) run_finished
- payload: email_id, report_id, result

14) llm_failed
- payload: message, strict_llm

15) run_failed
- payload: message

### 6.2 旧流接口事件
- /api/analyze/stream 会直接转发 run_analysis 过程中的 type/data。
- 实际类型集合与 v2 内部源事件一致（orchestrator_start、thinking、tool_call 等）。

---

## 7. Agent 清单（AGENT_PIPELINE）

来源：src/workflow/graph.py 的 AGENT_PIPELINE 与 src/agents/*.py 实现。

### 7.1 sender_profiler（发件人画像分析）
- key: sender_profiler
- name: 发件人画像分析
- 职责: 识别发件人类型、品牌仿冒、域名声誉、地址熵与子域名异常。
- 输入: EmailInput（主要用 sender）。
- 输出: { sender_profiler: SenderProfilerResult }

### 7.2 header_forensics（邮件头取证分析）
- key: header_forensics
- name: 邮件头取证分析
- 职责: SPF/DKIM/DMARC、Reply-To/Return-Path 一致性、X-Mailer、Received 路由异常。
- 输入: EmailInput（主要用 headers 与 sender）。
- 输出: { header_forensics: HeaderForensicsResult }

### 7.3 semantic（语义意图分析）
- key: semantic
- name: 语义意图分析
- 职责: 识别 phishing/legitimate/suspicious 与社会工程话术。
- 输入: EmailInput。
- 输出: { semantic: SemanticResult }

### 7.4 threat_intel（威胁情报关联）
- key: threat_intel
- name: 威胁情报关联
- 职责: IOC 模式匹配、威胁话术匹配、ATT&CK 映射、KB 命中、联网检索公开情报。
- 输入: EmailInput。
- 输出: { threat_intel: ThreatIntelResult }

### 7.5 detector（多维关联检测）
- key: detector
- name: 多维关联检测
- 职责: URL 风险、发件人可信度、附件风险、行为异常、KB 匹配与内容标记融合。
- 输入: EmailInput + semantic_result(可选)。
- 输出: { detection: DetectionResult }

### 7.6 risk（风险研判）
- key: risk
- name: 风险研判
- 职责: 规则预评分 + LLM 评分融合，输出风险等级和 ATT&CK。
- 输入: EmailInput + semantic_result + detection_result。
- 输出: { risk: RiskResult, is_phishing: bool }

### 7.7 response（响应处置）
- key: response
- name: 响应处置
- 职责: 根据风险等级给出 isolate/quarantine/alert/pass 与建议。
- 输入: EmailInput + semantic_result + detection_result + risk_result。
- 输出: { response: ResponseResult }

---

## 8. 前端清单（static/pages）

### 8.1 landing.html
- 职责:
  - 作为品牌封面页与产品介绍页。
  - 提供进入 /studio 的入口。
  - 弹窗展示“关于”和“核心能力”。
- 后端接口调用:
  - 无业务 API 调用。
- localStorage:
  - 未使用。

### 8.2 studio.html
- 职责:
  - 检测输入交互（subject/sender/body/prompt）。
  - 发起检测流请求并实时渲染事件。
  - 展示历史会话、风险总览、证据权重、最近报告。
  - 数据集样本选择与填充。

- 调用后端接口:
  - POST /api/v2/runs/stream
  - GET /api/datasets/{dataset_id}
  - GET /api/health/llm?probe=true
  - GET /api/reports?limit=5
  - GET /api/reports?limit=50

- localStorage 键:
  - phishing_detector_conversations
    - 保存 conversations 数组（id/title/sender/body/bodyPreview/timestamp/report/events/hasResult）。

---

## 9. 配置项（settings 字段与环境变量）

来源：src/config.py + .env.example

### 9.1 Settings 总字段
- llm: LLMConfig
- api: APIConfig
- db: DatabaseConfig
- data_dir: str
- log_level: str

### 9.2 LLMConfig
- provider
  - 环境变量: LLM_PROVIDER
  - 默认: minimax
- api_key
  - provider=qwen 时: QWEN_API_KEY
  - provider!=qwen 时: MINIMAX_API_KEY
- base_url
  - qwen: QWEN_BASE_URL（默认 dashscope compatible）
  - minimax: MINIMAX_BASE_URL
- model
  - qwen: QWEN_MODEL（默认 qwen-plus）
  - minimax: MINIMAX_MODEL（默认 MiniMax-Text-01）
- temperature
  - 环境变量: 当前代码未读取独立 env（使用代码默认 0.1）
- max_tokens
  - 环境变量: 当前代码未读取独立 env（使用代码默认 2048）

### 9.3 APIConfig
- host
  - 环境变量: API_HOST
  - 默认: 0.0.0.0
- port
  - 环境变量: API_PORT
  - 默认: 8000

### 9.4 DatabaseConfig
- url
  - 环境变量: DATABASE_URL
  - 默认: sqlite:///.../phishing_detector.db

### 9.5 其他
- data_dir
  - 环境变量: DATA_DIR
  - 默认: <ROOT>/data
- log_level
  - 环境变量: LOG_LEVEL
  - 默认: INFO

脱敏说明：
- 文档不记录任何真实密钥。
- 健康接口中仅返回掩码字段 api_key_masked。

---

## 10. 测试清单（tests/）

### test_attachment_behavior_analysis.py
- 覆盖点:
  - 附件样本应产生 possible_attachment_scam 标记。
  - 行为异常应生成 behavior_anomaly 证据。
  - 附件欺诈样本不应降级为 safe。

### test_cluster_execution_mode.py
- 覆盖点:
  - 验证 cluster 模式应比 serial 更快（通过 mock slow stub）。
- 现状说明:
  - 当前 run_analysis 已切换 Orchestrator 架构，execution_mode 在 graph.py 注释写明“Orchestrator 模式下始终串行”。
  - 此测试与当前实现可能不一致，待确认是否仍启用。

### test_evidence_fusion.py
- 覆盖点:
  - report 应包含结构化 evidence_items。
  - evidence_items 权重和应为 100。
  - 应含 semantic/detection/header_validation/attachment 等关键证据类型。

### test_health_llm.py
- 覆盖点:
  - /api/health/llm 在探针成功时返回 ok。
  - 缺失 API key 时返回 fail。
  - 校验 service signature 包含 has_studio_page 与 has_v2_stream。

### test_kb_search.py
- 覆盖点:
  - search_kb 对“IP+端口+紧急验证冻结”文本应命中相关知识库条目。

### test_rule_fallback.py
- 覆盖点:
  - LLM 不可用时，run_analysis 仍能返回风险结果（规则兜底）。
  - 检测结果应出现邮件头失败与附件诈骗相关标记。

### test_selected_steps.py
- 覆盖点:
  - selected_steps 执行控制与依赖补齐（response 前自动补 risk）。
- 现状说明:
  - 用例依赖 agent_start/thinking(agent=系统) 等事件格式。
  - 当前 orchestrator 回调事件类型已调整为 agent_call/agent_result 等，测试是否通过待确认。

### test_url_reputation.py
- 覆盖点:
  - URL 信誉证据应生成并具备最低权重/置信度。
  - URL 信誉流程异常时不应中断整体检测流。

---

## 已知脆弱点（扩展时最易踩坑）

1) 事件协议耦合高
- 前端 renderEvent 依赖具体 eventType 与 payload 字段名。
- 后端 callback 映射一旦改字段（如 step_id、channel、result_summary），前端会静默渲染异常。

2) 测试与实现存在演化漂移风险
- cluster/selected_steps 的部分测试用例仍基于旧执行模型或旧事件名。
- 新增编排逻辑后，若不同步更新测试，CI 可能出现“设计通过、测试失败”的分裂。

3) Agent 输出结构非统一 Pydantic
- sender_profiler/header_forensics/threat_intel 使用自定义类，semantic/detection/risk/response 用 Pydantic。
- 聚合层大量 getattr + dict 混用，字段更名时容易漏改。

4) search_kb 为关键词匹配，语义泛化有限
- 当前非向量检索，依赖 token 与关键词命中。
- 新增场景若措辞变化大，召回率会明显波动。

5) 联网检索路径不稳定
- threat_intel.web_search 依赖 DuckDuckGo 多端点与页面解析。
- 外部页面结构变化、限流或网络不稳会导致情报分波动，且难以完全可重复。

---

## 待确认项汇总

1) test_cluster_execution_mode.py、test_selected_steps.py 是否已按 Orchestrator 新事件协议更新。
2) backup 文件（src/agents/*副本.py）是否仍需保留在主分支。
3) pandas/requests/datasets 在生产主路径中的必要性边界（当前看更偏脚本与辅助能力）。
