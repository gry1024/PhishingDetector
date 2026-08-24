# AGENTS.md — PhishingDetector 项目指南

> 本文件面向 AI 编码代理，介绍项目架构、构建测试方式与开发约定。
> 依据当前仓库真实代码编写；README.md 中部分描述（4 Agent 串行流水线、Gradio UI）已过时，以本文件与 ARCHITECTURE.md 为准。

---

## 1. 项目概览

**PhishingDetector（AI 钓鱼邮件智能检测系统）**：基于多 Agent 协作的钓鱼邮件检测系统。用户在前端粘贴邮件内容，后端由主编排 Agent（Orchestrator）制定检测策略、依次调用 7 个专业子 Agent，最终聚合出结构化检测报告（风险分数、风险等级、ATT&CK 映射、处置建议），全过程通过 SSE 实时推送到前端。

- 入口：`main.py`（`init_db()` + uvicorn 启动 `src.api.server:app`）
- 前端：纯静态 HTML/CSS/JS 单文件页面，无前端构建步骤
- 存储：SQLite（原生 `sqlite3` 驱动，无 ORM），数据库文件 `phishing_detector.db` 自动生成
- LLM：通过 OpenAI 兼容接口调用 Minimax（默认）或通义千问 Qwen，由 `LLM_PROVIDER` 环境变量切换
- 语言/runtime：Python 3.10（仓库 `.venv` 中为 3.10.11），主要开发与运行环境为 Windows

### 运行时调用链

```
studio.html (点击"运行检测")
  → POST /api/v2/runs/stream            (src/api/routes.py: analyze_stream_v2)
    → db.save_email()                   (持久化邮件)
    → 后台线程 run_analysis()           (src/workflow/graph.py)
      → OrchestratorAgent.analyze()     (src/agents/orchestrator.py)
        Phase 1: 观察/假设/反思，生成检测策略（LLM 失败时 _fallback_strategy 规则兜底）
        Phase 2: 按 AGENT_PIPELINE 顺序调用子 Agent（可用 selected_steps 裁剪，自动补依赖）
        Phase 3: 聚合证据，生成最终报告
    → callback 事件 → 统一映射为 v2 SSE 事件 → StreamingResponse 逐条推送
```

子 Agent 默认顺序（`src/workflow/graph.py` 的 `AGENT_PIPELINE`）：

1. `sender_profiler` 发件人画像分析
2. `header_forensics` 邮件头取证分析（SPF/DKIM/DMARC 等）
3. `semantic` 语义意图分析
4. `threat_intel` 威胁情报关联（含联网检索，失败自动降级）
5. `detector` 多维关联检测（URL/发件人/附件/行为/KB 融合）
6. `risk` 风险研判（规则预评分 + LLM 评分融合）
7. `response` 响应处置（isolate/quarantine/alert/pass）

注意：`execution_mode` 参数保留在接口中，但 Orchestrator 模式下始终串行执行。

---

## 2. 技术栈与依赖

依赖仅有 `requirements.txt`（无 pyproject.toml / package.json / Cargo.toml）：

| 依赖 | 用途 |
|------|------|
| fastapi + uvicorn[standard] | REST API、SSE 流式响应、静态文件服务 |
| openai + httpx<0.28 | LLM 调用（OpenAI 兼容协议）；httpx 版本锁定是历史兼容修复，勿随意升级 |
| pydantic v2 | 请求体与内部数据模型校验 |
| python-dotenv | 从 `.env` 加载环境变量 |
| pandas / datasets / requests | 数据集下载与离线处理脚本使用，主检测链路非强依赖 |

前端零依赖：原生 fetch + ReadableStream 手动解析 SSE，无 npm/node。

---

## 3. 构建与运行命令

```bash
# 创建虚拟环境（Windows）
python -m venv venv
venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 配置环境变量（必须，否则 LLM 相关功能不可用）
copy .env.example .env   # 然后编辑填入 MINIMAX_API_KEY

# 启动服务（API + UI）
python main.py                # 默认端口 8000
python main.py --port 9000    # 指定端口

# 运行内置端到端样例（调用真实 LLM，需要有效 API Key）
python main.py --test         # 实际执行 scripts/run_test.py
```

启动后访问：

- `/` 或 `/landing`：品牌封面页
- `/studio`：检测工作台（主页面，SSE 实时渲染）
- `/knowledge`：知识库浏览与检索页
- `/docs`：FastAPI 自动生成的交互式 API 文档
- `GET /api/health/llm?probe=true`：LLM 连通性健康检查（探针真实调用一次 LLM）

数据集下载（可选，不进 Git）：`python scripts/download_datasets.py`（交互式菜单）。

---

## 4. 测试策略

测试框架为标准库 **unittest**（不是 pytest，仓库无 pytest 配置）：

```bash
# 全量测试（VS Code 任务 "acceptance-unittest-discover" 即此命令）
python -m unittest discover -s tests -v

# 单个测试文件
python -m unittest tests.test_kb_search -v
```

测试约定：

- 测试文件位于 `tests/`，命名 `test_*.py`，继承 `unittest.TestCase`
- **不依赖真实 LLM**：需要 Agent/LLM 的用例用 `unittest.mock.patch` 打桩（如 `tests/test_health_llm.py` patch `src.api.routes.get_llm`）；需要走完整 `run_analysis` 的用例通过 `settings.llm.api_key = ""` + `llm_module.llm_client = None` 强制 LLM 不可用，验证规则兜底路径（如 `tests/test_rule_fallback.py`）
- KB 检索测试直接调用 `src.database`（如 `tests/test_kb_search.py`），会初始化真实 SQLite 库
- 另有脚本级验收：`scripts/acceptance_kb_validation.py`（KB 种子/重建校验）、`scripts/tmp_full_regression_check.py`（需服务运行的回归脚本）、根目录 `verify_rag_embedding.py`（向量嵌入质量专项验收，需真实嵌入 API）
- 规则兜底离线评测：`scripts/eval_rule_offline.py`（不起服务、不联网、不调 LLM，直接驱动 semantic → detector → risk 规则链路对 test_set 批量评测并导出特征 dump 到 `datasets/rule_eval_dump.jsonl`，400 条约 12 秒；`datasets/` 已 gitignore）+ `scripts/tune_rule_fallback.py`（读 dump 离线复刻打分链做抬档规则调参）。**注意 ContextVar 不跨线程传播**：`set_llm_disabled(True)` 必须在每个 worker 线程内调用（已在 `evaluate_one` 内处理），在主线程设置后丢进线程池会静默走真实 LLM。

当前测试现状（2026-08 在本机实测）：

- `test_cluster_execution_mode.py` 与 `test_selected_steps.py` 已按 Orchestrator 新事件协议（`agent_call`/`agent_result`）重写，4 个用例全绿且毫秒级完成。打桩方式：`patch.dict(OrchestratorAgent.SUB_AGENTS, ...)` 替换注册表内的 `agent_class`——直接 patch 模块级类名无效（SUB_AGENTS 在类定义时已捕获原始类对象），否则真实子 Agent（含 threat_intel 联网检索）会被静默调用。
- `test_attachment_behavior_analysis.py` 原 FAIL 用例（发票附件样本误判 safe）已按方案 A 修复（2026-08）：`src/tools.py` 附件可疑词表补中文财务词 + `src/agents/detector.py` 无 URL 时 url_score 固定中性 0.5；`src/agents/risk.py` 的 safe_boundary 死代码仅加 TODO 注释标记，阈值与打分公式未动。
- 规则兜底准确率专项（2026-08-24）：`src/tools.py` 的 `PHISHING_PATTERNS` 补强第二批中文品类词（补贴变体/邮箱容量恐吓/薪资诱饵/学术征稿/BEC 询单，均经 200 条正常样本零命中验证），并新增 `WEAK_PHISHING_PATTERNS` 弱信号词表；`src/agents/risk.py` 规则兜底分支按"强模式 ≥1 命中阶梯抬档（61+7×(n-1)，封顶 82），强零命中时弱信号 ≥2 组合抬到 61"增强——只影响 LLM 不可用分支，不进 LLM prompt、不进 0.6/0.4 融合。test_set v1 纯规则路径实测：recall 0% → 80.5%、precision 100%、accuracy 90.25%（基线对照 `docs/BASELINE_EVAL_RULE_ONLY_2026-08-18.md`）。`test_rule_fallback.py` 的 `risk_score == rule_score` 旧断言已相应更新为 `risk_score >= rule_score` + 抬档生效断言。
- 走完整 `run_analysis` 的用例（如 `test_url_reputation.py`、`test_attachment_behavior_analysis.py`）会经过 `threat_intel` 的实时联网检索，**非常慢且在网络受限环境下可能长时间阻塞**（实测 3 个附件用例耗时约 283s；全量运行在 600s 超时处挂起于 URL 信誉用例）。有网环境下该路径可用但不稳定，勿在断言中依赖其具体返回。

---

## 5. 代码组织

```
main.py                  # 入口：argparse（--test/--port）→ init_db() → uvicorn
src/
  config.py              # Settings 单例：LLM/API/DB 配置，全部从 .env 读取
  models.py              # Pydantic 模型：EmailInput、SemanticResult、DetectionResult、
                         #   RiskResult、ResponseResult、EvidenceItem、AnalysisReport、WorkflowState
  database.py            # SQLite 数据层：emails/reports/kb_entries 三表 + KB 种子填充；
                         #   检索三通道：search_kb（关键词）/ vector_search_kb（向量）/ hybrid_search_kb（融合）
  llm.py                 # LLMClient（OpenAI 兼容，同步+流式）；
                         #   LLMUnavailableError / EmbeddingUnavailableError 兜底异常
  tools.py               # 工具注册中心：@register_tool(name, agents=[...]) 装饰器自动注册，
                         #   get_tools_for_agent() 按 Agent 取工具切片
  agents/
    base.py              # BaseAgent 抽象基类：事件发射、LLM JSON 解析
    orchestrator.py      # 主编排 Agent（核心调用链，Phase 1/2/3）
    sender_profiler.py / header_forensics.py / semantic.py / threat_intel.py /
    detector.py / risk.py / response.py   # 7 个子 Agent
    *__init__ - 副本.py、base - 副本.py*   # 历史备份文件，主流程未引用，勿修改引用关系
  workflow/graph.py      # run_analysis() 入口 + AGENT_PIPELINE 元数据
  api/server.py          # FastAPI app、CORS、页面路由（/ /landing /studio /knowledge）
  api/routes.py          # 业务 API，统一前缀 /api
  static/pages/          # landing.html / studio.html / knowledge.html（单文件前端）
scripts/                 # 数据集下载、端到端样例、KB 验收、回归等辅助脚本
tests/                   # unittest 测试
docs/                    # 路线图与演示文档（团队内部）
data/                    # 数据集与 kb_expansion.json（大数据文件已 gitignore）
```

关键设计约定：

- **Agent 结果模型不统一**：`semantic/detector/risk/response` 返回 Pydantic 模型，`sender_profiler/header_forensics/threat_intel` 返回自定义轻量类。聚合层因此大量 `getattr` + dict 混用——字段更名时必须全局检查。
- **事件协议耦合高**：前端 `studio.html` 的 `renderEvent` 依赖后端 v2 SSE 事件名与 payload 字段（`run_started/orchestrator_thinking/agent_call/step_progress/tool_finished/report/run_finished` 等）。改后端事件字段必须同步改前端，否则静默渲染异常。
- **LLM 永远有兜底**：LLM 不可用时各 Agent 走规则引擎路径，检测链路不中断；`risk` Agent 输出 `llm_participated` 标记。新增 LLM 调用点时必须保持这一行为。
- **KB 检索降级**：向量检索失败时静默退化为关键词检索，不抛错中断主流程。
- **联网检索不稳定**：`threat_intel` 的 web search 依赖 DuckDuckGo 公开端点，可能受限流/结构变化影响，测试不可依赖其结果。

---

## 6. 代码风格与提交规范

- 代码注释、docstring、文档一律使用**简体中文**；模块级 docstring 用 `标题\n====` 横幅格式
- 标识符（变量/函数/类名）使用英文；日志使用标准库 `logging`，`logger = logging.getLogger(__name__)`
- 提交信息遵循 [Conventional Commits](https://www.conventionalcommits.org/)，描述用中文：
  `feat(semantic): 增加 BEC 诈骗识别能力`、`fix(detector): 修复短链检测误报问题`
  常用 type：`feat / fix / docs / style / refactor / test / chore`（历史提交中中英文描述均有出现）
- 分支命名：`feature/xxx`、`fix/xxx`、`docs/xxx`、`refactor/xxx`、`test/xxx`（实际仓库中 `feat/` 前缀也有使用）
- 合并方式：Squash Merge，保持 main 历史整洁；无 CI 流水线配置，合入前本地跑通 unittest 全量

---

## 7. 配置项（.env）

模板见 `.env.example`。全部配置经 `src/config.py` 的 `settings` 单例读取：

| 环境变量 | 默认 | 说明 |
|----------|------|------|
| `LLM_PROVIDER` | `minimax` | `minimax` 或 `qwen` |
| `MINIMAX_API_KEY` / `MINIMAX_BASE_URL` / `MINIMAX_MODEL` | — / `https://api.minimax.chat/v1` / `MiniMax-Text-01` | Minimax 配置 |
| `QWEN_API_KEY` / `QWEN_BASE_URL` / `QWEN_MODEL` | — / dashscope 兼容端点 / `qwen-plus` | Qwen 配置（provider=qwen 时生效） |
| `MINIMAX_GROUP_ID` / `EMBEDDING_MODEL` / `EMBEDDING_DIM` | 空 / 空 / `1536` | 向量嵌入（KB 语义检索） |
| `LLM_MAX_TOKENS` | `4096` | LLM 单次最大输出 token（2048 曾被长 JSON 顶满截断） |
| `DATABASE_URL` | `sqlite:///<项目根>/phishing_detector.db` | SQLite 路径 |
| `API_HOST` / `API_PORT` | `0.0.0.0` / `8000` | 服务监听 |
| `DATA_DIR` / `LOG_LEVEL` | `<项目根>/data` / `INFO` | 数据目录 / 日志级别 |

---

## 8. 安全注意事项

- **API Key 只走 `.env`**，严禁硬编码进源码或提交；`.env` 已在 `.gitignore` 中
- 健康检查接口只返回掩码后的 `api_key_masked`，新增接口时不得泄露完整密钥
- `phishing_detector.db`、`data/raw|processed` 下的数据集文件均已 gitignore，勿提交
- CORS 当前为 `allow_origins=["*"]`（仅适合本地开发）；若要对外部署需收紧
- 系统会分析不可信邮件内容：不要把邮件正文/URL 直接拼进 shell 命令或 SQL；数据库层一律使用参数化查询（现有代码已遵守）
- `scripts/` 与根目录下 `tmp_*`、`_tmp_*` 文件多为一次性诊断脚本，改动前确认是否仍被 VS Code 任务引用

---

## 9. 部署

无 Docker、无 CI/CD 配置。部署方式为单机直接运行：

```bash
pip install -r requirements.txt
python main.py --port 8000
```

Windows 下 VS Code 任务（`.vscode/tasks.json`）提供了常用的本地运维操作：启动/停止 8000–8002 端口实例、按端口杀进程（`Get-NetTCPConnection` + `Stop-Process`）、运行 unittest、KB 验收等，可直接复用其命令。
