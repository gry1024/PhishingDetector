# 交接说明：PhishingDetector RAG 收尾（给编码 Agent）

> 本文档是项目交接的单一事实源。开始任何工作前，请先阅读本文件 + ARCHITECTURE.md。

## 1. 项目定位

FastAPI 后端（src/ 包）+ 静态页面（src/static/pages/）的多 Agent 钓鱼邮件检测系统。
架构、调用链、数据层、API、SSE 协议全部见 ARCHITECTURE.md（已更新至最新，可信）。

## 2. 已完成的进度

- 知识库功能：kb_entries 已扩 schema（summary/tags/iocs/attack_techniques/
  detection_points/sample_email/related），83 条精编条目，播种按 title 幂等；
- 前端：knowledge.html 知识库页（/knowledge 路由）、studio.html 命中面板可点击跳转、
  match_type 徽章、llm_participated 的"LLM 未参与"诚实显示；
- 后端：/api/kb/categories、/api/kb/entries/{id}、混合检索 hybrid_search_kb、
  risk.py 知识库注入研判上下文、llm_participated 标记、is_phishing 口径统一。

## 3. 当前卡点（为什么 RAG 语义检索没生效）

验收发现两个规格违反，导致语义检索从未真正工作：

1. **kb_entries 缺 embedding_model 列**：第一步迁移只做了一半
   （验收实测报 no such column: embedding_model）；
2. **存在未授权的本地伪嵌入**：EMBEDDING_MODEL 从未配置，但 83 条目的
   embedding 列已被写入 6 维假向量。规格要求：嵌入服务未配置/失败时只告警、
   不写入任何向量。

此外，MiniMax 的嵌入接口不是 OpenAI 兼容格式（见第 5 节），此前按 OpenAI
格式实现的 embed() 必然调不通。

## 4. 待办清单（按优先级）

### P0-1 修复规格违反（src/database.py、src/llm.py）
- 补 embedding_model 列迁移（PRAGMA table_info + ALTER TABLE，幂等，
  值格式 "模型名:维度"）；
- 删除本地伪嵌入/哈希兜底分支：embed() 未配置时抛 EmbeddingUnavailableError；
  embed_kb_entries() 捕获后只记 warning 跳过，不得生成任何替代向量；
- 验收：未配置 EMBEDDING_MODEL 时 init_db 后所有条目 embedding 为空；
  配置后写入真实维度向量且 embedding_model 记录正确。

### P0-2 适配 MiniMax 原生嵌入格式（src/llm.py、src/config.py、src/database.py）
接口事实见第 5 节。要点：
- config.py 新增 MINIMAX_GROUP_ID 环境变量；EMBEDDING_DIM 默认 1536；
- embed(texts, emb_type="db")：知识库条目用 "db"，检索查询用 "query"；
- 响应取 vectors[]；base_resp.status_code != 0 即业务失败（HTTP 200 也算），
  抛 EmbeddingUnavailableError 并附 status_msg。

### P0-3 验收闭环（按序执行）
```powershell
python verify_rag_embedding.py --clear-embeddings   # 清掉 6 维假向量
# 重启服务（init_db 按 embo-01 重算）
python verify_rag_embedding.py                      # 诊断必须全部通过
# 混合检索冒烟（三选一方式：临时脚本/接口/前端知识库页搜索）：
# "我的账户需要重新认证否则冻结" → 命中凭证钓鱼，match_type=semantic/hybrid
# "请立即验证 http://192.168.1.100:8080/verify" → "IP直连" Top1
```
通过标准：API 维度 1536；钓鱼查询↔凭证钓鱼条目余弦 > 0.6 且显著高于无关文本；
库中向量维度与 API 一致。

### P1 历史测试修复（不阻塞，最后做）
test_cluster_execution_mode.py / test_selected_steps.py 仍在 patch graph.py 中
已不存在的 ResponseAgent。按 Orchestrator 新事件协议（agent_call/agent_result）
重写这两个测试，不是恢复旧类名。test_attachment_behavior_analysis.py:56 的
失败另行排查附件评分逻辑。

## 5. MiniMax 嵌入接口事实（官方文档已核实，不得按 OpenAI 格式实现）

- URL：{base_url}/embeddings?GroupId={group_id}
  （base_url 复用 MINIMAX_BASE_URL，默认 https://api.minimax.chat/v1；
  GroupId 在用户中心→基本信息查询，配置到 .env 的 MINIMAX_GROUP_ID）；
- 请求体：{"model": "embo-01", "texts": [...], "type": "db"|"query"}
  —— 字段名是 texts 不是 input，type 必填（双塔算法：被检索文本用 db，
  检索查询用 query）；
- 响应体：vectors[]，float32，1536 维；错误在 base_resp.status_code；
- 鉴权：Authorization: Bearer {MINIMAX_API_KEY}；
- 模型固定 embo-01，约 0.0005 元/千 token。

## 6. 硬约束（任何时候不得违反）

- search_kb(text, limit) 签名、打分公式、返回字段零变化（关键词通道）；
  detector.py / threat_intel.py / routes.py / tests/test_kb_search.py 全部依赖它；
- severity 只用 critical/high/medium/low（severity_bonus 只有这四个键）；
- 播种保持按 title 幂等；phishing_detector.db 是派生文件可删除重建；
- 不修改 test_cluster_execution_mode / test_selected_steps 之外的既有测试；
  不动 src/agents/ 下的副本备份文件；
- 前端 SSE 事件协议字段名（step_id/channel/result_summary 等）不许改；
- 嵌入/RAG 任何失败路径都必须可回退到纯关键词检索，不得阻断检测流程。

## 7. 工作方式约定

- 按 P0-1 → P0-2 → P0-3 → P1 顺序执行，每完成一项先跑验收再汇报；
- 每步验收包含：python -m unittest discover -s tests 无新增失败
  （历史遗留 4 个失败除外）；
- 验收脚本 verify_rag_embedding.py 在项目根目录，结论看不懂时原样贴回给提问者；
- 完成后更新 ARCHITECTURE.md 相应章节。
