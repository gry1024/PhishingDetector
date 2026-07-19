# PhishingDetector 技术设计文档

> 本文档深入阐述系统的架构设计、Agent 实现细节、工作流编排策略以及扩展指南。

---

## 目录

1. [系统架构设计理念](#1-系统架构设计理念)
2. [Agent 设计详解](#2-agent-设计详解)
3. [LangGraph 工作流状态机](#3-langgraph-工作流状态机)
4. [规则引擎 + LLM 融合策略](#4-规则引擎--llm-融合策略)
5. [评分体系](#5-评分体系)
6. [MITRE ATT&CK 映射](#6-mitre-attck-映射)
7. [数据库 Schema 设计](#7-数据库-schema-设计)
8. [API 设计](#8-api-设计)
9. [扩展指南](#9-扩展指南)
10. [性能考量](#10-性能考量)

---

## 1. 系统架构设计理念

### 1.1 核心设计目标

PhishingDetector 的架构围绕三个核心目标设计：

- **高准确性**: 通过多维度分析（语义 + 技术 + 规则）交叉验证，降低误报和漏报
- **可解释性**: 每个 Agent 输出详细的分析推理过程，而非仅给出结论
- **可扩展性**: 模块化 Agent 设计，可独立替换、新增检测维度

### 1.2 多 Agent 协作架构

系统采用 **流水线（Pipeline）** 模式的多 Agent 架构，而非投票（Voting）或层级（Hierarchical）模式。选择依据：

| 架构模式 | 优势 | 劣势 | 适用场景 |
|---------|------|------|---------|
| **流水线** ✅ | 每个 Agent 专注一个维度，结果逐层传递深化 | Agent 间有顺序依赖 | 检测步骤有明确的先后关系 |
| 投票 | 并行执行，速度快 | 无法利用前序 Agent 的结论 | 独立的多模型集成 |
| 层级 | 灵活的任务分发 | 调度器本身可能成为瓶颈 | 复杂的多步骤任务 |

在钓鱼邮件检测场景中，语义分析 → 技术检测 → 风险研判 → 处置响应有天然的逻辑递进关系，因此流水线模式最为适合。

### 1.3 技术选型决策

| 技术选择 | 决策理由 |
|---------|---------|
| **LangGraph** | 原生支持状态机、流式输出、节点级别调试；比 AutoGen/CrewAI 更轻量可控 |
| **Minimax M3** | OpenAI 兼容接口、性价比高、中文理解能力强 |
| **FastAPI** | 异步支持好、自带 SSE 流式响应、OpenAPI 文档自动生成 |
| **Gradio** | 快速构建 Web UI、原生支持流式更新、适合原型验证 |
| **SQLite** | 零配置、嵌入式、单机部署无需额外数据库服务 |
| **Pydantic** | 类型安全、与 FastAPI/LangGraph 无缝集成、数据校验自动化 |

### 1.4 分层架构

```
┌─────────────────────────────────────────────┐
│           表示层 (Presentation)               │
│    Gradio Web UI / REST API Client           │
├─────────────────────────────────────────────┤
│           接口层 (Interface)                  │
│    FastAPI Routes + SSE Streaming            │
├─────────────────────────────────────────────┤
│           编排层 (Orchestration)              │
│    LangGraph StateGraph (4 Nodes)            │
├─────────────────────────────────────────────┤
│           智能层 (Intelligence)               │
│    4 Agents + Rule Engine + LLM              │
├─────────────────────────────────────────────┤
│           基础层 (Infrastructure)             │
│    SQLite / LLM Client / Config              │
└─────────────────────────────────────────────┘
```

---

## 2. Agent 设计详解

### 2.1 Agent 基类 (`BaseAgent`)

所有 Agent 继承自 `BaseAgent` 抽象基类，确保统一接口：

```python
class BaseAgent(ABC):
    name: str                              # Agent 名称，用于日志标识
    llm: LLMClient                         # 全局 LLM 客户端（懒加载单例）
    
    @abstractmethod
    def analyze(self, email: EmailInput) -> dict:
        """分析邮件，返回结果字典"""
        ...
    
    def log_step(self, message: str) -> str:
        """生成带 Agent 名称的格式化日志"""
```

**设计要点：**
- `analyze()` 返回字典而非模型对象，因为 LangGraph State 使用 TypedDict，需要字典格式
- `log_step()` 同时完成两件事：写入 Python logger 和返回格式化字符串（后者用于工作流日志的流式输出）
- LLM 客户端通过 `@property` 懒加载，避免在 Agent 实例化时就发起 API 连接

### 2.2 Agent #1: 语义意图分析 (`SemanticAgent`)

**角色**: 理解邮件的"真实意图"，而非依赖表面特征

**输入**: `EmailInput` — 邮件原始数据

**输出**: `SemanticResult`
```python
{
    "intent": "phishing | legitimate | suspicious",
    "persuasion_techniques": ["urgency", "authority", ...],
    "explanation": "详细的分析推理过程",
    "confidence": 0.85
}
```

**Prompt 设计策略**:

系统提示词（System Prompt）的核心设计：

1. **角色定义**: "你是一个专业的钓鱼邮件语义分析专家" — 让 LLM 进入专业角色
2. **分析框架**: 明确列出 7 种社会工程话术类型：
   - `urgency`: 制造紧急感（"立即行动"、"24小时内"）
   - `authority`: 冒充权威（"CEO"、"IT部门"、"银行"）
   - `fear`: 引发恐惧（"账户被盗"、"法律后果"）
   - `greed`: 利益诱惑（"中奖"、"退款"）
   - `curiosity`: 引发好奇（"查看您的文件"）
   - `impersonation`: 身份冒充
   - `credential_theft`: 凭证窃取
3. **输出格式约束**: 明确要求 JSON 格式，减少解析失败
4. **三分类设计**: `phishing / legitimate / suspicious`，比二分类多一个"可疑"缓冲带

**用户提示构造**:
- 如果存在 `raw_text`（用户直接粘贴的完整邮件），直接使用原始文本
- 否则将邮件各字段拼接为结构化描述，保留主题、发件人、正文、URL 等上下文

**关键价值**: 这是对抗 AI 生成钓鱼邮件的核心 Agent。传统基于关键词的检测在面对语法完美的 AI 生成邮件时失效，而语义分析关注"邮件想让人做什么"，不受表面文本质量影响。

### 2.3 Agent #2: 多维关联检测 (`DetectorAgent`)

**角色**: 从技术维度检测邮件的可疑特征

**输入**: `EmailInput` + Agent #1 的 `SemanticResult`（用于交叉验证）

**输出**: `DetectionResult`
```python
{
    "sender_score": 0.3,          # 发件人可信度 0-1
    "sender_analysis": "...",
    "url_score": 0.4,             # URL 安全性 0-1
    "url_analysis": "...",
    "content_flags": ["domain_typo_squatting", "ip_based_url"],
    "explanation": "..."
}
```

**三层分析架构**:

```
第一层: 规则引擎快速扫描
    ├── 发件人域名检测（拼写变体、免费邮箱冒充商务）
    ├── URL 格式检测（IP地址、短链、@符号、过多子域名）
    └── 关键词模式匹配（中英文钓鱼话术正则）

第二层: LLM 深度分析
    ├── 将规则扫描结果作为上下文提供给 LLM
    ├── LLM 结合邮件全文进行深度技术分析
    └── LLM 输出 sender_score / url_score / content_flags

第三层: 分数融合
    ├── sender_score = 规则分 × 0.3 + LLM分 × 0.7
    ├── url_score = 规则分 × 0.3 + LLM分 × 0.7
    └── content_flags = 合并去重
```

**规则引擎检测项**:

| 检测项 | 触发条件 | 扣分 | 标记名 |
|-------|---------|------|-------|
| 域名拼写变体 | 与可信域名编辑距离 1-2 | -0.5 | `domain_typo_squatting` |
| 免费邮箱冒充商务 | 免费域名 + 商务关键词 | -0.3 | `free_email_business_claim` |
| IP 地址 URL | 域名为 IP 地址 | -0.4 | `ip_based_url` |
| 短链服务 | bit.ly, t.co 等 | -0.2 | `url_shortener` |
| URL 含 @ 符号 | 重定向欺骗 | -0.3 | `url_with_at_sign` |
| 过多子域名 | 域名 > 3 个点 | -0.2 | `excessive_subdomains` |
| 钓鱼关键词 | 中英文正则匹配 | — | `phishing_keyword_pattern` |

**域名拼写变体检测算法** (`_is_typo`):
- 移除 TLD 后比较域名主体
- 要求长度相同且仅 1-2 个字符不同
- 例：`g00gle` vs `google`（2 字符差异）→ 命中

**Agent #1 结果交叉验证**: 将语义分析结果（意图判定 + 话术类型）作为额外上下文传入 LLM 提示，使 LLM 能够结合语义和技术两个维度做出判断。

### 2.4 Agent #3: 风险研判 (`RiskAgent`)

**角色**: "法官"——在听取所有证据后做出最终判决

**输入**: `EmailInput` + `SemanticResult` + `DetectionResult`

**输出**: `RiskResult` + 最终判定 `is_phishing`
```python
{
    "risk_score": 85,              # 0-100 综合风险评分
    "risk_level": "high",          # 五级风险等级
    "attack_techniques": ["T1566.002"],  # MITRE ATT&CK 映射
    "explanation": "..."
}
```

**双重评分融合**:

```
规则引擎预评分 (rule_score):
    ├── 语义意图: phishing +40, suspicious +20
    ├── 话术数量: min(N × 5, 20)
    ├── 发件人不可信: (1 - sender_score) × 20
    ├── URL 不安全: (1 - url_score) × 15
    └── 内容标记: min(N × 3, 15)
    → 总分 0-100

LLM 综合评分 (llm_score):
    ├── 综合所有 Agent 结果进行推理
    └── 输出 0-100 分数

最终评分 = llm_score × 0.6 + rule_score × 0.4
```

**风险等级映射**:

| 分数范围 | 等级 | 含义 |
|---------|------|------|
| 81-100 | `critical` | 极高 / 确认钓鱼 |
| 61-80 | `high` | 高风险 |
| 41-60 | `medium` | 中风险 |
| 21-40 | `low` | 低风险 |
| 0-20 | `safe` | 安全 |

**判定阈值**: `is_phishing = (final_score >= 60)`

**设计考量**: 规则引擎给 LLM 评分提供 baseline 参考。当 LLM 评分异常偏低但规则引擎检测到多项可疑特征时，加权融合能纠正 LLM 的遗漏。反之亦然。

### 2.5 Agent #4: 自主响应 (`ResponseAgent`)

**角色**: 安全运营中心 (SOC) 的自动化处置

**输入**: `EmailInput` + `SemanticResult` + `DetectionResult` + `RiskResult`

**输出**: `ResponseResult`
```python
{
    "action": "isolate",           # 处置动作
    "alert_message": "检测到高置信度钓鱼邮件...",
    "trace_report": "攻击者使用域名拼写变体...",
    "recommendation": "请勿点击邮件中的任何链接..."
}
```

**处置策略映射**:

| 风险等级 | 默认动作 | 说明 |
|---------|---------|------|
| `critical` | `isolate` | 立即隔离 |
| `high` | `isolate` | 立即隔离 |
| `medium` | `quarantine` | 隔离待人工审核 |
| `low` | `alert` | 标记告警但放行 |
| `safe` | `pass` | 正常放行 |

**安全底线机制** (`_enforce_action_policy`):

```python
# 即使 LLM 返回了与风险等级不匹配的 action，也会被纠正
# 原则：不能让 LLM 错误地放行高风险邮件
policy_action = policy[risk_level]
if severity[llm_action] >= severity[policy_action]:
    return llm_action    # LLM 建议更严格，保留
return policy_action     # 否则强制执行策略
```

这意味着：
- 如果 LLM 对 `medium` 风险建议 `isolate`（比策略更严格），保留 LLM 的建议
- 如果 LLM 对 `high` 风险建议 `alert`（比策略更宽松），强制纠正为 `isolate`

**快速放行优化**: 当 `risk_level == "safe"` 时，直接返回 `pass` 动作，不调用 LLM，减少延迟。

---

## 3. LangGraph 工作流状态机

### 3.1 状态定义

工作流状态使用 `TypedDict` 定义（LangGraph 原生支持）：

```python
class PhishingState(TypedDict):
    email: dict                  # 输入: EmailInput 字典
    semantic: Optional[dict]     # Agent #1 输出
    detection: Optional[dict]    # Agent #2 输出
    risk: Optional[dict]         # Agent #3 输出
    response: Optional[dict]     # Agent #4 输出
    is_phishing: bool            # 最终判定
    workflow_log: list[str]      # 全流程日志
```

**选择 TypedDict 而非 Pydantic 的原因**: LangGraph 的 `StateGraph` 原生使用 TypedDict 进行状态管理，TypedDict 是 Python 字典的类型注解，序列化/反序列化开销为零。Pydantic 模型在节点内部使用（输入解析和输出构造），但在节点间传递时转换为字典。

### 3.2 状态转换图

```
                    ┌─────────────┐
                    │    START     │
                    └──────┬──────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  semantic_analysis      │
              │  (Agent #1: 语义分析)   │
              │                         │
              │  读取: email            │
              │  写入: semantic,        │
              │        workflow_log     │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  multi_detection        │
              │  (Agent #2: 多维检测)   │
              │                         │
              │  读取: email, semantic  │
              │  写入: detection,       │
              │        workflow_log     │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  risk_assessment        │
              │  (Agent #3: 风险研判)   │
              │                         │
              │  读取: email, semantic, │
              │        detection        │
              │  写入: risk,            │
              │        is_phishing,     │
              │        workflow_log     │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  response               │
              │  (Agent #4: 自主响应)   │
              │                         │
              │  读取: email, semantic, │
              │        detection, risk  │
              │  写入: response,        │
              │        workflow_log     │
              └────────────┬────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │     END     │
                    └─────────────┘
```

### 3.3 节点函数实现

每个节点函数遵循统一的模式：

```python
def node_function(state: PhishingState) -> dict:
    # 1. 从字典状态反序列化为 Pydantic 模型
    email = EmailInput(**state["email"])
    semantic = SemanticResult(**state["semantic"])
    
    # 2. 调用 Agent 的 analyze() 方法
    result = agent.analyze(email, semantic)
    
    # 3. 返回需要更新的字段（Pydantic 模型转回字典）
    return {
        "detection": result["detection"].model_dump(),
        "workflow_log": state.get("workflow_log", []) + result["workflow_log"],
    }
```

**增量更新**: LangGraph 的 `StateGraph` 采用增量更新策略——节点函数只需返回需要更新的字段，未返回的字段保持不变。这避免了在每个节点手动复制完整状态。

**日志累积**: `workflow_log` 字段在每个节点中追加新日志，而非覆盖。使用 `state.get("workflow_log", []) + result["workflow_log"]` 实现。

### 3.4 流式执行

LangGraph 支持两种执行模式：

```python
# 同步执行：等待所有节点完成
result = graph.invoke(initial_state)

# 流式执行：逐节点返回更新
for chunk in graph.stream(initial_state, stream_mode="updates"):
    # chunk = {node_name: state_updates}
    for node_name, updates in chunk.items():
        print(f"节点 {node_name} 完成")
```

系统使用 `stream_mode="updates"` 模式，每当一个节点完成时立即获取其输出更新，实现实时进度反馈。

### 3.5 Agent 单例管理

4 个 Agent 在模块级别创建为单例实例：

```python
_semantic_agent = SemanticAgent()
_detector_agent = DetectorAgent()
_risk_agent = RiskAgent()
_response_agent = ResponseAgent()
```

避免在每次工作流执行时重复创建 Agent 实例。Agent 本身是无状态的（所有状态通过参数传递），因此单例模式安全。

---

## 4. 规则引擎 + LLM 融合策略

### 4.1 为什么需要双重引擎？

纯 LLM 和纯规则引擎各有盲区：

| 方法 | 优势 | 劣势 |
|------|------|------|
| **纯 LLM** | 理解语义、应对新型攻击、可解释 | 延迟高、成本高、偶尔幻觉 |
| **纯规则** | 快速、确定性强、零成本 | 无法理解语义、易被绕过 |
| **融合** ✅ | 兼顾准确性和效率 | 实现复杂度稍高 |

### 4.2 融合策略详解

系统在两个 Agent 中实施了不同层次的融合：

**Agent #2（多维检测）—— 分数级融合**:

```python
# 规则引擎和 LLM 分别对同一维度评分
rule_sender_score = 0.5    # 规则引擎: 域名可疑
llm_sender_score  = 0.3    # LLM: 深度分析认为更可疑

# 加权融合（LLM 权重更高，因为理解能力更强）
final_sender_score = rule_score × 0.3 + llm_score × 0.7
# = 0.5 × 0.3 + 0.3 × 0.7 = 0.36
```

LLM 权重设为 0.7 的理由：
- LLM 能理解上下文和语义，判断能力更强
- 规则引擎提供 baseline，防止 LLM 极端偏离
- 0.3 的规则权重足以在 LLM 评分异常时起到纠偏作用

**Agent #3（风险研判）—— 决策级融合**:

```python
# 规则引擎预评分: 基于上游 Agent 结果的确定性计算
rule_score = 70

# LLM 综合评分: 综合所有信息的推理结果
llm_score = 80

# 加权融合（LLM 权重 0.6，规则权重 0.4）
final_score = llm_score × 0.6 + rule_score × 0.4
# = 80 × 0.6 + 70 × 0.4 = 76
```

研判阶段规则权重提升到 0.4 的理由：
- 研判是最终决策点，需要更高的确定性保障
- 规则评分基于前两个 Agent 的结构化结果，可靠性较高
- 更高的规则权重可防止 LLM 在边缘案例上的误判

### 4.3 融合流程图

```
邮件输入
    │
    ├─── 规则引擎 ──→ 快速 baseline 分数
    │                   (确定性、零延迟)
    │
    ├─── 规则结果 ──→ 作为 LLM 上下文
    │
    └─── LLM 分析 ──→ 深度分析分数
                        (理解语义、高延迟)
    
    规则分 × 0.3 + LLM分 × 0.7 = 融合分数
```

### 4.4 安全底线

除分数融合外，Agent #4（响应）还设置了硬编码的安全策略，作为最终防线。无论 LLM 给出什么建议，处置动作不会低于策略规定的最低等级。这确保了即使 LLM 出现幻觉，高风险邮件也不会被错误放行。

---

## 5. 评分体系

### 5.1 多层评分架构

```
┌──────────────────────────────────────────────────────────┐
│                     最终风险评分 (0-100)                   │
│         = LLM综合评分 × 0.6 + 规则预评分 × 0.4            │
├──────────────────────────────────────────────────────────┤
│                                                            │
│  LLM 综合评分              规则预评分                      │
│  ┌────────────┐           ┌────────────────┐              │
│  │ Agent #3   │           │ 语义意图: 0-40 │              │
│  │ LLM 研判   │           │ 话术数量: 0-20 │              │
│  └────────────┘           │ 发件人:   0-20 │              │
│                            │ URL安全:  0-15 │              │
│                            │ 内容标记: 0-15 │              │
│                            └────────────────┘              │
│                                                            │
│  上游 Agent 评分                                            │
│  ┌────────────────────────────────────────────┐           │
│  │ Agent #2: sender_score (0-1)               │           │
│  │           = 规则分×0.3 + LLM分×0.7         │           │
│  │           url_score (0-1)                   │           │
│  │           = 规则分×0.3 + LLM分×0.7         │           │
│  ├────────────────────────────────────────────┤           │
│  │ Agent #1: confidence (0-1)                 │           │
│  │           intent (三分类)                   │           │
│  └────────────────────────────────────────────┘           │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

### 5.2 评分方向约定

为避免混淆，系统统一评分方向：

| 评分项 | 范围 | 方向 | 含义 |
|-------|------|------|------|
| `sender_score` | 0-1 | **越高越安全** | 发件人可信度 |
| `url_score` | 0-1 | **越高越安全** | URL 安全性 |
| `confidence` | 0-1 | **越高越确信** | 语义分析置信度 |
| `risk_score` | 0-100 | **越高越危险** | 综合风险评分 |

在规则引擎中，可疑特征通过**减分**方式作用于可信度评分（`sender_score`/`url_score`），而在风险评分中则通过**加分**方式累积。

### 5.3 钓鱼判定阈值

```python
is_phishing = (final_score >= 60)
```

阈值 60 对应 `high` 风险等级的下界。选择此阈值的原因：
- 低于 60 的 `medium` 等级邮件可能包含一些可疑但非恶意的特征（如营销邮件的紧急话术）
- 60 以上的邮件通常同时具备多个可疑维度（语义 + 技术 + 规则）
- 可通过调整此阈值在精确率和召回率之间取舍

---

## 6. MITRE ATT&CK 映射

### 6.1 覆盖的技术编号

系统映射 MITRE ATT&CK 框架中与钓鱼邮件相关的技术：

| 编号 | 名称 | 触发条件 |
|------|------|---------|
| **T1566** | Phishing | 通用钓鱼判定 |
| **T1566.001** | Spearphishing Attachment | 包含可疑附件的定向钓鱼 |
| **T1566.002** | Spearphishing Link | 包含可疑链接的定向钓鱼 |
| **T1566.003** | Spearphishing via Service | 通过第三方服务发起的钓鱼 |
| **T1598** | Phishing for Information | 以信息窃取为目标的钓鱼 |
| **T1657** | Financial Theft | 以资金盗窃为目标的攻击（BEC） |

### 6.2 映射机制

ATT&CK 映射由 Agent #3（风险研判）的 LLM 完成。系统提示词中明确列出所有技术编号和描述，LLM 根据分析结果自动选择适用的编号。

**设计考量**: ATT&CK 映射依赖 LLM 的判断而非硬编码规则，因为：
- 同一封邮件可能涉及多个 ATT&CK 技术
- 映射需要综合语义和技术分析结果
- LLM 能理解攻击意图而非仅匹配表面特征

---

## 7. 数据库 Schema 设计

### 7.1 ER 模型

```
┌─────────────────────────────┐
│         emails              │
├─────────────────────────────┤
│ PK  id          INTEGER     │
│     subject     TEXT        │
│     sender      TEXT        │
│     recipients  TEXT        │
│     body        TEXT        │
│     urls        TEXT (JSON) │
│     headers     TEXT (JSON) │
│     has_attachment INTEGER  │
│     raw_text    TEXT        │
│     created_at  TEXT        │
└──────────────┬──────────────┘
               │ 1
               │
               │
               │ N
┌──────────────┴──────────────┐
│         reports             │
├─────────────────────────────┤
│ PK  id          INTEGER     │
│ FK  email_id    INTEGER     │
│     timestamp   TEXT        │
│     is_phishing INTEGER     │
│     risk_score  REAL        │
│     risk_level  TEXT        │
│     semantic_result  TEXT   │  ← JSON
│     detection_result TEXT   │  ← JSON
│     risk_result TEXT        │  ← JSON
│     response_result TEXT    │  ← JSON
│     workflow_log TEXT       │  ← JSON
└─────────────────────────────┘
```

### 7.2 设计决策

**SQLite + WAL 模式**:
```sql
PRAGMA journal_mode=WAL;
```
WAL (Write-Ahead Logging) 模式允许多个读操作与写操作并发执行，提升 API 并发请求时的性能。

**JSON 存储嵌套数据**: Agent 的分析结果（`semantic_result`, `detection_result` 等）以 JSON 字符串存储在 TEXT 字段中，而非拆分为独立的关联表。

理由：
- 分析结果是只读快照，无需跨报告关联查询
- JSON 存储保持了结果结构的灵活性（不同 Agent 的输出字段可能变化）
- 避免了多表 JOIN 的复杂性

**索引设计**:
```sql
CREATE INDEX idx_reports_email ON reports(email_id);
CREATE INDEX idx_reports_timestamp ON reports(timestamp);
```
- `email_id` 索引：加速按邮件查询报告
- `timestamp` 索引：加速按时间排序的列表查询

### 7.3 数据流

```
用户输入邮件
    │
    ▼
emails 表 (INSERT)  ← 保存原始邮件
    │
    ▼
LangGraph 工作流执行
    │
    ▼
reports 表 (INSERT) ← 保存分析报告
    │
    ▼
API 查询 (SELECT)   ← 历史记录/统计
```

---

## 8. API 设计

### 8.1 同步 vs 流式 SSE

系统同时提供两种分析接口，满足不同使用场景：

**同步接口 (`POST /api/analyze`)**:
- 等待全部 4 个 Agent 执行完毕，一次性返回完整结果
- 适用于：API 集成、批量处理、自动化流水线
- 延迟：约 10-30 秒（取决于 LLM 响应速度）

**流式 SSE 接口 (`POST /api/analyze/stream`)**:
- 使用 Server-Sent Events 逐节点推送执行进度
- 适用于：Web UI 实时展示、需要进度反馈的交互场景
- Gradio UI 使用此接口

### 8.2 SSE 事件协议

```
event: agent_start
data: {"node": "semantic_analysis"}

event: agent_log
data: {"node": "semantic_analysis", "message": "[语义意图分析] 开始语义意图分析..."}

event: agent_log
data: {"node": "semantic_analysis", "message": "[语义意图分析] 正在调用 LLM 分析邮件意图..."}

event: agent_done
data: {"node": "semantic_analysis", "result": {"semantic": {...}}}

event: agent_start
data: {"node": "multi_detection"}

... (重复上述模式)

event: complete
data: {"email_id": 1, "report_id": 1, "is_phishing": true, ...}
```

### 8.3 SSE 实现细节

```python
# FastAPI StreamingResponse + LangGraph stream
async def event_generator():
    for chunk in graph.stream(initial_state, stream_mode="updates"):
        for node_name, updates in chunk.items():
            yield _sse_event("agent_start", {"node": node_name})
            # 发送新增日志
            for log_line in new_logs:
                yield _sse_event("agent_log", {"message": log_line})
            yield _sse_event("agent_done", {"node": node_name, "result": ...})
    
    # 保存报告后发送完成事件
    yield _sse_event("complete", final_report)

return StreamingResponse(
    event_generator(),
    media_type="text/event-stream",
    headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",  # 禁止 Nginx 缓冲
    },
)
```

关键配置：
- `Cache-Control: no-cache`: 防止浏览器/代理缓存 SSE 流
- `X-Accel-Buffering: no`: 防止 Nginx 缓冲事件流
- `Connection: keep-alive`: 保持长连接

### 8.4 CORS 配置

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # 允许 Gradio UI 跨域访问
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

因为 Gradio UI (localhost:7860) 和 FastAPI (localhost:8000) 运行在不同端口，需要 CORS 中间件允许跨域请求。

---

## 9. 扩展指南

### 9.1 添加新 Agent

以添加一个"附件安全分析 Agent"为例：

**步骤 1: 定义数据模型** (`src/models.py`)

```python
class AttachmentResult(BaseModel):
    has_suspicious_attachment: bool
    file_types: list[str]
    risk_indicators: list[str]
    explanation: str
```

**步骤 2: 实现 Agent** (`src/agents/attachment.py`)

```python
from src.agents.base import BaseAgent
from src.models import EmailInput, AttachmentResult

SYSTEM_PROMPT = """你是一个邮件附件安全分析专家..."""

class AttachmentAgent(BaseAgent):
    name = "附件安全分析"
    
    def analyze(self, email: EmailInput, ...) -> dict:
        log = []
        log.append(self.log_step("开始附件安全分析..."))
        
        # 分析逻辑
        result = self.llm.chat_json(SYSTEM_PROMPT, user_prompt)
        
        attachment = AttachmentResult(...)
        return {
            "attachment": attachment.model_dump(),
            "workflow_log": log,
        }
```

**步骤 3: 更新工作流状态** (`src/workflow/graph.py`)

```python
class PhishingState(TypedDict):
    ...
    attachment: Optional[dict]    # 新增字段
```

**步骤 4: 添加节点和边**

```python
def attachment_node(state: PhishingState) -> dict:
    email = EmailInput(**state["email"])
    result = _attachment_agent.analyze(email, ...)
    return {
        "attachment": result["attachment"].model_dump(),
        "workflow_log": state.get("workflow_log", []) + result["workflow_log"],
    }

def build_workflow():
    graph = StateGraph(PhishingState)
    
    # 添加新节点
    graph.add_node("attachment_analysis", attachment_node)
    
    # 修改边：在检测后、研判前插入
    graph.add_edge(START, "semantic_analysis")
    graph.add_edge("semantic_analysis", "multi_detection")
    graph.add_edge("multi_detection", "attachment_analysis")     # 新边
    graph.add_edge("attachment_analysis", "risk_assessment")      # 新边
    graph.add_edge("risk_assessment", "response")
    graph.add_edge("response", END)
    
    return graph.compile()
```

### 9.2 添加新检测规则

在 `src/agents/detector.py` 的 `_rule_scan()` 方法中添加新规则：

```python
def _rule_scan(self, email: EmailInput) -> dict:
    ...
    # --- 新增规则示例: 检测 HTML 表单 ---
    if "<form" in email.body.lower() or "<input" in email.body.lower():
        content_flags.append("embedded_form")
        url_score -= 0.3
    
    # --- 新增规则示例: 检测 Base64 编码内容 ---
    base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
    if re.search(base64_pattern, email.body):
        content_flags.append("base64_encoded_content")
        url_score -= 0.2
    
    ...
```

### 9.3 添加新数据源

在 `scripts/download_datasets.py` 中添加新的下载函数：

```python
def download_custom_dataset():
    """下载自定义数据集"""
    logger.info("下载自定义数据集...")
    
    # 从 URL 下载
    url = "https://example.com/dataset.csv"
    resp = requests.get(url, stream=True)
    save_path = RAW_DIR / "custom_dataset.csv"
    with open(save_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
```

然后在 `process_datasets()` 中添加对应的处理逻辑：

```python
# 处理自定义数据集
for csv_file in RAW_DIR.glob("custom_*.csv"):
    df = pd.read_csv(csv_file)
    # ... 处理逻辑
```

### 9.4 更换 LLM 提供商

由于系统使用 OpenAI 兼容接口，更换 LLM 提供商只需修改 `.env` 配置：

```env
# 切换到 OpenAI
MINIMAX_BASE_URL=https://api.openai.com/v1
MINIMAX_API_KEY=sk-...
MINIMAX_MODEL=gpt-4o

# 切换到 DeepSeek
MINIMAX_BASE_URL=https://api.deepseek.com/v1
MINIMAX_API_KEY=sk-...
MINIMAX_MODEL=deepseek-chat

# 切换到本地 Ollama
MINIMAX_BASE_URL=http://localhost:11434/v1
MINIMAX_API_KEY=ollama
MINIMAX_MODEL=llama3
```

无需修改任何代码——`LLMClient` 使用 OpenAI SDK，兼容所有支持 OpenAI API 协议的服务。

### 9.5 扩展 API 端点

在 `src/api/routes.py` 中添加新路由：

```python
@router.post("/batch-analyze")
async def batch_analyze(emails: list[AnalyzeRequest]):
    """批量分析多封邮件"""
    results = []
    for req in emails:
        # ... 复用现有分析逻辑
    return results
```

---

## 10. 性能考量

### 10.1 LLM 调用延迟

LLM 调用是系统的主要延迟来源：

| Agent | LLM 调用次数 | 预估延迟 |
|-------|-------------|---------|
| Agent #1 语义分析 | 1 次 | 3-8 秒 |
| Agent #2 多维检测 | 1 次 | 3-8 秒 |
| Agent #3 风险研判 | 1 次 | 3-8 秒 |
| Agent #4 自主响应 | 0-1 次（安全邮件不调用） | 0-5 秒 |
| **总计** | **3-4 次** | **9-29 秒** |

**优化措施**:
- LLM `temperature=0.1`：低温度减少生成随机性，加速收敛
- `max_tokens=2048`：限制输出长度，避免无限制生成
- 安全邮件快速放行：Agent #4 对 `safe` 等级跳过 LLM 调用
- 流式 SSE：用户无需等待全部完成即可看到进度

### 10.2 数据库性能

- **WAL 模式**: 读写并发不阻塞
- **连接管理**: 每次操作获取连接后立即关闭（`try/finally`），避免连接泄漏
- **JSON 序列化**: `ensure_ascii=False` 保持中文可读性
- **索引**: `email_id` 和 `timestamp` 索引加速常用查询

### 10.3 内存占用

- **Agent 单例**: 4 个 Agent 全局单例，避免重复创建
- **LLM 客户端单例**: 懒加载，全局共享一个 OpenAI 客户端
- **SQLite**: 嵌入式数据库，无需独立进程
- **数据集**: 不加载到内存，仅在磁盘存储

### 10.4 并发模型

- **FastAPI + Uvicorn**: 异步事件循环，处理并发 HTTP 请求
- **全栈模式**: API 在后台守护线程运行，UI 在主线程运行
- **LangGraph**: 同步执行（当前实现），每次分析请求在独立线程中运行

### 10.5 可扩展方向

| 优化方向 | 方法 | 复杂度 |
|---------|------|-------|
| Agent 并行化 | Agent #1 和 #2 无依赖，可并行执行 | 中 |
| LLM 缓存 | 对相同邮件内容缓存 LLM 响应 | 低 |
| 批量分析 | 使用 async + 并发控制批量处理 | 中 |
| 数据库升级 | SQLite → PostgreSQL | 低 |
| 流式 LLM | 使用 `chat_stream()` 实现 token 级流式输出 | 低 |
| Agent #1 #2 并行 | LangGraph 支持并行边 (`add_edge` 从同一节点出发) | 中 |

**并行化示例**（Agent #1 和 #2 并行执行）:

```python
# 当前: 串行
# START → semantic → detection → risk → response → END

# 优化: 并行
# START → semantic ──→ risk → response → END
#       → detection ─→
# 
# detection 不再等待 semantic 完成（但 risk 需要两者都完成）

graph.add_edge(START, "semantic_analysis")
graph.add_edge(START, "multi_detection")      # 并行启动
graph.add_edge("semantic_analysis", "risk_assessment")
graph.add_edge("multi_detection", "risk_assessment")
graph.add_edge("risk_assessment", "response")
graph.add_edge("response", END)
```

注意：并行化后 Agent #2 无法获取 Agent #1 的语义分析结果作为上下文。需要权衡是否可接受此信息损失。

---

*本文档最后更新: 2025年*
