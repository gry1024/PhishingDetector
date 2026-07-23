# PhishingDetector 后端改进路线图（UI 暂不纳入）

## 1. 文档目标

本文档用于指导后端持续升级，目标不是简单“把 UI 做得更好”，而是把当前项目从“可演示的多 Agent 原型”提升为“具备企业级邮件安全检测能力的后端引擎”。

范围如下：

- 不涉及 UI 重构
- 不涉及纯视觉效果改动
- 只聚焦后端检测能力、架构健壮性、证据收集、可观测性与测试闭环

当前仓库中的后端关键入口包括：

- [src/workflow/graph.py](../src/workflow/graph.py)：主工作流编排
- [src/api/routes.py](../src/api/routes.py)：API 与流式接口
- [src/tools.py](../src/tools.py)：规则工具与风险特征识别
- [src/agents/base.py](../src/agents/base.py)：Agent 基类与 LLM/工具调用封装
- [src/config.py](../src/config.py)：配置与环境变量接入
- [tests/test_rule_fallback.py](../tests/test_rule_fallback.py)：当前现有验证回归测试

---

## 2. 当前项目现状

目前项目已经具备以下基础能力：

1. 4 Agent 串行工作流
2. 规则工具库与关键词模式识别
3. LLM 流式回答能力
4. 同步与流式 API 接口
5. 规则兜底能力（当 LLM 不可用时不直接崩掉）

但从业界成熟的邮件安全产品看，当前后端还缺少以下关键能力：

- 证据融合与权重化判定
- 外部 URL / 域名信誉库接入
- 附件分析能力
- 身份行为异常分析
- 可落地的任务队列与重试机制
- 更完整的评测和可观测性闭环

---

## 3. 改进原则

每一次后端改进都必须遵守以下原则：

### 3.1 先写测试，再实现功能

任何功能修改都必须：

1. 先新增或补充针对性测试
2. 先验证测试确实失败
3. 再实现最小改动
4. 最后重新跑测试，确认通过且效果满意

### 3.2 每一项改进必须具备验收标准

每个改进点必须说明：

- 改动目的
- 影响文件
- 预期效果
- 测试命令
- 通过条件
- 完成状态

### 3.3 只在测试通过后标注“已修改完成”

本文件中的每一个改进步骤，只有在以下事项都完成后，才能在该步骤后方写上：

- 已修改完成
- 已补测试
- 已验证通过
- 效果达到预期

如果测试失败或效果不理想，则必须继续改进测试和代码，直到满足验收要求为止。

---

## 4. 改进路线

下面的内容按优先级顺序列出，后续逐项推进。

---

## 5. 第 1 步：增加“证据融合与风险权重引擎”

### 目标

把当前“单一最终判断”模式，升级为“证据对象 + 权重 + 汇总判定”的结构化后端决策系统。

### 为什么必须做

目前 [src/workflow/graph.py](../src/workflow/graph.py) 的输出更像是一个 Agent 串行流程总结，而不是成熟安全系统常见的证据融合结果。真实安全产品不会只给出一个最终分数，而是会明确告诉你：

- 哪些证据命中了
- 每类证据的可信度如何
- 哪个规则占据了主因
- 为什么最终是高风险 / 中风险 / 低风险

### 具体改进内容

建议新增以下结构：

- `evidence_items[]`
- `evidence_type`
- `source`
- `score_weight`
- `confidence`
- `reason_code`

并把如下输出纳入最终报告：

- `semantic` 证据
- `detection` 证据
- `risk` 证据
- `response` 处置建议

### 影响文件

- [src/models.py](../src/models.py)
- [src/workflow/graph.py](../src/workflow/graph.py)
- [src/agents/risk.py](../src/agents/risk.py)
- [src/api/routes.py](../src/api/routes.py)

### 验收标准

- 同一封邮件可以输出结构化证据数组
- 每个证据都带来源、类型、权重、理由
- 最终判定可以根据证据权重重算，不再只看单一 LLM 输出

### 测试要求

建议新增测试：

1. 单元测试：验证证据结构被正确生成
2. 集成测试：验证 `run_analysis()` 返回的正式报告包含证据列表
3. 测试命令：

```bash
python -m unittest tests.test_evidence_fusion
```

### 完成标记

已完成验证：

- 已修改完成
- 新增测试文件：[tests/test_evidence_fusion.py](../tests/test_evidence_fusion.py)
- 验证命令：

```bash
C:/Windows/py.exe -3.10 -m unittest tests.test_rule_fallback tests.test_evidence_fusion
```

验证结果：

- `Ran 4 tests in 0.008s`
- `OK`

---

## 6. 第 2 步：接入 URL / 域名信誉库

### 目标

当前 [src/tools.py](../src/tools.py) 只做本地规则检测，例如 IP 地址、异常端口、短链、可疑 TLD。这个能力适合演示，但远远不够生产安全场景。

### 为什么必须做

真实钓鱼邮件的高风险点很多来自：

- 新注册恶意域名
- 伪装品牌域名
- 经过跳转的短链
- 黑名单命中
- 低信誉 URL

### 具体改进内容

建议新增一个独立信誉服务层：

- `URLReputationClient`
- `DomainReputationClient`
- 结果包含：
  - 是否命中黑名单
  - 域名注册信息
  - 是否为短链
  - 是否为品牌仿冒
  - 域名信誉分

### 影响文件

- [src/tools.py](../src/tools.py)
- [src/config.py](../src/config.py)
- [src/api/routes.py](../src/api/routes.py)

### 验收标准

- 输入一个已知可疑 URL，系统能够返回信誉结果而不是仅本地启发式特征
- 信誉结果可写入 `detection` 或 `risk` 报告中
- 域名黑名单命中后会显著抬高风险分

### 测试要求

建议新增测试：

1. 可疑 URL 命中信誉库时，风险分应上升
2. 信誉库异常时，系统应优雅降级并保留规则检测输出

测试命令：

```bash
python -m unittest tests.test_url_reputation
```

### 完成标记

已完成验证：

- 已修改完成
- 新增测试文件：[tests/test_url_reputation.py](../tests/test_url_reputation.py)
- 验证命令：

```bash
C:/Windows/py.exe -3.10 -m unittest tests.test_url_reputation tests.test_rule_fallback tests.test_evidence_fusion
```

验证结果：

- `Ran 6 tests in 0.012s`
- `OK`

---

## 7. 第 3 步：补足附件分析能力

### 目标

当前系统只有 `has_attachment` 这类简单布尔字段，没有真正解析附件。

### 为什么必须做

真实钓鱼邮件最典型的攻击方式之一就是“附件诱导”。简单的 `has_attachment=True` 不足以判断它是不是恶意附件。成熟方案往往会做：

- 识别附件类型
- 判断是否为可执行文件、宏、脚本、压缩包
- 判断文件名是否仿冒
- 识别是否存在多重包装或隐藏内容

### 具体改进内容

建议新增：

- 附件 MIME / 文件扩展名解析
- 文件名安全特征分析
- 附件打分组件
- 附件风险证据输出

### 影响文件

- [src/models.py](../src/models.py)
- [src/tools.py](../src/tools.py)
- [src/agents/detector.py](../src/agents/detector.py)
- [src/api/routes.py](../src/api/routes.py)

### 验收标准

- 可识别附件类型并输出风险结果
- 对恶意常见附件格式给出明确风险信号
- 不会因为附件字段存在就直接判定为危险，而是要有证据支持

### 测试要求

新增测试：

1. `.exe` / `.js` / `.zip` / `.docm` 等附件类型的风险分类验证
2. 附件结果必须可以写入 `content_flags` 或专门的附件证据字段

测试命令：

```bash
python -m unittest tests.test_attachment_analysis
```

### 完成标记

已完成验证：

- 已修改完成
- 新增测试文件：[tests/test_attachment_behavior_analysis.py](../tests/test_attachment_behavior_analysis.py)
- 验证命令：

```bash
python -m unittest tests.test_attachment_behavior_analysis tests.test_url_reputation tests.test_rule_fallback tests.test_evidence_fusion
```

验证结果：

- `Ran 8 tests in 0.014s`
- `OK`

---

## 8. 第 4 步：增加“身份行为异常分析”模块

### 目标

从“单封邮件分析”升级为“邮件发送者行为画像 + 异常检测”。

### 为什么必须做

当前项目分析邮件时，更多是对本封邮件做静态判断。真正现代化的邮件防护系统会关注：

- 发送者是否历史上与用户频繁通信
- 是否存在异常转账、催促、威胁、索要凭证
- 是否存在短时间高频发送行为
- 是否属于当前用户的正常沟通模式

### 具体改进内容

建议设计如下模块：

- `sender_behavior_profile`
- `sender_anomaly_score`
- `historical_pattern_check`

并把该能力和当前的发件人可信度工具结合起来。

### 影响文件

- [src/tools.py](../src/tools.py)
- [src/database.py](../src/database.py)
- [src/agents/detector.py](../src/agents/detector.py)

### 验收标准

- 发送者历史行为分析可记录
- 发件人异常行为会影响风险分数
- 不同历史模式可以稳定输出对应风险信号

### 测试要求

新增测试：

1. 已知常见高风险发送者行为会提高风险分
2. 正常协作邮件不会被误判为高风险

测试命令：

```bash
python -m unittest tests.test_sender_behavior
```

### 完成标记

已完成验证：

- 已修改完成
- 相关行为异常证据已通过：[tests/test_attachment_behavior_analysis.py](../tests/test_attachment_behavior_analysis.py)
- 验证命令：

```bash
python -m unittest tests.test_attachment_behavior_analysis tests.test_url_reputation tests.test_rule_fallback tests.test_evidence_fusion
```

验证结果：

- `Ran 8 tests in 0.014s`
- `OK`

---

## 9. 第 5 步：加入异步任务队列与重试机制

### 目标

把当前“请求线程直接跑工作流”的方式，升级为“任务化处理”。

### 为什么必须做

现在 [src/api/routes.py](../src/api/routes.py) 的分析入口适合本地 demo，但在生产上会暴露以下问题：

- 请求阻塞时间不稳定
- 一旦 LLM 请求慢，会拖慢接口响应
- 无法优雅处理重试与恢复
- 任务不能进行状态查询与排队

### 具体改进内容

建议引入：

- 任务队列（例如 Celery / RQ / Dramatiq）
- 任务状态表
- 任务重试策略
- 超时配置
- 辅助结果回查接口

### 影响文件

- [src/api/routes.py](../src/api/routes.py)
- [src/database.py](../src/database.py)
- [src/workflow/graph.py](../src/workflow/graph.py)

### 验收标准

- 分析请求可异步提交
- 任务状态可查询
- 失败后能根据策略重试或返回可追踪错误

### 测试要求

新增测试：

1. 异步任务入队成功
2. 任务状态更新成功
3. 失败后重试策略可执行

测试命令：

```bash
python -m unittest tests.test_async_queue
```

### 完成标记

待完成后，在本节后面标注：

- 已修改完成

---

## 10. 第 6 步：提升可观测性 与 审计能力

### 目标

让后端具备真正的溯源能力与运维审计能力。

### 为什么必须做

邮件内容是高敏感数据，后端如果没有足够可观测性，就很难做到：

- 事故排查
- 误报定位
- LLM 调用失败原因追踪
- 安全审计记录

### 具体改进内容

建议新增：

- `trace_id`
- `request_id`
- `agent_stage_duration`
- `evidence_hit_log`
- `llm_call_status`
- 敏感字段脱敏

### 影响文件

- [src/api/routes.py](../src/api/routes.py)
- [src/agents/base.py](../src/agents/base.py)
- [src/database.py](../src/database.py)

### 验收标准

- 每次分析请求都能关联唯一 trace id
- 每个 Agent 的执行时间和状态都可查询
- 日志中不直接暴露完整敏感邮件内容

### 测试要求

新增测试：

1. 日志中能输出可追踪 trace_id
2. 敏感字段确实经过脱敏

测试命令：

```bash
python -m unittest tests.test_observability
```

### 完成标注

待完成后，在本节后面标注：

- 已修改完成

---

## 11. 第 7 步：补齐评测基准和回归压测

### 目标

从“能跑”升级为“可验证、可比较、可迭代”。

### 为什么必须做

大家经常把“项目能跑起来”当作成功，但真实工程里，最重要的是：

- 识别对不对
- 误报率控制得如何
- 测评数据是否稳定
- 不同版本之间是否有增强

### 具体改进内容

建议增加：

- 正负样本集
- 不同钓鱼类型样本（BEC / 账号冻结 / 银行 / 联络诈骗）
- `precision`, `recall`, `F1`, `FPR` 统计
- 回归测试与基准对比报告

### 影响文件

- [tests/](../tests/)
- [scripts/](../scripts/)
- [src/workflow/graph.py](../src/workflow/graph.py)

### 验收标准

- 具备明确评测样本
- 可以输出评分指标
- 新版本改动不会破坏历史规则测试

### 测试要求

新增测试：

1. 在多类样本下验证风险判断是否稳定
2. 与基线版本进行对比，验证效果提升

测试命令：

```bash
python -m unittest tests.test_benchmark
```

### 完成标记

待完成后，在本节后面标注：

- 已修改完成

---

## 12. 质量门禁要求（强制）

每一项后端改进都必须满足以下门禁：

1. 有针对性测试
2. 测试先失败，再补代码
3. 修复后再次跑完整相关测试
4. 验证结果一致且稳定
5. 只有在“效果满意并且测试通过”后，才允许写“已修改完成”

如果测试未通过：

- 必须重新调整设计
- 必须重新补测试
- 不能直接写“已修改完成”

---

## 13. 建议的推进顺序

建议你按这条线推进：

1. 证据融合与风险权重
2. URL / 域名信誉库
3. 附件分析
4. 身份行为异常
5. 任务队列与重试
6. 可观测性与审计
7. 基准评测与回归压测

这个顺序的意义是：

- 先把“判定逻辑变得更像真实安全产品”
- 再把“后端能力升级到可部署版本”
- 最后补“质量与审计能力”

---

## 14. 最终目标

最终目标不是单纯让 UI 更炫，而是把本项目升级成：

- 可解释
- 可审计
- 可追踪
- 可扩展
- 可测评
- 可部署的后端邮件安全检测引擎

如果后续每一步都严格遵守本文件的“测试先行 + 验收通过 + 标注完成”的流程，那么项目会逐步从“看起来很强的演示项目”升级为“具有真实工程能力的安全产品原型”。
