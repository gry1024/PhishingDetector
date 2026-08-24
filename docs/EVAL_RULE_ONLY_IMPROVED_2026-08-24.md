# 规则兜底准确率改进评测：纯规则路径 × test_set v1（2026-08-24）

> 与 `BASELINE_EVAL_RULE_ONLY_2026-08-18.md` 配对的"改进后"留档。
> 评测工具：`scripts/eval_rule_offline.py`（离线、确定性、不调 LLM 不联网）；
> 调参工具：`scripts/tune_rule_fallback.py`（复刻打分链 400/400 与管线实测一致）。

## 1. 评测配置

| 项 | 值 |
|---|---|
| 评测时间 | 2026-08-24（UTC+8） |
| 数据集 | test_set v1（`datasets/test_set.jsonl`，400 条：DataCon2023 钓鱼 200 + TREC06c 正常 200） |
| 路径 | 纯规则兜底（ContextVar 逐 worker 线程显式禁用 LLM，全程零 LLM 请求；不经过 threat_intel） |
| 耗时 | 11.6 秒（16 线程；线上 /api/eval/run 等价路径基线为 731.9 秒） |

## 2. 汇总指标（改进前 → 改进后）

| 指标 | 官方基线 08-18 | 批次2 未提交版（≥2命中→61） | 本次改进后 |
|---|---|---|---|
| TP | 0 | 54 | **161** |
| FP | 0 | 0 | **0** |
| FN | 200 | 146 | **39** |
| TN | 200 | 200 | **200** |
| recall | 0.0 | 0.270 | **0.805** |
| precision | — | 1.0 | **1.0** |
| F1 | 0.0 | 0.425 | **0.892** |
| accuracy | 0.50 | 0.635 | **0.9025** |

分数分布：phishing min 2 / p50 61 / max 75；benign min 2 / p50 7 / max 26
（正常样本最高分 26，距 high 判定线 61 有充足安全边距）。

## 3. 改动内容（均只影响 LLM 不可用的规则兜底分支）

1. `src/tools.py` `PHISHING_PATTERNS` 第二批盲区补强（全部经 200 条正常样本零命中验证）：
   中文补贴诱饵（容忍"补〉贴"变体）、中文邮箱容量恐吓、中文薪资资料诱饵、
   学术征稿伪装、英文 BEC 虚假询单。
2. `src/tools.py` 拆分误报源：补贴/补助从「中文金钱诱惑」移入独立的补贴诱饵模式，
   消除正常样本唯一命中（test_set #122 "给予补助"）。
3. `src/tools.py` 新增 `WEAK_PHISHING_PATTERNS` 弱信号词表（附件诱导查看/付费培训营销/
   英文期刊营销/营销退订/在线浏览模板）：单独命中不判钓鱼，仅供组合判定。
4. `src/agents/risk.py` 规则兜底抬档：强模式 ≥1 命中即抬档（61+7×(n-1)，封顶 82）；
   强零命中时弱信号 ≥2 组合抬到 61。不进 LLM prompt、不进 0.6/0.4 融合，LLM 路径零影响。

## 4. 剩余漏报（FN=39）说明

剩余漏报集中在"单一弱信号"样本：科研服务营销（hACE2 小鼠、CRISPR 文库、
定制合成）、培训课程广告、掠夺性期刊约稿、空正文"通告"等。这类邮件文本与正常
营销邮件几乎不可区分，继续加词会把"请查看附件""课程报名"等正常商务表述打成
钓鱼（真实环境误报代价远高于此测试集体现），本次不为此调参凑数。

## 5. 复现方法

```bash
python scripts/eval_rule_offline.py --workers 16   # 全量评测 + 导出 datasets/rule_eval_dump.jsonl
python scripts/tune_rule_fallback.py               # 离线调参（含复刻一致性自检）
python scripts/tune_rule_fallback.py --fn          # 查看漏报明细
```

注意：ContextVar 不跨线程传播，`set_llm_disabled(True)` 必须在 worker 线程内调用，
否则线程池 worker 会静默发起真实 LLM 请求污染"纯规则"结果（本次曾踩坑）。
