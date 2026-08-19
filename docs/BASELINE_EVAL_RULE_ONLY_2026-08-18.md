# 基线评测报告：纯规则路径 × test_set v1（2026-08-18）

> 本文件是评测中心的首次基线留档，作为后续阈值校准（safe/low 边界、融合权重 0.4/0.6）的对照基准。
> 如实记录，未做任何调参凑数。

## 1. 评测配置

| 项 | 值 |
|---|---|
| 评测时间 | 2026-08-18（UTC+8） |
| 数据集 | test_set v1（`datasets/test_set.jsonl`，400 条） |
| 数据集构成 | DataCon2023 邮件安全赛道（Coremail）真实中文钓鱼邮件 200 条 + TREC06c 中文语料 ham 部分真实正常邮件 200 条 |
| 抽样方式 | 固定随机种子 `20260818` 分层抽样（脚本：`scripts/download_datasets.py` 的 `build_test_set()`） |
| use_llm | false（纯规则路径，ContextVar 显式禁用 LLM） |
| skip_web_search | true（threat_intel 跳过联网检索） |
| limit | 400（全量） |
| 总耗时 | 731.9 秒（约 12.2 分钟，约 1.8 秒/样本） |
| job_id | dfe094ffe64b |

## 2. 汇总指标

```json
{
  "total": 400,
  "tp": 0,
  "fp": 0,
  "fn": 200,
  "tn": 200,
  "precision": 0.0,
  "recall": 0.0,
  "f1": 0.0,
  "accuracy": 0.5,
  "use_llm": false,
  "skip_web_search": true,
  "elapsed_sec": 731.9
}
```

明细：400 条全部成功，0 条 error。

## 3. 判定分布（真实性核查）

| 真实标签 | safe | medium | high/critical |
|---|---|---|---|
| phishing（200） | 171 | 29 | 0 |
| benign（200） | 200 | 0 | 0 |

- risk_score 区间：min 2.0 / max 43.0 / mean 12.1；
- 钓鱼样本最高分 43（medium 档，距 high 阈值线 61 分尚远）；
- `is_phishing` 判定线为 high/critical，故 TP=0。

## 4. 结论

1. **纯规则路径在真实中文钓鱼邮件上召回率为 0%**：DataCon2023 的真实钓鱼邮件（BEC、补贴/会议/招聘话术、仿系统通知）文本规整、技术特征弱，规则预评分最高只到 43 分（medium），无一越过 high 判定线。
2. **正常邮件零误报**：TREC06c ham 200 条全部判 safe，规则路径在中文正常邮件上不产生 FP。
3. **判别力主要由 LLM 层承担**：规则兜底的价值是保证链路可用，而非独立检出。后续阈值校准应以"规则分区分度不足"为前提，不能简单下调 high 线（会把 safe/medium 边界问题转化为误报）。
4. **评测基础设施可用**：skip_web_search 将单样本耗时从约 96s 降至约 1.8s（53 倍提速），400 条全量评测约 12 分钟可完成。

## 5. 与 rokibul（英文）基线对照

| 数据集 | 样本量 | tp | fp | fn | tn | recall |
|---|---|---|---|---|---|---|
| rokibul_phishing（英文，2026-08-17） | 20 | 1 | 0 | 19 | 0 | 5% |
| test_set v1（中文，2026-08-18） | 400 | 0 | 0 | 200 | 200 | 0% |

rokibul 为全钓鱼集（无 benign 样本，tn/fp 无意义）；test_set 为均衡集，可计算完整混淆矩阵。

## 6. 复现方法

```bash
# 1. 准备数据集（下载+解析+抽样，固定种子）
python scripts/download_datasets.py   # 选 5

# 2. 启动服务后发起评测
curl -X POST http://localhost:8000/api/eval/run \
  -H "Content-Type: application/json" \
  -d '{"dataset_id":"test_set","limit":400,"use_llm":false,"skip_web_search":true}'

# 3. 查询结果
curl http://localhost:8000/api/eval/<job_id>
```
