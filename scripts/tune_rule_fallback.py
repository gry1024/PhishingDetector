"""
规则兜底打分离线调参
====================
读取 scripts/eval_rule_offline.py 导出的特征 dump（datasets/rule_eval_dump.jsonl），
在进程内精确复刻规则兜底链路（semantic 兜底意图 → risk 规则预评分 → 兜底抬档），
对候选打分规则做网格评估，秒级出混淆矩阵，不用重跑全量 Agent 链路。

复刻逻辑必须与以下来源保持一致（改动源头文件后需同步此处）：
- src/agents/semantic.py  SemanticAgent._fallback_semantic_result
- src/agents/risk.py      RiskAgent._rule_risk_score / 兜底分支
- src/tools.py            PHISHING_PATTERNS / extract_urls

用法：
    python scripts/tune_rule_fallback.py                 # 评估内置候选规则
    python scripts/tune_rule_fallback.py --fn            # 列出漏报样本明细
    python scripts/tune_rule_fallback.py --fp            # 列出误报样本明细
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools import PHISHING_PATTERNS, WEAK_PHISHING_PATTERNS  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_PATH = os.path.join(PROJECT_ROOT, "datasets", "rule_eval_dump.jsonl")

HIGH_LINE = 61  # risk_level == high 的分数线，is_phishing 判定线


# ---------------------------------------------------------------------------
# 复刻：semantic 规则兜底（src/agents/semantic.py::_fallback_semantic_result）
# ---------------------------------------------------------------------------
def fallback_semantic(subject: str, body: str, has_attachment: bool = False) -> dict:
    combined_text = f"{subject} {body}"
    lower = combined_text.lower()

    matched_desc = [
        desc for pattern, desc in PHISHING_PATTERNS
        if re.search(pattern, combined_text, re.IGNORECASE)
    ]
    pattern_text = ("命中 %d 个模式: %s" % (len(matched_desc), ", ".join(matched_desc))).lower() \
        if matched_desc else "未匹配到已知钓鱼话术模式"

    urls = re.findall(r'https?://[^\s<>"\')\]\}]+', combined_text)

    techniques = []
    if "紧急" in pattern_text or "urgent" in pattern_text:
        techniques.append("urgency")
    if "保密" in pattern_text or "secrecy" in pattern_text:
        techniques.append("secrecy")
    if "凭证" in pattern_text or "verify" in pattern_text or "password" in pattern_text:
        techniques.append("credential_theft")
    if "冒充" in pattern_text or "authority" in pattern_text:
        techniques.append("authority")

    attachment_bec_signals = any(k in lower for k in (
        "附件", "付款", "invoice", "payment", "单据", "收据", "对账",
    ))
    if attachment_bec_signals:
        techniques.append("financial_request")
    if not techniques:
        techniques = ["generic_social_engineering"]

    if matched_desc:
        intent, confidence = "phishing", 0.82
    elif has_attachment and attachment_bec_signals:
        intent, confidence = "suspicious", 0.76
    elif not urls:
        intent, confidence = "legitimate", 0.64
    else:
        intent, confidence = "suspicious", 0.55

    return {
        "intent": intent,
        "confidence": confidence,
        "techniques": techniques,
        "category_hits": len(matched_desc),
        "matched": matched_desc,
    }


# ---------------------------------------------------------------------------
# 复刻：risk 规则预评分（src/agents/risk.py::_rule_risk_score）
# ---------------------------------------------------------------------------
def rule_risk_score(semantic: dict, detection: dict) -> int:
    score = 0
    if semantic["intent"] == "phishing":
        score += 35 if semantic["confidence"] >= 0.65 else 22
    elif semantic["intent"] == "suspicious":
        score += 12
    score += min(len(semantic["techniques"]) * 4, 15)

    sender_score = detection["sender_score"]
    url_score = detection["url_score"]
    attachment_score = detection["attachment_score"]
    behavior_score = detection["behavior_score"]
    content_flags = detection["content_flags"]

    if sender_score < 0.5:
        score += int((1 - sender_score) * 18)
    if url_score < 0.6:
        score += int((1 - url_score) * 12)
    score += int(attachment_score * 12)
    score += int(behavior_score * 10)
    score += min(len(content_flags) * 3, 12)

    benign_signals = 0
    if sender_score >= 0.75:
        benign_signals += 1
    if url_score >= 0.75:
        benign_signals += 1
    if attachment_score < 0.2:
        benign_signals += 1
    if behavior_score < 0.3:
        benign_signals += 1
    if len(content_flags) == 0:
        benign_signals += 1
    if benign_signals >= 4:
        score = max(0, score - 18)
    elif benign_signals >= 3:
        score = max(0, score - 10)
    elif benign_signals >= 2:
        score = max(0, score - 4)

    return max(0, min(score, 100))


# ---------------------------------------------------------------------------
# 候选兜底抬档规则：输入样本特征，输出最终分
# ---------------------------------------------------------------------------
def make_rule(threshold: int, boost: int, require_signal: str = ""):
    """threshold 个品类命中即抬到 boost 分；require_signal 可追加门控条件。"""
    def rule(feat: dict) -> int:
        final = feat["rule_score"]
        if feat["category_hits"] >= threshold:
            if require_signal == "behavior" and feat["detection"]["behavior_score"] < 0.4:
                return final
            if require_signal == "flags" and not feat["detection"]["content_flags"]:
                return final
            final = max(final, boost)
        return final
    return rule


def graduated(base: int, step: int, cap: int):
    """命中越多抬得越高：base + step*(hits-1)，封顶 cap。"""
    def rule(feat: dict) -> int:
        final = feat["rule_score"]
        hits = feat["category_hits"]
        if hits >= 1:
            final = max(final, min(base + step * (hits - 1), cap))
        return final
    return rule


def new_rule(feat: dict) -> int:
    """当前 risk.py 规则兜底分支：强命中阶梯抬档（61+7*(n-1)，封顶82），
    强零命中时弱信号 ≥2 组合抬到 61。"""
    final = feat["rule_score"]
    if feat["category_hits"] >= 1:
        final = max(final, min(61 + 7 * (feat["category_hits"] - 1), 82))
    elif feat["weak_hits"] >= 2:
        final = max(final, 61)
    return final


CANDIDATES = {
    "新版(强>=1阶梯+弱>=2→61)": new_rule,
    "旧版(>=2命中→61)": make_rule(2, 61),
    ">=1命中→61(无弱信号)": make_rule(1, 61),
    ">=3命中→61": make_rule(3, 61),
    "阶梯61+8/命中(封顶85)": graduated(61, 8, 85),
}


def evaluate(results: list[dict], rule) -> dict:
    tp = fp = fn = tn = 0
    details = []
    for feat in results:
        final = rule(feat)
        predicted = final >= HIGH_LINE
        actual = feat["label"] == "phishing"
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
        details.append({**feat, "final_score": final, "predicted": predicted})
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(results), 4),
        "details": details,
    }


def main():
    parser = argparse.ArgumentParser(description="规则兜底打分离线调参")
    parser.add_argument("--dump", default=DUMP_PATH)
    parser.add_argument("--fn", action="store_true", help="打印指定规则的漏报明细")
    parser.add_argument("--fp", action="store_true", help="打印指定规则的误报明细")
    parser.add_argument("--rule", default="新版(强>=1阶梯+弱>=2→61)", help="配合 --fn/--fp 使用的规则名")
    parser.add_argument("--hits-dist", action="store_true", help="按标签统计品类命中数分布")
    args = parser.parse_args()

    results = []
    with open(args.dump, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            row["rule_score_pipeline"] = row["rule_score"]  # 管线实测值，用于一致性自检
            sem = fallback_semantic(row["subject"], row["body"])
            row["category_hits"] = sem["category_hits"]
            row["matched"] = sem["matched"]
            row["weak_hits"] = sum(
                1 for pattern, _ in WEAK_PHISHING_PATTERNS
                if re.search(pattern, f"{row['subject']} {row['body']}", re.IGNORECASE)
            )
            row["semantic_recomputed"] = sem
            row["rule_score"] = rule_risk_score(sem, row["detection"])
            results.append(row)

    # 一致性自检：复刻的 rule_score 与管线实测值的偏差
    # （若 tools.py 的词表在 dump 生成后被改过，偏差异属预期，仅作提示）
    mismatches = [r for r in results if r["rule_score"] != r["rule_score_pipeline"]]
    print(f"复刻自检：{len(results) - len(mismatches)}/{len(results)} 条 rule_score 与管线实测一致")
    for r in mismatches[:5]:
        print(
            f"  偏差 [{r['index']}] 管线={r['rule_score_pipeline']} 复刻={r['rule_score']} "
            f"subj={r['subject'][:40]}"
        )

    if args.hits_dist:
        for label in ("phishing", "benign"):
            subset = [r["category_hits"] for r in results if r["label"] == label]
            dist = {}
            for h in subset:
                dist[h] = dist.get(h, 0) + 1
            print(f"{label} 品类命中数分布: {dict(sorted(dist.items()))} (n={len(subset)})")
        print()

    print(f"{'规则':<26} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'P':>7} {'R':>7} {'F1':>7} {'ACC':>7}")
    for name, rule in CANDIDATES.items():
        m = evaluate(results, rule)
        print(
            f"{name:<26} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} {m['tn']:>4} "
            f"{m['precision']:>7.3f} {m['recall']:>7.3f} {m['f1']:>7.3f} {m['accuracy']:>7.3f}"
        )

    if args.fn or args.fp:
        rule = CANDIDATES[args.rule]
        m = evaluate(results, rule)
        print(f"\n规则「{args.rule}」明细：")
        for d in m["details"]:
            is_fn = d["label"] == "phishing" and not d["predicted"]
            is_fp = d["label"] != "phishing" and d["predicted"]
            if (args.fn and is_fn) or (args.fp and is_fp):
                print(
                    f"  [{d['index']}] {d['label']} final={d['final_score']} rule={d['rule_score']} "
                    f"hits={d['category_hits']} {d['matched']} flags={d['detection']['content_flags']} "
                    f"subj={d['subject'][:50]}"
                )


if __name__ == "__main__":
    main()
