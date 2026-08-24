"""
离线纯规则批量评测 + 特征导出
==============================
用途：
1. 不启动服务、不联网、不调 LLM，直接驱动 semantic → detector → risk 的规则兜底链路，
   对 datasets/test_set.jsonl 做批量评测（与 /api/eval/run 的 use_llm=false +
   skip_web_search=true 路径等价：risk 只消费 semantic/detection 两个上游结果，
   sender_profiler/header_forensics/threat_intel 不影响研判）。
2. 导出每条样本的中间特征（语义意图、检测分数、内容标记、规则分、模式命中），
   供 scripts/tune_rule_fallback.py 离线调参，避免每次调参都重跑全量链路。

用法：
    python scripts/eval_rule_offline.py                # 全量 400 条，8 线程
    python scripts/eval_rule_offline.py --limit 50     # 快速试跑
    python scripts/eval_rule_offline.py --workers 1    # 串行（调试）
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import database as db  # noqa: E402
from src import llm as llm_module  # noqa: E402
from src.models import EmailInput  # noqa: E402
from src.agents.semantic import SemanticAgent  # noqa: E402
from src.agents.detector import DetectorAgent  # noqa: E402
from src.agents.risk import RiskAgent  # noqa: E402
from src.tools import PHISHING_PATTERNS  # noqa: E402
import re  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_ROOT, "datasets", "test_set.jsonl")
DUMP_PATH = os.path.join(PROJECT_ROOT, "datasets", "rule_eval_dump.jsonl")

# 与 /api/eval/run 的样本构造保持一致（无附件标记、无邮件头、无预填 URL）
def _build_email(item: dict) -> EmailInput:
    return EmailInput(
        subject=item.get("subject") or "",
        sender=item.get("sender") or "",
        body=item.get("body") or "",
        urls=[],
        headers={},
        has_attachment=False,
    )


def _pattern_hits(text: str) -> list[str]:
    return [desc for pattern, desc in PHISHING_PATTERNS if re.search(pattern, text, re.IGNORECASE)]


def evaluate_one(item: dict) -> dict:
    """单样本规则兜底链路评测，返回特征+判定明细。

    ContextVar 不跨线程传播，必须在 worker 线程内显式禁用 LLM，
    否则 worker 会拿到默认值 False 并发起真实 LLM 请求。
    """
    token = llm_module.set_llm_disabled(True)
    try:
        email = _build_email(item)
        text = f"{email.subject} {email.body}"

        sem = SemanticAgent().analyze(email)["semantic"]
        det = DetectorAgent().analyze(email, semantic_result=sem)["detection"]
        risk_out = RiskAgent().analyze(email, semantic_result=sem, detection_result=det)
        risk = risk_out["risk"]
    finally:
        llm_module.reset_llm_disabled(token)

    hits = _pattern_hits(text)
    return {
        "index": item["index"],
        "label": (item.get("label") or "").lower(),
        "subject": item.get("subject") or "",
        "sender": item.get("sender") or "",
        "body": item.get("body") or "",
        "semantic": {
            "intent": sem.intent,
            "confidence": sem.confidence,
            "techniques": list(sem.persuasion_techniques),
        },
        "detection": {
            "sender_score": det.sender_score,
            "url_score": det.url_score,
            "attachment_score": det.attachment_score,
            "behavior_score": det.behavior_score,
            "content_flags": list(det.content_flags),
        },
        "rule_score": risk.rule_score,
        "final_score": risk.risk_score,
        "risk_level": risk.risk_level,
        "predicted": bool(risk_out["is_phishing"]),
        "pattern_hits": hits,
        "category_hits": len(hits),
    }


def main():
    parser = argparse.ArgumentParser(description="离线纯规则批量评测 + 特征导出")
    parser.add_argument("--limit", type=int, default=0, help="只评测前 N 条（0=全量）")
    parser.add_argument("--workers", type=int, default=8, help="并发线程数")
    parser.add_argument("--dump", default=DUMP_PATH, help="特征导出路径")
    args = parser.parse_args()

    db.init_db()

    items = []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            row["index"] = idx
            items.append(row)
    if args.limit:
        items = items[: args.limit]

    start = time.time()
    results = []
    # 增量写入 dump：长任务被中断时已完成的样本不丢失
    dump_f = open(args.dump, "w", encoding="utf-8")
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for i, res in enumerate(pool.map(evaluate_one, items), 1):
                results.append(res)
                dump_f.write(json.dumps(res, ensure_ascii=False) + "\n")
                dump_f.flush()
                if i % 25 == 0 or i == len(items):
                    print(f"进度 {i}/{len(items)}，已耗时 {time.time() - start:.0f}s", flush=True)
    finally:
        dump_f.close()

    # 汇总混淆矩阵（判定线：high/critical 视为钓鱼，与线上一致）
    tp = fp = fn = tn = 0
    for r in results:
        actual = r["label"] == "phishing"
        predicted = r["predicted"]
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # 分数分布（按真实标签分组）
    for label in ("phishing", "benign"):
        scores = [r["final_score"] for r in results if r["label"] == label]
        if scores:
            scores.sort()
            print(
                f"{label}: n={len(scores)} min={scores[0]} "
                f"p50={scores[len(scores)//2]} max={scores[-1]} "
                f"mean={sum(scores)/len(scores):.1f}"
            )

    summary = {
        "total": len(results), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(results), 4) if results else 0.0,
        "elapsed_sec": round(time.time() - start, 1),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    with open(args.dump, "w", encoding="utf-8") as f:
        for r in sorted(results, key=lambda x: x["index"]):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"特征已导出: {args.dump}")

if __name__ == "__main__":
    main()
