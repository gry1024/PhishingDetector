"""
样例测试脚本
============
使用预设的钓鱼邮件和正常邮件样例，验证检测工作流的正确性。
在终端中流式输出每个 Agent 的执行过程。

使用方式：
    python scripts/run_test.py
"""

import sys
import json
import logging
from pathlib import Path

# 将项目根目录加入 Python 路径
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.workflow.graph import build_workflow
from src.models import EmailInput

# 配置终端日志输出
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test")


# ---- 测试样例 ----
TEST_SAMPLES = [
    {
        "name": "钓鱼邮件 #1: 假冒银行紧急通知",
        "expected": "phishing",
        "email": {
            "subject": "【紧急】您的银行账户存在异常，请立即验证",
            "sender": "security@bankofchina-verify.com",
            "recipients": "user@example.com",
            "body": (
                "尊敬的用户：\n\n"
                "我们检测到您的账户存在异常登录行为。为保护您的资金安全，"
                "请在24小时内点击以下链接完成身份验证：\n\n"
                "http://192.168.1.100:8080/verify?id=user123\n\n"
                "如未在24小时内完成验证，您的账户将被临时冻结。\n\n"
                "中国银行安全中心\n"
                "客服热线：400-xxx-xxxx"
            ),
            "urls": ["http://192.168.1.100:8080/verify?id=user123"],
        },
    },
    {
        "name": "钓鱼邮件 #2: AI生成的CEO诈骗",
        "expected": "phishing",
        "email": {
            "subject": "关于紧急资金调拨的机密指示",
            "sender": "ceo.wang@company.com",
            "recipients": "finance@company.com",
            "body": (
                "张总：\n\n"
                "我正在参加一个机密的投资方会议，需要立即完成一笔资金调拨。"
                "这是我们与红杉资本合作项目的预付款，金额为 48 万欧元。\n\n"
                "请将款项转入以下账户（对方财务已确认）：\n"
                "开户行：德意志银行法兰克福分行\n"
                "IBAN：DE89 3704 0044 0532 0130 00\n"
                "户名：Sequoia Capital Partners GmbH\n\n"
                "这是高度机密项目，请勿向其他人透露。我会议结束后会详细解释。\n\n"
                "王总"
            ),
        },
    },
    {
        "name": "钓鱼邮件 #3: 英文凭证窃取",
        "expected": "phishing",
        "email": {
            "subject": "Action Required: Verify Your Microsoft 365 Account",
            "sender": "noreply@mircosoft-security.com",
            "recipients": "employee@company.com",
            "body": (
                "Dear User,\n\n"
                "We have detected unusual sign-in activity on your Microsoft 365 account "
                "from an unrecognized device.\n\n"
                "To secure your account, please verify your identity immediately by "
                "clicking the link below:\n\n"
                "https://login.mircosoft-verify.com/@secure-login/validate\n\n"
                "If you do not verify within 24 hours, your account will be suspended.\n\n"
                "Microsoft Security Team"
            ),
            "urls": ["https://login.mircosoft-verify.com/@secure-login/validate"],
        },
    },
    {
        "name": "正常邮件 #1: 团队周报",
        "expected": "legitimate",
        "email": {
            "subject": "本周工作总结和下周计划",
            "sender": "li.ming@company.com",
            "recipients": "team@company.com",
            "body": (
                "Hi all,\n\n"
                "以下是本周的工作总结和下周计划：\n\n"
                "本周完成：\n"
                "1. 完成了用户认证模块的重构\n"
                "2. 修复了3个线上bug\n"
                "3. 参加了客户需求评审会议\n\n"
                "下周计划：\n"
                "1. 开始新功能的开发\n"
                "2. 准备版本发布的测试用例\n\n"
                "如有问题请随时沟通。\n\n"
                "李明"
            ),
        },
    },
    {
        "name": "正常邮件 #2: 会议邀请",
        "expected": "legitimate",
        "email": {
            "subject": "Q3 季度评审会议邀请",
            "sender": "hr@company.com",
            "recipients": "all@company.com",
            "body": (
                "各位同事好，\n\n"
                "Q3 季度评审会议定于下周三（10月16日）下午2:00在3楼大会议室举行。\n\n"
                "议程：\n"
                "1. 各部门 Q3 业绩汇报\n"
                "2. Q4 目标讨论\n"
                "3. 年度评优提名\n\n"
                "请各部门负责人提前准备汇报材料。\n\n"
                "人力资源部"
            ),
        },
    },
]


def run_test():
    """执行所有测试样例"""
    print("=" * 70)
    print("  PhishingDetector 样例测试")
    print("=" * 70)

    # 构建工作流
    graph = build_workflow()
    results = []

    for i, sample in enumerate(TEST_SAMPLES, 1):
        print(f"\n{'─' * 70}")
        print(f"  测试 #{i}: {sample['name']}")
        print(f"  预期: {sample['expected']}")
        print(f"{'─' * 70}")

        initial_state = {
            "email": sample["email"],
            "workflow_log": [],
        }

        try:
            # 使用 stream 模式逐节点执行并打印日志
            final_state = initial_state.copy()
            for chunk in graph.stream(initial_state, stream_mode="updates"):
                for node_name, updates in chunk.items():
                    # 打印新增的日志
                    new_logs = updates.get("workflow_log", [])
                    for log_line in new_logs:
                        if log_line not in final_state.get("workflow_log", []):
                            print(f"  {log_line}")
                    final_state.update(updates)

            # 提取结果
            is_phishing = final_state.get("is_phishing", False)
            risk = final_state.get("risk", {})
            actual = "phishing" if is_phishing else "legitimate"
            match = "✅" if actual == sample["expected"] else "❌"

            print(f"\n  结果: {actual} | 风险: {risk.get('risk_score', 0)}/100 "
                  f"({risk.get('risk_level', '?')}) {match}")

            results.append({
                "name": sample["name"],
                "expected": sample["expected"],
                "actual": actual,
                "match": actual == sample["expected"],
                "risk_score": risk.get("risk_score", 0),
            })

        except Exception as e:
            print(f"  ❌ 执行失败: {e}")
            results.append({
                "name": sample["name"],
                "expected": sample["expected"],
                "actual": "error",
                "match": False,
                "risk_score": 0,
            })

    # ---- 汇总报告 ----
    print(f"\n{'=' * 70}")
    print("  测试汇总")
    print(f"{'=' * 70}")
    passed = sum(1 for r in results if r["match"])
    total = len(results)
    print(f"  通过: {passed}/{total}")
    for r in results:
        status = "✅" if r["match"] else "❌"
        print(f"  {status} {r['name']} | 预期:{r['expected']} 实际:{r['actual']} | 风险:{r['risk_score']}")


if __name__ == "__main__":
    run_test()
