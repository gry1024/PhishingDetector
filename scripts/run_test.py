"""
端到端测试脚本
==============
使用预设的钓鱼/正常邮件样例，调用真实 LLM 验证整个工作流。
在终端中流式输出每个 Agent 的工具调用和分析过程。
"""

import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.models import EmailInput
from src.workflow.graph import run_analysis

# ---- 测试样例 ----
SAMPLES = [
    {
        "name": "钓鱼 #1: 假冒银行",
        "expected": True,
        "email": EmailInput(
            subject="【紧急】您的银行账户存在异常，请立即验证",
            sender="security@bankofchina-verify.com",
            body="尊敬的用户：\n\n我们检测到您的账户存在异常登录行为。为保护您的资金安全，"
                 "请在24小时内点击以下链接完成身份验证：\n\n"
                 "http://192.168.1.100:8080/verify?id=user123\n\n"
                 "如未在24小时内完成验证，您的账户将被临时冻结。\n\n中国银行安全中心",
            urls=["http://192.168.1.100:8080/verify?id=user123"],
        ),
    },
    {
        "name": "钓鱼 #2: CEO诈骗(BEC)",
        "expected": True,
        "email": EmailInput(
            subject="关于紧急资金调拨的机密指示",
            sender="ceo.wang@company.com",
            body="张总：\n\n我正在参加一个机密的投资方会议，需要立即完成一笔资金调拨。"
                 "这是我们与红杉资本合作项目的预付款，金额为 48 万欧元。\n\n"
                 "请将款项转入以下账户（对方财务已确认）：\n"
                 "开户行：德意志银行法兰克福分行\n"
                 "IBAN：DE89 3704 0044 0532 0130 00\n"
                 "户名：Sequoia Capital Partners GmbH\n\n"
                 "这是高度机密项目，请勿向其他人透露。\n\n王总",
        ),
    },
    {
        "name": "正常 #1: 团队周报",
        "expected": False,
        "email": EmailInput(
            subject="本周工作总结和下周计划",
            sender="li.ming@company.com",
            body="Hi all,\n\n以下是本周的工作总结和下周计划：\n\n"
                 "本周完成：\n1. 完成了用户认证模块的重构\n2. 修复了3个线上bug\n"
                 "3. 参加了客户需求评审会议\n\n"
                 "下周计划：\n1. 开始新功能的开发\n2. 准备版本发布的测试用例\n\n"
                 "如有问题请随时沟通。\n\n李明",
        ),
    },
]


def run_test():
    """运行所有测试样例"""
    print("=" * 70)
    print("  PhishingDetector 端到端测试（真实 LLM 调用）")
    print("=" * 70)

    results = []
    for i, sample in enumerate(SAMPLES, 1):
        print(f"\n{'─' * 70}")
        print(f"  [{i}/{len(SAMPLES)}] {sample['name']}")
        print(f"  预期: {'钓鱼' if sample['expected'] else '正常'}")
        print(f"{'─' * 70}")

        def callback(event):
            """实时打印事件"""
            etype = event.get("type", "")
            data = event.get("data", {})

            if etype == "agent_start":
                print(f"\n  ▸ {data.get('icon', '')} {data['agent']} 开始分析...")
            elif etype == "tool_call":
                print(f"    🔧 [{data['tool']}] {data['output'][:80]}")
            elif etype == "thinking":
                chunk = data.get("chunk", "")
                if chunk and len(chunk) < 100:
                    print(f"    💭 {chunk[:80]}")
            elif etype == "agent_done":
                result = data.get("result", {})
                print(f"  ✓ {data['agent']} 完成")
                # 打印关键结果
                for key in ["intent", "risk_score", "risk_level", "action", "sender_score", "url_score"]:
                    if key in result:
                        print(f"    {key}: {result[key]}")
            elif etype == "complete":
                pass
            elif etype == "error":
                print(f"  ❌ 错误: {data.get('message', '')}")

        try:
            report = run_analysis(sample["email"], callback=callback)
            actual = report.get("is_phishing", False)
            match = actual == sample["expected"]

            print(f"\n  {'✅' if match else '❌'} 结果: "
                  f"{'钓鱼' if actual else '正常'} | "
                  f"风险: {report.get('risk_score', 0)}/100 "
                  f"({report.get('risk_level', '?')})")

            results.append({"name": sample["name"], "match": match, "report": report})

        except Exception as e:
            print(f"  ❌ 执行失败: {e}")
            results.append({"name": sample["name"], "match": False, "report": {}})

    # ---- 汇总 ----
    print(f"\n{'=' * 70}")
    print(f"  测试汇总: {sum(1 for r in results if r['match'])}/{len(results)} 通过")
    print(f"{'=' * 70}")
    for r in results:
        print(f"  {'✅' if r['match'] else '❌'} {r['name']}")


if __name__ == "__main__":
    run_test()
