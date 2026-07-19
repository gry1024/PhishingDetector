"""快速端到端测试：用一封钓鱼邮件验证完整工作流"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import EmailInput
from src.workflow.graph import run_analysis
from src.database import init_db
init_db()

email = EmailInput(
    subject="【紧急】您的银行账户存在异常，请立即验证",
    sender="security@bankofchina-verify.com",
    body="尊敬的用户：我们检测到您的账户存在异常登录行为。为保护您的资金安全，"
         "请在24小时内点击以下链接完成身份验证：\n"
         "http://192.168.1.100:8080/verify?id=user123\n"
         "如未在24小时内完成验证，您的账户将被临时冻结。中国银行安全中心",
    urls=["http://192.168.1.100:8080/verify?id=user123"],
)

def callback(event):
    t = event.get("type", "")
    d = event.get("data", {})
    if t == "agent_start":
        print(f"\n>> {d.get('icon', '')} {d['agent']}")
    elif t == "tool_call":
        print(f"   TOOL [{d['tool']}] {d['output'][:70]}")
    elif t == "thinking":
        chunk = d.get("chunk", "")
        if len(chunk) < 80:
            print(f"   THINK: {chunk[:70]}")
    elif t == "agent_done":
        r = d.get("result", {})
        print(f"   DONE: {r}")
    elif t == "error":
        print(f"   ERROR: {d.get('message', '')}")

print("=" * 60)
print("PhishingDetector 快速端到端测试")
print("=" * 60)

report = run_analysis(email, callback=callback)

print(f"\n{'=' * 60}")
print(f"FINAL: phishing={report.get('is_phishing')} "
      f"score={report.get('risk_score')} "
      f"level={report.get('risk_level')}")
print(f"Action: {report.get('response', {}).get('action', 'N/A')}")
print(f"{'=' * 60}")
