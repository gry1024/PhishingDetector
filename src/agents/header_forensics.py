"""
邮件头取证分析 Agent
====================
专注于邮件头（Headers）的深层取证分析：
- SPF/DKIM/DMARC 认证状态解析
- Reply-To / Return-Path / From 一致性检测
- X-Mailer 异常识别
- Received 路由链分析
- 发件人显示名与地址一致性
"""

import json
import re
import logging

from src.agents.base import BaseAgent, EventCallback
from src.models import EmailInput

logger = logging.getLogger(__name__)


class HeaderForensicsResult:
    """邮件头取证结果（轻量 dataclass，避免修改 models.py 过多）"""

    def __init__(
        self,
        spf_status: str = "unknown",
        dkim_status: str = "unknown",
        dmarc_status: str = "unknown",
        auth_alignment: str = "unknown",
        reply_to_anomaly: bool = False,
        return_path_anomaly: bool = False,
        display_name_mismatch: bool = False,
        suspicious_x_mailer: bool = False,
        received_hops: int = 0,
        header_anomalies: list[str] = None,
        anomaly_score: float = 0.0,
        explanation: str = "",
    ):
        self.spf_status = spf_status
        self.dkim_status = dkim_status
        self.dmarc_status = dmarc_status
        self.auth_alignment = auth_alignment
        self.reply_to_anomaly = reply_to_anomaly
        self.return_path_anomaly = return_path_anomaly
        self.display_name_mismatch = display_name_mismatch
        self.suspicious_x_mailer = suspicious_x_mailer
        self.received_hops = received_hops
        self.header_anomalies = header_anomalies or []
        self.anomaly_score = anomaly_score
        self.explanation = explanation

    def to_dict(self) -> dict:
        return {
            "spf_status": self.spf_status,
            "dkim_status": self.dkim_status,
            "dmarc_status": self.dmarc_status,
            "auth_alignment": self.auth_alignment,
            "reply_to_anomaly": self.reply_to_anomaly,
            "return_path_anomaly": self.return_path_anomaly,
            "display_name_mismatch": self.display_name_mismatch,
            "suspicious_x_mailer": self.suspicious_x_mailer,
            "received_hops": self.received_hops,
            "header_anomalies": self.header_anomalies,
            "anomaly_score": self.anomaly_score,
            "explanation": self.explanation,
        }


class HeaderForensicsAgent(BaseAgent):
    """邮件头取证分析 Agent"""

    name = "邮件头取证分析"
    icon = "📨"

    def analyze(self, email: EmailInput, callback: EventCallback = None, **kwargs) -> dict:
        self.emit_sub_step("开始解析邮件头认证协议与路由信息", callback=callback)

        headers = email.headers or {}
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except Exception:
                headers = {}

        result = HeaderForensicsResult()

        # 1. 解析 SPF/DKIM/DMARC
        result.spf_status = self._normalize_auth(str(headers.get("spf", "unknown")))
        result.dkim_status = self._normalize_auth(str(headers.get("dkim", "unknown")))
        result.dmarc_status = self._normalize_auth(str(headers.get("dmarc", "unknown")))

        self.emit_sub_step(
            f"认证状态：SPF={result.spf_status}, DKIM={result.dkim_status}, DMARC={result.dmarc_status}",
            callback=callback,
        )

        # 2. 认证对齐性评估
        auth_failures = [
            result.spf_status == "fail",
            result.dkim_status == "fail",
            result.dmarc_status == "fail",
        ]
        auth_missing = [
            result.spf_status in {"none", "neutral", "unknown"},
            result.dkim_status in {"none", "neutral", "unknown"},
            result.dmarc_status in {"none", "neutral", "unknown"},
        ]

        if any(auth_failures):
            result.auth_alignment = "fail"
            result.header_anomalies.append("SPF/DKIM/DMARC 至少一项认证失败")
        elif all(auth_missing):
            result.auth_alignment = "missing"
            result.header_anomalies.append("邮件头缺少 SPF/DKIM/DMARC 认证信息")
        elif any(auth_missing):
            result.auth_alignment = "partial"
            result.header_anomalies.append("SPF/DKIM/DMARC 认证信息不完整")
        else:
            result.auth_alignment = "pass"

        # 3. Reply-To / Return-Path / From 一致性
        from_addr = self._extract_email(email.sender or "")
        reply_to = self._extract_email(str(headers.get("reply-to", "")))
        return_path = self._extract_email(str(headers.get("return-path", "")))

        if reply_to and reply_to.lower() != from_addr.lower():
            result.reply_to_anomaly = True
            result.header_anomalies.append(f"Reply-To ({reply_to}) 与发件人 ({from_addr}) 不一致")

        if return_path and return_path.lower() != from_addr.lower():
            result.return_path_anomaly = True
            result.header_anomalies.append(f"Return-Path ({return_path}) 与发件人 ({from_addr}) 不一致")

        # 4. 显示名与地址一致性
        display_name = self._extract_display_name(email.sender or "")
        if display_name:
            # 如果显示名包含知名品牌但地址不是该品牌域名
            brands = ["apple", "microsoft", "google", "amazon", "paypal", "bank", "alipay", "wechat", "taobao"]
            display_lower = display_name.lower()
            sender_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
            for brand in brands:
                if brand in display_lower and brand not in sender_domain:
                    result.display_name_mismatch = True
                    result.header_anomalies.append(f"显示名包含品牌 '{display_name}'，但发件域名 '{sender_domain}' 不匹配")
                    break

        # 5. X-Mailer 异常
        x_mailer = str(headers.get("x-mailer", "")).lower()
        suspicious_mailers = ["unknown", "custom", "script", "python", "java", "curl", "wget", "phpmailer"]
        if x_mailer and any(sm in x_mailer for sm in suspicious_mailers):
            result.suspicious_x_mailer = True
            result.header_anomalies.append(f"X-Mailer 字段可疑：{x_mailer}")

        # 6. Received 路由链
        received = headers.get("received", [])
        if isinstance(received, str):
            received = [received]
        result.received_hops = len(received)
        if result.received_hops == 0:
            result.header_anomalies.append("缺少 Received 路由链信息")

        # 7. 计算异常评分
        result.anomaly_score = self._calc_anomaly_score(result)

        # 8. 生成说明
        result.explanation = self._build_explanation(result)

        self.emit_sub_step(
            f"邮件头取证完成：发现 {len(result.header_anomalies)} 项异常，异常评分 {result.anomaly_score:.0f}/100",
            callback=callback,
        )

        return {"header_forensics": result}

    def _normalize_auth(self, value: str) -> str:
        value = value.lower().strip()
        if value in {"pass", "ok", "true", "yes"}:
            return "pass"
        if value in {"fail", "failed", "false", "no"}:
            return "fail"
        if value in {"none", "neutral"}:
            return "none"
        if value in {"temperror", "permerror", "softfail"}:
            return "error"
        return "unknown"

    def _extract_email(self, text: str) -> str:
        match = re.search(r"[\w.-]+@[\w.-]+\.\w+", text)
        return match.group(0) if match else ""

    def _extract_display_name(self, text: str) -> str:
        text = text.strip()
        if "<" in text and ">" in text:
            return text.split("<")[0].strip().strip('"')
        return ""

    def _calc_anomaly_score(self, result: HeaderForensicsResult) -> float:
        score = 0.0
        if result.spf_status == "fail":
            score += 25
        elif result.spf_status == "none":
            score += 10
        if result.dkim_status == "fail":
            score += 25
        elif result.dkim_status == "none":
            score += 10
        if result.dmarc_status == "fail":
            score += 25
        elif result.dmarc_status == "none":
            score += 10
        if result.reply_to_anomaly:
            score += 20
        if result.return_path_anomaly:
            score += 15
        if result.display_name_mismatch:
            score += 20
        if result.suspicious_x_mailer:
            score += 10
        if result.received_hops == 0:
            score += 10
        return min(score, 100)

    def _build_explanation(self, result: HeaderForensicsResult) -> str:
        parts = []
        parts.append(
            f"SPF={result.spf_status}, DKIM={result.dkim_status}, DMARC={result.dmarc_status}, "
            f"对齐性={result.auth_alignment}。"
        )
        if result.header_anomalies:
            parts.append(f"异常项：{'; '.join(result.header_anomalies)}。")
        else:
            parts.append("未发现明显邮件头异常。")
        parts.append(f"路由跳数 {result.received_hops}，异常评分 {result.anomaly_score:.0f}/100。")
        return " ".join(parts)
