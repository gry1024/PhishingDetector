"""
主编排 Agent（Orchestrator）
=============================
真正的多 Agent 调用架构：主编排器决定调用哪些子 Agent、调用顺序和策略。

核心特性：
- Orchestrator 通过 LLM 叙述自己的思考过程和决策逻辑
- Orchestrator 真正调用子 Agent（Python 函数调用），而非固定流水线
- 子 Agent 调用内嵌在 Orchestrator 的思考叙事中
- Orchestrator 可以灵活调整调用策略（跳过、重试、补充调用）
- 最终由 Orchestrator 综合所有子 Agent 结果生成完整报告
- 编排器思考包含元认知、多假设推理、置信度校准、反事实分析

子 Agent 作为可调用实体：
- 语义意图分析 Agent（SemanticAgent）
- 发件人画像分析 Agent（SenderProfilerAgent）
- 邮件头取证分析 Agent（HeaderForensicsAgent）
- 威胁情报关联 Agent（ThreatIntelAgent）
- 多维关联检测 Agent（DetectorAgent）
- 风险研判 Agent（RiskAgent）
- 响应处置 Agent（ResponseAgent）
"""

import json
import logging
from typing import Callable, Optional

from src.agents.base import BaseAgent, EventCallback
from src.agents.semantic import SemanticAgent
from src.agents.sender_profiler import SenderProfilerAgent
from src.agents.header_forensics import HeaderForensicsAgent
from src.agents.threat_intel import ThreatIntelAgent
from src.agents.detector import DetectorAgent
from src.agents.risk import RiskAgent
from src.agents.response import ResponseAgent
from src.llm import is_llm_available, LLMUnavailableError
from src.models import (
    EmailInput, SemanticResult, DetectionResult, RiskResult,
    ResponseResult, EvidenceItem, WorkflowState,
)
from src import database as db

logger = logging.getLogger(__name__)

ORCHESTRATOR_SYSTEM_PROMPT = """你是钓鱼邮件智能检测系统的主编排器。你的职责是：
1. 深入分析输入邮件的所有维度特征，从元认知角度审视自己的推理过程
2. 提出多个假设（钓鱼/正常/不确定），并为每个假设分配初始置信度
3. 依次调用专业的子 Agent 进行深度分析，根据每个子 Agent 的结果更新假设和置信度
4. 进行反事实分析：如果这封邮件不是钓鱼邮件，为什么会看起来像？反之亦然
5. 综合所有证据进行置信度校准，做出最终判定并给出可操作的安全建议

你拥有以下子 Agent 可以调用：
- 发件人画像分析：构建发件人的多维画像，检测品牌仿冒和域名可信度
- 邮件头取证分析：解析 SPF/DKIM/DMARC、路由链、显示名一致性
- 语义意图分析：深度理解邮件语义，识别钓鱼话术与社会工程攻击手法
- 威胁情报关联：将邮件特征与已知威胁模式（IOC、ATT&CK）进行关联
- 多维关联检测：从 URL、附件、行为异常等技术维度交叉验证
- 风险研判：融合所有检测结果，综合评估风险等级并映射 ATT&CK 框架
- 响应处置：根据风险等级制定精准的处置策略和安全建议

请先用自己的语言详细描述你的多假设推理过程（400-600字），包括：
- 邮件初步印象和第一直觉
- 三个假设（钓鱼/正常/不确定）的初始置信度
- 需要关注的关键线索和矛盾点
- 检测步骤安排和每步的预期收获
- 反事实思考：什么情况下这封邮件可能是合法的？

然后在新的一行输出 <<<JSON>>> 标记，最后输出严格 JSON：
{
    "strategy": "你选择的检测策略描述",
    "hypotheses": {
        "phishing": {"confidence": 0.0-1.0, "reasoning": "..."},
        "legitimate": {"confidence": 0.0-1.0, "reasoning": "..."},
        "uncertain": {"confidence": 0.0-1.0, "reasoning": "..."}
    },
    "key_clues": ["你识别到的关键线索列表"],
    "contradictions": ["矛盾点或不确定因素"],
    "expected_risk_direction": "你对风险方向的预判",
    "agents_to_call": ["sender_profiler", "header_forensics", "semantic", "threat_intel", "detector", "risk", "response"],
    "preliminary_opinion": "你的初步看法和置信度"
}"""


class OrchestratorAgent(BaseAgent):
    """
    主编排 Agent — 真正的多 Agent 调用架构
    
    Orchestrator 不是固定流水线，而是通过思考决策来调用子 Agent。
    它可以：
    - 先用 LLM 分析邮件，形成初步判断和策略
    - 根据邮件特征灵活调整子 Agent 调用顺序
    - 在子 Agent 之间进行思考叙事（为什么需要下一步）
    - 综合所有结果生成最终报告
    """

    name = "钓鱼检测编排器"
    icon = "🎯"

    # 子 Agent 注册表（7 个子 Agent）
    SUB_AGENTS = {
        "sender_profiler": {
            "agent_class": SenderProfilerAgent,
            "name": "发件人画像分析",
            "icon": "👤",
            "desc": "构建发件人多维画像，检测品牌仿冒和域名可信度",
        },
        "header_forensics": {
            "agent_class": HeaderForensicsAgent,
            "name": "邮件头取证分析",
            "icon": "📨",
            "desc": "解析 SPF/DKIM/DMARC 认证、路由链、显示名一致性",
        },
        "semantic": {
            "agent_class": SemanticAgent,
            "name": "语义意图分析",
            "icon": "🧠",
            "desc": "深度理解邮件语义，识别钓鱼话术与社会工程攻击",
        },
        "threat_intel": {
            "agent_class": ThreatIntelAgent,
            "name": "威胁情报关联",
            "icon": "🛰️",
            "desc": "IOC 指标匹配、ATT&CK 映射、知识库交叉验证",
        },
        "detector": {
            "agent_class": DetectorAgent,
            "name": "多维关联检测",
            "icon": "🔍",
            "desc": "从 URL、发件人、附件、行为等多维度交叉验证",
        },
        "risk": {
            "agent_class": RiskAgent,
            "name": "风险研判",
            "icon": "⚖️",
            "desc": "融合语义与检测结果，综合评估风险等级",
        },
        "response": {
            "agent_class": ResponseAgent,
            "name": "响应处置",
            "icon": "🛡️",
            "desc": "根据风险等级制定精准的处置策略",
        },
    }

    def __init__(self):
        super().__init__()
        # 预创建子 Agent 实例（避免每次调用时重复创建）
        self._sub_agent_instances = {}
        for key, meta in self.SUB_AGENTS.items():
            self._sub_agent_instances[key] = meta["agent_class"]()

    def analyze(
        self,
        email: EmailInput,
        callback: EventCallback = None,
        selected_steps: Optional[list[str]] = None,
        **kwargs,
    ) -> dict:
        """
        主编排分析流程
        
        Phase 1: Orchestrator 思考 — 用 LLM 分析邮件，形成策略
        Phase 2: 依次调用子 Agent — 真正的函数调用，内嵌在叙事中
        Phase 3: 综合结果生成报告
        """
        state = WorkflowState(email=email)

        # ---- Phase 1: Orchestrator 初步思考 ----
        self.emit_orchestrator_start(callback)
        strategy = self._phase1_orchestrator_think(email, callback)

        # 决定要调用哪些子 Agent
        agents_to_call = strategy.get("agents_to_call", ["semantic", "detector", "risk", "response"])
        if selected_steps:
            # 用户指定了步骤，尊重用户选择（但保证逻辑依赖）
            agents_to_call = self._ensure_dependencies(selected_steps)

        # ---- Phase 2: 依次调用子 Agent ----
        self._phase2_call_sub_agents(email, state, agents_to_call, callback)

        # ---- Phase 3: 综合生成报告 ----
        report = self._phase3_generate_report(email, state, strategy, callback)

        return report

    def emit_orchestrator_start(self, callback):
        """推送编排器启动事件"""
        if callback:
            callback({
                "type": "orchestrator_start",
                "data": {
                    "agent": self.name,
                    "icon": self.icon,
                }
            })

    def emit_orchestrator_thinking(self, text, callback):
        """推送编排器的思考叙事"""
        if callback:
            callback({
                "type": "orchestrator_thinking",
                "data": {"chunk": text}
            })

    def emit_agent_call(self, agent_key, callback):
        """推送子 Agent 调用事件"""
        meta = self.SUB_AGENTS[agent_key]
        if callback:
            callback({
                "type": "agent_call",
                "data": {
                    "agent_key": agent_key,
                    "agent_name": meta["name"],
                    "agent_icon": meta["icon"],
                    "agent_desc": meta["desc"],
                }
            })

    def emit_agent_result(self, agent_key, result_summary, callback):
        """推送子 Agent 返回结果事件"""
        meta = self.SUB_AGENTS[agent_key]
        if callback:
            callback({
                "type": "agent_result",
                "data": {
                    "agent_key": agent_key,
                    "agent_name": meta["name"],
                    "agent_icon": meta["icon"],
                    "result_summary": result_summary,
                }
            })

    def emit_report(self, report, callback):
        """推送最终报告事件"""
        if callback:
            callback({
                "type": "report",
                "data": report,
            })

    def _phase1_orchestrator_think(self, email: EmailInput, callback) -> dict:
        """
        Phase 1: 编排器进行多假设推理
        
        编排器阅读邮件内容，提出三个假设（钓鱼/正常/不确定），
        为每个假设分配初始置信度，并规划检测步骤。
        包含元认知反思和反事实分析。
        """
        # Step 1: 初步印象和第一直觉
        self.emit_orchestrator_thinking(
            f"收到一封邮件，让我先仔细阅读内容，然后从多个角度审视它的风险。\n"
            f"邮件主题：{email.subject or '(无主题)'}\n"
            f"发件人：{email.sender or '(未知)'}\n"
            f"正文摘要：{(email.body[:250] or '(空)')}...",
            callback,
        )

        # Step 2: 快速识别显性特征
        initial_observations = self._quick_observe(email)
        self.emit_orchestrator_thinking(
            f"初步扫描结果：{initial_observations}",
            callback,
        )

        # Step 3: 多假设推理 — 提出三个假设
        hypotheses = self._generate_hypotheses(email, initial_observations)
        self.emit_orchestrator_thinking(
            f"我基于初步印象，提出三个假设：\n"
            f"• 假设 A（钓鱼攻击）：置信度 {hypotheses['phishing']['confidence']:.0%}，理由：{hypotheses['phishing']['reasoning']}\n"
            f"• 假设 B（正常邮件）：置信度 {hypotheses['legitimate']['confidence']:.0%}，理由：{hypotheses['legitimate']['reasoning']}\n"
            f"• 假设 C（不确定/需进一步验证）：置信度 {hypotheses['uncertain']['confidence']:.0%}，理由：{hypotheses['uncertain']['reasoning']}",
            callback,
        )

        # Step 4: 反事实分析
        counterfactual = self._counterfactual_analysis(email, initial_observations)
        self.emit_orchestrator_thinking(
            f"让我做一个反事实思考：{counterfactual}",
            callback,
        )

        # Step 5: 元认知反思
        meta_reflection = self._meta_cognitive_reflection(initial_observations)
        self.emit_orchestrator_thinking(
            f"元认知反思：{meta_reflection}",
            callback,
        )

        # Step 6: LLM 策略思考（带规则兜底）
        if is_llm_available():
            self.emit_orchestrator_thinking(
                "现在让我调用大模型，从全局视角深入分析这封邮件的深层风险线索，更新假设置信度，并制定精细化的检测策略。",
                callback,
            )
            user_prompt = self._build_strategy_prompt(email, initial_observations)
            try:
                strategy = self.chat_json(ORCHESTRATOR_SYSTEM_PROMPT, user_prompt, callback=callback)
                # 合入多假设推理
                if "hypotheses" not in strategy:
                    strategy["hypotheses"] = hypotheses
                self.emit_orchestrator_thinking(
                    f"策略制定完成：{strategy.get('strategy', '全流程深度检测')}",
                    callback,
                )
                key_clues = strategy.get("key_clues", [])
                if key_clues:
                    self.emit_orchestrator_thinking(
                        f"关键线索：{', '.join(key_clues[:5])}",
                        callback,
                    )
                contradictions = strategy.get("contradictions", [])
                if contradictions:
                    self.emit_orchestrator_thinking(
                        f"矛盾点：{', '.join(contradictions[:3])}",
                        callback,
                    )
                return strategy
            except Exception as e:
                self.emit_orchestrator_thinking(
                    f"⚠️ LLM 策略思考不可用，采用规则推理策略。（原因：{str(e)[:80]}）",
                    callback,
                )
        else:
            self.emit_orchestrator_thinking(
                "LLM 未配置，采用规则推理策略（全流程检测 + 多假设校准）。",
                callback,
            )

        # 规则兜底策略
        return self._fallback_strategy(email, initial_observations, hypotheses)

    def _quick_observe(self, email: EmailInput) -> str:
        """快速观察邮件的显性特征"""
        observations = []

        if email.subject:
            # 紧急关键词
            urgent_keywords = ["紧急", "立即", "限时", "urgent", "immediately", "24小时"]
            if any(kw in email.subject.lower() for kw in urgent_keywords):
                observations.append("主题含有紧急施压关键词")
            # 验证关键词
            verify_keywords = ["验证", "核实", "verify", "confirm", "validate"]
            if any(kw in email.subject.lower() for kw in verify_keywords):
                observations.append("主题含有凭证验证诱导")

        if email.sender:
            # 异常发件人特征
            if any(tld in email.sender.lower() for tld in [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"]):
                observations.append("发件人使用可疑免费域名")
            if "-" in email.sender and "verify" in email.sender.lower():
                observations.append("发件人地址含有品牌仿冒特征")
            # 品牌名出现在域名但不在官方域名
            brands = ["apple", "microsoft", "google", "amazon", "paypal", "bank", "alipay", "wechat", "taobao"]
            sender_domain = email.sender.split("@")[-1].lower() if "@" in email.sender else ""
            sender_local = email.sender.split("@")[0].lower() if "@" in email.sender else ""
            for brand in brands:
                if brand in sender_domain or brand in sender_local:
                    official_domains = {
                        "apple": ["apple.com", "icloud.com"],
                        "microsoft": ["microsoft.com", "outlook.com", "office.com"],
                        "google": ["google.com", "gmail.com"],
                        "amazon": ["amazon.com", "amazon.cn"],
                        "paypal": ["paypal.com"],
                        "bank": ["bankofchina.com", "icbc.com.cn", "abchina.com"],
                        "alipay": ["alipay.com"],
                        "wechat": ["wechat.com", "qq.com"],
                        "taobao": ["taobao.com"],
                    }
                    if not any(d in sender_domain for d in official_domains.get(brand, [brand + ".com"])):
                        observations.append(f"疑似仿冒品牌「{brand}」")

        if email.urls:
            observations.append(f"包含 {len(email.urls)} 个 URL 链接")
            # 检查 IP 地址 URL
            import re
            for url in email.urls:
                if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                    observations.append("URL 使用 IP 地址（极高风险信号）")

        if email.has_attachment:
            observations.append("包含附件")

        # 正文关键词
        body_lower = email.body.lower() if email.body else ""
        if "冻结" in body_lower or "suspend" in body_lower:
            observations.append("正文含有账户冻结威胁")
        if "密码" in body_lower or "password" in body_lower or "验证码" in body_lower:
            observations.append("正文含有凭证窃取诱导")

        # 邮件头异常
        if isinstance(email.headers, dict):
            headers = email.headers or {}
            spf = str(headers.get("spf", "")).lower()
            dkim = str(headers.get("dkim", "")).lower()
            if spf == "fail" or dkim == "fail":
                observations.append("SPF/DKIM 校验失败")
            elif spf in {"none", "neutral"} or dkim in {"none", "neutral"}:
                observations.append("SPF/DKIM 校验缺失")

        if not observations:
            observations.append("未发现显性异常特征，需进一步深度分析")

        return "；".join(observations)

    def _generate_hypotheses(self, email: EmailInput, observations: str) -> dict:
        """基于初步观察生成三个假设"""
        high_risk_signals = any(kw in observations for kw in [
            "紧急施压", "凭证验证", "凭证窃取", "品牌仿冒", "可疑免费域名",
            "IP 地址", "SPF/DKIM 校验失败", "账户冻结威胁"
        ])
        no_risk_signals = any(kw in observations for kw in [
            "未发现显性异常"
        ])

        if high_risk_signals:
            phishing_conf = 0.65
            legitimate_conf = 0.10
            uncertain_conf = 0.25
            phishing_reason = "检测到多个高风险信号：紧急施压、凭证诱导、可疑发件人或 IP 地址 URL"
            legitimate_reason = "存在可能性：发件人可能是公司内部的安全提醒系统，紧急性有合理依据"
            uncertain_reason = "部分特征同时符合钓鱼和正常邮件的解释，需要技术维度验证"
        elif no_risk_signals:
            phishing_conf = 0.15
            legitimate_conf = 0.60
            uncertain_conf = 0.25
            phishing_reason = "虽然未发现显性风险，但钓鱼邮件可能伪装良好，需后续深度分析排除"
            legitimate_reason = "邮件特征看起来正常，没有常见的钓鱼信号"
            uncertain_reason = "缺少足够证据做出确定判断，需要更多技术层面的信息"
        else:
            phishing_conf = 0.40
            legitimate_conf = 0.30
            uncertain_conf = 0.30
            phishing_reason = "存在部分可疑特征，但不够充分，需要进一步验证"
            legitimate_reason = "某些特征可能是正常商业邮件的常见做法"
            uncertain_reason = "现有证据不足以明确判断方向"

        return {
            "phishing": {"confidence": phishing_conf, "reasoning": phishing_reason},
            "legitimate": {"confidence": legitimate_conf, "reasoning": legitimate_reason},
            "uncertain": {"confidence": uncertain_conf, "reasoning": uncertain_reason},
        }

    def _counterfactual_analysis(self, email: EmailInput, observations: str) -> str:
        """反事实分析：如果这不是钓鱼邮件，为什么看起来像？"""
        subject = email.subject or ""
        body = email.body or ""
        sender = email.sender or ""

        counterfactual = "如果这封邮件是合法的："
        legit_explanations = []

        if any(kw in subject.lower() for kw in ["紧急", "urgent", "立即", "immediately"]):
            legit_explanations.append("紧急主题可能是真实的安全告警或系统维护通知")
        if any(kw in body.lower() for kw in ["验证", "verify", "密码", "password"]):
            legit_explanations.append("验证请求可能是真实的账户安全检查流程")
        if "@" in sender and any(c in sender for c in ["-", "."]):
            legit_explanations.append("发件人域名中的连字符和点可能只是子品牌的标准命名规范")

        if not legit_explanations:
            legit_explanations.append("如果这确实是合法邮件，那它的表达方式和格式选择值得质疑")

        counterfactual += "；".join(legit_explanations) + "。"

        counterfactual += "\n反过来，如果这确实是钓鱼邮件："
        phishing_explanations = []

        if "@" in sender:
            phishing_explanations.append("精心选择的发件人地址可能是为了在域名层面伪装可信来源")
        if email.urls:
            phishing_explanations.append("URL 可能是精心构造的钓鱼入口，看似正常域名但实际指向恶意服务器")
        if any(kw in body.lower() for kw in ["否则", "将被", "will be"]):
            phishing_explanations.append("威胁性措辞（否则将...）是社会工程攻击的核心话术")

        if not phishing_explanations:
            phishing_explanations.append("钓鱼者可能故意控制攻击强度以降低被检测的概率")

        counterfactual += "；".join(phishing_explanations) + "。"

        return counterfactual

    def _meta_cognitive_reflection(self, observations: str) -> str:
        """元认知反思：审视自身推理过程的局限性"""
        reflections = []

        # 信息完整性反思
        if "SPF/DKIM 校验缺失" in observations or "未发现显性异常" in observations:
            reflections.append("当前信息可能不完整——缺少邮件头认证数据可能导致误判")

        # 认知偏差反思
        if any(kw in observations for kw in ["紧急施压", "凭证验证", "账户冻结威胁"]):
            reflections.append("我需要警惕确认偏差——看到紧急措辞时容易倾向于判定为钓鱼，但紧急性本身也可能是真实的")

        # 检测盲区反思
        reflections.append("规则检测可能遗漏语义层面的微妙欺骗，需要 LLM 和知识库弥补这一盲区")

        # 置信度校准反思
        reflections.append("我的初始置信度是基于有限的显性特征得出的，随着后续子 Agent 的深入分析，置信度会动态更新")

        return "；".join(reflections)

    def _build_strategy_prompt(self, email, observations) -> str:
        """构造策略思考提示词"""
        parts = [
            "请分析以下邮件，进行多假设推理并制定检测策略：",
            f"主题: {email.subject or '(无)'}",
            f"发件人: {email.sender or '(未知)'}",
            f"正文: {(email.body[:600] or '(空)')}",
        ]
        if email.urls:
            parts.append(f"URL: {', '.join(email.urls[:5])}")
        if email.has_attachment:
            parts.append("⚠️ 包含附件")
        if isinstance(email.headers, dict) and email.headers:
            parts.append(f"邮件头: SPF={email.headers.get('spf','?')}, DKIM={email.headers.get('dkim','?')}, DMARC={email.headers.get('dmarc','?')}")
        parts.append(f"\n初步观察: {observations}")
        parts.append("\n请特别关注：发件人域名可信度、邮件头认证状态、URL 安全性、社会工程话术模式。")
        return "\n".join(parts)

    def _fallback_strategy(self, email, observations, hypotheses) -> dict:
        """LLM 不可用时的规则兜底策略（包含多假设推理）"""
        high_risk_signals = any(kw in observations for kw in [
            "紧急施压", "凭证验证", "凭证窃取", "品牌仿冒", "可疑免费域名",
            "IP 地址", "SPF/DKIM 校验失败", "账户冻结威胁"
        ])

        if high_risk_signals:
            strategy_desc = "检测到高风险信号，执行全流程深度检测（含发件人画像、邮件头取证、威胁情报关联）"
            agents = ["sender_profiler", "header_forensics", "semantic", "threat_intel", "detector", "risk", "response"]
        else:
            strategy_desc = "执行标准全流程检测，确保从多维度全面验证邮件安全性"
            agents = ["sender_profiler", "header_forensics", "semantic", "threat_intel", "detector", "risk", "response"]

        return {
            "strategy": strategy_desc,
            "hypotheses": hypotheses,
            "key_clues": observations.split("；"),
            "contradictions": [],
            "expected_risk_direction": "需进一步分析确认",
            "agents_to_call": agents,
            "preliminary_opinion": "规则兜底模式，执行全流程检测",
        }

    def _phase2_call_sub_agents(
        self,
        email: EmailInput,
        state: WorkflowState,
        agents_to_call: list[str],
        callback: EventCallback,
    ):
        """
        Phase 2: 依次调用子 Agent
        
        每个子 Agent 调用都内嵌在编排器的思考叙事中：
        - 编排器先叙述为什么要调用这个子 Agent
        - 然后真正调用子 Agent（Python 函数调用）
        - 子 Agent 的思考/工具/LLM 输出通过同一 callback 流式推送
        - 编排器接收结果后继续思考下一步
        """
        for agent_key in agents_to_call:
            if agent_key not in self.SUB_AGENTS:
                logger.warning(f"未知子 Agent: {agent_key}, 跳过")
                continue

            meta = self.SUB_AGENTS[agent_key]

            # 编排器叙事：为什么调用这个子 Agent
            narrative = self._call_narrative(agent_key, state)
            self.emit_orchestrator_thinking(narrative, callback)

            # 推送子 Agent 调用事件
            self.emit_agent_call(agent_key, callback)

            # 真正调用子 Agent
            agent_instance = self._sub_agent_instances[agent_key]
            try:
                result = agent_instance.analyze(
                    email,
                    callback=callback,
                    semantic_result=state.semantic,
                    detection_result=state.detection,
                    risk_result=state.risk,
                )

                # 更新工作流状态
                if agent_key == "sender_profiler" and "sender_profiler" in result:
                    obj = result["sender_profiler"]
                    state.sender_profiler_result = obj
                elif agent_key == "header_forensics" and "header_forensics" in result:
                    obj = result["header_forensics"]
                    state.header_forensics_result = obj
                elif agent_key == "semantic" and "semantic" in result:
                    state.semantic = result["semantic"]
                elif agent_key == "threat_intel" and "threat_intel" in result:
                    obj = result["threat_intel"]
                    state.threat_intel_result = obj
                elif agent_key == "detector" and "detection" in result:
                    state.detection = result["detection"]
                elif agent_key == "risk" and "risk" in result:
                    state.risk = result["risk"]
                    state.is_phishing = result.get("is_phishing", False)
                elif agent_key == "response" and "response" in result:
                    state.response = result["response"]

                # 推送子 Agent 结果事件
                result_summary = self._summarize_result(agent_key, state)
                self.emit_agent_result(agent_key, result_summary, callback)

                # 编排器叙事：接收结果后的思考
                post_narrative = self._post_call_narrative(agent_key, state)
                self.emit_orchestrator_thinking(post_narrative, callback)

            except Exception as e:
                logger.error(f"子 Agent {agent_key} 执行失败: {e}", exc_info=True)
                self.emit_orchestrator_thinking(
                    f"⚠️ 子 Agent「{meta['name']}」执行出现异常：{str(e)[:100]}。"
                    f"我将继续后续分析步骤。",
                    callback,
                )
                self.emit_agent_result(agent_key, {"error": str(e)[:200]}, callback)

    def _call_narrative(self, agent_key: str, state: WorkflowState) -> str:
        """编排器叙述调用子 Agent 的原因"""
        narratives = {
            "sender_profiler": (
                "首先，我需要搞清楚这封邮件到底是谁发的。"
                "发件人的身份是最基础也最重要的检测维度。"
                "我将调用「发件人画像分析」子 Agent，让它构建发件人的多维画像："
                "域名类型、品牌仿冒可能性、地址结构异常、声誉评分。"
                "如果发件人本身就不可信，后续分析的权重就需要调整。"
            ),
            "header_forensics": (
                "发件人画像给了我一个初步的发件人可信度评估。"
                "现在我要深入邮件头层面，进行取证级别的分析。"
                "我将调用「邮件头取证分析」子 Agent，让它解析 SPF/DKIM/DMARC 认证状态、"
                "Reply-To/Return-Path 一致性、路由链完整性、显示名匹配度。"
                "这些是技术层面最硬的证据——邮件头无法被正文伪装所掩盖。"
            ),
            "semantic": (
                "发件人和邮件头的分析已经完成了技术层面的基础验证。"
                "现在，我需要深入理解这封邮件的语义意图。"
                "我将调用「语义意图分析」子 Agent，让它识别邮件中可能存在的社会工程话术和钓鱼意图。"
                "技术维度是硬证据，语义维度是软证据——两者互补才能做出准确判断。"
            ),
            "threat_intel": (
                "语义分析已经给出了初步意图判断和话术识别。"
                "接下来，我需要将这些特征与已知的威胁情报模式进行关联。"
                "我将调用「威胁情报关联」子 Agent，让它进行 IOC 指标匹配、"
                "钓鱼话术库对比、ATT&CK 技战术映射、知识库交叉验证。"
                "这能告诉我：这封邮件的特征与已知攻击模式有多高的相似度。"
            ),
            "detector": (
                "威胁情报和语义分析都已完成。"
                "接下来，我需要从更多技术维度进行交叉验证。"
                "我将调用「多维关联检测」子 Agent，让它从 URL 安全、发件人身份、附件风险、行为异常等角度交叉验证。"
            ),
            "risk": (
                "所有前置分析的结果都已收集——发件人画像、邮件头取证、语义意图、威胁情报、多维检测。"
                "现在我需要综合这些证据，做出风险等级判定。"
                "我将调用「风险研判」子 Agent，让它融合所有分析结果，映射 ATT&CK 框架，给出最终风险评分。"
            ),
            "response": (
                "风险研判已经给出了明确的等级和评分。"
                "最后，我需要制定具体的处置策略和可操作的安全建议。"
                "我将调用「响应处置」子 Agent，让它根据风险等级生成告警消息、溯源报告和安全建议。"
            ),
        }
        base = narratives.get(agent_key, f"正在调用「{self.SUB_AGENTS[agent_key]['name']}」子 Agent。")

        # 根据已有状态增加上下文叙述
        # 发件人画像结果
        sp_result = getattr(state, "sender_profiler_result", None)
        if agent_key == "header_forensics" and sp_result:
            reputation = getattr(sp_result, "domain_reputation", "?")
            score = getattr(sp_result, "reputation_score", 0.5)
            brand = getattr(sp_result, "brand_impersonated", "")
            if brand:
                base += f"\n发件人画像显示声誉「{reputation}」（评分 {score:.2f}），且疑似仿冒品牌「{brand}」。邮件头取证将进一步验证身份真实性。"
            else:
                base += f"\n发件人画像显示声誉「{reputation}」（评分 {score:.2f}），邮件头取证将补充认证协议层面的证据。"

        # 邮件头取证结果
        hf_result = getattr(state, "header_forensics_result", None)
        if agent_key == "semantic" and hf_result:
            anomalies = getattr(hf_result, "header_anomalies", [])
            anomaly_score = getattr(hf_result, "anomaly_score", 0)
            base += f"\n邮件头取证发现 {len(anomalies)} 项异常（评分 {anomaly_score:.0f}/100），这些技术层面证据会影响语义分析的置信度校准。"

        # 语义结果
        if agent_key == "threat_intel" and state.semantic:
            intent = state.semantic.intent
            confidence = state.semantic.confidence
            techniques = state.semantic.persuasion_techniques
            base += f"\n当前语义判定为「{intent}」（置信度 {confidence:.0%}），识别到 {len(techniques)} 种话术。威胁情报将验证这些话术是否与已知攻击模式匹配。"

        # 威胁情报结果
        ti_result = getattr(state, "threat_intel_result", None)
        if agent_key == "detector" and ti_result:
            ioc_count = getattr(ti_result, "ioc_count", 0)
            threat_patterns = getattr(ti_result, "threat_patterns", [])
            base += f"\n威胁情报发现 {ioc_count} 个 IOC 和 {len(threat_patterns)} 种威胁话术模式。多维检测将从 URL 和附件等角度补充技术层面证据。"

        if agent_key == "risk" and state.semantic and state.detection:
            sender = state.detection.sender_score
            url = state.detection.url_score
            base += f"\n当前发件人可信度 {sender:.2f}，URL 安全分 {url:.2f}，研判将综合所有维度进行评分融合。"

        if agent_key == "response" and state.risk:
            level = state.risk.risk_level
            score = state.risk.risk_score
            base += f"\n当前风险等级「{level}」（评分 {score}/100），处置将据此匹配精准策略。"

        return base

    def _post_call_narrative(self, agent_key: str, state: WorkflowState) -> str:
        """编排器叙述接收子 Agent 结果后的思考（包含置信度更新）"""
        narratives = {
            "sender_profiler": (
                f"发件人画像分析完成。"
            ),
            "header_forensics": (
                f"邮件头取证分析完成。"
            ),
            "semantic": (
                f"语义意图分析完成。邮件被判定为「{state.semantic.intent}」，"
                f"置信度 {state.semantic.confidence:.0%}，"
                f"识别到 {len(state.semantic.persuasion_techniques)} 种社会工程话术。"
                f"这个结果显著影响了我对钓鱼假设的置信度。"
            ) if state.semantic else "语义分析完成，但未获得有效结果。",
            "threat_intel": (
                f"威胁情报关联分析完成。"
            ),
            "detector": (
                f"多维关联检测完成。发件人可信度 {state.detection.sender_score:.2f}，"
                f"URL 安全分 {state.detection.url_score:.2f}，"
                f"发现 {len(state.detection.content_flags)} 个内容标记。"
            ) if state.detection else "技术检测完成，但未获得有效结果。",
            "risk": (
                f"风险研判完成。最终风险等级「{state.risk.risk_level}」，"
                f"评分 {state.risk.risk_score}/100，"
                f"映射到 {len(state.risk.attack_techniques)} 个 ATT&CK 技术。"
                f"我现在可以基于此做出最终判定。"
            ) if state.risk else "风险研判完成，但未获得有效结果。",
            "response": (
                f"响应处置完成。处置动作：「{state.response.action}」，"
                f"已生成告警消息和安全建议。"
            ) if state.response else "响应处置完成，但未获得有效结果。",
        }
        base = narratives.get(agent_key, "子 Agent 执行完成。")

        # 动态添加置信度更新叙事
        sp_result = getattr(state, "sender_profiler_result", None)
        if agent_key == "sender_profiler" and sp_result:
            reputation = getattr(sp_result, "domain_reputation", "?")
            score = getattr(sp_result, "reputation_score", 0.5)
            brand = getattr(sp_result, "brand_impersonated", "")
            base += f"发件人声誉「{reputation}」（评分 {score:.2f}）。"
            if brand:
                base += f"⚠️ 检测到疑似仿冒品牌「{brand}」，钓鱼假设置信度上调。"

        hf_result = getattr(state, "header_forensics_result", None)
        if agent_key == "header_forensics" and hf_result:
            anomalies = getattr(hf_result, "header_anomalies", [])
            anomaly_score = getattr(hf_result, "anomaly_score", 0)
            auth_alignment = getattr(hf_result, "auth_alignment", "?")
            base += f"认证对齐性「{auth_alignment}」，发现 {len(anomalies)} 项异常（评分 {anomaly_score:.0f}/100）。"
            if anomaly_score >= 50:
                base += " ⚠️ 邮件头证据强烈指向钓鱼假设，置信度大幅上调。"

        ti_result = getattr(state, "threat_intel_result", None)
        if agent_key == "threat_intel" and ti_result:
            ioc_count = getattr(ti_result, "ioc_count", 0)
            threat_patterns = getattr(ti_result, "threat_patterns", [])
            threat_score = getattr(ti_result, "threat_score", 0)
            base += f"发现 {ioc_count} 个 IOC、{len(threat_patterns)} 种威胁话术、威胁评分 {threat_score:.0f}/100。"
            if threat_score >= 60:
                base += " ⚠️ 威胁情报与已知攻击模式高度匹配，钓鱼假设置信度继续上调。"

        return base

    def _summarize_result(self, agent_key: str, state: WorkflowState) -> dict:
        """为子 Agent 结果生成摘要"""
        summaries = {
            "sender_profiler": lambda: {
                "sender_type": getattr(state.sender_profiler_result, "sender_type", "?"),
                "domain_reputation": getattr(state.sender_profiler_result, "domain_reputation", "?"),
                "reputation_score": getattr(state.sender_profiler_result, "reputation_score", 0.5),
                "brand_impersonated": getattr(state.sender_profiler_result, "brand_impersonated", ""),
            } if hasattr(state, "sender_profiler_result") else {},
            "header_forensics": lambda: {
                "auth_alignment": getattr(state.header_forensics_result, "auth_alignment", "?"),
                "anomaly_score": getattr(state.header_forensics_result, "anomaly_score", 0),
                "header_anomalies": getattr(state.header_forensics_result, "header_anomalies", []),
            } if hasattr(state, "header_forensics_result") else {},
            "semantic": lambda: {
                "intent": state.semantic.intent if state.semantic else "unknown",
                "confidence": state.semantic.confidence if state.semantic else 0,
                "techniques": state.semantic.persuasion_techniques if state.semantic else [],
            },
            "threat_intel": lambda: {
                "ioc_count": getattr(state.threat_intel_result, "ioc_count", 0),
                "threat_patterns": getattr(state.threat_intel_result, "threat_patterns", []),
                "threat_score": getattr(state.threat_intel_result, "threat_score", 0),
                "attack_techniques": getattr(state.threat_intel_result, "attack_techniques", []),
            } if hasattr(state, "threat_intel_result") else {},
            "detector": lambda: {
                "sender_score": state.detection.sender_score if state.detection else 0.5,
                "url_score": state.detection.url_score if state.detection else 0.5,
                "content_flags": state.detection.content_flags if state.detection else [],
                "kb_hits": len(state.detection.kb_hits) if state.detection else 0,
            },
            "risk": lambda: {
                "risk_score": state.risk.risk_score if state.risk else 0,
                "risk_level": state.risk.risk_level if state.risk else "unknown",
                "attack_techniques": state.risk.attack_techniques if state.risk else [],
            },
            "response": lambda: {
                "action": state.response.action if state.response else "alert",
                "has_alert": bool(state.response.alert_message) if state.response else False,
            },
        }
        func = summaries.get(agent_key, lambda: {})
        return func()

    def _ensure_dependencies(self, selected_steps: list[str]) -> list[str]:
        """确保子 Agent 调用顺序的依赖关系"""
        steps = list(selected_steps)
        # 响应处置依赖风险研判
        if "response" in steps and "risk" not in steps:
            idx = steps.index("response")
            steps.insert(idx, "risk")
        # 风险研判依赖检测
        if "risk" in steps and "detector" not in steps:
            idx = steps.index("risk")
            steps.insert(idx, "detector")

        # 按逻辑顺序排列
        order = {
            "sender_profiler": 0,
            "header_forensics": 1,
            "semantic": 2,
            "threat_intel": 3,
            "detector": 4,
            "risk": 5,
            "response": 6,
        }
        steps.sort(key=lambda s: order.get(s, 99))
        return steps

    def _phase3_generate_report(
        self,
        email: EmailInput,
        state: WorkflowState,
        strategy: dict,
        callback: EventCallback,
    ) -> dict:
        """
        Phase 3: 综合所有子 Agent 结果生成最终报告
        
        构建证据列表、生成完整报告、推送报告事件。
        """
        self.emit_orchestrator_thinking(
            "所有子 Agent 的分析已经完成。现在让我综合所有证据，生成最终检测报告。",
            callback,
        )

        # 构建证据列表
        state.evidence_items = [
            EvidenceItem(**item)
            for item in self._build_evidence_items(email, state.semantic, state.detection, state.risk)
        ]

        # 编排器最终总结叙事
        final_narrative = self._final_narrative(state)
        self.emit_orchestrator_thinking(final_narrative, callback)

        # 构建完整报告
        report = {
            "is_phishing": state.is_phishing,
            "risk_score": state.risk.risk_score if state.risk else 0,
            "risk_level": state.risk.risk_level if state.risk else "unknown",
            "strategy": strategy.get("strategy", ""),
            "key_clues": strategy.get("key_clues", []),
            "hypotheses": strategy.get("hypotheses", {}),
            "sender_profiler": {
                "sender_type": getattr(state.sender_profiler_result, "sender_type", ""),
                "domain_reputation": getattr(state.sender_profiler_result, "domain_reputation", ""),
                "reputation_score": getattr(state.sender_profiler_result, "reputation_score", 0),
                "brand_impersonated": getattr(state.sender_profiler_result, "brand_impersonated", ""),
                "lookalike_domains": getattr(state.sender_profiler_result, "lookalike_domains", []),
                "suspicious_patterns": getattr(state.sender_profiler_result, "suspicious_patterns", []),
                "explanation": getattr(state.sender_profiler_result, "explanation", ""),
            } if hasattr(state, "sender_profiler_result") and state.sender_profiler_result else {},
            "header_forensics": {
                "spf_status": getattr(state.header_forensics_result, "spf_status", ""),
                "dkim_status": getattr(state.header_forensics_result, "dkim_status", ""),
                "dmarc_status": getattr(state.header_forensics_result, "dmarc_status", ""),
                "auth_alignment": getattr(state.header_forensics_result, "auth_alignment", ""),
                "header_anomalies": getattr(state.header_forensics_result, "header_anomalies", []),
                "anomaly_score": getattr(state.header_forensics_result, "anomaly_score", 0),
                "explanation": getattr(state.header_forensics_result, "explanation", ""),
            } if hasattr(state, "header_forensics_result") and state.header_forensics_result else {},
            "semantic": {
                "intent": state.semantic.intent,
                "confidence": state.semantic.confidence,
                "persuasion_techniques": state.semantic.persuasion_techniques,
                "explanation": state.semantic.explanation,
            } if state.semantic else {},
            "threat_intel": {
                "ioc_count": getattr(state.threat_intel_result, "ioc_count", 0),
                "ioc_list": getattr(state.threat_intel_result, "ioc_list", []),
                "threat_patterns": getattr(state.threat_intel_result, "threat_patterns", []),
                "threat_score": getattr(state.threat_intel_result, "threat_score", 0),
                "attack_techniques": getattr(state.threat_intel_result, "attack_techniques", []),
                "explanation": getattr(state.threat_intel_result, "explanation", ""),
            } if hasattr(state, "threat_intel_result") and state.threat_intel_result else {},
            "detection": {
                "sender_score": state.detection.sender_score,
                "sender_analysis": state.detection.sender_analysis,
                "url_score": state.detection.url_score,
                "url_analysis": state.detection.url_analysis,
                "url_reputation_score": state.detection.url_reputation_score,
                "url_reputation_summary": state.detection.url_reputation_summary,
                "attachment_score": state.detection.attachment_score,
                "attachment_summary": state.detection.attachment_summary,
                "behavior_score": state.detection.behavior_score,
                "behavior_summary": state.detection.behavior_summary,
                "content_flags": state.detection.content_flags,
                "kb_hits": state.detection.kb_hits,
                "kb_summary": state.detection.kb_summary,
                "explanation": state.detection.explanation,
            } if state.detection else {},
            "risk": {
                "risk_score": state.risk.risk_score,
                "risk_level": state.risk.risk_level,
                "rule_score": state.risk.rule_score,
                "llm_score": state.risk.llm_score,
                "score_gap": state.risk.score_gap,
                "consistency_warning": state.risk.consistency_warning,
                "attack_techniques": state.risk.attack_techniques,
                "explanation": state.risk.explanation,
            } if state.risk else {},
            "response": {
                "action": state.response.action,
                "alert_message": state.response.alert_message,
                "trace_report": state.response.trace_report,
                "recommendation": state.response.recommendation,
            } if state.response else {},
            "evidence_items": [
                item.model_dump(mode="json") for item in state.evidence_items
            ],
        }

        # 推送报告事件
        self.emit_report(report, callback)

        # 推送完成事件
        if callback:
            callback({
                "type": "orchestrator_done",
                "data": {
                    "agent": self.name,
                    "is_phishing": state.is_phishing,
                    "risk_level": state.risk.risk_level if state.risk else "unknown",
                    "risk_score": state.risk.risk_score if state.risk else 0,
                }
            })

        return report

    def _final_narrative(self, state: WorkflowState) -> str:
        """编排器最终总结叙事（含多假设校准和反事实反思）"""
        risk = state.risk
        semantic = state.semantic
        detection = state.detection
        response = state.response

        if not risk:
            return "检测流程完成，但风险研判结果缺失。建议人工复核。"

        level_map = {
            "critical": "极高风险",
            "high": "高风险",
            "medium": "中等风险",
            "low": "低风险",
            "safe": "安全",
        }
        level_desc = level_map.get(risk.risk_level, risk.risk_level)

        narrative = (
            f"所有分析环节已完成。让我做出最终判定。\n"
            f"综合检测结论：这封邮件的最终风险等级为「{level_desc}」（评分 {risk.risk_score}/100）。"
        )

        # 多假设校准总结
        narrative += "\n\n【多假设校准结果】"
        if semantic:
            narrative += f"\n• 假设 A（钓鱼攻击）：语义判定「{semantic.intent}」，置信度 {semantic.confidence:.0%}。"
        if detection:
            narrative += f"\n• 技术验证：发件人可信度 {detection.sender_score:.2f}，URL 安全分 {detection.url_score:.2f}。"

        # 反事实反思
        narrative += "\n\n【反事实反思】"
        sp_result = getattr(state, "sender_profiler_result", None)
        hf_result = getattr(state, "header_forensics_result", None)
        ti_result = getattr(state, "threat_intel_result", None)

        counter_phishing = []
        if sp_result and getattr(sp_result, "brand_impersonated", ""):
            counter_phishing.append(f"发件人仿冒品牌「{getattr(sp_result, 'brand_impersonated', '')}」")
        if hf_result and getattr(hf_result, "anomaly_score", 0) >= 50:
            counter_phishing.append(f"邮件头异常评分 {getattr(hf_result, 'anomaly_score', 0):.0f}/100")
        if ti_result and getattr(ti_result, "threat_score", 0) >= 60:
            counter_phishing.append(f"威胁情报匹配评分 {getattr(ti_result, 'threat_score', 0):.0f}/100")

        if counter_phishing:
            narrative += f"\n支持钓鱼假设的硬证据：{', '.join(counter_phishing)}。"
        else:
            narrative += "\n支持钓鱼假设的硬证据较弱。"

        # 处置建议
        if response:
            narrative += f"\n\n【处置建议】\n处置动作：「{response.action}」。"

        if risk.attack_techniques:
            narrative += f"\n攻击技术映射：{', '.join(risk.attack_techniques)}。"

        if risk.consistency_warning:
            narrative += f"\n⚠️ {risk.consistency_warning}"

        return narrative

    def _build_evidence_items(
        self, email: EmailInput, semantic, detection, risk
    ) -> list[dict]:
        """构建结构化证据列表"""
        evidence_items = []

        if semantic:
            evidence_items.append({
                "type": "semantic",
                "source": "semantic_agent",
                "weight": 25,
                "confidence": max(0.0, min(1.0, float(semantic.confidence))),
                "reason": semantic.explanation[:200] or semantic.intent,
            })

        if detection:
            evidence_items.append({
                "type": "detection",
                "source": "detector_agent",
                "weight": 30,
                "confidence": max(0.0, min(1.0, float((detection.sender_score + detection.url_score) / 2))),
                "reason": detection.explanation[:200] or ",".join(detection.content_flags),
            })

            if getattr(detection, "url_reputation_score", None) is not None and getattr(detection, "url_reputation_summary", None):
                evidence_items.append({
                    "type": "url_reputation",
                    "source": "detector_agent",
                    "weight": 15,
                    "confidence": max(0.0, min(1.0, float(detection.url_reputation_score))),
                    "reason": detection.url_reputation_summary[:200],
                })

            if getattr(detection, "attachment_score", 0) >= 0.4 and getattr(detection, "attachment_summary", None):
                evidence_items.append({
                    "type": "attachment",
                    "source": "detector_agent",
                    "weight": 12,
                    "confidence": max(0.0, min(1.0, float(detection.attachment_score))),
                    "reason": detection.attachment_summary[:200],
                })

            if getattr(detection, "behavior_score", 0) >= 0.4 and getattr(detection, "behavior_summary", None):
                evidence_items.append({
                    "type": "behavior_anomaly",
                    "source": "detector_agent",
                    "weight": 12,
                    "confidence": max(0.0, min(1.0, float(detection.behavior_score))),
                    "reason": detection.behavior_summary[:200],
                })

        # 邮件头风险
        header_risk = 0.0
        if isinstance(email.headers, dict):
            headers = email.headers or {}
            for status in (headers.get("spf", ""), headers.get("dkim", ""), headers.get("dmarc", "")):
                value = str(status).lower()
                if value in {"none", "neutral"}:
                    header_risk += 20
                elif value == "fail":
                    header_risk += 40
        header_risk = min(header_risk, 100)

        if header_risk >= 40:
            evidence_items.append({
                "type": "header_validation",
                "source": "mail_headers",
                "weight": 15,
                "confidence": 0.9,
                "reason": "SPF/DKIM/DMARC 头部校验存在异常，说明邮件身份真实性下降。",
            })

        if email.has_attachment:
            evidence_items.append({
                "type": "attachment",
                "source": "attachment_check",
                "weight": 10,
                "confidence": 0.75,
                "reason": "邮件包含附件，附件诱导钓鱼风险需要进一步审查。",
            })

        if risk:
            evidence_items.append({
                "type": "risk",
                "source": "risk_agent",
                "weight": 20,
                "confidence": max(0.0, min(1.0, float(risk.risk_score / 100))),
                "reason": risk.explanation[:200] or risk.risk_level,
            })

        total = sum(item["weight"] for item in evidence_items)
        if total <= 0:
            total = 1

        normalized = []
        for item in evidence_items:
            normalized.append({
                **item,
                "weight": int(round(item["weight"] / total * 100)),
            })

        diff = 100 - sum(item["weight"] for item in normalized)
        if normalized:
            normalized[-1]["weight"] += diff

        return normalized
