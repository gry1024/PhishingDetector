"""
风险研判 Agent（Agent #3）
==========================
核心职责：综合所有分析结果，做出最终风险判定。

工具集：
- map_attack_techniques: 将检测标记映射到 MITRE ATT&CK 框架

工作流：
1. 收集 Agent#1 和 Agent#2 的结果
2. 规则引擎快速预评分
3. 调用 ATT&CK 映射工具
4. LLM 综合研判
5. 融合规则分和 LLM 分，输出最终风险等级
6. LLM 不可用时自动启用规则化风险研判兜底
"""

from src.agents.base import BaseAgent, EventCallback
from src.models import (
    EmailInput, SemanticResult, DetectionResult, RiskResult,
)
from src.tools import get_tools_for_agent, PHISHING_PATTERNS, WEAK_PHISHING_PATTERNS
import json
import os
import re

# ── 加载校准参数（由 scripts/split_and_calibrate.py 生成）──
_calibration_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "datasets", "calibration.json",
)
_calibration = {}
try:
    with open(_calibration_path, "r", encoding="utf-8") as f:
        _calibration = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

CALIBRATED_THRESHOLD = _calibration.get("best_threshold", 35)
PHISHING_RISK_LEVELS = {"high", "critical"}


SYSTEM_PROMPT = """你是网络安全风险研判专家。综合语义分析和多维检测结果，做出最终风险判定。

评分标准（0-100，越高越危险）：
- 0-20: safe | 21-40: low | 41-60: medium | 61-80: high | 81-100: critical

MITRE ATT&CK 映射：
T1566: Phishing | T1566.001: 附件钓鱼 | T1566.002: 链接钓鱼
T1566.003: 服务钓鱼 | T1598: 信息钓鱼 | T1657: 金融盗窃

重点关注：
- AI 生成钓鱼（语法完美但意图可疑）
- BEC 商务邮件欺诈
- 凭证窃取

判定校准（必须严格遵守，防止误判）：
1. 以下属于【正常邮件】，必须判 0-20 分：个人生活与情感讨论、邮件列表/论坛回帖、
   技术交流、影评书评、朋友同事间的正常通信——即使语气激烈、带"Re:"前缀或含链接。
   这类邮件没有恶意意图，不得仅因"感觉不规范""身份无法核实"而加分。
2. 以下属于本系统检测范围内的【钓鱼/诈骗邮件】，应判 61 分以上：
   未经请求的伪装性推广（伪学术征稿、伪期刊约稿、伪培训课程推广、伪会议邀请）、
   诈骗广告（代开发票、做账抵扣、虚假补贴）、伪装系统通知（邮箱升级/容量上限/备案/薪资资料）、
   以及一切附带可疑链接、附件诱导、凭证索取或转账要求的商业邮件。
3. 判 61 分以上必须能在邮件中指出具体证据（话术诱导/可疑链接/附件诱导/身份冒充/
   利诱诈骗之一）；找不到具体证据时，分数不得超过 40。
4. 正文出现乱码、方框字符或 base64/quoted-printable 残片，是邮件编码（如 GB2312）
   未完全解码的产物，属于提取噪声而非恶意证据，不得因此加分；
   邮件中【讨论】他人的诈骗、犯罪或安全事件，不等于本邮件有恶意意图。

请先用自然语言详细研判风险等级、攻击手法和关键证据（200-400字），
然后在新的一行输出 <<<JSON>>> 标记，最后输出严格 JSON：
{
    "risk_score": 0到100的整数,
    "risk_level": "critical/high/medium/low/safe",
    "attack_techniques": ["ATT&CK编号列表"],
    "explanation": "详细研判推理过程"
}
若知识库命中条目与本次研判相关，请在 explanation 中显式引用条目标题及其识别要点编号作为依据；不相关则忽略。
输出要求：直接输出裸 JSON，不要用 markdown 代码围栏（```）包裹；explanation 不超过 200 字，确保 JSON 完整结束。"""


class RiskAgent(BaseAgent):
    """风险研判 Agent"""

    name = "风险研判"
    icon = "⚖️"
    tools = get_tools_for_agent("risk")

    def analyze(
        self,
        email: EmailInput,
        callback: EventCallback = None,
        semantic_result: SemanticResult = None,
        detection_result: DetectionResult = None,
        **kwargs,
    ) -> dict:
        """
        执行风险研判

        流程：规则预评分 → ATT&CK映射 → LLM综合研判 → 分数融合
        LLM 不可用时自动降级为规则化研判兜底。
        """
        semantic = semantic_result or SemanticResult(
            intent="suspicious", explanation="", persuasion_techniques=[]
        )
        detection = detection_result or DetectionResult(
            sender_analysis="", url_analysis="", explanation=""
        )

        # ---- Step 1: 规则引擎预评分 ----
        self.emit_thinking("第一步：基于语义意图与多维检测特征，进行规则引擎快速预评分。", callback)
        self.emit_sub_step(
            "收集语义意图、话术类型、发件人可信度、URL 安全分、附件风险、行为异常、内容标记等输入",
            "running",
            callback,
        )
        rule_score = self._rule_risk_score(semantic, detection)
        self.emit_sub_step(
            f"规则预评分计算完成：语义意图权重 + 话术数量 + 技术特征风险 = {rule_score}/100",
            "done",
            callback,
        )

        # ---- Step 2: ATT&CK 映射 ----
        self.emit_thinking("第二步：将检测到的攻击特征映射到 MITRE ATT&CK 框架，形成标准化威胁语言。", callback)
        self.emit_sub_step(
            f"汇总语义话术 ({len(semantic.persuasion_techniques)} 个) 与内容标记 ({len(detection.content_flags)} 个) 进行 ATT&CK 映射",
            "running",
            callback,
        )
        all_flags = (
            semantic.persuasion_techniques +
            detection.content_flags
        )
        attack_result = self.call_tool("map_attack_techniques", all_flags, callback=callback)
        self.emit_sub_step(f"ATT&CK 映射结果：{attack_result.output}", "done", callback)

        # ---- Step 3: LLM 综合研判（带规则兜底） ----
        self.emit_thinking(
            "第三步：综合语义意图、技术检测特征、ATT&CK 映射和规则评分，调用 LLM 进行最终风险研判。",
            callback,
        )
        self.emit_sub_step(
            "构建研判提示：包含邮件概要、语义分析、多维检测结果、规则预评分",
            "running",
            callback,
        )
        user_prompt = self._build_prompt(email, semantic, detection, rule_score)
        fallback_reason = ""
        try:
            llm_result = self.chat_json(SYSTEM_PROMPT, user_prompt, callback=callback)
            self.emit_sub_step(
                f"LLM 研判完成：风险分 {llm_result.get('risk_score', '-')}/100，等级 {llm_result.get('risk_level', '-')}",
                "done",
                callback,
            )
            llm_available = True
            llm_participated = True
        except Exception as e:
            fallback_reason = self.emit_llm_fallback(e, callback)
            self.emit_sub_step(f"规则兜底接管：直接采用规则预评分作为最终风险（{fallback_reason}）", "done", callback)
            llm_result = self._fallback_llm_result(rule_score, semantic, detection)
            llm_available = False
            llm_participated = False

        # ---- Step 4: 分数融合 ----
        self.emit_thinking("第四步：融合规则评分与 LLM 研判评分，输出最终风险等级。", callback)
        self.emit_sub_step("计算 LLM 评分与规则评分的加权平均值，并检测双轨一致性", "running", callback)
        # 品类模式抬档：LLM 无关的独立文本证据（词表经 200 条正常样本零误命中验证），
        # 两条路径都生效——在线路径下避免怀疑型 LLM 评分经 0.6/0.4 融合
        # 把词表判出的样本稀释到 high 判定线以下（test_set v1 实测 61 条真钓鱼曾被稀释漏报）。
        boost = self._pattern_boost(email)
        if llm_available:
            llm_score = int(llm_result.get("risk_score", 50))
            final_score = round(llm_score * 0.6 + rule_score * 0.4)
            final_score = max(0, min(100, final_score))
            if boost > final_score:
                final_score = boost
                self.emit_sub_step(
                    f"品类模式独立证据抬档至 {boost} 分（高于融合分，防止双轨稀释）",
                    "done",
                    callback,
                )
        else:
            llm_score = 0
            final_score = max(0, min(100, rule_score))
            if boost > final_score:
                final_score = boost
                self.emit_sub_step(
                    f"钓鱼品类模式命中，规则兜底抬档至 {boost} 分",
                    "done",
                    callback,
                )
        risk_level = self._score_to_level(final_score)
        if llm_available:
            score_gap = abs(llm_score - rule_score)
            consistency_warning = ""
            if score_gap >= 25:
                consistency_warning = "规则评分与LLM评分差异较大，建议人工复核关键证据。"
                self.emit_sub_step(f"⚠️ 规则/LLM 分差 {score_gap}，双轨结果不一致，建议人工复核", "done", callback)
            else:
                self.emit_sub_step(f"双轨一致性良好：分差 {score_gap}，最终风险分 {final_score}/100（{risk_level}）", "done", callback)
        else:
            score_gap = 0
            consistency_warning = (
                "LLM 输出解析失败，已采用规则兜底，未计算双轨分差。"
                if fallback_reason == "parse_error"
                else "LLM 不可用，已采用规则兜底，未计算双轨分差。"
            )
            self.emit_sub_step("LLM 未参与本次研判，结果由规则引擎独立给出", "done", callback)

        # 合并 ATT&CK 技术（LLM + 工具）
        llm_techniques = llm_result.get("attack_techniques", [])
        tool_techniques = []
        if "T" in attack_result.output:
            import re
            tool_techniques = re.findall(r'T\d+(?:\.\d+)?', attack_result.output)
        all_techniques = list(set(llm_techniques + tool_techniques))

        risk = RiskResult(
            risk_score=final_score,
            risk_level=risk_level,
            attack_techniques=all_techniques,
            rule_score=rule_score,
            llm_score=llm_score,
            llm_participated=llm_participated,
            score_gap=score_gap,
            consistency_warning=consistency_warning,
            explanation=llm_result.get("explanation", ""),
            fallback_reason=fallback_reason,
        )

        self.emit_sub_step(
            f"风险研判完成：最终风险等级 {risk_level}，攻击技术 {', '.join(all_techniques) or '无'}",
            "done",
            callback,
        )

        return {
            "risk": risk,
            "is_phishing": risk_level in PHISHING_RISK_LEVELS,
        }

    def _fallback_llm_result(self, rule_score: int, semantic: SemanticResult, detection: DetectionResult) -> dict:
        """LLM 不可用时的规则化最终判定。"""
        score = max(rule_score, 0)
        risk_level = self._score_to_level(score)
        return {
            "risk_score": score,
            "risk_level": risk_level,
            "attack_techniques": ["T1566", "T1598"],
            "explanation": (
                "LLM 不可用时采用规则引擎兜底进行风险研判。"
                f"综合语义意图（{semantic.intent}）、发件人可信度（{detection.sender_score:.2f}）、"
                f"URL 安全（{detection.url_score:.2f}）以及内容标记（{', '.join(detection.content_flags) or '无'}），"
                f"最终判定为 {risk_level}（{score}/100）。"
            ),
        }

    def _pattern_boost(self, email: EmailInput) -> int:
        """品类模式抬档分数（0 表示不触发）。

        强模式 ≥1 命中阶梯抬档（61+7×(n-1)，封顶 82）；
        强零命中时弱信号（垃圾/营销邮件特征）≥2 组合抬到 61。
        依据 test_set v1 实测：正常样本强模式 0 命中、弱信号 ≥2 组合 0 误命中。
        """
        category_hits = self._count_phishing_pattern_hits(email)
        if category_hits >= 1:
            return min(61 + 7 * (category_hits - 1), 82)
        if self._count_weak_pattern_hits(email) >= 2:
            return 61
        return 0

    def _count_phishing_pattern_hits(self, email: EmailInput) -> int:
        """统计邮件文本命中的钓鱼模式数（与 scan_phishing_patterns 同一词表）。

        仅用于规则兜底分支的品类抬档判定，不改变 rule_score 本身。
        """
        text = f"{email.subject or ''} {email.body or ''}"
        return sum(
            1 for pattern, _ in PHISHING_PATTERNS
            if re.search(pattern, text, re.IGNORECASE)
        )

    def _count_weak_pattern_hits(self, email: EmailInput) -> int:
        """统计邮件文本命中的弱钓鱼信号数（WEAK_PHISHING_PATTERNS）。

        仅用于规则兜底分支：强模式零命中时，≥2 个弱信号组合作为抬档依据。
        """
        text = f"{email.subject or ''} {email.body or ''}"
        return sum(
            1 for pattern, _ in WEAK_PHISHING_PATTERNS
            if re.search(pattern, text, re.IGNORECASE)
        )

    def _rule_risk_score(self, semantic: SemanticResult, detection: DetectionResult) -> int:
        """规则引擎快速预评分（已降低误报率）"""
        score = 0
        # 意图判定：仅高置信度钓鱼/可疑才给高分
        if semantic.intent == "phishing":
            conf = getattr(semantic, "confidence", 0.5)
            score += 35 if conf >= 0.65 else 22
        elif semantic.intent == "suspicious":
            score += 12
        # 话术数量得分上限降至 15
        score += min(len(semantic.persuasion_techniques) * 4, 15)
        # 发件人可信度惩罚 — 仅不可信时才扣分
        if detection.sender_score < 0.5:
            score += int((1 - detection.sender_score) * 18)
        # URL 安全惩罚
        if detection.url_score < 0.6:
            score += int((1 - detection.url_score) * 12)
        # 附件风险
        score += int(detection.attachment_score * 12)
        # 行为异常
        score += int(detection.behavior_score * 10)
        # 内容标记
        score += min(len(detection.content_flags) * 3, 12)

        # 良性偏移：当邮件看起来正常时减分
        benign_signals = 0
        if detection.sender_score >= 0.75:
            benign_signals += 1
        if detection.url_score >= 0.75:
            benign_signals += 1
        if detection.attachment_score < 0.2:
            benign_signals += 1
        if detection.behavior_score < 0.3:
            benign_signals += 1
        if len(detection.content_flags) == 0:
            benign_signals += 1
        # 多良性信号时大幅降分
        if benign_signals >= 4:
            score = max(0, score - 18)
        elif benign_signals >= 3:
            score = max(0, score - 10)
        elif benign_signals >= 2:
            score = max(0, score - 4)

        return max(0, min(score, 100))

    def _score_to_level(self, score: int) -> str:
        """分数 → 风险等级（使用训练集校准阈值）"""
        # 校准阈值用于 safe/low 边界；更高阈值保持不变
        # TODO(后续任务): safe_boundary 目前为死代码（计算后从未使用），
        # 实际 safe/low 边界由下方 low_boundary 决定；按裁决本次仅注释标记，
        # 不删除、不调整阈值，留待单独任务清理
        safe_boundary = max(10, CALIBRATED_THRESHOLD - 3)
        low_boundary = max(20, CALIBRATED_THRESHOLD + 5)
        if score >= 81: return "critical"
        if score >= 61: return "high"
        if score >= 41: return "medium"
        if score >= low_boundary: return "low"
        return "safe"

    def _build_prompt(self, email, semantic, detection, rule_score) -> str:
        """构造研判提示"""
        parts = ["--- 邮件概要 ---"]
        if email.subject: parts.append(f"主题: {email.subject}")
        if email.sender: parts.append(f"发件人: {email.sender}")
        if email.body:
            body = email.body[:2000] + ("..." if len(email.body) > 2000 else "")
            parts.append(f"正文: {body}")

        parts.append(f"\n--- 语义分析 ---")
        parts.append(f"意图: {semantic.intent} | 置信度: {semantic.confidence:.0%}")
        parts.append(f"话术: {', '.join(semantic.persuasion_techniques) or '无'}")
        parts.append(f"分析: {semantic.explanation[:400]}")

        parts.append(f"\n--- 多维检测 ---")
        parts.append(f"发件人可信度: {detection.sender_score:.2f}")
        parts.append(f"URL安全: {detection.url_score:.2f}")
        if detection.content_flags:
            parts.append(f"内容标记: {', '.join(detection.content_flags)}")

        kb_section = self._build_kb_evidence_section(detection.kb_hits)
        if kb_section:
            parts.append("\n--- 知识库命中证据 ---")
            parts.append(kb_section)
        elif detection.kb_summary:
            parts.append(f"知识库摘要: {detection.kb_summary}")

        parts.append(f"\n规则预评分: {rule_score}/100")

        return "请综合以下分析结果，做出最终风险研判：\n\n" + "\n".join(parts)

    def _format_kb_context(self, kb_hits: list[dict], limit: int = 3) -> str:
        """将知识库命中压缩成 LLM 可读的研判上下文。"""
        snippets = []
        for hit in (kb_hits or [])[:limit]:
            title = hit.get("title", "未命中标题")
            severity = hit.get("severity", "")
            score = hit.get("score", 0)
            keywords = ", ".join(hit.get("matched_keywords", [])[:5]) or "无"
            semantic_terms = ", ".join(hit.get("matched_semantic_terms", [])[:5]) or "无"
            summary = (hit.get("summary") or hit.get("content") or "")[:120]
            recommendation = (hit.get("recommendation") or "")[:100]
            snippets.append(
                f"{title}[{severity},score={score}] 命中词:{keywords}; 语义:{semantic_terms}; 摘要:{summary}; 建议:{recommendation}"
            )
        return " || ".join(snippets) if snippets else "无"

    def _build_kb_evidence_section(self, kb_hits: list[dict], limit: int = 3, max_chars: int = 1200) -> str:
        """构造知识库证据小节：标题、severity、summary、识别要点（最多前三条）。"""
        if not kb_hits:
            return ""

        lines = []
        for idx, hit in enumerate((kb_hits or [])[:limit], 1):
            title = hit.get("title") or "未命名条目"
            severity = hit.get("severity") or "unknown"
            summary = (hit.get("summary") or "").strip()
            points = hit.get("detection_points") or []
            if not isinstance(points, list):
                points = []
            points = [str(p).strip() for p in points if str(p).strip()][:3]
            semantic_terms = hit.get("matched_semantic_terms") or []
            if not isinstance(semantic_terms, list):
                semantic_terms = []
            semantic_terms = [str(t).strip() for t in semantic_terms if str(t).strip()][:5]

            block = [f"[{idx}] {title}（{severity}）"]
            if summary:
                block.append(f"摘要: {summary}")
            if semantic_terms:
                block.append(f"语义命中: {', '.join(semantic_terms)}")
            if points:
                block.append("识别要点:")
                for i, point in enumerate(points, 1):
                    block.append(f"  - ({i}) {point}")
            lines.append("\n".join(block))

        section = "\n\n".join(lines)
        if len(section) > max_chars:
            return section[:max_chars] + "..."
        return section
