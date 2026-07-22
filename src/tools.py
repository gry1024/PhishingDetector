"""
Agent 工具集
============
每个 Agent 可调用的工具函数。
工具调用会被记录并流式推送到前端，展示在对应 Agent 节点上。
"""

import re
import time
import logging
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
#
# Tools self-register via the @register_tool(name, agents=[...]) decorator.
# Each Agent then asks for the slice it owns via get_tools_for_agent(name).
# Adding a new tool no longer requires touching the 4 hard-coded *TOOLS dicts.

_TOOL_REGISTRY: dict[str, dict] = {}


def register_tool(name: str, agents: Iterable[str]):
    """Decorator that registers a callable as a tool available to the given agents.

    Args:
        name: tool identifier (must be unique across the registry).
        agents: agent names that may call this tool (e.g. ["semantic", "detector"]).

    Usage::

        @register_tool("scan_phishing_patterns", agents=["semantic", "detector"])
        def scan_phishing_patterns(text: str) -> ToolResult:
            ...
    """
    agents = tuple(agents)

    def decorator(fn):
        if name in _TOOL_REGISTRY:
            raise ValueError(f"tool '{name}' already registered")
        _TOOL_REGISTRY[name] = {"fn": fn, "agents": agents}
        return fn

    return decorator


def get_tools_for_agent(agent_name: str) -> dict[str, object]:
    """Return {name: callable} for every tool registered for the given agent."""
    return {
        name: meta["fn"]
        for name, meta in _TOOL_REGISTRY.items()
        if agent_name in meta["agents"]
    }


def registered_tool_names() -> list[str]:
    """List all registered tool names (mainly for diagnostics/tests)."""
    return sorted(_TOOL_REGISTRY.keys())

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """工具调用结果"""
    tool_name: str       # 工具名称
    input_summary: str   # 输入摘要（显示在 UI 上）
    output: str          # 工具输出
    duration_ms: int = 0 # 执行耗时


@dataclass
class ToolCallLog:
    """工具调用日志，用于流式输出到前端"""
    calls: list = field(default_factory=list)


# ============================================================
# URL 分析工具
# ============================================================

@register_tool("analyze_url", agents=["detector"])
def analyze_url(url: str) -> ToolResult:
    """
    分析 URL 的安全特征
    
    检测项：IP地址域名、短链、@符号、过多子域名、可疑TLD、
    URL编码、异常端口等。
    """
    start = time.time()
    findings = []
    risk_score = 0  # 0=安全, 越高越危险

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    # IP 地址作为域名
    if re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
        findings.append("IP地址直接作为域名")
        risk_score += 40

    # 短链服务
    shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "buff.ly"}
    if hostname in shorteners:
        findings.append(f"短链服务: {hostname}")
        risk_score += 20

    # URL 中包含 @（重定向欺骗）
    if "@" in url:
        findings.append("URL包含@符号（可能重定向欺骗）")
        risk_score += 30

    # 过多子域名
    if hostname.count(".") > 3:
        findings.append(f"过多子域名({hostname.count('.')}层)")
        risk_score += 15

    # 可疑 TLD
    suspicious_tlds = {".xyz", ".top", ".click", ".link", ".work", ".gq", ".tk", ".ml", ".cf"}
    for tld in suspicious_tlds:
        if hostname.endswith(tld):
            findings.append(f"可疑TLD: {tld}")
            risk_score += 20

    # 异常端口
    if parsed.port and parsed.port not in (80, 443):
        findings.append(f"异常端口: {parsed.port}")
        risk_score += 15

    # URL 编码过多（可能隐藏真实地址）
    encoded_count = url.count("%")
    if encoded_count > 3:
        findings.append(f"大量URL编码({encoded_count}处)")
        risk_score += 10

    # 仿冒关键词在域名中
    brand_keywords = ["login", "verify", "secure", "account", "bank", "update", "signin"]
    for kw in brand_keywords:
        if kw in hostname:
            findings.append(f"域名含敏感关键词: {kw}")
            risk_score += 15
            break

    # 连字符过多
    if hostname.count("-") > 2:
        findings.append(f"域名含多个连字符({hostname.count('-')}个)")
        risk_score += 10

    if not findings:
        findings.append("未发现明显异常特征")

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="URL分析",
        input_summary=url[:80],
        output=f"风险分: {min(risk_score, 100)}/100 | " + "; ".join(findings),
        duration_ms=duration,
    )


# ============================================================
# 发件人域名检测工具
# ============================================================

# 已知高可信域名
TRUSTED_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "qq.com", "163.com", "126.com", "foxmail.com",
    "microsoft.com", "google.com", "apple.com", "amazon.com",
}


@register_tool("check_sender_domain", agents=["detector"])
def check_sender_domain(sender: str) -> ToolResult:
    """
    检测发件人域名的可信度
    
    检测项：域名仿冒（typo-squatting）、免费邮箱冒充企业、
    可疑域名格式等。
    """
    start = time.time()
    findings = []
    trust_score = 100  # 100=完全可信, 越低越可疑

    if not sender or "@" not in sender:
        findings.append("发件人地址格式无效")
        trust_score = 20
    else:
        domain = sender.split("@")[-1].lower().strip().rstrip(">")
        base = domain.split(".")[0] if "." in domain else domain

        # 检查域名仿冒
        for trusted in TRUSTED_DOMAINS:
            t_base = trusted.split(".")[0]
            if base != t_base and len(base) == len(t_base):
                diff = sum(1 for a, b in zip(base, t_base) if a != b)
                if 1 <= diff <= 2:
                    findings.append(f"疑似仿冒 {trusted}（差异{diff}字符）")
                    trust_score -= 50

        # 免费邮箱发商务邮件
        free_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "qq.com", "163.com"}
        if domain in free_domains:
            findings.append(f"使用免费邮箱域名: {domain}")
            trust_score -= 20

        # 域名含数字替换（如 g00gle）
        if any(c.isdigit() for c in base):
            findings.append("域名含数字替换（可能仿冒）")
            trust_score -= 25

        # 域名过长或含多连字符
        if len(base) > 15:
            findings.append("域名异常长")
            trust_score -= 10
        if domain.count("-") > 1:
            findings.append("域名含多个连字符")
            trust_score -= 10

    if not findings:
        findings.append("域名检测未发现异常")

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="发件人检测",
        input_summary=sender[:60],
        output=f"可信度: {max(trust_score, 0)}/100 | " + "; ".join(findings),
        duration_ms=duration,
    )


# ============================================================
# 钓鱼关键词扫描工具
# ============================================================

PHISHING_PATTERNS = [
    (r"(verify|confirm|update|secure)\s+(your|my)\s+(account|password|card|identity)", "英文凭证窃取话术"),
    (r"(click|visit|open)\s+(here|this|the link|below)", "诱导点击链接"),
    (r"(suspended|locked|restricted|compromised|disabled)\s*(account|card|access)", "账户冻结恐吓"),
    (r"(urgent|immediate|action required|respond within|deadline)", "制造紧急感"),
    (r"(wire transfer|bank detail|tax refund|lottery|prize|winner)", "金钱诱惑"),
    (r"(ceo|cfo|director|manager).*(transfer|payment|urgent|immediately)", "冒充高管"),
    (r"(验证|确认|更新|冻结|锁定|解冻)\s*(账户|密码|银行|身份|信息)", "中文凭证窃取"),
    (r"(紧急|立即|马上|限时|尽快)\s*(操作|处理|回复|转账|打款|验证)", "中文紧急施压"),
    (r"(中奖|退款|汇款|转账|打款|奖金|补贴)", "中文金钱诱惑"),
    (r"(领导|老板|总经理|董事长).*(转|汇|打).*(款|钱)", "中文冒充领导"),
    (r"(机密|保密|不要告诉|请勿声张)", "保密要求（BEC特征）"),
]


@register_tool("scan_phishing_patterns", agents=["semantic", "detector"])
def scan_phishing_patterns(text: str) -> ToolResult:
    """
    扫描文本中的钓鱼关键词模式
    
    使用正则匹配常见的话术模式，覆盖中英文。
    """
    start = time.time()
    matched = []

    for pattern, description in PHISHING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(description)

    if not matched:
        output = "未匹配到已知钓鱼话术模式"
    else:
        output = f"命中 {len(matched)} 个模式: " + ", ".join(matched)

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="关键词扫描",
        input_summary=f"文本长度 {len(text)} 字符",
        output=output,
        duration_ms=duration,
    )


# ============================================================
# URL 提取工具
# ============================================================

@register_tool("extract_urls", agents=["semantic", "detector"])
def extract_urls(text: str) -> ToolResult:
    """从文本中提取所有 URL"""
    start = time.time()
    url_pattern = r'https?://[^\s<>"\')\]\}]+'
    urls = re.findall(url_pattern, text)
    urls = list(set(urls))  # 去重

    if urls:
        output = f"提取到 {len(urls)} 个URL:\n" + "\n".join(f"  - {u}" for u in urls[:10])
    else:
        output = "文本中未发现URL"

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="URL提取",
        input_summary=f"文本长度 {len(text)} 字符",
        output=output,
        duration_ms=duration,
    )


# ============================================================
# ATT&CK 映射工具
# ============================================================

ATTACK_TECHNIQUES = {
    "phishing_link": ("T1566.002", "鱼叉式钓鱼链接"),
    "phishing_attachment": ("T1566.001", "鱼叉式钓鱼附件"),
    "phishing_service": ("T1566.003", "通过服务的钓鱼"),
    "credential_theft": ("T1598", "凭证窃取钓鱼"),
    "bec_fraud": ("T1657", "商务邮件欺诈(BEC)"),
    "social_engineering": ("T1566", "钓鱼攻击（社工话术）"),
    "ai_generated": ("T1566", "AI生成钓鱼内容"),
}


@register_tool("map_attack_techniques", agents=["risk"])
def map_attack_techniques(flags: list[str]) -> ToolResult:
    """
    将检测到的特征映射到 MITRE ATT&CK 框架
    
    根据检测标记自动匹配对应的技战术编号。
    """
    start = time.time()
    mapped = []

    flag_set = set(f.lower() for f in flags)

    # 根据标记映射
    if any("url" in f or "link" in f for f in flag_set):
        mapped.append(("T1566.002", "鱼叉式钓鱼链接"))
    if any("attachment" in f for f in flag_set):
        mapped.append(("T1566.001", "鱼叉式钓鱼附件"))
    if any("credential" in f or "verify" in f or "password" in f for f in flag_set):
        mapped.append(("T1598", "凭证窃取钓鱼"))
    if any("bec" in f or "transfer" in f or "wire" in f or "转账" in f for f in flag_set):
        mapped.append(("T1657", "商务邮件欺诈(BEC)"))
    if any("authority" in f or "impersonat" in f or "冒充" in f for f in flag_set):
        mapped.append(("T1566", "钓鱼攻击-身份冒充"))
    if any("urgency" in f or "fear" in f or "紧急" in f for f in flag_set):
        mapped.append(("T1566", "钓鱼攻击-社工话术"))

    # 去重
    seen = set()
    unique = []
    for code, name in mapped:
        if code not in seen:
            seen.add(code)
            unique.append((code, name))

    if unique:
        output = "映射到 " + " | ".join(f"{code}: {name}" for code, name in unique)
    else:
        output = "未映射到 ATT&CK 技术"

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="ATT&CK映射",
        input_summary=f"{len(flags)} 个标记",
        output=output,
        duration_ms=duration,
    )


# Tools are now self-registered via @register_tool above; helper:
#   from src.tools import get_tools_for_agent
#   semantic_tools = get_tools_for_agent("semantic")
