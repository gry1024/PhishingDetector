"""
Agent 工具集
============
每个 Agent 可调用的工具函数。
工具调用会被记录并流式推送到前端，展示在对应 Agent 节点上。
"""

import re
import json
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
    extra: dict = field(default_factory=dict)  # 附加结构化数据（如联网搜索的结构化结果）


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
    (r"(紧急|立即|马上|限时|尽快|今日|当天)\s*(操作|处理|回复|转账|打款|验证|申请|办理|领取|兑换)", "中文紧急施压"),
    # 注：补贴/补助已拆分为独立的「中文补贴诱饵」模式（容忍"补〉贴"类变体），
    # 避免正常邮件中"给予补助"等合法表述误命中金钱诱惑
    (r"(中奖|退款|汇款|转账|打款|奖金)", "中文金钱诱惑"),
    (r"(领导|老板|总经理|董事长).*(转|汇|打).*(款|钱)", "中文冒充领导"),
    (r"(机密|保密|不要告诉|请勿声张)", "保密要求（BEC特征）"),
    # --- 中文钓鱼品类词（DataCon2023 实测盲区补强：只加词，不改权重与打分公式） ---
    (r"(邮箱|邮件系统|账号|账户).{0,4}(升级|扩容|维护|异常|迁移|冻结)", "中文系统升级伪装"),
    (r"(备案|续费|到期|过期|失效|停用)", "中文备案续费恐吓"),
    (r"(发票|对账单|报销|付款单据|电子收据)", "中文财务票据诱导"),
    (r"(积分|兑换码|好礼|礼包|奖品|领奖)", "中文积分福利诱饵"),
    (r"(邀请函|诚邀|请柬|参会回执)", "中文会议邀请伪装"),
    (r"(优青|依托申报|人才计划|高薪诚聘)", "中文招聘申报伪装"),
    (r"(客服|专员|顾问|服务中心)\s*(联系|电话|热线|微信|QQ)", "中文客服引流"),
    # --- 第二批盲区补强（test_set v1 漏报样本分析，全部经 200 条正常邮件零命中验证） ---
    (r"补.{0,2}贴", "中文补贴诱饵"),  # 容忍"补〉贴"等插入符号的变体
    (r"(容量|空间|内存).{0,3}(上限|不足|已满|爆满)", "中文邮箱容量恐吓"),
    (r"(薪资|工资|薪酬|绩效).{0,6}(补全|补录|资料|登记|核对|确认)", "中文薪资资料诱饵"),
    (r"(征稿|投稿|约稿|征文|call for papers|special issue)", "学术征稿伪装"),
    (r"\b(inquiry|purchase order|quotation|rfq)\b", "英文BEC虚假询单"),
]

# 弱钓鱼信号词表（垃圾/营销邮件特征）：单独一个命中不足以判定钓鱼，
# 仅在 risk 规则兜底分支按"≥2 个弱信号组合"使用，不进 scan_phishing_patterns、
# 不参与语义兜底意图判定，避免"请查看附件"这类正常商务表述单独触发误报。
# 全部经 test_set v1 的 200 条正常邮件验证：≥2 组合零误命中。
WEAK_PHISHING_PATTERNS = [
    (r"(请|详细|具体|详见).{0,4}(查看|查阅|参见).{0,3}附\s*件", "附件诱导查看"),
    (r"(课程|培训班|研修班|训练营).{0,30}(元/人|费用|报名|咨询)", "付费培训营销"),
    (r"(journal|manuscript).{0,40}(submit|submission|publish|publication)", "英文期刊营销"),
    (r"(退订|unsubscribe)", "营销退订"),
    (r"(无法正常查看|在线浏览|view online)", "营销模板在线浏览"),
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


@register_tool("analyze_attachment_risk", agents=["detector"])
def analyze_attachment_risk(text: str) -> ToolResult:
    """分析邮件附件风险特征。"""
    start = time.time()
    suspicious_terms = [
        ("exe", "可执行文件"),
        ("dll", "动态链接库"),
        ("js", "脚本文件"),
        ("hta", "脚本宿主"),
        ("zip", "压缩包"),
        ("rar", "压缩包"),
        ("docm", "宏文档"),
        ("xlsm", "宏表格"),
        ("pptm", "宏演示"),
        ("invoice", "付款单据"),
        ("payment", "付款单据"),
        ("statement", "对账单"),
        ("receipt", "收据"),
        # 中文财务词：覆盖 BEC/发票类附件钓鱼话术（此前纯英文词表存在盲区）
        ("发票", "付款单据"),
        ("付款", "付款单据"),
        ("单据", "付款单据"),
        ("对账", "对账单"),
        ("收据", "收据"),
    ]
    hits = []
    risk_score = 0
    lower = text.lower()

    for token, label in suspicious_terms:
        if token in lower:
            hits.append(label)
            risk_score += 10

    if "attachment" in lower or "附件" in lower:
        hits.append("附件诱导")
        risk_score += 10

    if "立即" in lower or "urgent" in lower or "紧急" in lower:
        hits.append("诱导性语气")
        risk_score += 10

    if not hits:
        hits.append("未见明显附件恶意特征")

    score = max(0, min(100, risk_score))
    output = f"附件风险分: {score}/100 | " + "; ".join(hits)

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="附件风险检查",
        input_summary=text[:80],
        output=output,
        duration_ms=duration,
    )


@register_tool("analyze_behavior_anomalies", agents=["detector"])
def analyze_behavior_anomalies(payload: str) -> ToolResult:
    """分析身份/行为异常模式。"""
    start = time.time()
    lower = payload.lower()
    signals = []
    score = 0

    if any(word in lower for word in ("立即", "urgent", "紧急", "马上", "尽快")):
        signals.append("高压语气")
        score += 25
    if any(word in lower for word in ("verify", "verify", "验证", "更新账户", "登录", "密码", "验证码")):
        signals.append("账号验证诱导")
        score += 25
    if any(word in lower for word in ("收款", "付款", "invoice", "payment", "financial", "转账")):
        signals.append("商务款项诱导")
        score += 20
    if any(word in lower for word in ("禁止告知", "请勿告知", "保密", "仅限")):
        signals.append("保密/绕过流程")
        score += 20
    if any(domain in lower for domain in ("verify", "secure-click", "quick-verify", "account-verify")):
        signals.append("仿冒域名行为")
        score += 20

    if not signals:
        signals.append("未见明显行为异常")
        score = 10

    score = max(0, min(100, score))
    output = f"行为异常分: {score}/100 | " + "; ".join(signals)

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="行为异常扫描",
        input_summary=payload[:80],
        output=output,
        duration_ms=duration,
    )


@register_tool("check_url_reputation", agents=["detector"])
def check_url_reputation(url: str) -> ToolResult:
    """对 URL 做信誉级别评分，增强 URL 信任度判定。"""
    start = time.time()
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    findings = []
    risk_score = 0

    if re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
        findings.append("IP 直接作为域名")
        risk_score += 40

    suspicious_tlds = {".xyz", ".top", ".click", ".link", ".work", ".gq", ".tk", ".ml", ".cf"}
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        findings.append("可疑 TLD")
        risk_score += 20

    if any(keyword in hostname for keyword in ("verify", "secure", "account", "login", "bank", "update")):
        findings.append("域名包含敏感词")
        risk_score += 15

    if parsed.port and parsed.port not in (80, 443):
        findings.append("异常端口")
        risk_score += 15

    if hostname.count(".") > 3:
        findings.append("过多子域名")
        risk_score += 10

    if not findings:
        findings.append("未发现明显恶意信誉特征")

    reputation_score = max(0, 100 - min(risk_score, 100))
    output = f"信誉分: {reputation_score}/100 | " + "; ".join(findings)

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="URL信誉检查",
        input_summary=url[:80],
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


# ============================================================
# 联网搜索工具（供 Agent 在需要时检索公开情报）
# ============================================================

import urllib.request
import urllib.parse
from html.parser import HTMLParser


class _DDGResultParser(HTMLParser):
    """极简 DuckDuckGo HTML 结果解析器（兼容多种 DDG 页面结构）"""

    def __init__(self):
        super().__init__()
        self.results = []
        self._current = None
        self._in_result = False
        self._capture_tag = None
        self._capture_data = []
        self._seen_urls = set()

    def _flush_snippet(self):
        if self._current and self._current.get("title"):
            url = self._current.get("url", "")
            if url and url in self._seen_urls:
                self._current = {"title": "", "url": "", "snippet": ""}
                return
            if url:
                self._seen_urls.add(url)
            self.results.append(self._current)
        self._current = {"title": "", "url": "", "snippet": ""}
        self._in_result = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        cls = attrs_dict.get("class", "")
        cls_tokens = cls.split()

        # 结果块容器：兼容 result / results_links / web-result 等
        if tag == "div" and any("result" in c for c in cls_tokens):
            self._in_result = True
            self._current = {"title": "", "url": "", "snippet": ""}

        if not self._in_result:
            return

        href = attrs_dict.get("href", "")
        # 标题链接：兼容 result__a / result-link / result__url
        if tag == "a" and href and (
            "result__a" in cls
            or "result-link" in cls
            or "result__url" in cls
        ):
            self._capture_tag = "title" if "result__a" in cls or "result-link" in cls else "url"
            self._capture_data = []
            if href.startswith("//"):
                href = "https:" + href
            elif href.startswith("/"):
                href = "https://duckduckgo.com" + href
            if self._capture_tag == "title":
                self._current["url"] = href
        elif tag == "a" and "result__url" in cls:
            self._capture_tag = "url"
            self._capture_data = []
        elif (tag == "div" or tag == "span" or tag == "a") and "result__snippet" in cls:
            self._capture_tag = "snippet"
            self._capture_data = []

    def handle_data(self, data):
        if self._capture_tag:
            self._capture_data.append(data)

    def handle_endtag(self, tag):
        if not self._capture_tag:
            return

        text = "".join(self._capture_data).strip()
        if self._capture_tag == "title":
            if text:
                self._current["title"] = text
        elif self._capture_tag == "url":
            if text and not self._current["url"]:
                self._current["url"] = text
        elif self._capture_tag == "snippet":
            if text:
                self._current["snippet"] = text
                self._flush_snippet()

        self._capture_tag = None
        self._capture_data = []


def _fetch_page_content(url: str, timeout: int = 8) -> str:
    """抓取网页并提取纯文本内容（用于深度威胁分析）。"""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text" not in content_type and "html" not in content_type:
                return ""
            raw = resp.read(200_000)  # 最多读 200KB
            # 尝试检测编码
            encoding = "utf-8"
            if hasattr(resp, "headers"):
                ct = resp.headers.get("Content-Type", "")
                if "charset=" in ct:
                    encoding = ct.split("charset=")[-1].split(";")[0].strip()
            html = raw.decode(encoding, errors="replace")
        return _extract_text_from_html(html)
    except Exception:
        return ""


def _extract_text_from_html(html: str) -> str:
    """从 HTML 中提取可读纯文本，去除脚本/样式/标签。"""
    # 移除 script 和 style 块
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.S | re.I)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.S | re.I)
    html = re.sub(r"<nav[^>]*>.*?</nav>", "", html, flags=re.S | re.I)
    html = re.sub(r"<footer[^>]*>.*?</footer>", "", html, flags=re.S | re.I)
    # 提取 <p>, <div>, <span>, <li>, <td>, <h1>-<h6> 内容
    text_parts = re.findall(
        r"<(?:p|div|span|li|td|h[1-6]|blockquote|article|section)[^>]*>(.*?)</(?:p|div|span|li|td|h[1-6]|blockquote|article|section)>",
        html, flags=re.S | re.I
    )
    if not text_parts:
        # 兜底：直接去掉所有标签
        text_parts = [re.sub(r"<[^>]+>", " ", html)]
    # 清理标签和空白
    tag_re = re.compile(r"<[^>]+>")
    ws_re = re.compile(r"\s+")
    cleaned = []
    for part in text_parts:
        text = tag_re.sub("", part).strip()
        text = ws_re.sub(" ", text)
        if len(text) > 20:  # 只保留有意义的段落
            cleaned.append(text)
    return " ".join(cleaned)[:5000]  # 最多 5000 字符


@register_tool("web_search", agents=["threat_intel", "semantic", "detector"])
def web_search(query: str, limit: int = 5) -> ToolResult:
    """
    联网检索公开威胁情报并深度分析网页内容。

    流程：
    1. DuckDuckGo 搜索获取候选网页（多端点容错）
    2. 实际抓取排名前 3 的网页，提取正文内容
    3. 对正文进行深度威胁指标分析（钓鱼话术、诈骗报告、品牌冒充等）
    4. 提取具体威胁情报（被举报域名、攻击手法、受害者报告等）
    5. 返回结构化情报，实际影响最终风险评分
    """
    start = time.time()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    results: list[dict] = []

    # ── 策略 1: DuckDuckGo HTML 端点（含重试） ──
    safe_query = urllib.parse.quote_plus(query)
    ddg_html_url = f"https://html.duckduckgo.com/html/?q={safe_query}"
    for attempt in range(2):
        try:
            req = urllib.request.Request(ddg_html_url, headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            parser = _DDGResultParser()
            parser.feed(html)
            results = parser.results
            if not results:
                results = _regex_extract_ddg(html, limit)
            if results:
                break
        except Exception:
            pass
        if attempt == 0:
            time.sleep(1.5)  # 重试前等待，避免 DuckDuckGo 限流

    # ── 策略 2: DuckDuckGo Lite 端点 ──
    if not results:
        ddg_lite_url = f"https://lite.duckduckgo.com/lite/?q={safe_query}"
        try:
            req = urllib.request.Request(ddg_lite_url, headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            results = _parse_ddg_lite(html, limit)
        except Exception:
            pass

    # ── 策略 3: DuckDuckGo Instant Answer API ──
    if not results:
        ddg_api_url = f"https://api.duckduckgo.com/?q={safe_query}&format=json&no_redirect=1"
        try:
            req = urllib.request.Request(ddg_api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("AbstractText"):
                results.append({
                    "title": data.get("Heading", query),
                    "url": data.get("AbstractURL", ""),
                    "snippet": data.get("AbstractText", ""),
                })
            for topic in (data.get("RelatedTopics") or [])[:5]:
                if isinstance(topic, dict) and topic.get("Text"):
                    results.append({
                        "title": topic.get("Text", "")[:80],
                        "url": topic.get("FirstURL", ""),
                        "snippet": topic.get("Text", ""),
                    })
        except Exception:
            pass

    # 去重 + 截断
    seen = set()
    deduped = []
    for r in results:
        u = r.get("url", "")
        if u in seen or not r.get("title"):
            continue
        seen.add(u)
        deduped.append(r)
    results = deduped[:limit]

    if not results:
        duration = int((time.time() - start) * 1000)
        return ToolResult(
            tool_name="联网搜索",
            input_summary=query[:80],
            output="未获取到公开搜索结果。已退回本地规则与知识库分析。",
            duration_ms=duration,
            extra={"results": [], "query": query, "threat_indicators": {"score": 0, "matched_types": [], "matched_count": 0, "has_threat_signals": False}, "page_contents": []},
        )

    # ── 深度抓取：实际获取排名前 3 的网页正文 ──
    pages_to_fetch = min(3, len(results))
    page_contents = []
    for r in results[:pages_to_fetch]:
        page_url = r.get("url", "")
        # 解析 DuckDuckGo 重定向 URL，获取真实目标地址
        if "duckduckgo.com/l/" in page_url:
            parsed_ddg = urllib.parse.urlparse(page_url)
            qs = urllib.parse.parse_qs(parsed_ddg.query)
            if "uddg" in qs:
                page_url = urllib.parse.unquote(qs["uddg"][0])
                r["url"] = page_url  # 更新为真实 URL
        if not page_url or not page_url.startswith("http"):
            continue
        content = _fetch_page_content(page_url, timeout=8)
        if content and len(content) > 50:
            page_contents.append({
                "url": page_url,
                "title": r.get("title", ""),
                "content": content,
                "content_length": len(content),
            })

    # ── 深度威胁分析：基于搜索摘要 + 实际网页正文 ──
    threat_indicators = _analyze_search_threats(results, query, page_contents)

    # ── 提取具体威胁情报 ──
    threat_intel = _extract_threat_intel(results, query, page_contents)

    # 构建输出
    lines = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "") or "无标题"
        snippet = r.get("snippet", "") or ""
        result_url = r.get("url", "") or ""
        lines.append(f"[{i}] {title}\n    {snippet[:160]}\n    {result_url}")

    output = f"检索到 {len(results)} 条公开结果，深度抓取 {len(page_contents)} 个网页:\n" + "\n".join(lines)

    if page_contents:
        output += "\n\n── 网页正文深度分析 ──"
        for pc in page_contents:
            output += f"\n[{pc['title'][:50]}] ({pc['content_length']} 字符)"

    if threat_intel.get("findings"):
        output += "\n\n威胁情报发现："
        for f in threat_intel["findings"]:
            output += f"\n  • {f}"

    if threat_indicators["score"] > 0:
        output += f"\n\n威胁指标分析：命中 {threat_indicators['matched_count']} 项（{', '.join(threat_indicators['matched_types'])}），联网情报风险分 +{threat_indicators['score']}"
    else:
        output += "\n\n联网情报分析完成，未在公开网页中发现明显威胁信号。"

    duration = int((time.time() - start) * 1000)
    return ToolResult(
        tool_name="联网搜索",
        input_summary=query[:80],
        output=output,
        duration_ms=duration,
        extra={
            "results": results,
            "query": query,
            "threat_indicators": threat_indicators,
            "page_contents": [{"url": pc["url"], "title": pc["title"], "content_preview": pc["content"][:300]} for pc in page_contents],
            "threat_intel": threat_intel,
        },
    )


def _regex_extract_ddg(html: str, limit: int) -> list[dict]:
    """正则兜底从 DuckDuckGo HTML 提取结果。"""
    link_re = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    snippet_re = re.compile(r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.S)
    tag_re = re.compile(r"<[^>]+>")
    links = link_re.findall(html)
    snippets = snippet_re.findall(html)
    results = []
    for i, (href, raw_title) in enumerate(links[:limit]):
        title = tag_re.sub("", raw_title).strip()
        snippet = tag_re.sub("", snippets[i]).strip() if i < len(snippets) else ""
        if href.startswith("//"):
            href = "https:" + href
        elif href.startswith("/"):
            href = "https://duckduckgo.com" + href
        if title:
            results.append({"title": title, "url": href, "snippet": snippet})
    return results


def _parse_ddg_lite(html: str, limit: int) -> list[dict]:
    """解析 DuckDuckGo Lite 端点结果。"""
    tag_re = re.compile(r"<[^>]+>")
    results = []
    # Lite 页面结果在 <a class="result-link"> 和 <td class="result-snippet"> 中
    link_re = re.compile(r'<a[^>]+class="[^"]*result-link[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    snippet_re = re.compile(r'<td[^>]+class="[^"]*result-snippet[^"]*"[^>]*>(.*?)</td>', re.S)
    links = link_re.findall(html)
    snippets = snippet_re.findall(html)
    for i, (href, raw_title) in enumerate(links[:limit]):
        title = tag_re.sub("", raw_title).strip()
        snippet = tag_re.sub("", snippets[i]).strip() if i < len(snippets) else ""
        if href.startswith("//"):
            href = "https:" + href
        if title:
            results.append({"title": title, "url": href, "snippet": snippet})
    return results


# 钓鱼/诈骗关键词库（用于分析搜索结果中的威胁信号）
_PHISHING_KEYWORDS = {
    "scam": ["scam", "fraud", "phishing", "fake", "legit", "legitimate", "suspicious", "malicious", "dangerous", "ripoff"],
    "credential_theft": ["password", "credential", "login", "account", "verify", "confirm", "steal", "harvest"],
    "brand_impersonation": ["impersonat", "spoof", "fake", "lookalike", "typosquat", "clone"],
    "report": ["report", "warning", "alert", "advisory", "blocked", "blacklist", "blocklist"],
    "financial": ["bitcoin", "crypto", "wire transfer", "gift card", "payment", "bank", "refund"],
}

def _analyze_search_threats(results: list[dict], query: str, page_contents: list[dict] = None) -> dict:
    """分析搜索结果摘要 + 实际网页正文中的钓鱼/诈骗威胁指标。"""
    # 合并搜索摘要
    snippet_text = (query + " " + " ".join(
        r.get("title", "") + " " + r.get("snippet", "") for r in results
    )).lower()

    # 合并实际网页正文（深度分析）
    page_text = ""
    if page_contents:
        page_text = " ".join(pc.get("content", "") for pc in page_contents).lower()

    combined_text = snippet_text + " " + page_text

    matched_types = []
    score = 0
    matched_evidence = []

    for threat_type, keywords in _PHISHING_KEYWORDS.items():
        for kw in keywords:
            if kw in combined_text:
                matched_types.append(threat_type)
                # 在网页正文中命中则加权（实际内容比摘要更可信）
                in_page = kw in page_text
                weight = 1.5 if in_page else 1.0
                if threat_type in ("scam", "credential_theft"):
                    base = 15
                elif threat_type == "brand_impersonation":
                    base = 12
                elif threat_type == "report":
                    base = 10
                else:
                    base = 8
                score += int(base * weight)
                source = "网页正文" if in_page else "搜索摘要"
                matched_evidence.append(f"{threat_type}: 关键词 '{kw}' 命中于{source}")
                break  # 每个类型只计一次

    # 额外检测：网页正文中出现的具体威胁模式
    extra_findings = []
    if page_text:
        # 检测被举报的钓鱼域名
        domain_pattern = re.compile(r'\b([a-z0-9][-a-z0-9]*\.[a-z]{2,6})\b')
        mentioned_domains = set(domain_pattern.findall(page_text))
        suspicious_domains = [d for d in mentioned_domains if any(
            kw in d for kw in ["verify", "secure", "login", "account", "update", "confirm", "bank", "pay"]
        )]
        if suspicious_domains:
            extra_findings.append(f"网页正文中提及可疑域名: {', '.join(suspicious_domains[:5])}")
            score += 8

        # 检测受害者报告模式
        victim_patterns = [
            r"lost\s+\$?\d", r"被骗", r"lost money", r"stolen\s+(funds|money|credentials)",
            r"victim", r"受害者", r"钱财损失", r"账户被盗",
        ]
        for pat in victim_patterns:
            if re.search(pat, page_text):
                extra_findings.append(f"发现受害者报告模式: {pat}")
                score += 6
                break

        # 检测安全厂商报告
        vendor_patterns = ["mcafee", "norton", "kaspersky", "symantec", "fortinet", "proofpoint", "reported by", "according to"]
        for vendor in vendor_patterns:
            if vendor in page_text:
                extra_findings.append(f"引用安全厂商报告: {vendor}")
                score += 5
                break

    return {
        "matched_types": matched_types,
        "matched_count": len(matched_types),
        "score": min(score, 45),  # 联网情报最高贡献 45 分
        "has_threat_signals": len(matched_types) > 0 or len(extra_findings) > 0,
        "evidence": matched_evidence + extra_findings,
    }


def _extract_threat_intel(results: list[dict], query: str, page_contents: list[dict] = None) -> dict:
    """从搜索结果和网页正文中提取具体威胁情报。"""
    findings = []
    sources = []

    # 从搜索结果标题/摘要中提取
    for r in results:
        title = r.get("title", "").lower()
        snippet = r.get("snippet", "").lower()
        combined = title + " " + snippet

        # 检测是否为举报/报告类页面
        report_keywords = ["scam", "fraud", "phishing", "fake", "warning", "alert", "report", "举报", "诈骗", "钓鱼"]
        if any(kw in combined for kw in report_keywords):
            source_desc = f"举报页面: {r.get('title', '')[:60]}"
            if source_desc not in sources:
                sources.append(source_desc)

    # 从网页正文中提取具体情报
    if page_contents:
        for pc in page_contents:
            content = pc.get("content", "").lower()
            title = pc.get("title", "")

            # 提取攻击手法描述
            attack_patterns = {
                "credential_harvesting": ["credential", "password", "login form", "fake login", "凭证窃取", "密码窃取"],
                "brand_spoofing": ["impersonat", "spoof", "lookalike", "clone site", "仿冒", "冒充"],
                "malware_delivery": ["malware", "ransomware", "trojan", "病毒", "木马", "勒索"],
                "social_engineering": ["social engineering", "manipulation", "社工", "诱骗"],
                "financial_fraud": ["wire transfer", "bitcoin", "crypto", "gift card", "转账", "加密货币", "礼品卡"],
            }

            for attack_type, kws in attack_patterns.items():
                for kw in kws:
                    if kw in content:
                        # 提取包含关键词的上下文句子
                        idx = content.find(kw)
                        context_start = max(0, idx - 60)
                        context_end = min(len(content), idx + len(kw) + 80)
                        context = pc.get("content", "")[context_start:context_end].strip()
                        findings.append(f"[{title[:40]}] 检测到 {attack_type}: ...{context}...")
                        break

    # 去重
    findings = list(dict.fromkeys(findings))

    return {
        "findings": findings[:10],
        "sources": sources[:5],
        "pages_analyzed": len(page_contents) if page_contents else 0,
    }


# Tools are now self-registered via @register_tool above; helper:
#   from src.tools import get_tools_for_agent
#   semantic_tools = get_tools_for_agent("semantic")
