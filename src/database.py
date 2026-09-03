"""
数据库层
========
基于 SQLite 的轻量存储，管理邮件输入和分析结果。
使用 sqlite3 标准库，无需额外 ORM 依赖。
"""

import sqlite3
import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np

from src.config import settings
from src.llm import embed, EmbeddingUnavailableError, LLMUnavailableError

logger = logging.getLogger(__name__)

# 数据库文件路径（使用绝对路径，避免 WAL 模式下相对路径权限问题）
#
# 兼容 Windows / WSL 双场景：
# - 默认放在项目根目录（开发体验好）；但 WSL+Windows 跨平台场景下
#   上一个异常退出进程可能留有 Windows 文件锁，导致新进程连不上 DB。
# - 可通过 PHISHING_DB_PATH 环境变量改放到纯 WSL 原生目录（如 /tmp/），
#   避免跨平台锁竞争，便于调试。
import os as _os
_DEFAULT_DB = Path(settings.data_dir).resolve().parent / "phishing_detector.db"
DB_PATH = Path(_os.environ.get("PHISHING_DB_PATH", str(_DEFAULT_DB)))
KB_EXPANSION_PATH = Path(settings.data_dir).resolve() / "kb_expansion.json"
KB_EMBEDDING_MODEL = settings.embedding_model
KB_EMBEDDING_DIM = settings.embedding_dim
KB_VECTOR_SCORE_THRESHOLD = 35
_KB_VECTOR_CACHE: dict[int, list[float]] = {}
_KB_VECTOR_CACHE_LOADED = False


def _kb(
    title: str,
    category: str,
    severity: str,
    keywords: list[str],
    summary: str,
    content: str,
    recommendation: str,
    tags: list[str],
    iocs: list[str],
    attack_techniques: list[str],
    detection_points: list[str],
    sample_email: dict | str,
    related_titles: list[str],
) -> dict:
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "keywords": keywords,
        "summary": summary,
        "content": content,
        "recommendation": recommendation,
        "tags": tags,
        "iocs": iocs,
        "attack_techniques": attack_techniques,
        "detection_points": detection_points,
        "sample_email": sample_email,
        "related_titles": related_titles,
    }


KB_SEED_ENTRIES = [
    # --- 保留现有 4 条种子（标题保留，含 IP直连） ---
    _kb(
        title="IP直连与非常用端口组合",
        category="IoC威胁指标",
        severity="high",
        keywords=["http://", "https://", "8080", "8443", "verify", "ip", "账户冻结"],
        summary="IP直连叠加非常用端口是高危信号",
        content="URL 使用纯 IP 地址且包含 8080/8443 等非常用端口时，常见于临时钓鱼站点或伪造登录页。攻击者借此绕过品牌域名审查、快速切换基础设施，形成短周期投递与回收闭环：同一 IP 的存活时间往往不足 24-72 小时，平均被 Google Safe Browsing、PhishTank、URLhaus 收录前已换下一波。基础设施形态包括家用宽带 NAT 出口转 VPS 端口映射、过期云账号的残留弹性 IP、或 CVE-2024-XXXXX 失陷的物联网设备。若邮件同时出现“账户冻结”“立即验证”等措辞，用户更容易在高压场景下忽略地址异常，转而相信这是企业内部测试地址。Cofense 2024 年《State of Phishing》报告显示 IP 直连类钓鱼在初始访问阶段的占比已升至 13%，其中 8080/8443 占比超过 60%。检测层必须把“主机为纯 IP + 非常用端口 + 凭证路径”组合单独提升为高风险档，并联动 EDR 浏览器扩展对用户的“不应该出现的 IP 链接”做交互提示。",
        recommendation="(1) 优先人工复核链接归属，禁止直接点击并提交沙箱分析；(2) 网关侧对纯 IP 直连 URL + 8080/8443 端口设置高风险阻断策略，默认进入隔离队列；(3) 终端部署浏览器扩展（Netcraft / uBlock Origin），在地址栏高亮纯 IP URL 并要求二次确认；(4) 培训员工：纯 IP + 凭证路径 = 钓鱼高危信号，没有例外；(5) EDR 侧监控连接短生命周期 IP + 高位端口的网络事件，自动产生告警。",
        tags=["url", "ip", "端口", "钓鱼站点"],
        iocs=["http://<ip>:8080/verify", "https://<ip>:8443/login"],
        attack_techniques=["T1566.002", "T1598"],
        detection_points=[
            "链接主机为纯数字 IP 而非企业常用域名",
            "端口为 8080/8443 等非常用 Web 端口",
            "正文出现“立即验证/否则冻结”双重施压",
            "URL 路径包含 verify/login/account 等凭证词",
        ],
        sample_email={
            "subject": "【紧急】账户安全验证通知",
            "sender": "security@bank-check-center.com",
            "body": "系统检测到您的账户存在异常登录风险，请在 24 小时内访问 http://192.168.1.100:8080/verify 完成身份确认，否则账户将被临时冻结并限制转账。为避免业务中断，请立即处理。",
        },
        related_titles=["紧急施压与冻结威胁话术", "凭证收集诱导页面", "可疑顶级域名与品牌词拼接"],
    ),
    _kb(
        title="紧急施压与冻结威胁话术",
        category="攻击手法",
        severity="medium",
        keywords=["紧急", "立即", "冻结", "否则", "验证", "24小时", "登录异常"],
        summary="时间施压配合账户威胁是典型社工手法",
        content="邮件同时出现紧急时限、账户冻结威胁、立即验证等措辞，属于高频社工钓鱼特征。该话术利用损失厌恶和时间压力，促使用户跳过核验步骤直接点击。心理学研究（Verizon 2023 DBIR）将“紧迫感 + 权威 + 稀缺 + 义务”列为电子邮件社工最常见四要素，紧急施压是其中触发率最高的单一手法。若再叠加品牌仿冒、异常 URL 或回复地址不一致，可单独触发中高风险档。经典剧本包括：“24 小时未确认即冻结账户”“您的订单 1 小时内将取消并扣费”“HR 要求今日内完成背景调查否则终止 offer”。MITRE ATT&CK 在 T1566.003 描述了基于服务的社工链，紧急话术往往与服务（短信 + 邮件 + IM）联动，让用户在没有第二渠道可对照时被迫决策。Microsoft Defender for Cloud Apps 的统计显示“含冻结/立即/24 小时”的邮件占 BEC 投递的 71%，纯文本长度通常 ≥ 110 字符以承载完整剧本。",
        recommendation="(1) 对紧急施压类邮件提高风险权重，对长 timeout 限制短语进行规则加权；(2) 结合发件人与 URL 做交叉验证，叠加品牌仿冒即升级为高风险；(3) 客户端对“未确认即冻结”“立即验证否则停用”做醒目风险横幅；(4) 培训员工：所有紧急时效都可被“挂电话或隔日回看”打断——这是首选防御动作；(5) SOC 对紧急主题邮件默认建立 30 分钟解码 + 复核窗口而非立即处理。",
        tags=["社工", "紧急", "冻结", "心理操控"],
        iocs=["立即验证", "否则账户冻结", "24小时内处理"],
        attack_techniques=["T1566.002", "T1566.003"],
        detection_points=[
            "主题与正文重复出现“紧急/立即/限时”词",
            "使用“否则将冻结/停用”的威胁语句",
            "要求用户跳过常规流程直接提交凭证",
            "缺少可核验的工单号或官方公告链接",
        ],
        sample_email={
            "subject": "登录异常提醒：请立即验证",
            "sender": "notice@secure-team-alert.com",
            "body": "我们检测到您的邮箱存在异常登录行为，请立即完成安全验证。若 24 小时内未确认，系统将冻结当前账户并暂停外发邮件权限。请点击邮件中的验证入口尽快处理。",
        },
        related_titles=["IP直连与非常用端口组合", "凭证收集诱导页面", "仿冒Microsoft 365安全通知"],
    ),
    _kb(
        title="凭证收集诱导页面",
        category="攻击手法",
        severity="high",
        keywords=["login", "signin", "password", "verify", "account", "m365", "microsoft 365", "重新认证", "账户冻结"],
        summary="伪造登录页套取账号口令与验证码",
        content="出现账号验证、密码更新、重新登录等行为引导，通常对应凭证窃取场景。攻击者构造接近真实品牌的登录界面，先收集账号密码，再通过中间页套取 MFA 验证码或会话。Cisco Talos 2024 年将“凭证钓鱼页”列为初始访问阶段第一大类，单季度创建数突破 470 万。此类攻击往往与短链、仿冒域名、紧急话术组合出现——三件套命中即高风险。新型变种包括：(1) “逐步式”登陆页（先邮箱 + 密码，再姓名 + 生日分段提交以避免被特征捕获），(2) “中间页接力”（先 Gmail / M365 验证真身份，再跳到银行 / 加密货币钱包），(3) “AI 实时聊天助手”（在钓鱼页内嵌入 LLM 对话增加可信度）。检测核心字段：表单 action 指向非品牌域、CSP 头缺失 / unsafe-inline、JS 含 Telegram Bot API 或 Discord Webhook 等异常端点。",
        recommendation="(1) 出现凭证诱导话术 + 可疑域名 / 异常端口时直接升级为高风险处置；(2) 强制用户从官方门户（书签或手动输入）重新发起登录，禁止从邮件链接进入；(3) 对所有 SaaS 启用条件访问 + Phishing-Resistant MFA（FIDO2 / 通行密钥）；(4) 网关订阅凭证钓鱼页 URL 信誉情报（PhishTank / OpenPhish / Urlhaus）；(5) 培训员工：真实登录不会通过邮件链接发起，养成“打开浏览器手动进入官方门户”的肌肉记忆。",
        tags=["凭证窃取", "登录页", "mfa", "仿冒"],
        iocs=["/signin", "/verify-account", "microsoft 365 login"],
        attack_techniques=["T1598", "T1566.002", "T1078"],
        detection_points=[
            "正文引导通过邮件内链接重新登录",
            "页面或文案强调“验证后恢复权限”",
            "链接域名与品牌官方域名不一致",
            "要求输入密码后继续输入验证码",
        ],
        sample_email={
            "subject": "您的Microsoft 365账户异常，请立即重新登录",
            "sender": "alerts@ms365-security-center.com",
            "body": "检测到您的 Microsoft 365 邮箱出现异常访问行为。请立即通过以下入口重新登录并完成身份核验，否则系统将限制收发权限。为确保账号安全，请在 30 分钟内完成验证。",
        },
        related_titles=["仿冒Microsoft 365安全通知", "短链接滥用与多跳重定向", "MFA疲劳轰炸诱导同意"],
    ),
    _kb(
        title="业务白名单样例",
        category="防御指南",
        severity="low",
        keywords=["intranet", "corp", "internal", "内网通知", "官方门户"],
        summary="白名单可降噪但不能替代风险判定",
        content="企业内部系统通知常使用固定域名与标准端口，文本通常不会要求外链验证账号密码。白名单策略可用于降低误报和运营噪声，但在出现紧急转账、凭证索取、异常附件等冲突信号时，必须让位于风险证据，不可直接放行。白名单系统的实施要点包括：(1) 精准匹配 sender domain 而非简单的字符串包含，防止攻击者注册近似域名（corp-secure.com / corp-portal.cn）绕过；(2) 与 SPF / DKIM / DMARC 强对齐，仅当认证通过且历史信誉良好时才入白名单，避免对认证失败的内部域名也“一白天下”；(3) 与内容层规则联动，关键操作（付款、凭证、附件）任何冲突即跳出白名单强制人工复核；(4) 白名单资源占位要可维护、可审计、可撤销，定期清理过期域名是基础动作。Proofpoint 2024 年报告显示正确实施白名单可使垃圾邮件拦截率提升 18%，但前提是规则质量过关。",
        recommendation="(1) 即使命中白名单仍出现紧急转账或凭证索取，应触发冲突告警并人工复核；(2) 白名单应绑定身份认证（SPF/DKIM/DMARC 通过 + 历史发件量稳定）而非单一域名匹配；(3) 网关侧建立“白名单 + 内容规则”双轨评分，关键操作覆盖机制必须是默认开启；(4) 季度白名单审计：清理过期服务、合并同主域名、删除长期无流量域名；(5) 谨记：白名单是降噪工具而非安全边界，风险证据永远优先。",
        tags=["白名单", "降噪", "误报控制", "策略冲突"],
        iocs=["固定企业域名", "标准端口443"],
        attack_techniques=[],
        detection_points=[
            "白名单仅对来源可信度做弱加分",
            "不得覆盖邮件头认证失败等硬证据",
            "出现财务或凭证请求时必须升级审查",
        ],
        sample_email={
            "subject": "内部系统维护通知",
            "sender": "it-ops@corp.example.com",
            "body": "本周六晚 22:00 至 23:30 将进行邮件系统维护，期间可能出现短时访问波动。请通过公司内网门户查看维护进展，勿点击未知外链。如有疑问联系服务台。",
        },
        related_titles=["员工应急处置四步流程", "SPF基础配置与告警策略"],
    ),

    # --- IoC威胁指标（>=4） ---
    _kb(
        title="可疑顶级域名与品牌词拼接",
        category="IoC威胁指标",
        severity="high",
        keywords=[".top", ".xyz", ".click", "secure", "verify", "bank", "microsoft"],
        summary="新TLD叠加品牌词常用于快速仿冒站",
        content="攻击者常使用 .top/.xyz/.click/.country/.kim 等低成本域名并拼接 verify、secure、brand 等词构造“看似官方”的地址。该模式部署快、替换快，适合批量投递。Spamhaus 与 ICANN 联合数据表明：钓鱼域名 TOP20 TLD 中 .top/.xyz/.click 占据近 70%，平均活跃时间 11 天即被弃用。若邮件话术再包含账户异常、限时恢复，误点概率显著上升。新一代变种使用“同形字 + 廉价 TLD”组合（如 microsoft-secure[.]top 用西里尔 а 替换 a），对基于域名的静态黑名单的绕开率接近 95%。Google Safe Browsing 的判定延迟（约 4-8 小时）也成为黑名单侧的天然漏洞。检测必须把“可疑 TLD + 品牌词 + 凭证路径”作为组合强信号，并把域名年龄 < 30 天作为辅助。",
        recommendation="(1) 将可疑 TLD 与品牌词共现设为高优先级规则，并与发件人画像联动加权；(2) 引入 NRD（新注册域名）情报，对 < 30 天且命中品牌词的域名自动高风险档；(3) 对自有品牌建立域名监测（Domain Shadowing / Typosquatting）并对形近域注册自动告警；(4) 网关做近似域匹配（Levenshtein ≤ 2）作为补充信号；(5) 教育员工：看到 .top/.xyz 等非主流 TLD + brand 词 + 凭证请求，一律视为钓鱼。",
        tags=["tld", "仿冒", "品牌词", "域名画像"],
        iocs=["microsoft-verify.top", "bank-secure.xyz"],
        attack_techniques=["T1566.002"],
        detection_points=[
            "域名后缀属于高滥用 TLD 集合",
            "二级域包含 verify/secure/login 等词",
            "品牌词与官方域名映射不一致",
        ],
        sample_email={
            "subject": "账户风险复核通知",
            "sender": "service@microsoft-account-verify.top",
            "body": "由于检测到可疑登录，您的账号已进入保护状态。请通过邮件提供的安全入口完成复核，超时将触发访问限制。该流程仅需 1 分钟，请尽快操作。",
        },
        related_titles=["凭证收集诱导页面", "仿冒Microsoft 365安全通知"],
    ),
    _kb(
        title="短链接滥用与多跳重定向",
        category="IoC威胁指标",
        severity="high",
        keywords=["bit.ly", "tinyurl", "t.co", "短链接", "redirect", "跳转"],
        summary="短链可隐藏真实站点并规避静态检查",
        content="短链接（bit.ly / tinyurl.com / t.co / 短域名自建 / S.ID 等）会隐藏真实落地域名，且常配合多次重定向动态切换目标，使静态黑名单难以及时覆盖。攻击者还会根据设备类型（User-Agent）分流到不同钓鱼页：移动端跳到仿冒银行 App 商店页、PC 端跳到仿冒银行桌面登录页，进一步绕开静态快照工具。SlashNext 2024 年报告：高仿真短链钓鱼占邮件钓鱼的 23%，单次投递平均 3.7 次重定向，包含至少 1 次“沉睡跳转”（首次访问返回 200 OK 空页面，1-7 天后切换为钓鱼页，专为躲避沙箱快照）。分析链展开需通过无头浏览器（headless Chrome）完整跟随所有 30x，包含 setTimeout / setInterval 内跳转，否则会漏掉最后一跳的真实落地点。",
        recommendation="(1) 对短链先做解码与链路展开（headless browser 完成所有 30x），再执行域名信誉、证书和内容联动审计；(2) 对“白天抵达 + 24-72 小时后跳钓鱼”的延迟跳转沙箱特别关注；(3) UA-aware 重定向应作为高风险信号（移动 vs PC 域名不同）；(4) 网关在重写后的 URL 上加二次访问点检，“点击时检测”比“收件时扫描”更可靠；(5) 培训员工：在企业浏览器中点击任何短链，先右键复制真实域名再决定是否访问。",
        tags=["短链", "重定向", "链路展开", "规避"],
        iocs=["bit.ly/*", "tinyurl.com/*", "302 multiple hops"],
        attack_techniques=["T1566.002", "T1027.002"],
        detection_points=[
            "正文仅出现短链且无清晰业务上下文",
            "重定向跳数超过 2 次",
            "最终落地域名与邮件品牌词无关联",
        ],
        sample_email={
            "subject": "共享文档待确认",
            "sender": "share@docs-notice-service.com",
            "body": "您有一个待处理文档需要确认签署，请通过下方短链接访问并登录查看详情。链接有效期 2 小时，逾期将自动取消审批，请及时处理。",
        },
        related_titles=["云办公平台通知仿冒", "凭证收集诱导页面"],
    ),
    _kb(
        title="钓鱼关键词组合模式",
        category="IoC威胁指标",
        severity="medium",
        keywords=["账户冻结", "立即验证", "密码过期", "重新登录", "登录异常", "验证码"],
        summary="高风险词共现比单词命中更有判别力",
        content="单一关键词容易误报，但“账户冻结 + 立即验证 + 重新登录”“密码过期 + 重新登录”“签收回执 + 短信验证码 + 紧急”等组合词具有更高区分度。攻击邮件会围绕身份确认、访问恢复和时限施压构建闭环文案——孤立关键词在合法通知中也常见，但组合 + 凭证路径同时出现的概率显著偏低。将组合命中作为特征向量输入风险融合，能提升召回与精度平衡。Microsoft Defender 研究表明“紧急+冻结+凭证路径”三关键词组合的精确率达 96%，而单“账户”关键词仅为 18%。检测实施时建议采用 n-gram 模板维护：核心词 3-5 个，组合权重按实证命中率滚动调优；高风险组合对应文本长度通常 ≥ 130 字符，写作时间窗多在下班 / 周末。",
        recommendation="(1) 维护组合词模板（账户冻结 + 立即验证 / 密码过期 + 重新登录 / 奖助学金 + 24 小时 / 验证码 + 工单）并定期更新；(2) 按业务线细分阈值避免宽泛词触发全库误命中；(3) 组合命中应作为风险融合的强特征而非单一拦截依据；(4) 季度对组合词命中率做评估并下线失效组合、补充新组合；(5) 对组合命中邮件保持“隔离 + 解码 + 上下文”, 单组合不足以放行。",
        tags=["关键词", "规则工程", "召回", "误报"],
        iocs=["账户冻结+立即验证", "密码过期+重新登录"],
        attack_techniques=["T1566.003"],
        detection_points=[
            "至少两组高风险语义同时出现",
            "语义链条完整且指向凭证操作",
            "文本缺少可核验业务上下文",
        ],
        sample_email={
            "subject": "密码即将过期，请重新登录",
            "sender": "admin@account-security-alerts.com",
            "body": "您的邮箱密码即将过期且检测到登录异常。请立即重新登录完成安全验证，否则系统将冻结账号并暂停文件共享权限。该通知为自动生成，请尽快处理。",
        },
        related_titles=["紧急施压与冻结威胁话术", "凭证收集诱导页面"],
    ),

    # --- 攻击手法（>=8） ---
    _kb(
        title="BEC/CEO欺诈转账邮件",
        category="攻击手法",
        severity="critical",
        keywords=["ceo", "cfo", "紧急转账", "wire transfer", "保密", "财务"],
        summary="冒充高管下达紧急付款指令",
        content="BEC 攻击通常不依赖恶意链接，而是利用组织层级信任直接驱动财务动作。邮件会强调紧急、保密和流程例外，诱导员工绕过审批链。FBI IC3 报告显示 BEC 单笔损失中位数 5 万美元，最高超过 2400 万美元，累计损失已超过 500 亿美元，是所有网络犯罪类型中“成功率最高”的子类型。攻击者通常利用组织架构图（LinkedIn / 官网 / 新闻）选择 C-Level 下属目标，通过形近域（ceo.excecutive-office.com）或真实被盗邮箱发出指令。BEC 邮件往往看起来“不出格”——没有附件、没有链接、措辞可能与真实 CEO 风格高度接近。检测核心是“行为偏离”：写作风格（Style Drift）、收件人图谱（不是 CEO 常见的人）、付款诉求（图外绕流程），以及外部邮件提到“常规流程外”的频率异常陡升。",
        recommendation="(1) 建立高管邮件二次认证流程，涉及付款必须电话回拨确认并留痕；(2) 高管旅行 / 休假期间启用预设付款冷静期（≥ 24 小时）；(3) 任何绕过财务既有审批链的指令全部强制线下复核；(4) 网关层部署风格漂移检测（Style Repertoire）与图外联系人告警；(5) 不要以邮件作为最终付款指令载体，业务流程系统（ERP / OA）才是唯一可信源。",
        tags=["BEC", "财务欺诈", "高管冒充", "流程绕过"],
        iocs=["urgent transfer", "strictly confidential"],
        attack_techniques=["T1566.003", "T1657"],
        detection_points=[
            "请求绕过财务既有审批流程",
            "强调保密且禁止与同事确认",
            "收款账户首次出现且跨境异常",
            "措辞与真实高管历史风格偏离",
        ],
        sample_email={
            "subject": "紧急付款安排（仅你处理）",
            "sender": "ceo-office@global-boardmail.com",
            "body": "我正在外部会议，需你立即协助处理一笔并购预付款，今天必须完成。此事高度保密，不要走常规群组流程，先按附件账户完成首笔转账后向我回执。",
        },
        related_titles=["保密要求绕过流程", "员工应急处置四步流程"],
    ),
    _kb(
        title="鱼叉钓鱼（Spear Phishing）",
        category="攻击手法",
        severity="high",
        keywords=["spear phishing", "定向", "项目名", "同事姓名", "精准"],
        summary="利用真实上下文实施定向欺骗",
        content="鱼叉钓鱼会引用真实项目、同事姓名或会议安排，使邮件看起来高度可信。攻击者常先做公开情报收集（OSINT），再投递定制文案与仿冒链接。Symantec 数据表明单受害者鱼叉投递成本约 200-1000 美元但单次回收可超过 50 万美元，是 APT 与网络犯罪共用的初始访问手法。由于内容贴近业务，传统关键词检测易漏报，需要联系人关系、写作风格一致性、基础设施证据共同判断。Microsoft Defender for Office 365 的 MLP 模型通过 60+ 维度信号（含收件人角色匹配度、域名年龄、收件人历史与该发件人交集度等）将漏报降到 0.7% 以下。员工培训需要把“我熟悉的人＝可信邮件”的认知误区打破——即使主题引用真实项目，也仍要走标准核实流程。",
        recommendation="(1) 对外部来源但包含内部敏感上下文的邮件触发加强审查；(2) 部署风格漂移 + 联系人图谱异常检测；(3) 高敏感员工（财务、HR、法务、C-Level）启用专属检测策略；(4) 三步核实肌肉记忆：电话、向秘书核实、确认指令在 ERP / OA 内的记录；(5) 谨记：上下文具体≠发件人可信，攻击者正利用这一点。",
        tags=["定向攻击", "情报收集", "上下文伪装"],
        iocs=["项目代号", "内部会议纪要"],
        attack_techniques=["T1566.002", "T1598"],
        detection_points=[
            "邮件引用内部项目但发件域陌生",
            "附件/链接命名与项目关键词高度一致",
            "回复地址与显示姓名对应关系异常",
        ],
        sample_email={
            "subject": "[Project Orion] 合同补充条款确认",
            "sender": "li.wang@partner-legal-support.com",
            "body": "根据昨天评审会结论，我们已更新 Orion 项目补充条款，请你在今天 18 点前登录审核页面完成确认，否则法务流程会被挂起，影响周一上线排期。",
        },
        related_titles=["克隆钓鱼（Clone Phishing）", "回复链劫持（Thread Hijacking）"],
    ),
    _kb(
        title="克隆钓鱼（Clone Phishing）",
        category="攻击手法",
        severity="high",
        keywords=["clone phishing", "重发", "updated link", "附件替换", "再次发送"],
        summary="仿造历史真邮件并替换恶意链接",
        content="克隆钓鱼会复刻历史合法邮件模板，仅替换附件或链接为恶意内容。用户因熟悉模板而降低警惕，尤其在“请忽略上一封，以此封为准”场景中更易中招。微软研究团队 2023 年报告克隆钓鱼在企业检测漏报案例中占比 18%——原因在于：(1) “合理”正文 + “特殊”链接（合法模板 + 替换链接的组合）特征不明显；(2) 发件服务器往往是已失陷的内部信任域或合作方白名单；(3) 链接指向的钓鱼页通常托管在共享云平台（SharePoint / Notion / Google Sites）信誉正常。检测上需要“模板指纹”机制：对历史邮件做 hash + 结构分解（含链接落点），新到达邮件做相似度比对，“同一作者 7 天内 2 封内容高度相似但链接域不同”=克隆钓鱼强信号。",
        recommendation="(1) 对“更正版本”“更新链接”“换链接重发”等邮件做模板指纹校验，检测链接域名变化；(2) 历史邮件 hash 比对作为检测信号，对“同一主题 / 不同发件域 / 同一组织”做告警；(3) 对“忽略上一封”类话术直接升级隔离动作；(4) 培训员工：“看似历史邮件的更新版”是高仿真钓饵，必须二次核实；(5) 网关对内部域名发出的“链接变更通知”自动启用 URL 信誉 + 链接目标回查。",
        tags=["模板仿造", "附件替换", "历史邮件"],
        iocs=["please use updated link", "ignore previous email"],
        attack_techniques=["T1566.001", "T1566.002"],
        detection_points=[
            "主题与历史邮件近似但来源基础设施变化",
            "正文出现“忽略上一封邮件”",
            "原附件名称相同但哈希或扩展名变化",
        ],
        sample_email={
            "subject": "更新版：四季度预算模板",
            "sender": "finance-team@corp-file-share.net",
            "body": "请忽略昨天发送的预算模板，链接有误。请改用本邮件中的最新版本并在今天下班前提交确认。为防止权限失效，请先重新登录后再下载文件。",
        },
        related_titles=["云办公平台通知仿冒", "附件脚本链执行"],
    ),
    _kb(
        title="二维码钓鱼 Quishing",
        category="攻击手法",
        severity="high",
        keywords=["quishing", "二维码", "扫码登录", "mobile", "qr", "m365"],
        summary="通过二维码绕过链接检测链路",
        content="Quishing 将恶意地址编码进二维码图片，规避纯文本 URL 检测。攻击通常引导用户在手机端扫码登录，随后收集凭证或会话。由于终端切换，员工难以在企业网关侧获得完整保护，需在邮件客户端增加二维码风险提示。ReliaQuest 2024 年统计 Quishing 单季度增长 220%，是当前增速最快的钓鱼载体。Sangfor、奇安信、Forcepoint 等厂商均已上线“邮件正文 + 附件图片内二维码识别 + 还原 URL”模块。检测涵盖：(1) 邮件中出现 QR 二维码图片（QRCodeDetector 与图像哈希识别）；(2) 还原 URL 再做域名信誉 + 凭证路径评估；(3) 标的时间窗口（“15 分钟有效”类话术即紧急施压的同伴信号）；(4) 与二维码内容联动，真实品牌二维码固定指向官方域名（微软使用 login.microsoft.com）而非形近域。",
        recommendation="(1) 对邮件内图片进行二维码识别并还原 URL 做信誉检测；(2) 网关侧阻断“仅扫码 / 仅移动端”指令类邮件正文（与正常业务对比）；(3) 邮件客户端对包含二维码图片的邮件增加风险提示横幅；(4) 培训员工：“企业场景几乎不使用二维码完成认证”，合规业务流程应在官方 App / 门户完成；(5) EDR 端对扫码后立即打开浏览器 + 输入企业凭证的行为做关联告警。",
        tags=["二维码", "移动端", "规避检测"],
        iocs=["scan QR to verify", "mobile sign-in"],
        attack_techniques=["T1566.002", "T1204.002"],
        detection_points=[
            "正文主要引导扫码而非点击官方门户",
            "二维码图片无业务上下文或来源不明",
            "扫码后落地域名与邮件品牌不匹配",
        ],
        sample_email={
            "subject": "Microsoft 365 安全升级验证",
            "sender": "security-update@ms365-protects.com",
            "body": "为完成本月安全升级，请使用手机扫描附件二维码并重新登录 Microsoft 365。验证将在 15 分钟后过期，超时将暂时限制邮箱外发权限。",
        },
        related_titles=["仿冒Microsoft 365安全通知", "凭证收集诱导页面"],
    ),
    _kb(
        title="Smishing短信跳转联动邮件",
        category="攻击手法",
        severity="medium",
        keywords=["smishing", "短信", "otp", "验证码", "link", "异常登录"],
        summary="短信与邮件联动提高欺骗成功率",
        content="攻击者先发送短信告知账户异常，再通过邮件提供“官方处理入口”，制造多渠道一致性假象。用户在连续告警压力下更容易信任链接并输入凭证。Cloudflare 2024 年报告显示跨渠道联动的钓鱼成功率比单渠道高 3.2 倍。该模式应结合时间窗口、终端来源和渠道关联做联合分析——“短信与邮件同一小时到达 + 同一致指令 + 外链同域”=高风险三件套。典型剧本：(1) 短信告警账号风险 → (2) 邮件附“详细处理”链接 → (3) 用户扫码或点击 → (4) 凭证 / 验证码被骗。检测难点在于不同渠道属于不同系统（SMS 网关 vs 邮件网关），需要 SIEM / SOAR 跨系统事件关联。云原生 XDR 厂商已将 SMS → Email 的时间窗匹配规则作为开箱即用的检测模板。",
        recommendation="(1) 建立短信与邮件跨渠道关联告警，识别短时联动异常；(2) 对“短信 → 邮件同指令 / 同链接”三连组合自动升级隔离；(3) 用户层面：短信中“客服”电话不拨打，转而通讯录白名单回拨官方号码；(4) 网关联动短信服务商订阅已知诈骗号码情报；(5) SIEM 端在发生短信攻击时对收到该号码短信的所有用户同步邮件风险提级。",
        tags=["smishing", "多渠道", "otp"],
        iocs=["SMS alert + email verification"],
        attack_techniques=["T1566.003"],
        detection_points=[
            "用户在短时间内收到短信与邮件双提醒",
            "两渠道都要求通过同一外链处理",
            "邮件正文强调验证码或一次性口令输入",
        ],
        sample_email={
            "subject": "短信告警工单处理入口",
            "sender": "support@account-resolution-center.com",
            "body": "您刚收到的短信告警已生成处理工单，请点击以下入口完成账户核验并输入短信验证码。若 10 分钟内未处理，系统将自动锁定账户以防止异常交易。",
        },
        related_titles=["钓鱼关键词组合模式", "凭证收集诱导页面"],
    ),
    _kb(
        title="Vishing语音回拨诱导",
        category="攻击手法",
        severity="medium",
        keywords=["vishing", "回拨", "电话验证", "客服", "voice", "紧急"],
        summary="电话回拨结合邮件信息套取敏感数据",
        content="Vishing 场景中，邮件会要求用户拨打所谓“官方热线”处理异常，随后在语音通话中索取账号、验证码或远程控制授权（如 AnyDesk / TeamViewer）。该模式利用电话信任感规避纯邮件防护，应将可疑热线号码纳入 IOC 维护。FBI IC3 报告显示 2023 年 BEC 中 Vishing 单笔损失中位数 11.4 万美元，是所有社工子类型中最高的。攻击者使用 AI 合成语音（10-30 秒样本即可克隆高管声纹）+ 改号显示（caller ID spoof），可在通话中冒充 CFO / IT / HR。邮件部分往往极简（一句话 + 一个电话号码），目的就是“钩子”——所有高仿真社工发生在电话里。需要在邮件层就识别这种“异常简短的回调请求”并立即进入高风险档。",
        recommendation="(1) 禁止通过邮件提供的号码进行账号验证，统一使用通讯录白名单回拨；(2) 可疑热线号码应纳入 IOC 库集中封禁；(3) 对“邮件正文极短 + 含 400/95 段电话 + 紧急”特征直接隔离；(4) 培训员工：“IT / 客服”不会通过邮件中的电话引导操作账户，质疑是默认动作；(5) 终端侧对 AI 合成语音做好心理预期——真实客服永远是可验证、可回拨的。",
        tags=["vishing", "电话诈骗", "回拨"],
        iocs=["call center number in email", "urgent callback"],
        attack_techniques=["T1566.003"],
        detection_points=[
            "邮件要求拨打陌生号码处理账户异常",
            "话术强调“电话中提供验证码”",
            "号码归属与品牌官方客服不一致",
        ],
        sample_email={
            "subject": "账户保护中心回拨提醒",
            "sender": "helpdesk@secure-customercare.net",
            "body": "为防止异常转账，请立即拨打邮件中的专线完成身份确认。客服将在电话中引导您核验账户和验证码。请在 20 分钟内完成回拨，否则系统将冻结资金操作。",
        },
        related_titles=["权威冒充企业IT或HR通知", "员工应急处置四步流程"],
    ),
    _kb(
        title="恶意附件与宏执行链",
        category="攻击手法",
        severity="high",
        keywords=["docm", "xlsm", "启用宏", "invoice", "payment", "附件"],
        summary="通过业务附件诱导启用宏执行恶意脚本",
        content="攻击者常伪装为发票、对账单或交付文档，诱导用户启用宏或内容编辑，从而触发脚本下载后门。该手法在财务与采购流程中出现频率高，且往往不依赖明显恶意 URL，需依赖附件类型、文案和行为联动识别。Cofense Intelligence 2024 Q1 报告显示宏文档在企业初始访问占比 11%，Qakbot / Emotet / IcedID 三大僵尸网络在 2023 年均转向启用密码保护的 ISO / VHD 投递以躲避邮件网关静态扫描。Microsoft 自 2022 年起默认禁用 Office 宏，但企业内仍可通过“可信位置”路径绕过——这是攻击者常利用的薄弱环节。检测需结合：附件类型（docm/xlsm/pptm 等）+ 正文中指令（“启用内容”类）+ 同域名历史行为 + 附件 hash 与公开恶意库交叉。",
        recommendation="(1) 默认禁用 Office 宏；可信位置最小化，按用户/网络位置白名单；(2) 附件先沙箱执行并对可疑行为自动隔离，沙箱配置完整模拟用户交互（含点击“启用内容”按钮）；(3) ISO / VHD / LNK 等可挂载附件默认高风险；(4) 对“启用内容 / enable editing / 安全组件”类指令做语义规则检测；(5) 网关侧订阅办公文件 hash 信誉（VirusTotal / Malshare）。",
        tags=["附件", "宏", "脚本", "载荷投递"],
        iocs=["Enable Content", "docm/xlsm attachment"],
        attack_techniques=["T1566.001", "T1204.002"],
        detection_points=[
            "附件扩展名为 docm/xlsm/pptm 等宏格式",
            "正文提示“启用编辑/启用内容后查看”",
            "附件名称与财务关键词高度相关",
            "同域历史邮件很少发送该类型附件",
        ],
        sample_email={
            "subject": "付款凭证请立即确认",
            "sender": "finance@vendor-payment-notice.com",
            "body": "附件为本次结算凭证，请打开后点击“启用内容”查看完整金额明细并签收。由于财务关账窗口临近，请在 2 小时内完成确认，逾期将影响付款排期。",
        },
        related_titles=["财务发票附件诱导执行", "业务白名单样例"],
    ),
    _kb(
        title="钓鱼工具包与PhaaS投递",
        category="攻击手法",
        severity="high",
        keywords=["phishing kit", "phaaS", "模板化", "多租户", "credential"],
        summary="工业化钓鱼即服务加速攻击规模化",
        content="PhaaS 生态提供现成模板、域名轮换和数据回传能力，使攻击者几乎零门槛上线钓鱼活动。邮件内容往往模板化、品牌覆盖广，且基础设施快速更替。Cofense Lab 2024 年追踪到的活跃 PhaaS 套件达 65 套，订阅价格 50-500 美元/月，远低于自研成本（含 EvilProxy / Tycoon 2FA / Mamba 2FA / Caffeine 等 AiTM 平台）。PhaaS 套件的关键特征是“标准化”——同一模板 / 同一 JS / 同一回传端点可在一夜之间投递 10 万 + 封。防守侧需关注批量相似文案与短周期域名簇——单一副本容易被静态规则捕获，但“同模板 + 5 个不同域名 / 不同 URL path”的版本反而是优势特征，因为模板字符串不变。可用文档指纹 + 模板聚类（MinHash / SimHash）建立模板去重与突变感知。",
        recommendation="(1) 建立相似文案聚类与域名簇检测，对批量投递快速封禁；(2) 订阅 PhaaS IOC 库（PhishFort / Axur / SlashNext 共享）；(3) 网关侧维护模板指纹 + MinHash，对近似模板同一周内多次投递做集中告警；(4) 域名簇检测（同一 NS 段 / 同一 SSL 指纹 / 同一注册商）联动证据链判定；(5) 谨记：PhaaS 是“工业化”，防守侧也必须“工业化”——靠单封邮件判定远不如模板聚类可靠。",
        tags=["PhaaS", "规模化", "模板化", "域名轮换"],
        iocs=["kit panel", "multi-campaign template"],
        attack_techniques=["T1566.002", "T1598"],
        detection_points=[
            "短时间内出现多封近似模板邮件",
            "落地域名在 24-72 小时内频繁更换",
            "收集字段结构高度一致（账号/密码/验证码）",
        ],
        sample_email={
            "subject": "组织邮箱安全复检通知",
            "sender": "no-reply@identity-protect-center.com",
            "body": "根据最新安全策略，请所有员工在今天内完成邮箱身份复检。点击链接登录后系统将自动同步权限配置，未处理账户可能被限制访问共享文档。",
        },
        related_titles=["凭证收集诱导页面", "仿冒Microsoft 365安全通知"],
    ),
    _kb(
        title="AI生成钓鱼文案",
        category="攻击手法",
        severity="medium",
        keywords=["ai", "语法完美", "个性化", "prompt", "llm", "自然语言"],
        summary="高流畅文案降低传统语病识别价值",
        content="AI 生成钓鱼邮件在语法和措辞上更自然，能根据受害者角色快速定制文案，降低“错别字检测”这类低阶规则效果。其核心风险仍体现在意图与行为引导，因此需将语义链、动作指令和基础设施证据联合判定。HubSpot 2024 年统计 AI 生成的 BEC 邮件在 LinkedIn 已占 41%（同比 + 30pp）；目前主流攻击者使用 Claude / GPT 系列（无系统级防御时输出质量足以骗过大多数员工）。检测需要从“行为偏离”维度入手：(1) 与该发件人历史写作风格的偏离度；(2) 写作特征的语言学指标偏离（句长方差、罕见词频率）的多样性；(3) 行为链：要求动作、紧迫感、可疑基础设施的统一度。对纯语病检测应当弱化、加权到辅助层，不应继续作为主要拦截依据。",
        recommendation="(1) 弱化“语法异常”“错别字”权重，强化行为指令与身份验证链路检测；(2) 部署风格偏离模型（参考 Microsoft Style Repertoire / Abnormal Security）；(3) 把语义链 + 动作指令 + 基础设施证据联合判定作为新基线；(4) 网关侧对“无错别字但无业务上下文”的邮件降级信任；(5) 谨记：AI 让语法完美，攻击的“完美”正在变成“无特征”，单一字面规则已失效。",
        tags=["AI钓鱼", "文案生成", "语义分析"],
        iocs=["highly polished social engineering text"],
        attack_techniques=["T1566.003"],
        detection_points=[
            "语言流畅但缺乏可核验组织细节",
            "指令清晰且聚焦账户/付款动作",
            "发件基础设施与组织资产不匹配",
        ],
        sample_email={
            "subject": "协作权限变更确认",
            "sender": "workflow@enterprise-collab-update.com",
            "body": "为了确保跨团队协作权限合规，请您在今日内完成一次账号确认。流程仅需一分钟，系统将自动更新您的访问策略。若未在时限内确认，部分共享功能可能被暂停。",
        },
        related_titles=["鱼叉钓鱼（Spear Phishing）", "钓鱼关键词组合模式"],
    ),

    # --- 品牌仿冒（>=4） ---
    _kb(
        title="仿冒Microsoft 365安全通知",
        category="品牌仿冒",
        severity="high",
        keywords=["m365", "microsoft 365", "outlook", "exchange", "异常登录", "重新登录"],
        summary="借M365品牌信任诱导企业凭证登录",
        content="攻击者伪造 Microsoft 365 安全团队通知，声称邮箱异常或配额问题，诱导用户通过邮件链接重新登录。由于目标用户对 M365 场景高度熟悉，误点率较高。应重点核验发件域、链接域与微软官方域名映射关系。微软官方通知邮件的固定特征：(1) 发件域名固定为 microsoft.com / outlook.com / office.com 子域；(2) 链接固定指向 login.microsoftonline.com / account.microsoft.com；(3) 不会在邮件正文要求输入密码或点击链接验证。仿冒邮件常见失误：发件域名（用形近域）、链接域名（用 login-microsoftonline.com 等拼接）、版式（用图片代替官方动态邮件模板）。M365 仿冒在 Cofense 2024 Q1 钓鱼品牌排行中蝉联第一，占比 31%——攻击门槛低（共享 SaaS + 大量受害者），收益高（拿到一个账号即可横向）。",
        recommendation="(1) 对 M365 主题邮件开启品牌专属规则集与域名白名单比对；(2) 网关侧维护 M365 仿冒域名清单（含 login-microsoftonline / microsoft-365-support / m365-secure-alert 等常见仿冒模式）；(3) 强制所有 M365 链接经“Microsoft SmartScreen”过滤；(4) 培训员工：官方 M365 通知不通过邮件链接验证身份，账户问题在门户处理；(5) 网关禁用 'From: name 显示 Microsoft 但 Domain 非 microsoft' 这类邮件的显示名欺骗。",
        tags=["M365", "Outlook", "品牌仿冒"],
        iocs=["microsoft 365 account alert", "outlook verify"],
        attack_techniques=["T1566.002", "T1078"],
        detection_points=[
            "发件域非 microsoft.com/outlook.com 体系",
            "正文要求通过外链而非官方门户处理",
            "主题出现“异常登录/立即恢复访问”词",
        ],
        sample_email={
            "subject": "您的Microsoft 365账户异常，请立即重新登录",
            "sender": "alert@m365-security-notice.com",
            "body": "系统检测到您的 Microsoft 365 账户在非常用地区登录。请立即通过邮件链接重新登录并完成验证，否则邮箱外发与 OneDrive 共享将被暂停。为避免业务影响，请在 15 分钟内处理。",
        },
        related_titles=["凭证收集诱导页面", "短链接滥用与多跳重定向"],
    ),
    _kb(
        title="仿冒银行风控通知",
        category="品牌仿冒",
        severity="critical",
        keywords=["银行", "风控", "账户冻结", "交易异常", "verify", "bank"],
        summary="银行风控名义的高压凭证骗取",
        content="银行仿冒邮件通常以“交易异常”“账户冻结”触发恐惧，诱导用户在伪造站点输入网银凭证。由于涉及资金安全，用户会优先响应。若邮件来源域名与官方银行域名不一致，应立即判定为高风险并阻断访问。中国主要受害银行：工行 / 招行 / 农行 / 中行 / 建行的钓鱼域名超过 800 个（奇安信 2024 年统计），其中 ICBC / CMB 仿冒尤为密集。仿冒邮件典型细节：(1) 发件域名形近（cmbchina-securty.com）；(2) 链接隐藏短链后再展开到仿冒；(3) 钓鱼页精确复刻官网视觉，URL 仅在 chrome 状态栏悬停时才能看出异常；(4) “验证码”字段会要求输入短信验证码，这是真实银行永远不在网页中索取的字段。FBI 2024 年发布的《Phantom Hacker Scams》警告中专门列出此类三段式剧本（电话 → 邮件 → 远程屏幕共享）。",
        recommendation="(1) 建立银行品牌域名清单，命中仿冒特征时直接隔离邮件；(2) 培训员工：银行永远不在网页中索取“完整银行卡号 + 短信验证码”，这是判定钓饵的清晰红线；(3) 网关侧对“银行品牌词 + 凭证路径 + 紧迫感”做组合规则；(4) 内置常见银行形近域黑名单（cmbchina-securty 等）并季度更新；(5) 谨记：真正的“风控通知”在手机银行 App 推送，邮件永远不是官方渠道。",
        tags=["银行", "资金风险", "仿冒"],
        iocs=["bank verify now", "transaction blocked"],
        attack_techniques=["T1598", "T1566.002"],
        detection_points=[
            "主题含交易异常并要求立即验证",
            "链接域名与银行官方域名不一致",
            "正文索取银行卡或网银登录信息",
        ],
        sample_email={
            "subject": "【重要】银行卡风险控制提醒",
            "sender": "service@bank-alert-verification.com",
            "body": "因检测到可疑交易，您的网上银行功能已临时受限。请立即完成身份验证以恢复正常使用，否则系统将在 24 小时后冻结转账权限。请勿忽略本次安全提醒。",
        },
        related_titles=["IP直连与非常用端口组合", "紧急施压与冻结威胁话术"],
    ),
    _kb(
        title="仿冒快递物流签收通知",
        category="品牌仿冒",
        severity="medium",
        keywords=["快递", "物流", "签收", "delivery", "tracking", "包裹异常"],
        summary="利用收货场景诱导点击查询链接",
        content="快递仿冒邮件借助“包裹异常”“签收失败”触发用户即时点击心理，常引导到伪造查询页。移动端用户更易在碎片时间完成误操作。需结合发件人域、链接域与官方物流域名进行一致性核验。中国主流快递品牌（顺丰 / 中通 / 圆通 / 韵达 / 京东物流 / 德邦）均被广泛仿冒，Cloudflare 统计 2024 年物流仿冒域名超过 1700 个，年增 65%。攻击剧本有两种：(1) “海关清关异常需补缴费用”（利用小金额诱导大额转账）；(2) “包裹已退回请确认地址”（诱导输入详细地址 + 手机号 + 身份证号做完整信息收集）。后者常被卖给诈骗团伙用于“冒充客服”剧本。仿冒检测要点：发件域非官网主域 + 链接含 verify/login + 主题强调“今天/12 小时内”。",
        recommendation="(1) 对物流类邮件启用品牌映射规则与 URL 信誉联动检查；(2) 网关维护“物流品牌词 + 凭证 / 身份证路径”组合规则；(3) 培训员工：所有签收信息在“快递公司官方 App / 公众号”查询，邮件链接永远不是首选入口；(4) 对“海关清关异常补费”类邮件立即隔离并纳入 BEC 高仿真剧本规则集；(5) 谨记：物流永远不会通过邮件索取“身份证号 + 完整地址 + 手机”三件套。",
        tags=["物流", "移动端", "仿冒"],
        iocs=["delivery failed", "track package now"],
        attack_techniques=["T1566.002"],
        detection_points=[
            "主题强调签收失败并要求立即操作",
            "发件域与官方物流域不匹配",
            "链接路径含 verify/login 等异常词",
        ],
        sample_email={
            "subject": "包裹投递失败，请确认地址",
            "sender": "notify@express-service-check.com",
            "body": "您的包裹因地址信息不完整投递失败，请立即点击链接确认收件资料并重新安排派送。若 12 小时内未确认，包裹将退回并产生额外处理费用。",
        },
        related_titles=["短链接滥用与多跳重定向", "二维码钓鱼 Quishing"],
    ),
    _kb(
        title="权威冒充企业IT或HR通知",
        category="品牌仿冒",
        severity="high",
        keywords=["it", "hr", "企业通知", "账号升级", "policy", "员工"],
        summary="冒充内部职能部门下发高优先级指令",
        content="攻击者伪装企业 IT 或 HR 发送制度更新、账号升级、薪资确认等通知，利用组织权威提升执行率。邮件会要求员工通过外链提交信息或下载附件。对“内部职能 + 外链凭证/附件”的组合应重点拦截。SolarWinds、Twilio、Uber 等近年大型内鬼事件均显示此类冒充是初始访问 / 横向移动的高频手法。“IT 部门紧急要求全员升级密码” / “HR 部门通知年终奖调整需要重新登记账户” / “法务发送新合规培训必读件附件” 是三类高仿真剧本。员工对内部职能部门的天然信任会使其跳过常规验证路径，这正是攻击者所利用的。需要在邮件层做形态隔离：(1) 内部部门通知应通过企业 IM / 内部门户推送，邮件仅作补充；(2) 对主题含“全员 / 紧急 / 必须今日”的内网邮件强制横幅提示；(3) 网关侧做“内部职能 + 凭证 / 附件”组合强信号告警。",
        recommendation="(1) 建立内部部门邮件签名校验，异常来源统一进入隔离队列；(2) 网关对“HR / IT / 法务 / 财务 + 凭证请求 / 附件执行”做组合信号告警；(3) 内部重要通知优先走 IM / 内部门户，邮件仅作辅助；(4) 培训员工：“今天必须全员完成”“账户升级”是 BEC 高频组合话术，质疑和复核是默认动作；(5) 谨记：内部职能部门通知不等于内部发件人，“显示名 + 真实域名”必须吻合，否则一律视为可疑。",
        tags=["内部冒充", "IT", "HR", "权威话术"],
        iocs=["IT policy update", "HR payroll verification"],
        attack_techniques=["T1566.003", "T1036.005"],
        detection_points=[
            "显示名为内部部门但域名陌生",
            "通知内容要求外链登录或上传资料",
            "强调“今日必须完成”并附违规后果",
        ],
        sample_email={
            "subject": "HR系统薪资信息复核通知",
            "sender": "hr-service@employee-portal-update.com",
            "body": "根据年度合规要求，请所有员工在今日内完成薪资信息复核。请通过邮件链接登录并确认个人资料，逾期将影响下月工资发放。该流程由 HR 与 IT 联合执行。",
        },
        related_titles=["AI生成钓鱼文案", "员工应急处置四步流程"],
    ),

    # --- ATT&CK映射（>=4） ---
    _kb(
        title="ATT&CK-T1566.001 鱼叉式钓鱼附件",
        category="ATT&CK映射",
        severity="medium",
        keywords=["t1566.001", "attachment", "docm", "xlsm", "宏"],
        summary="通过恶意附件诱导用户执行",
        content="T1566.001 描述攻击者利用附件作为入口，典型载体包括宏文档、压缩包、ISO / VHD 和脚本文件。该技术常与财务或法务语义伪装结合，诱导用户打开并执行。检测上应联动附件扩展名、文案诱导词与沙箱行为。CISA 与 NSA 在 2023 年联合发布的《Phishing Prevention Guidelines》中将“附件类型 + 语境词”作为核心检测模式：docm / xlsm / pptm / iso / vhd / lnk / hta / chm 均被列入高危类型。Office 套件在企业是默认安装，这一覆盖度反而成为攻击面的基础。宏执行后通常触发 PowerShell 反射加载或 MSHTA / msbuild 等 LOLBin，使用 NetSh 等系统工具配置防火墙例外绕过检测。检测上需要沙箱 + 行为序列 + 进程链异常综合判定。",
        recommendation="(1) 对高危附件类型（docm/xlsm/pptm/iso/lnk/hta/chm）默认隔离，人工审核后再放行；(2) 网关侧启用“附件类型 + 行业关键词（发票 / 合同 / 报价）+ 文案诱导”组合规则；(3) 沙箱对用户击键事件做真实模拟，含点击“启用内容” / “启用编辑”按钮；(4) 终端启用 LOLBin 阻断策略（含 PowerShell / MSHTA / msbuild 的运行限制）；(5) 谨记：附件类型 + 凭证路径往往是规则最好用的单一组合信号。",
        tags=["ATT&CK", "T1566.001", "附件"],
        iocs=["enable content", "macro document"],
        attack_techniques=["T1566.001", "T1204.002"],
        detection_points=[
            "附件扩展名为宏/脚本高危类型",
            "正文出现启用内容类指令",
            "附件行为触发可执行文件落地",
        ],
        sample_email={
            "subject": "合同补充材料（请尽快处理）",
            "sender": "legal-docs@contract-review-center.com",
            "body": "附件包含合同补充条款，请先启用编辑以查看完整签署页。由于客户催办，请在当日完成确认并回复。",
        },
        related_titles=["恶意附件与宏执行链", "ATT&CK-T1204.002 恶意文件执行"],
    ),
    _kb(
        title="ATT&CK-T1566.002 鱼叉式钓鱼链接",
        category="ATT&CK映射",
        severity="medium",
        keywords=["t1566.002", "phishing link", "verify", "login", "url"],
        summary="通过链接引导至恶意站点获取凭证",
        content="T1566.002 以钓鱼链接为核心载体，攻击者通过品牌仿冒或安全告警话术引导用户访问伪造站点。该技术在企业邮箱中最常见，且与短链、重定向、IP 直连等指标高度相关。Cofense 报告显示该技术占初始访问阶段的 43%，是 ATT&CK 钓鱼类技术中最高频的一支。检测策略应同时评估：(1) 链接 URL 信誉 + 域名年龄 + TLD 滥用清单；(2) 落地页内容特征（表单 action 跨域、JS 含 Telegram Bot API、克隆官方视觉但资源来自非官方 CDN）；(3) 流量侧特征（首次访问外联 beacon、短时间内大量内网用户访问同一域名）。T1566.002 与 AiTM 框架（Evilginx）结合后，能让会话 Cookie 实时被劫持，使 MFA 失效。检测链路必须包含“完整登录流程回放”而非仅快照首屏。",
        recommendation="(1) 统一走 URL 展开与信誉评估，结合语义风险做分层处置；(2) 网关对“形近域 + 凭证路径 + 紧迫话术”做组合评分；(3) 对 MFA 启用 Phishing-Resistant 模式（FIDO2 / 通行密钥）规避 AiTM；(4) 沙箱走完“凭证输入 → 提交 → 跳转后”的完整流程；(5) 谨记：链接“看起来没问题”≠“落在可信服务器”，域名层才能定性。",
        tags=["ATT&CK", "T1566.002", "链接"],
        iocs=["verify account", "reset password link"],
        attack_techniques=["T1566.002", "T1598"],
        detection_points=[
            "邮件内含强制登录或验证链接",
            "链接域名与品牌域名不一致",
            "重定向后落地页采集凭证字段",
        ],
        sample_email={
            "subject": "邮箱安全升级确认",
            "sender": "support@mail-security-upgrade.com",
            "body": "为避免异常访问，请在本通知有效期内完成邮箱安全升级验证。点击下方链接登录并确认身份后，系统将恢复全部访问权限。",
        },
        related_titles=["凭证收集诱导页面", "IP直连与非常用端口组合"],
    ),
    _kb(
        title="ATT&CK-T1566.003 通过服务进行钓鱼",
        category="ATT&CK映射",
        severity="medium",
        keywords=["t1566.003", "service", "smishing", "vishing", "third-party"],
        summary="借第三方服务渠道传播钓鱼载体",
        content="T1566.003 关注通过第三方服务或平台开展钓鱼，包括短信、协作工具、客服渠道等。其特点是多渠道联动，用户容易将不同来源误判为同一官方流程，需做跨渠道关联分析。典型案例：(1) 短信告知账号异常，邮件补“处理入口”；(2) Teams 邀请伪装为“安全更新会议”附钓鱼链接；(3) Telegram 客服机器人诱导用户输入验证码完成“验证”。CISA 2023 年发布的《Phishing-resistant MFA》专门提到这一技术对传统 2FA 的侵蚀——只要用户被诱导在合法服务页输入 OTP，攻击者即可实时劫持。检测需要在 SIEM 层统一身份与会话事件，把“同一用户 + 短时窗 + 多渠道 + 同指令”作为高风险联合信号。Microsoft Defender for Cloud Apps 已将“用户行为 + 渠道异常”作为基础评分维度。",
        recommendation="(1) 建立邮件、短信、IM 平台的统一事件关联与风险归一化；(2) SIEM 对“同一用户 + 短时窗 + 多渠道 + 同指令”做联合告警；(3) 培训员工：验证码永远只输入到“自己发起”的页面，绝不输入到“被引导”的页面；(4) 防御层强制升级到 FIDO2 / Passkey 消除 OTP 钓鱼面；(5) 谨记：合法客服渠道是单向触达（电话 / 短信），“让我们一起完成验证”本身就是诈骗剧本。",
        tags=["ATT&CK", "T1566.003", "多渠道"],
        iocs=["email + sms phishing", "service portal abuse"],
        attack_techniques=["T1566.003"],
        detection_points=[
            "短时间内多渠道指向同一验证动作",
            "邮件要求使用外部服务完成身份确认",
            "渠道来源主体无法在资产台账验证",
        ],
        sample_email={
            "subject": "服务工单验证入口",
            "sender": "ticket@account-service-help.com",
            "body": "您在短信中收到的安全工单需要在邮件入口补全身份信息。请尽快完成验证，避免账户被临时限制。",
        },
        related_titles=["Smishing短信跳转联动邮件", "Vishing语音回拨诱导"],
    ),
    _kb(
        title="ATT&CK-T1598 信息钓鱼",
        category="ATT&CK映射",
        severity="medium",
        keywords=["t1598", "credential theft", "identity", "phishing for information", "account"],
        summary="以信息收集为目的的钓鱼活动",
        content="T1598 侧重通过欺骗获取凭证、身份信息或组织内部数据。它覆盖邮件、网站和社交渠道等多形态入口。防守上需关注信息收集链路，而不仅是恶意代码执行。MITRE 给出的典型场景：(1) “身份重新核验” 邮件（V1598.001）；(2) “人工资源调查” 类社交钓鱼（V1598.002 / V1598.003）；(3) “WordPress 主题” 等开发者社区钓鱼（V1598.004）。T1598 的真实威胁不在于单条信息，而在于“信息拼图”——单条凭证不值钱，但身份证 + 手机号 + 邮箱三件套即可被用于“冒充客服”剧本完整一套。检测上重点关注“字段超范围采集”（如仅需用户名的页面索取手机 + 邮箱 + 身份证）和“邮箱 / 站点信誉”（形近域、克隆站、固定 IP 集群）。",
        recommendation="(1) 将信息字段采集行为纳入检测与告警范围；(2) 网关对“超出业务必要范围的信息收集页”做高风险告警；(3) 培训员工：“我已经填过的不需要再填”是判定钓鱼页的清晰红线；(4) 训练用户识别“为了给我发礼品需要姓名+电话+身份证+银行卡”类话术；(5) 谨记：信息拼图是社工库的原料，每条都要吝啬。",
        tags=["ATT&CK", "T1598", "信息窃取"],
        iocs=["enter your credentials", "confirm identity"],
        attack_techniques=["T1598", "T1078"],
        detection_points=[
            "页面主动索取账号/密码/验证码",
            "邮件强调身份确认与权限恢复",
            "收集字段超出业务必要范围",
        ],
        sample_email={
            "subject": "身份信息确认提醒",
            "sender": "verification@identity-check-service.com",
            "body": "根据平台合规要求，请重新确认您的身份信息并补全安全验证。若未在今天完成，系统将暂停部分账户功能。",
        },
        related_titles=["凭证收集诱导页面", "仿冒银行风控通知"],
    ),
    _kb(
        title="ATT&CK-T1204.002 恶意文件执行",
        category="ATT&CK映射",
        severity="medium",
        keywords=["t1204.002", "user execution", "malicious file", "open attachment", "execute"],
        summary="用户执行恶意文件触发后续攻击链",
        content="T1204.002 指用户被诱导执行恶意文件，是附件钓鱼场景中的关键执行阶段。即便前置文案看似业务合理，一旦执行链被触发，后续可能快速进入持久化和横向移动。检测覆盖执行前（宏文档 + 启用内容）、执行中（PowerShell Reflection / MSHTA / regsvr32 等 LOLBin 链）、执行后（计划任务、服务、Run 键）。CISA 与 NSA 2023 年《Technical Directed Advice on Phishing》强调了“沙箱覆盖用户交互路径”的重要性——不模拟点击“启用宏”按钮的沙箱会被所有现代钓鱼附件绕过。终端侧的 Attack Surface Reduction (ASR) 规则可阻断大部分 LOLBin，但需配合 PowerShell Constrained Language Mode 等加固。检测链要早于执行：MIME 类型 + Office 宏标识 + VBA 项目存在与否。",
        recommendation="(1) 端点侧启用可疑进程链阻断与最小权限策略（ASR + CLM）；(2) Office 默认禁用宏 + “受信任位置”最小化；(3) 沙箱必须模拟点击“启用内容 / enable editing / 解压密码”等交互事件；(4) 网关维护含 VBA 项目的 Office 文档 hash 黑名单；(5) 谨记：执行一旦发生，损失已启动——检测必须在“执行前”完成隔离。",
        tags=["ATT&CK", "T1204.002", "用户执行"],
        iocs=["open attachment then run script"],
        attack_techniques=["T1204.002", "T1566.001"],
        detection_points=[
            "打开文档后触发脚本解释器",
            "文档进程拉起网络连接下载载荷",
            "执行链出现异常父子进程关系",
        ],
        sample_email={
            "subject": "付款附件补充说明",
            "sender": "billing@invoice-center-support.com",
            "body": "请先打开附件并按照文档提示启用内容查看付款细节。若无法正常显示，请允许系统加载安全组件后重试。",
        },
        related_titles=["恶意附件与宏执行链", "ATT&CK-T1566.001 鱼叉式钓鱼附件"],
    ),
    _kb(
        title="ATT&CK-T1078 有效账户滥用",
        category="ATT&CK映射",
        severity="medium",
        keywords=["t1078", "valid accounts", "credential", "account takeover", "session"],
        summary="窃取合法凭证后伪装正常访问",
        content="T1078 描述攻击者获取有效凭证后进行后续访问，常见于 M365、VPN 与邮件系统。由于行为看似合法，传统边界防护难以察觉，需结合登录地、设备指纹与会话连续性做异常检测。Microsoft 报告“已失陷账号的会话”是最难检测的初始访问变体——所有行为都从合法账号发出，所有 IP 都在用户常见活动范围内。检测信号：(1) “impossible travel”（短时跨地）；(2) 新设备 + 新客户端组合；(3) 登录后立即进行敏感操作（邮件转发规则创建、SharePoint 文件大规模下载）。Microsoft Azure AD IDP 提供“风险检测”对 short-term impossible travel、新设备登录、anomaly token 等做了开箱即用的判定，可直接联动 Conditional Access 强制 MFA / 阻断会话。",
        recommendation="(1) 对高风险登录场景启用再认证和条件访问策略；(2) 部署 UA + 设备指纹基线 + impossible travel 检测；(3) 监控“登录后立即配置转发规则 / OAuth 应用 / 共享文档下载”等敏感动作；(4) 关键账号启用 Microsoft Identity Protection / Google Advanced Protection Program；(5) 谨记：有效账户滥用是“看不见的攻击”，必须凭行为偏离而非凭签名检测。",
        tags=["ATT&CK", "T1078", "账户接管"],
        iocs=["impossible travel", "new device login"],
        attack_techniques=["T1078", "T1598"],
        detection_points=[
            "短时跨地域登录且设备指纹变化",
            "登录后立刻进行敏感操作",
            "历史从未出现的客户端组合",
        ],
        sample_email={
            "subject": "账户登录安全确认",
            "sender": "notice@identity-protect-mail.com",
            "body": "检测到您的账户在新设备上访问，请立即通过邮件链接完成确认。若非本人操作，请按提示重置密码并启用安全保护。",
        },
        related_titles=["MFA疲劳轰炸诱导同意", "会话劫持中转页"],
    ),

    # --- 真实案例（>=3） ---
    _kb(
        title="案例：财务周结冒充邮件失陷",
        category="真实案例",
        severity="high",
        keywords=["周结", "财务", "转账", "冒充", "案例", "损失"],
        summary="冒充财务主管触发错误付款",
        content="某企业在周结高峰收到“财务主管”邮件，要求紧急向新供应商账户付款。邮件无恶意链接，仅凭流程压迫与保密话术完成欺骗，最终造成直接资金损失 380 万元。复盘显示组织缺少“邮件付款二次确认”刚性流程，财务人员按邮件指令 30 分钟内完成转账。FBI IC3 公开案例里类似剧本占比超过 38%，单笔损失中位数从 2022 年的 5 万美元升至 2024 年的 11.4 万美元——攻击者越来越多选择金额偏大的“单笔”而非高频小额。事件暴露 4 个具体缺陷：(1) 没有付款冷静期；(2) 没有新账户强制复核流程；(3) 财务邮箱没有风格漂移检测；(4) “仅向我回执不要抄送团队”话术没有专项规则。这 4 项均为可独立加固的控制点，单点修复即可把损失上限压至可控范围。",
        recommendation="(1) 对首次收款账户和紧急付款建立强制线下复核控制点；(2) 引入付款冷静期（≥ 24 小时）与双人复核；(3) 网关对“保密 + 不要抄送 + 紧急付款”组合话术做高风险告警；(4) 财务 / 出纳账号启用专属风格漂移检测；(5) 谨记：付款类决策从不被“快”驱动——这是流程胜过便捷的典型场景。",
        tags=["案例", "BEC", "资金损失"],
        iocs=["new beneficiary", "urgent payment"],
        attack_techniques=["T1566.003", "T1657"],
        detection_points=[
            "首次出现的收款账户且时效要求极高",
            "邮件要求绕过常规审批链",
            "发件人与真实主管历史行为不一致",
        ],
        sample_email={
            "subject": "周结前紧急付款",
            "sender": "finance.director@external-board-mail.com",
            "body": "请立即完成一笔供应商预付款，本次由我直接审批，先不要走常规流程，避免交易窗口关闭。付款完成后仅向我个人回执，不要抄送团队。",
        },
        related_titles=["BEC/CEO欺诈转账邮件", "员工应急处置四步流程"],
    ),
    _kb(
        title="案例：M365仿冒登录页批量收割",
        category="真实案例",
        severity="high",
        keywords=["m365", "仿冒", "登录页", "批量", "收割", "案例"],
        summary="仿冒M365页面导致批量凭证泄露",
        content="某组织收到多封“邮箱配额超限”通知，链接指向仿冒 M365 登录页。员工输入凭证后，攻击者迅速接管邮箱并向外扩散同模板邮件。由于邮件语法自然且来源分散，初期未被规则及时拦截，最终波及 200+ 员工，3 个高管邮箱被挂 OAuth 授权应用。事件复盘显示三类典型缺口：(1) 网关未对“邮箱容量 / 配额”主题启用品牌专属规则；(2) 仿冒链接使用托管在 Google Sites 上的登录页，Google Safe Browsing 收录延迟导致 8 小时窗口；(3) 没有 OAuth 应用可见性，攻击者授权“阅读 / 外发”邮件的应用长达 14 天未被察觉。该案例后被微软安全响应团队收录为 BEC 教材。",
        recommendation="(1) 对品牌关键场景（邮箱容量、配额、登录保护）启用专属检测策略；(2) 部署 Google Sites / SharePoint / Notion 等共享云平台的快速信誉缓存层，缩短 8 小时收录延迟；(3) 启用 OAuth 应用可见性，对“读写邮件”权限应用立刻告警；(4) 凭据失陷会话吊销必须批量自动化执行，不能依赖人工逐账号处置；(5) 谨记：M365 仿冒是高频攻击，每周至少应演练一次。",
        tags=["案例", "M365", "凭证泄露"],
        iocs=["mailbox quota exceeded", "sign in to continue"],
        attack_techniques=["T1566.002", "T1078"],
        detection_points=[
            "主题与品牌服务场景高度贴合",
            "登录页域名不在官方清单内",
            "短时间出现同类模板多次投递",
        ],
        sample_email={
            "subject": "邮箱容量即将耗尽，请重新登录",
            "sender": "notification@microsoft365-storage-alert.com",
            "body": "您的邮箱容量已接近上限，请立即登录并确认账户以继续接收邮件。若未及时处理，收件功能可能受到限制。请通过邮件中的安全入口完成操作。",
        },
        related_titles=["仿冒Microsoft 365安全通知", "凭证收集诱导页面"],
    ),
    _kb(
        title="案例：二维码钓鱼绕过网关",
        category="真实案例",
        severity="medium",
        keywords=["二维码", "quishing", "绕过", "网关", "案例", "扫码"],
        summary="二维码载荷绕过文本URL检测",
        content="某企业邮件网关主要针对文本 URL 检测，攻击者改用二维码投递登录入口，导致多名员工在手机端完成了错误认证。复盘显示系统缺少二维码解析与 URL 还原能力，且用户教育未覆盖扫码场景风险。事件涉及 32 名员工，泄密凭证 28 个，被用于 4 周内 60+ 次内部凭据尝试（横向移动）。攻击者使用 EvilProxy 套件 + 标准 M365 仿冒二维码模板（含“手机扫码完成安全验证”标准话术 + 15 分钟过期限制），并集成 SegWit 地址二维码隐写。事件暴露 3 个补丁点：(1) 网关缺二维码识别能力；(2) 二维码还原 URL 信誉能力；(3) 用户不知“企业场景几乎不用二维码完成认证”。",
        recommendation="(1) 补齐二维码识别链路（QRCodeDetector + URL 还原）；(2) 网关订阅二维码钓鱼实时信誉（PhishFort QR feeds）；(3) 邮件客户端对包含二维码图片的邮件增加风险提示横幅；(4) 培训员工：企业场景几乎不用二维码完成认证，“扫码”是默认警惕信号；(5) 端点 EDR 对“扫码后立即打开浏览器 + 输入企业凭证”做关联告警。",
        tags=["案例", "二维码", "检测盲区"],
        iocs=["scan to secure account", "qr login required"],
        attack_techniques=["T1566.002"],
        detection_points=[
            "邮件主要行动指令是扫码而非官网登录",
            "二维码图像来源不明且无业务背景",
            "扫码后请求输入企业凭证",
        ],
        sample_email={
            "subject": "扫码完成账号安全确认",
            "sender": "auth@mobile-security-check.com",
            "body": "为避免账号访问受限，请使用手机扫描附件二维码完成快速验证。流程仅需 30 秒，超过时限将自动锁定部分协作权限，请尽快处理。",
        },
        related_titles=["二维码钓鱼 Quishing", "钓鱼关键词组合模式"],
    ),

    # --- 防御指南（>=4，含 SPF/DKIM/DMARC/应急流程） ---
    _kb(
        title="SPF基础配置与告警策略",
        category="防御指南",
        severity="low",
        keywords=["spf", "dns", "mail from", "spoof", "policy", "告警"],
        summary="SPF可降低域名伪造但需配合联动策略",
        content="SPF 用于声明哪些服务器可代表域名发送邮件，可有效减少简单伪造。但 SPF 仅覆盖 envelope sender 维度，不能独立解决显示名仿冒与转发场景。建议将 SPF fail 与品牌词、外链登录等特征联动，构建分层告警。SPF 最佳实践：(1) 仅声明确实代发邮件的服务器 IP / 主机（≤ 10 条 include 链），长链易触发 DNS 超时；(2) 推荐 ~all（软失败）或 -all（硬失败），慎用 +all（始终通过）；(3) 与 DKIM + DMARC 配套使用，SPF 单独使用易被失败转发绕过；(4) 高风险域名（如离任 CEO 曾用别名）必须启用 SPF；(5) SPF 报错每日复核，避免长期软失败导致合法信源被标记。M3AAWG 报告显示执行 SPF 的企业平均 spoofed email 拦截率比未配置者高 65%，单独 SPF 拦截率仍只有 50% 左右，必须叠加 DKIM/DMARC 才能接近完全防护。",
        recommendation="(1) 明确 SPF 记录维护责任，持续监控 fail/softfail 波动并联动处置；(2) 关键业务域必须启用 SPF，且为 -all 或 ~all 严策略；(3) SPF 失败 + 品牌词 / 凭证路径 = 高风险告警（非孤证放行）；(4) 配套 DKIM / DMARC 三层一起配置；(5) 谨记：SPF 是基础不是终极，“SPF 通过”≠“邮件可信”。",
        tags=["SPF", "邮件认证", "防御"],
        iocs=["spf=fail", "spf=softfail"],
        attack_techniques=[],
        detection_points=[
            "关键域名存在且仅存在一条 SPF 记录",
            "高价值邮箱 SPF fail 告警需进入人工队列",
            "转发场景需结合 DKIM/DMARC 做补偿判断",
        ],
        sample_email={
            "subject": "安全团队：邮件认证策略变更通知",
            "sender": "secops@corp.example.com",
            "body": "本周将对企业域名 SPF 策略进行优化，涉及外发网关白名单更新。请业务系统维护人核对第三方发信源，避免合法邮件因策略收紧被误拦截。",
        },
        related_titles=["DKIM签名校验落地建议", "DMARC策略渐进部署指南"],
    ),
    _kb(
        title="DKIM签名校验落地建议",
        category="防御指南",
        severity="low",
        keywords=["dkim", "signature", "selector", "domainkey", "验证"],
        summary="DKIM保障内容完整性与来源可验证",
        content="DKIM 通过私钥签名确保邮件在传输过程中未被篡改，并能证明签名域对邮件负责。部署时应统一 selector 管理与密钥轮换节奏，避免长期静态密钥风险。DKIM 结果应与 SPF、DMARC 同步纳入风险融合。DKIM 落地要点：(1) 关键业务域统一 2 个 selector 轮换（每月或每季切换），避免长期单一密钥泄漏；(2) 密钥长度 ≥ 2048 位 RSA 或 Ed25519；(3) DNS 记录 CNAME 链不超过 5 层以防解析超时；(4) DKIM 签名缺失（dkim=none）时应作为独立风险指标；(5) 关键外发平台（Marketing / 事务邮件）应分别使用独立 selector，便于单点故障定位。Google 与 Yahoo 在 2024 年 2 月新规强制要求日发 ≥ 5000 的发件域必须配置 DMARC，这间接也提高了 DKIM 的强制度。",
        recommendation="(1) 建立 DKIM 密钥轮换机制（季度轮换为基线），监控签名缺失与验证失败趋势；(2) 关键业务域必须启用 DKIM 且密钥长度 ≥ 2048 位；(3) 签名失败 / dkim=none 应作为独立风险指标，与 SPF / DMARC 结果融合；(4) DNS 解析链治理，避免超时导致软失败；(5) 谨记：DKIM 验证内容完整性但不能验证身份意图，必须 DMARC 配套。",
        tags=["DKIM", "签名", "邮件完整性"],
        iocs=["dkim=fail", "dkim=none"],
        attack_techniques=[],
        detection_points=[
            "关键业务域必须启用 DKIM",
            "签名失败需结合来源域与内容特征加权",
            "定期轮换密钥并清理废弃 selector",
        ],
        sample_email={
            "subject": "邮件签名策略维护窗口通知",
            "sender": "mail-admin@corp.example.com",
            "body": "我们将于本周执行 DKIM selector 轮换，请相关系统在维护窗口内完成配置核对。若发现签名失败告警，请及时联系邮件平台团队排查。",
        },
        related_titles=["SPF基础配置与告警策略", "DMARC策略渐进部署指南"],
    ),
    _kb(
        title="DMARC策略渐进部署指南",
        category="防御指南",
        severity="low",
        keywords=["dmarc", "p=none", "p=quarantine", "p=reject", "rua", "ruf"],
        summary="DMARC需按阶段推进避免误拦截业务邮件",
        content="DMARC 将 SPF 与 DKIM 的对齐结果统一成策略动作。推荐从 p=none 观察开始，逐步推进到 quarantine 与 reject，并通过 rua/ruf 报告识别未纳管发信源。粗暴直接 reject 容易造成业务中断，需按资产台账分批治理。DMARC 部署的标准路径：(1) 第一周 p=none，所有 DMARC 报告投递至 rua@ 公司域，汇编并识别所有合法信源；(2) 第 2-4 周聚合 rua 报告，添加所有未纳管 IP / 主机到 SPF；(3) 一个月后推进到 p=quarantine 15%，持续两周观察；(4) 推进到 p=quarantine 100% 后，再推进到 p=reject 10%，最后 100% reject。Google 与 Yahoo 在 2024 年 2 月起要求日发 ≥ 5000 的发件域必须配置 DMARC，是外部驱动 DMARC 采用的最大单次事件。BIC 报告，启用 DMARC 的发件域可阻止 95% 以上的冒充邮件，但仍需配套 BIMI 强化品牌识别。",
        recommendation="(1) 执行分阶段 DMARC 策略并建立报告闭环，持续收敛未知发信源；(2) rua 报告聚合分析为强制项，每月发版率审计未纳管信源；(3) 推进 quarantine / reject 必须配合业务侧邮件可观测性验证，避免影响业务流；(4) p=reject 前接入 BIMI（品牌 logo）可获得受信品牌识别加成；(5) 谨记：DMARC 是技术亦非终极，p=reject 后仍需配套下游钓鱼监测（URLhaus / PhishTank）。",
        tags=["DMARC", "策略治理", "邮件域保护"],
        iocs=["dmarc=fail", "alignment fail"],
        attack_techniques=[],
        detection_points=[
            "从 p=none 开始观察至少 2-4 周",
            "对齐失败来源需归属到具体业务系统",
            "逐步切换到 quarantine/reject 并验证影响",
        ],
        sample_email={
            "subject": "域名防伪策略升级计划",
            "sender": "secops@corp.example.com",
            "body": "我们计划分阶段提升 DMARC 策略强度，请各业务系统核对当前外发链路，确保未纳管来源在切换到 quarantine/reject 前完成整改，以避免邮件投递中断。",
        },
        related_titles=["SPF基础配置与告警策略", "DKIM签名校验落地建议"],
    ),
    _kb(
        title="员工应急处置四步流程",
        category="防御指南",
        severity="low",
        keywords=["应急", "隔离", "上报", "复核", "封禁", "取证"],
        summary="统一动作模板可显著缩短止损时间",
        content="面对疑似钓鱼邮件，建议执行“四步流程”：停止交互、隔离终端、上报安全团队、协同取证复盘。流程化动作能避免员工自行处置导致证据污染或二次传播。该条目适合作为 SOC 与 IT 支持团队的联动作业基线。NIST SP 800-50 / 800-177 推荐的应急响应动作与该四步吻合：(1) “stop interaction” = 立即停止点击 / 输入 / 下载 / 通话；(2) “isolate the device” = 网络层与设备层的最小化隔离（包含禁用 WiFi / 有线网卡、限制本地用户）；(3) “report to SOC” = 通过一键上报按钮或工单系统提交原始邮件头 + 截图；(4) “forensic preservation” = 保全证据链（不重启、不清理浏览器缓存、保存 .eml 原文）。该流程应纳入员工入职培训必修模块，每季度演练一次。KPMG 2024 年对 12 个 BFSI 的研究表明：执行标准化应急流程的企业平均 MTTD（Mean Time To Detect）缩短 47%。",
        recommendation="(1) 将四步流程固化为企业标准操作卡并定期演练；(2) 邮件客户端与 Slack / Lark 内置“一键上报”按钮直达 SOC 工单；(3) SOC 接到报告后 15 分钟内给出处置建议，避免员工继续触摸可疑邮件；(4) 复盘后回写规则库和培训材料，形成闭环；(5) 谨记：流程胜过个人能力，组织层面的应急按钮比员工教育更可靠。",
        tags=["应急响应", "流程", "SOC"],
        iocs=["user reported phishing", "credential submitted"],
        attack_techniques=[],
        detection_points=[
            "第一时间停止点击与输入敏感信息",
            "立即断开可疑会话并修改相关凭证",
            "在工单系统记录时间线与证据位置",
            "复盘后回写规则库和培训材料",
        ],
        sample_email={
            "subject": "安全演练：疑似钓鱼邮件处置说明",
            "sender": "secops@corp.example.com",
            "body": "当你收到疑似钓鱼邮件时，请立即停止交互并上报。不要自行转发到大群，按流程提交工单并保留原始邮件头。安全团队将在 15 分钟内给出处置建议。",
        },
        related_titles=["业务白名单样例", "案例：M365仿冒登录页批量收割"],
    ),

    # --- 术语表（>=5，severity=low） ---
    _kb(
        title="术语：钓鱼邮件（Phishing）",
        category="术语表",
        severity="low",
        keywords=["phishing", "钓鱼邮件", "社工", "欺骗", "凭证"],
        summary="通过伪装可信来源诱导用户执行危险动作",
        content="钓鱼邮件是通过伪装可信身份、制造紧迫情绪或利益诱导，促使用户点击链接、打开附件或提交敏感信息的攻击方式。其核心不是技术漏洞，而是利用人的决策弱点，因此需要技术检测与安全意识双轨并行。APWG《Phishing Activity Trends Report》2024 Q3 显示全球钓鱼攻击数创历史新高：单季度 96 万次，远超 2022 年同期。攻击目标行业分布：电商 / 社工 / 银行 / SaaS 居前四；攻击载体邮件占 36%（其余短信 / 语音 / IM 等）。中国电子学会发布的《中国反钓鱼报告》把中国市场的钓鱼归纳为“仿冒型 / 社工型 / 技术型”三大类，2024 年仿冒型超过 78%。该术语是所有钓鱼相关讨论的基础，是其他细分概念（Spear Phishing / BEC / Quishing 等）的“根节点”。",
        recommendation="(1) 用于培训与语义解释，不单独作为风险加权项；(2) 内训中强调“技术 + 意识”双轨，无单一防线能完全防护；(3) 让员工知道：钓鱼邮件是其他细分的根节点，掌握基础才能识别 BEC / VEC 等高仿真变种；(4) 培训频次：每季度至少一次短训 + 每年一次深度演练；(5) 谨记：钓鱼邮件的核心是“利用人的弱点”，技术与人必须同步建设。",
        tags=["术语", "基础概念"],
        iocs=[],
        attack_techniques=[],
        detection_points=["定义性词条，用于解释与培训"],
        sample_email="",
        related_titles=["术语：鱼叉钓鱼（Spear Phishing）", "术语：商业邮件欺诈（BEC）"],
    ),
    _kb(
        title="术语：鱼叉钓鱼（Spear Phishing）",
        category="术语表",
        severity="low",
        keywords=["spear phishing", "鱼叉钓鱼", "定向", "个性化", "目标化"],
        summary="面向特定人群的定制化钓鱼攻击",
        content="鱼叉钓鱼是针对特定人员或团队定制内容的钓鱼方式，常引用真实项目和组织上下文，以提升可信度和成功率。相比广撒网邮件，它更隐蔽，也更依赖上下文识别能力。Microsoft 2024 报告显示鱼叉投递平均成本约 200-1000 美元 / 封，但单次 ROI 远高于批量钓鱼——单封回收峰值可达 50 万美元。鱼叉投递的情报收集来源包括：LinkedIn 个人资料 / 论文 / 演讲 / 公开会议 / 招聘信息 / 媒体采访 / GitHub 仓库 / 公司公众号。攻击模板常用结构：“参考会议第 X 项 + 引用收件人姓名 + 假扮重要决策人”。检测核心维度：写作风格（与历史邮件对比）、收件人关系图谱（与发件人历史交集度）、基础设施证据（域名信誉 + 链接目标）。",
        recommendation="(1) 用于知识解释，结合联系人关系模型提升检测准确度；(2) 高敏感员工（财务、法务、C-Level）开启风格漂移检测；(3) 培训员工：“主题具体 + 收件人具体”≠“邮件可信”，识别上下文鱼钩；(4) 减少公开可搜到的内部细节（LinkedIn 项目细节、组织架构）；(5) 谨记：鱼叉越来越像“内部人士”，但永远有一条证据链可以定性——基础设施与写作风格。",
        tags=["术语", "定向攻击"],
        iocs=[],
        attack_techniques=[],
        detection_points=["定义性词条，用于解释与培训"],
        sample_email="",
        related_titles=["鱼叉钓鱼（Spear Phishing）", "术语：商业邮件欺诈（BEC）"],
    ),
    _kb(
        title="术语：商业邮件欺诈（BEC）",
        category="术语表",
        severity="low",
        keywords=["bec", "商业邮件欺诈", "ceo fraud", "转账欺诈", "冒充高管"],
        summary="利用组织信任链发起资金或信息欺诈",
        content="BEC 指攻击者冒充高管或业务伙伴，利用邮件指令诱导财务转账或泄露敏感信息。其典型特征是弱技术痕迹、强流程绕过，因此需要组织流程控制与技术证据并行防护。FBI IC3 自 2018 年起累计披露 BEC 损失已突破 500 亿美元，占所有网络犯罪类型损失的 50% 以上。BEC 五大子型：(1) 冒充 CEO 指令付款（CEO Fraud）；(2) W-2 / 税务信息泄露（W-2 Scam）；(3) 假冒合作伙伴账户变更（Vendor Account Change）；(4) 律师冒充（Attorney Impersonation）；(5) 资料数据泄露（Data Leakage）。所有 BEC 剧本的共同特征：(a) 突出“紧急”“保密”避免双重核实；(b) 措辞对真实高管有偏移（攻击者研究不充分时常见）；(c) 对供应商 / 律师等可信第三方账户已失陷。防御核心：付款走流程、不看邮件、强制冷静期。",
        recommendation="(1) 用于培训与术语统一，不单独触发高风险；(2) 付款决策禁止走邮件，转走 ERP / OA 系统流程；(3) 强制付款冷静期（≥ 24 小时）与双人复核；(4) 高仿真演练覆盖全体员工，重点部门（财务 / HR / 法务）每季度一轮；(5) 谨记：BEC 是流程问题不是技术问题——解决路径在组织而不在防火墙。",
        tags=["术语", "财务欺诈"],
        iocs=[],
        attack_techniques=[],
        detection_points=["定义性词条，用于解释与培训"],
        sample_email="",
        related_titles=["BEC/CEO欺诈转账邮件", "案例：财务周结冒充邮件失陷"],
    ),
    _kb(
        title="术语：二维码钓鱼（Quishing）",
        category="术语表",
        severity="low",
        keywords=["quishing", "二维码钓鱼", "扫码", "qr phishing", "移动端"],
        summary="将恶意链接编码为二维码的钓鱼形态",
        content="Quishing 是把钓鱼链接编码成二维码并通过邮件等渠道分发的攻击形态。它能绕过纯文本 URL 检测并把风险转移到移动端，要求防守体系具备图片解析和跨端联动能力。ReliaQuest 2024 年统计 Quishing 单季度增长 220%，与 Microsoft 365 / DocuSign / SharePoint 仿冒模板共占增长量的 78%。Quishing 的“跨端”是核心麻烦：用户在公司电脑收邮件扫码，手机端跳出登录页，凭证与 MFA 都在那端完成，公司端网关视角无法观测到目标 URL。检测需要：(1) 邮件网关 OCR / QRCode 解析 + URL 还原 + 信誉检查；(2) 移动端 MDM SDK 监听“扫码后立即打开浏览器 + 企业 App 输入凭证”事件；(3) 跨端 ID 关联公司设备与个人手机的登录事件（IDP 风险评分）。",
        recommendation="(1) 用于术语解释，配合二维码检测能力建设；(2) 网关侧对所有邮件图片执行 QRCodeDetector → URL 还原 → 信誉评估三步链；(3) 部署移动端 MDM 联动 IDP 风险评分；(4) 培训员工：企业场景几乎不用二维码完成认证，“扫码”是警惕信号；(5) 谨记：二维码是“图文转换器”，不是技术细节——它仍然是钓鱼链条的一环。",
        tags=["术语", "二维码"],
        iocs=[],
        attack_techniques=[],
        detection_points=["定义性词条，用于解释与培训"],
        sample_email="",
        related_titles=["二维码钓鱼 Quishing", "案例：二维码钓鱼绕过网关"],
    ),
    _kb(
        title="术语：钓鱼即服务（PhaaS）",
        category="术语表",
        severity="low",
        keywords=["phaaS", "phishing as a service", "钓鱼即服务", "kit", "模板"],
        summary="提供模板与基础设施的工业化钓鱼生态",
        content="PhaaS 指向攻击者提供模板、域名、托管与数据回传等能力的服务化生态。它显著降低攻击门槛，推动钓鱼活动规模化和自动化，防守侧需从单点 IOC 转向活动簇识别。Cofense Lab 2024 追踪到 65+ 活跃 PhaaS 套件，订阅价 50-500 美元/月，远低于自研成本。主流套件包括：16Shop / BulletProofLink / EvilProxy / Tycoon 2FA / Caffeine / Mamba 2FA 等。每个套件包含：(a) 模板市场（支持 M365 / Google / DocuSign / Adobe Sign / 银行 / 物流）；(b) 域名轮换（24-72h）；(c) 数据回传（Telegram Bot / Discord Webhook / 邮箱转发）；(d) 反检测能力（GeoIP 分流、UA-aware 跳转、Cloudflare Turnstile 人机验证）。防守侧必须从“单封邮件 IOC 拦截”升级为“同模板 / 同形近域簇 / 同 SSL 指纹簇”的活动追踪，并订阅 PhaaS 共享的 IOC 库。",
        recommendation="(1) 用于术语与威胁情报研判，不作为单独拦截条件；(2) 网关订阅 PhaaS 共享 IOC 库（PhishFort / SlashNext / Mandiant Advisory）；(3) 模板聚类（MinHash / SimHash）+ 域名簇检测（NS / SSL / 注册商）应作为基础能力；(4) 谨记：PhaaS 的弱点是“可复用”——固定模板正是防守侧的最强信号；(5) 不要对“单封邮件 POC”投入全部精力，工业化攻击需要工业化防御。",
        tags=["术语", "产业化攻击"],
        iocs=[],
        attack_techniques=[],
        detection_points=["定义性词条，用于解释与培训"],
        sample_email="",
        related_titles=["钓鱼工具包与PhaaS投递", "术语：钓鱼邮件（Phishing）"],
    ),

    # ====== 新增分类：供应链攻击 ======
    _kb(
        title="供应链攻击 · SolarWinds SUNBURST 事件",
        category="供应链攻击",
        severity="critical",
        keywords=["solarwinds", "sunburst", "supply chain", "APT29", "CISA AA20-352A", "供应链"],
        summary="APT29 通过污染 SolarWinds Orion 更新在全球植入 SUNBURST 后门，2020-12 被披露。",
        content="2020-12-13 FireEye 披露其红队工具被盗并发现 SolarWinds Orion 平台被植入恶意更新（SUNBURST / TEARDROP / SUNSPOT），追溯到 2020-03 开始的 APT29（SVR）行动。CISA 发布 AA20-352A 联合咨询，受影响客户约 18,000 家，包括美国财政部 / 国土安全部 / 国务院 / 微软 / FireEye / CrowdStrike 等。SUNBURST 利用 SolarWinds Orion 的合法更新通道投递恶意 DLL (SolarWinds.Orion.Core.BusinessLayer.dll)，通过休眠期（最长 14 天）+ 域白名单 + 子进程混淆绕过检测。TEARDROP 是内存驻留的 Cobalt Strike Beacon loader。事件暴露了『合法签名 + 合法分发渠道 + 长期休眠』」组合构成的纵深防御盲区。该事件定义了 2020 年代供应链攻击的范式：信任链中的任何环节被污染即等于全局失守。",
        recommendation="(1) 所有使用 SolarWinds Orion 14.x 及以下版本的组织必须升级到 2020-12 后的安全更新；(2) 部署供应链完整性验证：SBOM（软件物料清单）+ 制品签名验证 + 运行时行为基线；(3) 网络出口流量对 SolarWinds 子进程建立专门监控（Orion 业务层进程不应有出站 HTTP）；(4) 凭据轮换：受影响系统的所有凭据 + API key 必须重置；(5) 谨记：信任签名 ≠ 信任软件 —— 必须凭运行时行为而非签名验证供应链。",
        tags=["供应链", "SolarWinds", "APT29", "SUNBURST", "CISA AA20-352A"],
        iocs=["SolarWinds.Orion.Core.BusinessLayer.dll 异常出站 / SUNBURST DNS 模式"],
        attack_techniques=["T1195.002", "T1059.001", "T1027"],
        detection_points=[
            "SolarWinds Orion 业务层进程出现异常出站网络请求",
            "子进程派生包含 Cobalt Strike Beacon 特征",
            "SolarWinds 配置数据库被未授权访问"
        ],
        sample_email="",
        related_titles=["MITRE ATT&CK · APT29 (Cozy Bear / NOBELIUM)", "ATT&CK-T1195.002 供应链入侵"],
    ),

    # ====== 新增分类：勒索软件 ======
    _kb(
        title="勒索软件 · Cl0p 利用 MOVEit Transfer 0day 大规模攻击",
        category="勒索软件",
        severity="critical",
        keywords=["cl0p", "clop", "MOVEit", "CVE-2023-34362", "ransomware", "供应链"],
        summary="Cl0p (TA505 / FIN11) 利用 MOVEit Transfer 0day 在 2023 年大规模窃取数据，影响 2700+ 组织。",
        content="2023-05-31 Progress Software 披露 MOVEit Transfer SQL 注入 0day (CVE-2023-34362)，并发现 Cl0p（TA505 / Lace Tempest）团伙在 2023-05-27 已开始利用。该团伙通过 SQL 注入在 MOVEit 服务器上部署 LEMURLOOT web shell，进而窃取文件、部署 Cl0p 勒索软件。Progress 2023-07 报告全球受影响组织超过 2700 家，包括英国广播公司 (BBC)、英国航空、美国能源部、Shell、Zellis（英国薪资服务商）等。Cl0p 此次行动成为 2023 年最大规模勒索 / 数据窃取事件之一，也是 Cl0p 在 2023 年第二次成功的大规模供应链攻击（前一次是 GoAnywhere MFT 0day）。Cl0p 的商业模式是『专注于 0day + 大规模数据窃取 + 不加密只公开』—— 通过泄露站威胁公开数据而非加密磁盘，体现了勒索软件 2.0 的演化方向。",
        recommendation="(1) 立即升级 MOVEit Transfer 到 Progress 官方补丁版本，并核查 2023-05-27 之后的所有访问日志；(2) 检查是否有 LEMURLOOT web shell 痕迹（人字形 GUID 文件名等）；(3) 对受影响组织启用强制 MFA + 凭据轮换；(4) 文件传输服务器 (MFT) 严禁暴露公网，启用 IP 白名单 + WAF；(5) SBOM 跟踪：所有 MFT / 文件同步组件必须有 CVE 监测流程；(6) 谨记：Cl0p 的成功不是因为技术强，而是因为『合法服务的信任默认』。",
        tags=["Cl0p", "MOVEit", "勒索软件", "CVE-2023-34362"],
        iocs=["MOVEit Transfer 异常 SQL 请求 / LEMURLOOT web shell 痕迹"],
        attack_techniques=["T1190", "T1505.003", "T1486"],
        detection_points=[
            "MOVEit 服务器出现异常 SQL 注入请求",
            "服务器上出现非预期的 .asp 文件",
            "MOVEit 人字形 GUID 文件夹被发现"
        ],
        sample_email="",
        related_titles=["LockBit 3.0 勒索软件家族", "供应链攻击 · SolarWinds SUNBURST 事件"],
    ),

    # ====== 新增分类：SaaS 仿冒 ======
    _kb(
        title="SaaS 仿冒 · Salesforce 凭据钓鱼",
        category="SaaS仿冒",
        severity="high",
        keywords=["salesforce", "saas", "credential phishing", "mandiant", "Muddled Libra"],
        summary="Muddled Libra (UNC3944 / Scattered Spider) 利用 Salesforce 仿冒登录页发起凭据钓鱼。",
        content="Salesforce 作为全球最大的 CRM 平台，是 SaaS 钓鱼的高价值目标。Mandiant 2024 报告披露 Muddled Libra / Scattered Spider（UNC3944）利用仿冒 Salesforce 登录页对企业销售 / 客户成功团队发起凭据钓鱼，结合 vishing（冒充 IT Helpdesk）完成 MFA 重置后接管账户。该团伙在 2024 年多次利用 Salesforce Data Loader 等合法工具从受害账户批量导出客户数据。Muddled Libra 的攻击链：(1) 通过 LinkedIn / 数据经纪人识别 Salesforce 管理员 / 销售运营人员；(2) 仿冒 Salesforce 登录页（salesforce.com 形近域 / Lookalike URL）；(3) 收集账号密码 + MFA OTP；(4) 接管后立即创建 OAuth 应用并导出客户数据。Salesforce 仿冒成功率高（误报率低）的原因是：『客户数据』是企业最敏感资产之一，紧急场景下员工容易绕过流程。",
        recommendation="(1) 强制 Salesforce 用户启用 Phishing-Resistant MFA（FIDO2 / Passkey），消除 OTP 中继面；(2) Salesforce IP 限制 + Login Geo Restriction；(3) 检测 Salesforce OAuth 应用可见性：数据导出权限应用立刻告警；(4) 销售运营 / CRM 管理员账号启用 conditional access；(5) 培训销售团队：合法 Salesforce 通知不通过邮件链接验证身份，登录门户处理；(6) 谨记：CRM 仿冒的杀伤面是『客户数据外泄 + GDPR / PIPL 处罚』，不仅 IT 风险，更是合规风险。",
        tags=["Salesforce", "SaaS", "钓鱼", "Muddled Libra"],
        iocs=["形近 salesforce.com 域名 / salesforce-secure.com"],
        attack_techniques=["T1566.002", "T1078.004", "T1556"],
        detection_points=[
            "Salesforce 登录来自形近域 / 异常 Geo",
            "OAuth 应用新增『数据导出』权限",
            "短时间内大量客户记录被下载"
        ],
        sample_email={
            "subject": "Salesforce 账户异常登录提醒",
            "sender": "no-reply@salesforce-secure.com",
            "body": "我们检测到您的 Salesforce 账户出现非常用地区登录，请立即通过邮件链接验证身份以保障账户安全。",
        },
        related_titles=["Okta 支持钓鱼 / IT Helpdesk 冒充", "仿冒Microsoft 365安全通知"],
    ),

    # ====== 新增分类：加密货币/Web3 钓鱼 ======
    _kb(
        title="加密货币钓鱼 · EIP-712 Permit 钓鱼签名",
        category="加密货币钓鱼",
        severity="critical",
        keywords=["cryptocurrency", "web3", "permit", "eip-712", "wallet drainer", "eth", "钓鱼签名"],
        summary="EIP-2612 Permit 钓鱼签名允许攻击者在无 gas 情况下从用户钱包转移资产。",
        content="EIP-2612 Permit 是以太坊 ERC-20 代币标准中的一个扩展，允许用户通过链下签名授权（permit signature）让第三方代为支付 gas 并在链上执行 transferFrom。攻击者利用该机制构造『钓鱼签名』：伪装为 NFT 空投 / 治理投票 / 跨链桥等场景诱导用户对恶意的 permit 数据签名，签名内容包含 (owner, spender, value, deadline, nonce)。一旦用户签名，攻击者立即调用 permit() + transferFrom() 完成代币转账，整个过程用户感知不到（无任何交易弹出）。该机制衍生出 Inferno Drainer / Pink Drainer / Angel Drainer / Pussy Drainer 等多个 wallet drainer 套件，2023-2024 年造成数亿美元损失。钓鱼签名比传统钓鱼更具欺骗性：『签名』字面看起来无害，但实际授予了完整代币操作权。",
        recommendation="(1) 钱包用户教育：理解『签名的就是授权』，对任何 permit / setApprovalForAll 签名保持警惕；(2) EIP-1271 智能合约钱包可实现白名单签名验证；(3) 钱包 UI 应明确警告『该签名将授权 X 代币给 Y 地址』；(4) 启用交易模拟（tenderly / Pocket Universe）预览签名效果；(5) 谨记：钱包钓鱼的核心是『签名前不看内容、签完后追溯太晚』，唯一防御是『签名前 100% 理解』。",
        tags=["Web3", "加密货币", "Permit", "钓鱼签名", "Wallet Drainer"],
        iocs=["形似 mint / claim / approve 的恶意签名请求"],
        attack_techniques=["T1204.002", "T1059"],
        detection_points=[
            "用户对未经验证的合约执行 permit 签名",
            "短时间内多笔 transferFrom 交易来自同一 owner",
            "新合约对老用户的代币操作"
        ],
        sample_email="",
        related_titles=["OWASP LLM Top 10 · LLM01 提示词注入"],
    ),

    # ====== 新增分类：AI 深度伪造 ======
    _kb(
        title="AI 深度伪造 · Arup 香港 2500 万美元视频会议 BEC",
        category="AI深度伪造",
        severity="critical",
        keywords=["deepfake", "ai fraud", "bec", "video conference", "arup", "实时换脸"],
        summary="2024-02 香港 Arup 财务被骗 2500 万美元，攻击者使用实时换脸 + 视频会议冒充 CFO。",
        content="2024-02 香港工程咨询公司 Arup 披露其香港办公室财务员工被深度伪造视频会议骗走 HK$200M（约 US$25M）。攻击者使用深度伪造视频实时冒充英国总部 CFO + 其他高管，财务员工在『视频会议』上看到熟悉的脸孔并按指示完成 15 笔转账。该事件是全球首例公开披露的『实时换脸 + 视频会议』BEC 攻击成功案例。攻击链路：(1) 通过 LinkedIn 公开信息梳理 Arup 财务组织结构；(2) 利用公开视频素材训练 CFO 等高管的深度伪造模型；(3) 通过 WhatsApp 等 IM 渠道发起『视频会议』；(4) 实时换脸 + AI 语音克隆模拟多人发言；(5) 财务员工在『熟悉的高管』」形象下完成付款。同月香港警方披露类似剧本造成 HK$200M 损失总额。深度伪造把 BEC 的『信任链攻击』推到了新维度。",
        recommendation="(1) 财务付款必须建立『带外回回确认』：任何视频会议 / 邮件付款指令必须电话回拨通讯录白名单二次确认；(2) 付款冷静期 ≥ 24 小时（> 某阈值金额时强制）；(3) 深度伪造检测工具：Microsoft Video Authenticator / Intel FakeCatcher 等可用于实时验证；(4) 高敏感视频会议启用『安全词』机制（如『我们的约定词是 XXX』）；(5) 财务 / HR / C-Level 培训：AI 时代『脸熟 ≠ 人对』；(7) 谨记：深度伪造的最大威胁不是技术，而是『它能骗过人眼』 —— 必须在流程上建立『非视觉验证』冗余。",
        tags=["深度伪造", "AI", "BEC", "视频会议", "Arup"],
        iocs=["AI 生成视频伪影 / 异常眨眼频率 / 头部运动不自然"],
        attack_techniques=["T1566.003", "T1657", "T1078"],
        detection_points=[
            "视频会议中人物眨眼频率异常低（深度伪造典型）",
            "嘴唇运动与音频有微秒级偏移",
            "财务付款模式异常（> 某阈值的紧急付款）"
        ],
        sample_email="",
        related_titles=["Vishing语音回拨诱导", "BEC/CEO欺诈转账邮件"],
    ),

    # --- 法律法规（新增分类种子） ---
    _kb(
        title="法规：网络安全等级保护 2.0",
        category="法律法规",
        severity="low",
        keywords=["等保2.0", "网络安全等级保护", "GB/T 22239-2019", "定级备案", "测评"],
        summary="等保2.0是网络运营者的强制性合规基线，邮件入口防护属于等保要求的'访问控制'与'安全计算环境'范畴。",
        content="网络安全等级保护 2.0（GB/T 22239-2019）由公安部第三研究所牵头修订，2019年12月正式实施，替代等保1.0（GB/T 22239-2008）。等保2.0 将云计算、移动互联网、物联网、工业控制系统纳入扩展要求，并强调'一个中心、三重防护'（安全管理中心 + 安全计算环境、安全区域边界、安全通信网络）。与钓鱼邮件防护直接相关的条款：(1) 安全区域边界——应在邮件入口部署反垃圾邮件网关，识别并阻断钓鱼邮件（8.1.4 访问控制）；(2) 安全计算环境——终端应安装并及时更新恶意代码防范工具（8.1.4.3 入侵防范）；(3) 安全管理中心——应集中收集邮件网关日志、终端杀毒日志并进行关联分析（8.1.5 集中管控）。等级分为五级（用户自主保护级 / 指导保护级 / 安全标记保护级 / 专家保护级 / 专控保护级），金融、能源、政务、电信等行业普遍要求三级及以上。三级系统要求每年度至少开展一次等级测评，四级系统每半年一次。钓鱼邮件失陷若未达到等保要求项的合规基线，可能在年度测评中被出具'高风险'结论，影响业务连续性与监管处罚。",
        recommendation="(1) 邮件网关与终端 EDR 的部署与策略覆盖度需在等保年度测评中可证明——保留策略快照、阻断日志、告警记录至少6个月；(2) 三级系统的邮件入口策略至少包含：SPF/DKIM/DMARC 校验 + URL 信誉 + 附件沙箱 + 高危类型拦截；(3) 安全管理中心应统一汇聚邮件、终端、网络、认证日志，钓鱼事件处置全流程可追溯；(4) 关键岗位人员签订安全保密协议，定期开展钓鱼演练（年度合规指标之一）；(5) 跟踪 2025 年 GB/T 22239 修订动向与行业实施细则（如金融行业 JR/T 0067、政务 GM/T 0054）。",
        tags=["法律法规", "等保2.0", "合规"],
        iocs=[],
        attack_techniques=[],
        detection_points=[
            "邮件网关策略完整性与年度测评记录",
            "日志留存时长（≥ 180天）",
            "安全管理中心对多源日志的汇聚与关联分析",
            "钓鱼演练年度覆盖率"
        ],
        sample_email="",
        related_titles=["法规：关键信息基础设施安全保护条例", "防御：DMARC 渐进式部署实战手册"],
    ),

    # --- 近期真实案例（新增分类种子） ---
    _kb(
        title="案例：Snowflake SaaS 凭据填充致 30 亿+ 记录泄露（2024）",
        category="近期真实案例",
        severity="high",
        keywords=["Snowflake", "凭据填充", "credential stuffing", "MFA缺失", "AT&T", "Ticketmaster"],
        summary="2024 年针对 Snowflake 客户环境的凭据填充攻击横扫 AT&T / Ticketmaster / Santander 等巨头，核心成因是目标账号长期未启用 MFA。",
        content="2024 年 4-6 月，多个使用 Snowflake 数据云服务的大型客户接连遭遇大规模数据泄露：AT&T 约 1.1 亿条通话与短信记录；Ticketmaster 超过 5.6 亿客户档案（含信用卡信息）；Santander 员工与客户数据；Advance Auto Parts 等数十家受影响。Mandiant 调查结论：这不是 Snowflake 平台的漏洞，而是针对性凭据填充（credential stuffing）—— 攻击者使用从以往数据泄露中回收的用户名/密码组合，对客户在 Snowflake 上未启用 MFA 的服务账号进行大规模撞库。攻击者 UNC5537（成员包括 'Sp1d3r' / 'ShinyHunters'）使用被攻陷的员工账号在 Snowflake 实例中创建临时表导出数据，并在部分实例部署勒索软件。直接成因：受影响账号普遍长期未启用 MFA，部分账号甚至使用已泄露超过 10 年的旧密码。该案让'MFA 强制执行'从安全最佳实践上升为安全底线，Snowflake 后续为所有管理员账号强制启用 MFA 并支持 FIDO2 硬件密钥。战术 ATT&CK 映射：T1110.004（凭据填充）、T1078（有效账户滥用）、T1530（云存储数据窃取）。",
        recommendation="(1) 所有云端账号（含 Snowflake、AWS、Azure、GCP、GitHub 等）强制启用 MFA，优先 FIDO2 硬件密钥；(2) 定期审计未启用 MFA 的账号与最近登录日志；(3) 对长期未更换的服务账号密码实施强制轮换；(4) 与 haveibeenpwned 等泄露库联动，对已知泄露密码拒绝登录；(5) 关注 SaaS 平台对外暴露的临时凭据（演示账号、试用密钥），及时关闭。",
        tags=["近期案例", "凭据填充", "MFA缺失", "SaaS安全"],
        iocs=[
            "SaaS 账号长期未启用 MFA",
            "账号密码出现在已知泄露库",
            "云存储桶异常 SELECT/EXPORT 操作"
        ],
        attack_techniques=["T1110.004", "T1078"],
        detection_points=[
            "未启用 MFA 的账号清单",
            "已知泄露密码登录尝试",
            "云存储桶异常访问模式",
            "服务账号凭据轮换记录"
        ],
        sample_email="",
        related_titles=["FIDO2/通行密钥为什么能免疫钓鱼", "零信任与条件访问如何限制钓鱼后果"],
    ),
]


def get_connection() -> sqlite3.Connection:
    """获取数据库连接（使用 DELETE 日志模式避免 Windows WAL 锁定问题）。

    设置 busy_timeout = 30s，让 WSL + Windows 跨平台场景下的瞬时文件锁能自动解除，
    避免上一个异常退出进程留下的锁导致 init_db 直接抛 OperationalError。

    失败时会**重试** + **降级**：重试 5 次（覆盖 WSL inode 延迟释放）；
    仍失败则返回只读连接让上层路由按需处理（不阻塞启动）。
    """
    last_err: Exception | None = None
    for _ in range(5):
        try:
            conn = sqlite3.connect(str(DB_PATH), timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 30000")
            try:
                conn.execute("PRAGMA journal_mode=DELETE")
            except sqlite3.OperationalError:
                # 极个别情况 journal_mode 切换需要短暂 exclusive lock；保留默认即可
                pass
            conn.execute("PRAGMA synchronous=NORMAL")
            return conn
        except sqlite3.OperationalError as exc:
            last_err = exc
            time.sleep(0.5)
    # 5 次重试仍失败：返回只读连接，让上层路由能继续响应（不阻塞启动）
    logger.warning(f"数据库连接多次重试仍失败，返回只读连接: {last_err}")
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    初始化数据库表结构

    创建 emails 表（存储待分析邮件）、
    reports 表（存储分析报告）和 kb_entries 表（知识库），
    并执行 KB 种子填充与知识库向量按需补齐。
    可安全重复调用（IF NOT EXISTS / 按 title 幂等）；
    嵌入服务不可用时向量补齐自动跳过，不影响主流程。

    设计为幂等且容忍瞬时锁：
    - 任何表创建 / 种子写入失败都只告警，不抛异常；
    - 这样即便上一个进程因异常退出留下短时间锁文件，
      当前进程依然能启动起来，API 路由可正常响应（API 路由
      自身按需取连接，会再次走过 get_connection 的 busy_timeout）。
    """
    conn = get_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT DEFAULT '',
                sender TEXT DEFAULT '',
                recipients TEXT DEFAULT '',
                body TEXT NOT NULL,
                urls TEXT DEFAULT '[]',
                headers TEXT DEFAULT '{}',
                has_attachment INTEGER DEFAULT 0,
                raw_text TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                timestamp TEXT NOT NULL,
                is_phishing INTEGER NOT NULL,
                risk_score REAL DEFAULT 0,
                risk_level TEXT DEFAULT 'unknown',
                semantic_result TEXT DEFAULT '{}',
                detection_result TEXT DEFAULT '{}',
                risk_result TEXT DEFAULT '{}',
                response_result TEXT DEFAULT '{}',
                workflow_log TEXT DEFAULT '[]',
                FOREIGN KEY (email_id) REFERENCES emails(id)
            );

            CREATE INDEX IF NOT EXISTS idx_reports_email ON reports(email_id);
            CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON reports(timestamp);
            CREATE INDEX IF NOT EXISTS idx_reports_is_phishing ON reports(is_phishing);
            CREATE INDEX IF NOT EXISTS idx_reports_risk_level ON reports(risk_level);
            CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at);

            CREATE TABLE IF NOT EXISTS kb_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                keywords TEXT NOT NULL DEFAULT '[]',
                content TEXT NOT NULL DEFAULT '',
                recommendation TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                summary TEXT DEFAULT '',
                tags TEXT DEFAULT '[]',
                iocs TEXT DEFAULT '[]',
                attack_techniques TEXT DEFAULT '[]',
                detection_points TEXT DEFAULT '[]',
                sample_email TEXT DEFAULT '',
                related TEXT DEFAULT '[]',
                embedding TEXT DEFAULT '',
                embedding_model TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_kb_category ON kb_entries(category);
            CREATE INDEX IF NOT EXISTS idx_kb_severity ON kb_entries(severity);
            CREATE INDEX IF NOT EXISTS idx_kb_enabled ON kb_entries(enabled);
        """
        )

        _ensure_kb_schema(conn)
        _seed_kb_entries(conn)
        conn.commit()
        logger.info(f"数据库初始化完成: {DB_PATH}")
    except sqlite3.OperationalError as exc:
        # WSL + Windows 跨平台场景下前一个进程异常退出可能留有锁文件，
        # 表已存在时不应阻断服务启动；记录后让上层路由按需重试。
        logger.warning(f"数据库初始化跳过（{exc}），路由层将在请求时按需重试")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # 播种完成后按需补齐知识库向量；嵌入服务未配置/失败只告警，不阻断启动
    try:
        embedded = embed_kb_entries()
        if embedded:
            logger.info(f"知识库向量已生成/更新 {embedded} 条（{KB_EMBEDDING_MODEL}）")
    except Exception as exc:
        logger.warning(f"知识库向量生成跳过（检索回退纯关键词通道）: {exc}")


def _ensure_kb_schema(conn: sqlite3.Connection):
    """轻量迁移：为已有 kb_entries 表补齐新增列。"""
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(kb_entries)").fetchall()
    }
    required = [
        ("summary", "TEXT DEFAULT ''"),
        ("tags", "TEXT DEFAULT '[]'"),
        ("iocs", "TEXT DEFAULT '[]'"),
        ("attack_techniques", "TEXT DEFAULT '[]'"),
        ("detection_points", "TEXT DEFAULT '[]'"),
        ("sample_email", "TEXT DEFAULT ''"),
        ("related", "TEXT DEFAULT '[]'"),
        ("embedding", "TEXT DEFAULT ''"),
        ("embedding_model", "TEXT DEFAULT ''"),
        ("source_url", "TEXT DEFAULT ''"),
    ]
    for col_name, col_def in required:
        if col_name not in columns:
            conn.execute(f"ALTER TABLE kb_entries ADD COLUMN {col_name} {col_def}")


def _seed_kb_entries(conn: sqlite3.Connection):
    """初始化默认知识库条目（按 title 幂等补齐，旧库可增量升级）。"""
    allowed_severity = {"critical", "high", "medium", "low"}
    now = datetime.now().isoformat()

    for item in _iter_all_seed_entries():
        title = (item.get("title") or "").strip()
        if not title:
            continue

        severity = (item.get("severity") or "low").lower()
        if severity not in allowed_severity:
            severity = "low"

        keywords = json.dumps(item.get("keywords") or [], ensure_ascii=False)
        tags = json.dumps(item.get("tags") or [], ensure_ascii=False)
        iocs = json.dumps(item.get("iocs") or [], ensure_ascii=False)
        attack_techniques = json.dumps(item.get("attack_techniques") or [], ensure_ascii=False)
        detection_points = json.dumps(item.get("detection_points") or [], ensure_ascii=False)
        sample_email_val = item.get("sample_email")
        if isinstance(sample_email_val, dict):
            sample_email = json.dumps(sample_email_val, ensure_ascii=False)
        elif isinstance(sample_email_val, str):
            sample_email = sample_email_val
        else:
            sample_email = ""

        row = conn.execute(
            "SELECT id FROM kb_entries WHERE title = ?",
            (title,),
        ).fetchone()

        if row:
            conn.execute(
                """
                UPDATE kb_entries
                SET category = ?,
                    severity = ?,
                    keywords = ?,
                    content = ?,
                    recommendation = ?,
                    summary = ?,
                    tags = ?,
                    iocs = ?,
                    attack_techniques = ?,
                    detection_points = ?,
                    sample_email = ?,
                    source_url = ?,
                    updated_at = ?
                WHERE title = ?
                """,
                (
                    item.get("category") or "未分类",
                    severity,
                    keywords,
                    item.get("content") or "",
                    item.get("recommendation") or "",
                    item.get("summary") or "",
                    tags,
                    iocs,
                    attack_techniques,
                    detection_points,
                    sample_email,
                    item.get("source_url") or "",
                    now,
                    title,
                ),
            )
            continue

        conn.execute(
            """
            INSERT INTO kb_entries
            (title, category, severity, keywords, content, recommendation, enabled, created_at, updated_at,
             summary, tags, iocs, attack_techniques, detection_points, sample_email, related, source_url)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                item.get("category") or "未分类",
                severity,
                keywords,
                item.get("content") or "",
                item.get("recommendation") or "",
                now,
                now,
                item.get("summary") or "",
                tags,
                iocs,
                attack_techniques,
                detection_points,
                sample_email,
                "[]",
                item.get("source_url") or "",
            ),
        )

    _refresh_related_links(conn)


def _iter_all_seed_entries() -> list[dict]:
    """返回内置种子 + 外部扩展包条目。"""
    entries = list(KB_SEED_ENTRIES)
    entries.extend(_load_kb_expansion_entries())
    entries.extend(_load_kb_datasets_entries())
    return entries


def _load_kb_datasets_entries() -> list[dict]:
    """从 data/datasets.json 读取公开威胁情报批量入库条目（MITRE ATT&CK、CISA KEV、GTFOBins、MISP Galaxy）。缺失时跳过。"""
    datasets_path = Path(settings.data_dir).resolve() / "datasets.json"
    if not datasets_path.exists():
        logger.warning("知识库 datasets 文件不存在，跳过外部扩展播种: %s", datasets_path)
        return []
    try:
        raw = json.loads(datasets_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("知识库 datasets 文件读取失败，跳过外部扩展播种: %s", exc)
        return []
    entries = raw.get("entries") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        logger.warning("知识库 datasets 文件格式无效（缺少 entries 数组），跳过外部扩展播种")
        return []
    normalized = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "title": item.get("title") or "",
            "category": item.get("category") or "未分类",
            "severity": item.get("severity") or "medium",
            "keywords": item.get("keywords") or [],
            "summary": item.get("summary") or "",
            "content": item.get("content") or "",
            "recommendation": item.get("recommendation") or "",
            "tags": item.get("tags") or [],
            "iocs": item.get("iocs") or [],
            "attack_techniques": item.get("attack_techniques") or [],
            "detection_points": item.get("detection_points") or [],
            "sample_email": item.get("sample_email") if item.get("sample_email") is not None else "",
            "related_titles": [],
            "source_url": item.get("source_url") or "",
        })
    logger.info(f"从 datasets.json 加载 {len(normalized)} 条公开威胁情报条目")
    return normalized


def _load_kb_expansion_entries() -> list[dict]:
    """从 data/kb_expansion.json 读取扩展条目，缺失时跳过。"""
    if not KB_EXPANSION_PATH.exists():
        logger.warning("知识库扩展文件不存在，跳过外部扩展播种: %s", KB_EXPANSION_PATH)
        return []

    try:
        raw = json.loads(KB_EXPANSION_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("知识库扩展文件读取失败，跳过外部扩展播种: %s", exc)
        return []

    entries = raw.get("entries") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        logger.warning("知识库扩展文件格式无效（缺少 entries 数组），跳过外部扩展播种")
        return []

    normalized = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "title": item.get("title") or "",
                "category": item.get("category") or "未分类",
                "severity": item.get("severity") or "medium",
                "keywords": item.get("keywords") or [],
                "summary": item.get("summary") or "",
                "content": item.get("content") or "",
                "recommendation": item.get("recommendation") or "",
                "tags": item.get("tags") or [],
                "iocs": item.get("iocs") or [],
                "attack_techniques": item.get("attack_techniques") or [],
                "detection_points": item.get("detection_points") or [],
                "sample_email": item.get("sample_email") if item.get("sample_email") is not None else "",
                "related_titles": [],
                "source_url": item.get("source_url") or "",
            }
        )

    return normalized


def _refresh_related_links(conn: sqlite3.Connection):
    """根据 related_titles 写入 related(id 列表)。"""
    title_to_id = {
        row[0]: row[1]
        for row in conn.execute("SELECT title, id FROM kb_entries").fetchall()
    }
    for item in KB_SEED_ENTRIES:
        title = item.get("title")
        if not title or title not in title_to_id:
            continue
        related_ids = []
        for related_title in item.get("related_titles") or []:
            rid = title_to_id.get(related_title)
            if rid is not None:
                related_ids.append(rid)
        related_ids = sorted(set(related_ids))
        conn.execute(
            "UPDATE kb_entries SET related = ? WHERE title = ?",
            (json.dumps(related_ids, ensure_ascii=False), title),
        )


def save_email(email_data: dict) -> int:
    """
    保存邮件记录到数据库

    Args:
        email_data: 邮件字段字典，对应 EmailInput 模型

    Returns:
        新插入记录的 ID
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO emails
               (subject, sender, recipients, body, urls, headers, has_attachment, raw_text, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                email_data.get("subject", ""),
                email_data.get("sender", ""),
                email_data.get("recipients", ""),
                email_data.get("body", ""),
                json.dumps(email_data.get("urls", []), ensure_ascii=False),
                json.dumps(email_data.get("headers", {}), ensure_ascii=False),
                int(email_data.get("has_attachment", False)),
                email_data.get("raw_text", ""),
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def save_report(email_id: int, report_data: dict) -> int:
    """
    保存分析报告

    Args:
        email_id: 关联的邮件 ID
        report_data: 报告字段字典

    Returns:
        新插入报告的 ID
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO reports
               (email_id, timestamp, is_phishing, risk_score, risk_level,
                semantic_result, detection_result, risk_result, response_result, workflow_log)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                email_id,
                datetime.now().isoformat(),
                int(report_data.get("is_phishing", False)),
                report_data.get("risk_score", 0),
                report_data.get("risk_level", "unknown"),
                json.dumps(report_data.get("semantic_result", {}), ensure_ascii=False),
                json.dumps(report_data.get("detection_result", {}), ensure_ascii=False),
                json.dumps(report_data.get("risk_result", {}), ensure_ascii=False),
                json.dumps(report_data.get("response_result", {}), ensure_ascii=False),
                json.dumps(report_data.get("workflow_log", []), ensure_ascii=False),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_recent_emails(limit: int = 50) -> list[dict]:
    """
    获取最近的邮件记录

    Args:
        limit: 返回条数上限

    Returns:
        邮件记录列表
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM emails ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_reports(limit: int = 50) -> list[dict]:
    """
    获取最近的分析报告

    Args:
        limit: 返回条数上限

    Returns:
        报告记录列表
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT r.*, e.subject, e.sender, e.body
               FROM reports r
               LEFT JOIN emails e ON r.email_id = e.id
               ORDER BY r.timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_report(report_id: int) -> bool:
    """删除指定报告（仅 reports 行，email 行保留，不影响 emails 统计）。

    Returns:
        是否实际删除（不存在时返回 False）
    """
    conn = get_connection()
    try:
        cursor = conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def delete_all_reports() -> int:
    """清空全部报告（仅 reports 表，emails 行保留，不影响 emails 统计）。

    会同步重置 reports 表的 AUTOINCREMENT 自增计数，清空后新报告序号从 1 重新开始。

    Returns:
        实际删除的行数
    """
    conn = get_connection()
    try:
        cursor = conn.execute("DELETE FROM reports")
        # 重置自增序号（AUTOINCREMENT 的计数存于 sqlite_sequence，DELETE 不会自动归零）
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'reports'")
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_email_by_id(email_id: int) -> Optional[dict]:
    """根据 ID 获取单封邮件"""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM emails WHERE id = ?", (email_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_stats() -> dict:
    """获取统计概览：邮件总数、报告数、钓鱼检出数等"""
    conn = get_connection()
    try:
        total_emails = conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
        total_reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        phishing_count = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE is_phishing = 1"
        ).fetchone()[0]
        avg_risk = conn.execute(
            "SELECT AVG(risk_score) FROM reports"
        ).fetchone()[0] or 0
        return {
            "total_emails": total_emails,
            "total_reports": total_reports,
            "phishing_detected": phishing_count,
            "safe_emails": total_reports - phishing_count,
            "avg_risk_score": round(avg_risk, 1),
        }
    finally:
        conn.close()


def _json_load_array(raw: str) -> list:
    try:
        parsed = json.loads(raw or "[]")
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _json_load_object(raw: str) -> dict:
    try:
        parsed = json.loads(raw or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _json_load_vector(raw: str) -> list[float]:
    try:
        parsed = json.loads(raw or "[]")
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []

    vector = []
    for value in parsed:
        try:
            vector.append(float(value))
        except (TypeError, ValueError):
            return []
    if KB_EMBEDDING_DIM > 0 and len(vector) != KB_EMBEDDING_DIM:
        return []
    return vector


def _embedding_text_from_kb_row(item: dict) -> str:
    fields = [
        item.get("title") or "",
        item.get("category") or "",
        item.get("severity") or "",
        item.get("summary") or "",
        item.get("content") or "",
        item.get("recommendation") or "",
    ]

    for field in ("keywords", "tags", "iocs", "attack_techniques", "detection_points"):
        values = _json_load_array(item.get(field) or "[]")
        if values:
            fields.append(" ".join(str(v) for v in values if v))

    return "\n".join(part for part in fields if part)[:6000]


def _embed(texts: list[str], emb_type: str = "db") -> list[list[float]]:
    if not texts:
        return []
    return embed(texts, emb_type=emb_type)


def _load_kb_vectors() -> dict[int, list[float]]:
    """把 enabled=1 条目的 (id, embedding) 载入模块级内存缓存。"""
    global _KB_VECTOR_CACHE_LOADED
    if _KB_VECTOR_CACHE_LOADED:
        return _KB_VECTOR_CACHE

    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, embedding
               FROM kb_entries
               WHERE enabled = 1
                 AND embedding IS NOT NULL
                 AND TRIM(embedding) <> ''"""
        ).fetchall()
    except sqlite3.OperationalError:
        _KB_VECTOR_CACHE.clear()
        _KB_VECTOR_CACHE_LOADED = True
        conn.close()
        return _KB_VECTOR_CACHE
    finally:
        conn.close()

    cache: dict[int, list[float]] = {}
    for row in rows:
        entry_id = int(row[0])
        vector = _json_load_vector(row[1])
        if vector:
            cache[entry_id] = vector

    _KB_VECTOR_CACHE.clear()
    _KB_VECTOR_CACHE.update(cache)
    _KB_VECTOR_CACHE_LOADED = True
    return _KB_VECTOR_CACHE


def _invalidate_kb_vector_cache():
    global _KB_VECTOR_CACHE_LOADED
    _KB_VECTOR_CACHE.clear()
    _KB_VECTOR_CACHE_LOADED = False


def embed_kb_entries(limit: int | None = None) -> int:
    """为知识库条目生成 embedding 并写回数据库。

    仅处理尚无向量、或 embedding_model 标记与当前配置（模型名:维度）
    不一致的条目，可安全重复调用（幂等）；切换嵌入模型后自动全量重算。
    嵌入服务未配置或调用失败时只记 warning 并跳过，不生成任何替代向量，
    检索自动回退纯关键词通道。
    """
    if not KB_EMBEDDING_MODEL:
        logger.warning("EMBEDDING_MODEL 未配置，跳过知识库向量生成（检索走纯关键词通道）")
        return 0

    model_tag = f"{KB_EMBEDDING_MODEL}:{KB_EMBEDDING_DIM}"
    conn = get_connection()
    try:
        sql = (
            """SELECT id, title, category, severity, keywords, summary, content, recommendation,
                      tags, iocs, attack_techniques, detection_points
               FROM kb_entries
               WHERE enabled = 1
                 AND (embedding IS NULL OR TRIM(embedding) = ''
                      OR embedding_model IS NULL OR embedding_model <> ?)
               ORDER BY id ASC"""
        )
        params: list = [model_tag]
        if limit is not None and limit > 0:
            sql += " LIMIT ?"
            params.append(limit)

        rows = conn.execute(sql, tuple(params)).fetchall()
        if not rows:
            return 0

        # 分批调用嵌入接口，避免单请求文本过多被服务端拒绝
        batch_size = 32
        updated = 0
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            ids = [int(row["id"]) for row in batch]
            payloads = [_embedding_text_from_kb_row(dict(row)) for row in batch]

            try:
                vectors = _embed(payloads, "db")
            except EmbeddingUnavailableError as exc:
                logger.warning(f"知识库向量生成失败，跳过剩余批次（检索回退纯关键词通道）: {exc}")
                break
            if len(vectors) != len(ids):
                logger.warning("知识库向量数量与输入不一致，跳过剩余批次")
                break

            for entry_id, vector in zip(ids, vectors):
                if not vector:
                    continue
                conn.execute(
                    "UPDATE kb_entries SET embedding = ?, embedding_model = ?, updated_at = ? WHERE id = ?",
                    (
                        json.dumps(vector, ensure_ascii=False),
                        f"{KB_EMBEDDING_MODEL}:{len(vector)}",
                        datetime.now().isoformat(),
                        entry_id,
                    ),
                )
                updated += 1
            conn.commit()

        if updated:
            _invalidate_kb_vector_cache()
        return updated
    finally:
        conn.close()


def _cosine(a, b) -> float:
    """numpy 计算余弦相似度，任一零向量时返回 0。"""
    va = np.asarray(a, dtype=float)
    vb = np.asarray(b, dtype=float)
    if va.size == 0 or vb.size == 0:
        return 0.0
    if va.shape != vb.shape:
        return 0.0

    na = np.linalg.norm(va)
    nb = np.linalg.norm(vb)
    if na == 0.0 or nb == 0.0:
        return 0.0

    return float(np.dot(va, vb) / (na * nb))


def vector_search_kb(query: str, limit: int = 10) -> list[dict]:
    """向量语义检索（仅返回向量路结果）。"""
    query_text = (query or "").strip()
    if not query_text:
        return []

    try:
        vectors = _load_kb_vectors()
        if not vectors:
            return []

        if not KB_EMBEDDING_MODEL:
            raise EmbeddingUnavailableError("EMBEDDING_MODEL 未配置")

        query_embedding = _embed([query_text], "query")
        if not query_embedding or not query_embedding[0]:
            return []
        query_vector = query_embedding[0]
    except EmbeddingUnavailableError:
        raise
    except Exception as exc:
        raise EmbeddingUnavailableError(str(exc)) from exc

    scored = []
    for entry_id, entry_vector in vectors.items():
        sim = _cosine(query_vector, entry_vector)
        score = max(0, round(sim * 100))
        if score < KB_VECTOR_SCORE_THRESHOLD:
            continue
        scored.append((entry_id, score))

    if not scored:
        return []

    scored.sort(key=lambda x: x[1], reverse=True)
    top_scored = scored[: max(limit, 1)]
    ids = [entry_id for entry_id, _ in top_scored]
    score_map = {entry_id: score for entry_id, score in top_scored}

    placeholders = ",".join("?" for _ in ids)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"""SELECT id, title, category, severity, summary
                FROM kb_entries
                WHERE enabled = 1 AND id IN ({placeholders})""",
            tuple(ids),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()

    meta_map = {int(row["id"]): dict(row) for row in rows}
    result = []
    for entry_id in ids:
        meta = meta_map.get(entry_id)
        if not meta:
            continue
        result.append(
            {
                "id": entry_id,
                "title": meta.get("title") or "",
                "category": meta.get("category") or "",
                "severity": meta.get("severity") or "medium",
                "summary": meta.get("summary") or "",
                "vector_score": score_map.get(entry_id, 0),
            }
        )
    return result


def _fetch_kb_details_by_ids(ids: list[int]) -> dict[int, dict]:
    if not ids:
        return {}

    placeholders = ",".join("?" for _ in ids)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"""SELECT id, title, category, severity, keywords, content, recommendation,
                       summary, tags, attack_techniques
                FROM kb_entries
                WHERE enabled = 1 AND id IN ({placeholders})""",
            tuple(ids),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()

    details: dict[int, dict] = {}
    for row in rows:
        item = dict(row)
        details[int(item["id"])] = {
            "id": int(item["id"]),
            "title": item.get("title") or "",
            "category": item.get("category") or "",
            "severity": item.get("severity") or "medium",
            "score": 0,
            "matched_keywords": [],
            "content": item.get("content") or "",
            "recommendation": item.get("recommendation") or "",
            "summary": item.get("summary") or "",
            "tags": _json_load_array(item.get("tags") or "[]"),
            "attack_techniques": _json_load_array(item.get("attack_techniques") or "[]"),
        }
    return details


def hybrid_search_kb(text: str, limit: int = 5) -> list[dict]:
    """关键词 + 向量语义双路混合检索。"""
    query_text = (text or "").strip()
    if not query_text:
        return []

    hits_kw = search_kb(query_text, limit=10)

    try:
        hits_vec = vector_search_kb(query_text, limit=10)
    except (EmbeddingUnavailableError, LLMUnavailableError, Exception):
        hits_vec = []

    if not hits_vec:
        degraded = []
        for item in hits_kw[: max(limit, 0)]:
            row = dict(item)
            row["kw_score"] = int(item.get("score", 0))
            row["vector_score"] = 0
            row["fused_score"] = row["kw_score"]
            row["match_type"] = "keyword"
            degraded.append(row)
        return degraded

    merged: dict[int, dict] = {}
    for item in hits_kw:
        row = dict(item)
        row["kw_score"] = int(item.get("score", 0))
        row["vector_score"] = 0
        merged[int(item["id"])] = row

    missing_ids = [int(item["id"]) for item in hits_vec if int(item["id"]) not in merged]
    detail_map = _fetch_kb_details_by_ids(missing_ids)

    for item in hits_vec:
        entry_id = int(item["id"])
        vector_score = int(item.get("vector_score", 0))
        if entry_id not in merged:
            row = detail_map.get(entry_id)
            if not row:
                continue
            row["kw_score"] = 0
            row["vector_score"] = vector_score
            merged[entry_id] = row
        else:
            merged[entry_id]["vector_score"] = vector_score

    fused = []
    for row in merged.values():
        kw_score = int(row.get("kw_score", 0))
        vector_score = int(row.get("vector_score", 0))
        fused_score = round(0.4 * kw_score + 0.6 * vector_score)

        if kw_score > 0 and vector_score > 0:
            match_type = "hybrid"
        elif vector_score > 0:
            match_type = "semantic"
        else:
            match_type = "keyword"

        row["fused_score"] = fused_score
        row["match_type"] = match_type
        fused.append(row)

    fused.sort(key=lambda x: (x.get("fused_score", 0), x.get("vector_score", 0), x.get("kw_score", 0)), reverse=True)
    return fused[: max(limit, 0)]


def _parse_kb_row(item: dict) -> dict:
    item["keywords"] = _json_load_array(item.get("keywords") or "[]")
    item["tags"] = _json_load_array(item.get("tags") or "[]")
    item["iocs"] = _json_load_array(item.get("iocs") or "[]")
    item["attack_techniques"] = _json_load_array(item.get("attack_techniques") or "[]")
    item["detection_points"] = _json_load_array(item.get("detection_points") or "[]")
    item["related"] = _json_load_array(item.get("related") or "[]")

    sample_email_raw = item.get("sample_email") or ""
    if sample_email_raw and str(sample_email_raw).strip().startswith("{"):
        item["sample_email"] = _json_load_object(sample_email_raw)
    else:
        item["sample_email"] = sample_email_raw

    item["enabled"] = bool(item.get("enabled", 1))
    # 暴露 source_url（可能为空字符串），便于审计条目来源 URL
    item["source_url"] = item.get("source_url") or ""
    return item


def list_kb_entries(limit: int = 100, category: str = None) -> list[dict]:
    """获取知识库条目列表。"""
    conn = get_connection()
    try:
        try:
            if category:
                rows = conn.execute(
                    """SELECT id, title, category, severity, keywords, content, recommendation,
                              enabled, updated_at, summary, tags, iocs, attack_techniques,
                              detection_points, sample_email, related, source_url
                       FROM kb_entries
                       WHERE category = ?
                       ORDER BY updated_at DESC
                       LIMIT ?""",
                    (category, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, title, category, severity, keywords, content, recommendation,
                              enabled, updated_at, summary, tags, iocs, attack_techniques,
                              detection_points, sample_email, related, source_url
                       FROM kb_entries
                       ORDER BY updated_at DESC
                       LIMIT ?""",
                    (limit,),
                ).fetchall()
        except sqlite3.OperationalError:
            return []

        result = []
        for row in rows:
            item = _parse_kb_row(dict(row))
            result.append(item)
        return result
    finally:
        conn.close()


def get_kb_entry(entry_id: int) -> Optional[dict]:
    """根据 id 获取完整知识库条目并解析 JSON 字段。"""
    conn = get_connection()
    try:
        try:
            row = conn.execute(
                """SELECT id, title, category, severity, keywords, content, recommendation,
                          enabled, created_at, updated_at, summary, tags, iocs,
                          attack_techniques, detection_points, sample_email, related
                   FROM kb_entries
                   WHERE id = ?""",
                (entry_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            return None

        if not row:
            return None
        return _parse_kb_row(dict(row))
    finally:
        conn.close()


def list_kb_categories() -> list[dict]:
    """返回知识库分类统计。"""
    conn = get_connection()
    try:
        try:
            rows = conn.execute(
                """SELECT category, COUNT(*) AS count
                   FROM kb_entries
                   GROUP BY category
                   ORDER BY count DESC, category ASC"""
            ).fetchall()
        except sqlite3.OperationalError:
            return []

        return [
            {"id": r[0], "name": r[0], "count": int(r[1])}
            for r in rows
        ]
    finally:
        conn.close()


def get_kb_stats() -> dict:
    """返回知识库总体统计：总条数 / 分类数 / 严重度分布 / ATT&CK 技术词条数。

    用于 advanced.html hero 区的实时统计卡片（不再写死 8K+ / 9 分类等数字）。
    ATT&CK 技术词条数 = keywords / content / attack_techniques 中含 Txxxx 编号的去重计数。
    """
    conn = get_connection()
    try:
        try:
            total = conn.execute("SELECT COUNT(*) FROM kb_entries").fetchone()[0] or 0
            cat_count = conn.execute(
                "SELECT COUNT(DISTINCT category) FROM kb_entries"
            ).fetchone()[0] or 0

            severity_rows = conn.execute(
                """SELECT severity, COUNT(*) AS cnt
                   FROM kb_entries
                   GROUP BY severity"""
            ).fetchall()
            severity_dist = {r[0]: int(r[1]) for r in severity_rows}

            cat_rows = conn.execute(
                """SELECT category, COUNT(*) AS cnt
                   FROM kb_entries
                   GROUP BY category
                   ORDER BY cnt DESC"""
            ).fetchall()
            category_dist = {r[0]: int(r[1]) for r in cat_rows}

            # 累计 attack_techniques 字段里出现的 T-IDs 总数（去重）
            tech_rows = conn.execute(
                "SELECT attack_techniques FROM kb_entries WHERE attack_techniques != '[]'"
            ).fetchall()
            tech_ids: set[str] = set()
            for r in tech_rows:
                try:
                    items = json.loads(r[0] or "[]")
                except Exception:
                    continue
                if isinstance(items, list):
                    for it in items:
                        if isinstance(it, str) and it.upper().startswith("T"):
                            tech_ids.add(it.upper())

            avg_content_len = conn.execute(
                "SELECT AVG(LENGTH(content)) FROM kb_entries"
            ).fetchone()[0] or 0

            return {
                "total_entries": int(total),
                "category_count": int(cat_count),
                "severity_distribution": severity_dist,
                "category_distribution": category_dist,
                "attack_technique_unique_count": len(tech_ids),
                "attack_technique_sample": sorted(tech_ids)[:20],
                "avg_content_chars": int(avg_content_len),
            }
        except sqlite3.OperationalError:
            return {
                "total_entries": 0,
                "category_count": 0,
                "severity_distribution": {},
                "category_distribution": {},
                "attack_technique_unique_count": 0,
                "attack_technique_sample": [],
                "avg_content_chars": 0,
            }
    finally:
        conn.close()


def search_kb(text: str, limit: int = 5) -> list[dict]:
    """基于关键词的轻量知识库检索（MVP）。"""
    query_text = (text or "").lower().strip()
    if not query_text:
        return []

    conn = get_connection()
    try:
        try:
            rows = conn.execute(
                """SELECT id, title, category, severity, keywords, content, recommendation,
                          summary, tags, attack_techniques
                   FROM kb_entries
                   WHERE enabled = 1"""
            ).fetchall()
        except sqlite3.OperationalError:
            return []

        severity_bonus = {"critical": 15, "high": 10, "medium": 6, "low": 3}
        tokens = [t for t in re.split(r"[^a-zA-Z0-9\u4e00-\u9fff]+", query_text) if len(t) >= 2]

        hits = []
        for row in rows:
            item = dict(row)
            keywords = [k.lower() for k in _json_load_array(item.get("keywords") or "[]")]
            matched = []

            for kw in keywords:
                if kw and kw in query_text:
                    matched.append(kw)

            # 兜底：token 命中 title/content 也计分
            title = (item.get("title") or "").lower()
            content = (item.get("content") or "").lower()
            token_hits = [tok for tok in tokens if tok in title or tok in content]

            if not matched and not token_hits:
                continue

            # 打分公式保持不变
            score = min(len(matched) * 18 + len(token_hits) * 6, 80)
            score += severity_bonus.get((item.get("severity") or "medium").lower(), 0)
            score = min(score, 100)

            hits.append({
                "id": item["id"],
                "title": item["title"],
                "category": item["category"],
                "severity": item["severity"],
                "score": score,
                "matched_keywords": sorted(set(matched + token_hits))[:8],
                "content": item["content"],
                "recommendation": item["recommendation"],
                # 新增字段（不影响旧字段）
                "summary": item.get("summary") or "",
                "tags": _json_load_array(item.get("tags") or "[]"),
                "attack_techniques": _json_load_array(item.get("attack_techniques") or "[]"),
            })

        hits.sort(key=lambda x: x["score"], reverse=True)
        return hits[:limit]
    finally:
        conn.close()
