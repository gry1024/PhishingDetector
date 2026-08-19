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
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np

from src.config import settings
from src.llm import embed, EmbeddingUnavailableError, LLMUnavailableError

logger = logging.getLogger(__name__)

# 数据库文件路径（使用绝对路径，避免 WAL 模式下相对路径权限问题）
DB_PATH = Path(settings.data_dir).resolve().parent / "phishing_detector.db"
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
        content="URL 使用纯 IP 地址且包含 8080/8443 等非常用端口时，常见于临时钓鱼站点或伪造登录页。攻击者借此绕过品牌域名审查，快速切换基础设施，形成短周期投递与回收闭环。若邮件同时出现“账户冻结”“立即验证”等措辞，用户更容易在高压场景下忽略地址异常。",
        recommendation="优先人工复核链接归属，禁止直接点击并提交沙箱分析；在网关侧对 IP 直连 URL 设置高风险阻断策略。",
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
        content="邮件同时出现紧急时限、账户冻结威胁、立即验证等措辞，属于高频社工钓鱼特征。该话术利用损失厌恶和时间压力，促使用户跳过核验步骤直接点击。若再叠加品牌仿冒、异常 URL 或回复地址不一致，通常可判定为中高风险攻击。",
        recommendation="对该类邮件提高风险权重，并结合发件人与 URL 进行交叉验证；在客户端突出显示“时间施压”风险提示。",
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
        content="出现账号验证、密码更新、重新登录等行为引导，通常对应凭证窃取场景。攻击者会构造接近真实品牌的登录界面，先收集账号密码，再通过中间页套取 MFA 验证码或会话。此类攻击往往与短链、仿冒域名和紧急话术组合出现。",
        recommendation="若伴随可疑域名或异常端口，应直接升级为高风险处置；强制用户从官方门户重新发起登录。",
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
        content="企业内部系统通知常使用固定域名与标准端口，文本通常不会要求外链验证账号密码。白名单策略可用于降低误报和运营噪声，但在出现紧急转账、凭证索取、异常附件等冲突信号时，必须让位于风险证据，不可直接放行。",
        recommendation="如命中白名单仍出现紧急转账或凭证索取，应触发冲突告警并人工复核。",
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
        content="攻击者常使用 .top/.xyz/.click 等低成本域名并拼接 verify、secure、brand 等词构造“看似官方”的地址。该模式部署快、替换快，适合批量投递。若邮件话术再包含账户异常、限时恢复，误点概率显著上升。",
        recommendation="将可疑 TLD 与品牌词共现设为高优先级规则，并与发件人画像联动加权。",
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
        content="短链接会隐藏真实落地域名，且常配合多次重定向动态切换目标，使静态黑名单难以及时覆盖。攻击者还会根据设备类型分流到不同钓鱼页。若短链与登录验证话术共现，应作为高风险信号处理。",
        recommendation="对短链先做解码与链路展开，再执行域名信誉、证书和内容联动审计。",
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
        content="单一关键词容易误报，但“账户冻结+立即验证+重新登录”等组合词具有更高区分度。攻击邮件会围绕身份确认、访问恢复和时限施压构建闭环文案。将组合命中作为特征向量输入风险融合，能提升召回与精度平衡。",
        recommendation="维护组合词模板并按业务线细分阈值，避免宽泛词触发全库误命中。",
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
        content="BEC 攻击通常不依赖恶意链接，而是利用组织层级信任直接驱动财务动作。邮件会强调紧急、保密和流程例外，诱导员工绕过审批链。若来自陌生域名或历史上未出现的写作风格，应立即中断执行并发起线下核验。",
        recommendation="建立高管邮件二次认证流程，涉及付款必须电话回拨确认并留痕。",
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
        content="鱼叉钓鱼会引用真实项目、同事姓名或会议安排，使邮件看起来高度可信。攻击者常先做公开情报收集，再投递定制文案与仿冒链接。由于内容贴近业务，传统关键词检测易漏报，需要联系人关系与基础设施一致性共同判断。",
        recommendation="对外部来源但包含内部敏感上下文的邮件触发加强审查。",
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
        content="克隆钓鱼会复刻历史合法邮件模板，仅替换附件或链接为恶意内容。用户因熟悉模板而降低警惕，尤其在“请忽略上一封，以此封为准”场景中更易中招。该手法需结合历史邮件哈希和模板指纹比对识别。",
        recommendation="对“更正版本”邮件做模板指纹校验，检测链接域名变化。",
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
        content="Quishing 将恶意地址编码进二维码图片，规避纯文本 URL 检测。攻击通常引导用户在手机端扫码登录，随后收集凭证或会话。由于终端切换，员工难以在企业网关侧获得完整保护，需在邮件客户端增加二维码风险提示。",
        recommendation="对邮件内图片进行二维码识别并还原 URL 做信誉检测。",
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
        content="攻击者先发送短信告知账户异常，再通过邮件提供“官方处理入口”，制造多渠道一致性假象。用户在连续告警压力下更容易信任链接并输入凭证。该模式应结合时间窗口、终端来源和渠道关联做联合分析。",
        recommendation="建立短信与邮件跨渠道关联告警，识别短时联动异常。",
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
        content="Vishing 场景中，邮件会要求用户拨打所谓“官方热线”处理异常，随后在语音通话中索取账号、验证码或远程控制授权。该模式利用电话信任感规避纯邮件防护，应将可疑热线号码纳入 IOC 维护。",
        recommendation="禁止通过邮件提供的号码进行账号验证，统一使用通讯录白名单回拨。",
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
        content="攻击者常伪装为发票、对账单或交付文档，诱导用户启用宏或内容编辑，从而触发脚本下载后门。该手法在财务与采购流程中出现频率高，且往往不依赖明显恶意 URL，需依赖附件类型、文案和行为联动识别。",
        recommendation="默认禁用 Office 宏，附件先沙箱执行并对可疑行为自动隔离。",
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
        content="PhaaS 生态提供现成模板、域名轮换和数据回传能力，使攻击者几乎零门槛上线钓鱼活动。邮件内容往往模板化、品牌覆盖广，且基础设施快速更替。防守侧需关注批量相似文案与短周期域名簇。",
        recommendation="建立相似文案聚类与域名簇检测，对批量投递快速封禁。",
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
        content="AI 生成钓鱼邮件在语法和措辞上更自然，能根据受害者角色快速定制文案，降低“错别字检测”这类低阶规则效果。其核心风险仍体现在意图与行为引导，因此需将语义链、动作指令和基础设施证据联合判定。",
        recommendation="弱化“语法异常”权重，强化行为指令与身份验证链路检测。",
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
        content="攻击者伪造 Microsoft 365 安全团队通知，声称邮箱异常或配额问题，诱导用户通过邮件链接重新登录。由于目标用户对 M365 场景高度熟悉，误点率较高。应重点核验发件域、链接域与微软官方域名映射关系。",
        recommendation="对 M365 主题邮件开启品牌专属规则集与域名白名单比对。",
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
        content="银行仿冒邮件通常以“交易异常”“账户冻结”触发恐惧，诱导用户在伪造站点输入网银凭证。由于涉及资金安全，用户会优先响应。若邮件来源域名与官方银行域名不一致，应立即判定为高风险并阻断访问。",
        recommendation="建立银行品牌域名清单，命中仿冒特征时直接隔离邮件。",
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
        content="快递仿冒邮件借助“包裹异常”“签收失败”触发用户即时点击心理，常引导到伪造查询页。移动端用户更易在碎片时间完成误操作。需结合发件人域、链接域与官方物流域名进行一致性核验。",
        recommendation="对物流类邮件启用品牌映射规则与 URL 信誉联动检查。",
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
        content="攻击者伪装企业 IT 或 HR 发送制度更新、账号升级、薪资确认等通知，利用组织权威提升执行率。邮件会要求员工通过外链提交信息或下载附件。对“内部职能 + 外链凭证/附件”的组合应重点拦截。",
        recommendation="建立内部部门邮件签名校验，异常来源统一进入隔离队列。",
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
        content="T1566.001 描述攻击者利用附件作为入口，典型载体包括宏文档、压缩包和脚本文件。该技术常与财务或法务语义伪装结合，诱导用户打开并执行。检测上应联动附件扩展名、文案诱导词与沙箱行为。",
        recommendation="对高危附件类型默认隔离，人工审核后再放行。",
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
        content="T1566.002 以钓鱼链接为核心载体，攻击者通过品牌仿冒或安全告警话术引导用户访问伪造站点。该技术在企业邮箱中最常见，且与短链、重定向、IP 直连等指标高度相关。",
        recommendation="统一走 URL 展开与信誉评估，结合语义风险做分层处置。",
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
        content="T1566.003 关注通过第三方服务或平台开展钓鱼，包括短信、协作工具、客服渠道等。其特点是多渠道联动，用户容易将不同来源误判为同一官方流程，需做跨渠道关联分析。",
        recommendation="建立邮件、短信、IM 平台的统一事件关联与风险归一化。",
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
        content="T1598 侧重通过欺骗获取凭证、身份信息或组织内部数据。它覆盖邮件、网站和社交渠道等多形态入口。防守上需关注信息收集链路，而不仅是恶意代码执行。",
        recommendation="将信息字段采集行为纳入检测与告警范围。",
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
        content="T1204.002 指用户被诱导执行恶意文件，是附件钓鱼场景中的关键执行阶段。即便前置文案看似业务合理，一旦执行链被触发，后续可能快速进入持久化和横向移动。",
        recommendation="端点侧启用可疑进程链阻断与最小权限策略。",
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
        content="T1078 描述攻击者获取有效凭证后进行后续访问，常见于 M365、VPN 与邮件系统。由于行为看似合法，传统边界防护难以察觉，需结合登录地、设备指纹与会话连续性做异常检测。",
        recommendation="对高风险登录场景启用再认证和条件访问策略。",
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
        content="某企业在周结高峰收到“财务主管”邮件，要求紧急向新供应商账户付款。邮件无恶意链接，仅凭流程压迫与保密话术完成欺骗，最终造成直接资金损失。复盘显示组织缺少“邮件付款二次确认”刚性流程。",
        recommendation="对首次收款账户和紧急付款建立强制线下复核控制点。",
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
        content="某组织收到多封“邮箱配额超限”通知，链接指向仿冒 M365 登录页。员工输入凭证后，攻击者迅速接管邮箱并向外扩散同模板邮件。由于邮件语法自然且来源分散，初期未被规则及时拦截。",
        recommendation="对品牌关键场景启用专属检测策略并执行会话吊销。",
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
        content="某企业邮件网关主要针对文本 URL 检测，攻击者改用二维码投递登录入口，导致多名员工在手机端完成了错误认证。复盘显示系统缺少二维码解析与 URL 还原能力，且用户教育未覆盖扫码场景风险。",
        recommendation="补齐二维码识别链路并加强移动端安全提示。",
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
        content="SPF 用于声明哪些服务器可代表域名发送邮件，可有效减少简单伪造。但 SPF 仅覆盖 envelope sender 维度，不能独立解决显示名仿冒与转发场景。建议将 SPF fail 与品牌词、外链登录等特征联动，构建分层告警。",
        recommendation="明确 SPF 记录维护责任，持续监控 fail/softfail 波动并联动处置。",
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
        content="DKIM 通过私钥签名确保邮件在传输过程中未被篡改，并能证明签名域对邮件负责。部署时应统一 selector 管理与密钥轮换节奏，避免长期静态密钥风险。DKIM 结果应与 SPF、DMARC 同步纳入风险融合。",
        recommendation="建立 DKIM 密钥轮换机制，监控签名缺失与验证失败趋势。",
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
        content="DMARC 将 SPF 与 DKIM 的对齐结果统一成策略动作。推荐从 p=none 观察开始，逐步推进到 quarantine 与 reject，并通过 rua/ruf 报告识别未纳管发信源。粗暴直接 reject 容易造成业务中断，需按资产台账分批治理。",
        recommendation="执行分阶段 DMARC 策略并建立报告闭环，持续收敛未知发信源。",
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
        content="面对疑似钓鱼邮件，建议执行“四步流程”：停止交互、隔离终端、上报安全团队、协同取证复盘。流程化动作能避免员工自行处置导致证据污染或二次传播。该条目适合作为 SOC 与 IT 支持团队的联动作业基线。",
        recommendation="将四步流程固化为企业标准操作卡并定期演练。",
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
        content="钓鱼邮件是通过伪装可信身份、制造紧迫情绪或利益诱导，促使用户点击链接、打开附件或提交敏感信息的攻击方式。其核心不是技术漏洞，而是利用人的决策弱点，因此需要技术检测与安全意识双轨并行。",
        recommendation="用于培训与语义解释，不单独作为风险加权项。",
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
        content="鱼叉钓鱼是针对特定人员或团队定制内容的钓鱼方式，常引用真实项目和组织上下文，以提升可信度和成功率。相比广撒网邮件，它更隐蔽，也更依赖上下文识别能力。",
        recommendation="用于知识解释，结合联系人关系模型提升检测准确度。",
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
        content="BEC 指攻击者冒充高管或业务伙伴，利用邮件指令诱导财务转账或泄露敏感信息。其典型特征是弱技术痕迹、强流程绕过，因此需要组织流程控制与技术证据并行防护。",
        recommendation="用于培训与术语统一，不单独触发高风险。",
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
        content="Quishing 是把钓鱼链接编码成二维码并通过邮件等渠道分发的攻击形态。它能绕过纯文本 URL 检测并把风险转移到移动端，要求防守体系具备图片解析和跨端联动能力。",
        recommendation="用于术语解释，配合二维码检测能力建设。",
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
        content="PhaaS 指向攻击者提供模板、域名、托管与数据回传等能力的服务化生态。它显著降低攻击门槛，推动钓鱼活动规模化和自动化，防守侧需从单点 IOC 转向活动簇识别。",
        recommendation="用于术语与威胁情报研判，不作为单独拦截条件。",
        tags=["术语", "产业化攻击"],
        iocs=[],
        attack_techniques=[],
        detection_points=["定义性词条，用于解释与培训"],
        sample_email="",
        related_titles=["钓鱼工具包与PhaaS投递", "术语：钓鱼邮件（Phishing）"],
    ),
]


def get_connection() -> sqlite3.Connection:
    """获取数据库连接（使用 DELETE 日志模式避免 Windows WAL 锁定问题）"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    # Windows 环境下 WAL 模式容易因进程异常退出导致 readonly 锁定，改用 DELETE 模式
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """
    初始化数据库表结构

    创建 emails 表（存储待分析邮件）、
    reports 表（存储分析报告）和 kb_entries 表（知识库），
    并执行 KB 种子填充与知识库向量按需补齐。
    可安全重复调用（IF NOT EXISTS / 按 title 幂等）；
    嵌入服务不可用时向量补齐自动跳过，不影响主流程。
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
    finally:
        conn.close()

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
                    now,
                    title,
                ),
            )
            continue

        conn.execute(
            """
            INSERT INTO kb_entries
            (title, category, severity, keywords, content, recommendation, enabled, created_at, updated_at,
             summary, tags, iocs, attack_techniques, detection_points, sample_email, related)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )

    _refresh_related_links(conn)


def _iter_all_seed_entries() -> list[dict]:
    """返回内置种子 + 外部扩展包条目。"""
    entries = list(KB_SEED_ENTRIES)
    entries.extend(_load_kb_expansion_entries())
    return entries


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
                              detection_points, sample_email, related
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
                              detection_points, sample_email, related
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
