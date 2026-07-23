"""
数据模型定义
============
定义整个工作流中流转的数据结构，使用 Pydantic 确保类型安全。
这些模型是 LangGraph State 的组成部分。
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    """
    邮件输入模型
    支持两种输入方式：手动输入邮件文本 / 从数据库拉取已有邮件
    """
    subject: str = Field(default="", description="邮件主题")
    sender: str = Field(default="", description="发件人地址")
    recipients: str = Field(default="", description="收件人地址")
    body: str = Field(description="邮件正文内容")
    urls: list[str] = Field(default_factory=list, description="邮件中包含的URL列表")
    headers: dict = Field(default_factory=dict, description="邮件原始头部信息")
    has_attachment: bool = Field(default=False, description="是否包含附件")
    raw_text: str = Field(default="", description="原始完整邮件文本（用于直接粘贴场景）")


class SemanticResult(BaseModel):
    """语义意图分析 Agent 的输出"""
    intent: str = Field(description="识别到的邮件意图类别: phishing/legitimate/suspicious")
    persuasion_techniques: list[str] = Field(
        default_factory=list,
        description="检测到的社会工程话术，如 urgency(紧急), authority(权威), fear(恐惧)"
    )
    explanation: str = Field(description="LLM 的分析推理过程")
    confidence: float = Field(default=0.0, description="置信度 0-1")


class DetectionResult(BaseModel):
    """多维关联检测 Agent 的输出"""
    sender_score: float = Field(default=0.5, description="发件人可信度 0-1")
    sender_analysis: str = Field(default="", description="发件人分析说明")
    url_score: float = Field(default=0.5, description="URL安全性评分 0-1，越低越危险")
    url_analysis: str = Field(default="", description="URL分析说明")
    url_reputation_score: float = Field(default=0.5, description="URL信誉评分 0-1，越低越危险")
    url_reputation_summary: str = Field(default="", description="URL信誉分析说明")
    attachment_score: float = Field(default=0.0, description="附件风险评分 0-1，越高越危险")
    attachment_summary: str = Field(default="", description="附件风险分析说明")
    behavior_score: float = Field(default=0.0, description="身份行为异常评分 0-1，越高越异常")
    behavior_summary: str = Field(default="", description="身份行为异常分析说明")
    content_flags: list[str] = Field(
        default_factory=list,
        description="内容标记列表，如 suspicious_link, brand_impersonation 等"
    )
    explanation: str = Field(default="", description="检测推理过程")


class RiskResult(BaseModel):
    """风险研判 Agent 的输出"""
    risk_score: float = Field(description="综合风险评分 0-100，越高越危险")
    risk_level: str = Field(description="风险等级: critical/high/medium/low/safe")
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK 技战术映射"
    )
    explanation: str = Field(description="研判推理过程")


class ResponseResult(BaseModel):
    """自主响应 Agent 的输出"""
    action: str = Field(description="处置动作: isolate/quarantine/alert/pass")
    alert_message: str = Field(default="", description="告警消息")
    trace_report: str = Field(default="", description="溯源分析摘要")
    recommendation: str = Field(default="", description="对用户的安全建议")


class EvidenceItem(BaseModel):
    """用于结构化汇总的证据对象。"""
    type: str = Field(description="证据类型，如 semantic / detection / header_validation / attachment / risk")
    source: str = Field(description="证据来源，例如 semantic_agent / detector_agent / header / attachment")
    weight: int = Field(default=0, description="归一化后的权重，范围 0-100")
    confidence: float = Field(default=0.0, description="该证据的置信度 0-1")
    reason: str = Field(default="", description="该证据导致风险升高的简要理由")


class AnalysisReport(BaseModel):
    """
    完整分析报告
    由工作流最终节点汇总各 Agent 结果生成
    """
    email_id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    email: EmailInput
    semantic: Optional[SemanticResult] = None
    detection: Optional[DetectionResult] = None
    risk: Optional[RiskResult] = None
    response: Optional[ResponseResult] = None
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    # 工作流执行日志（用于流式输出展示）
    workflow_log: list[str] = Field(default_factory=list)


class WorkflowState(BaseModel):
    """
    LangGraph 工作流状态模型
    ========================
    这是整个检测工作流的核心状态，每个 Agent 节点读取并更新对应的字段。
    LangGraph 通过此状态实现节点间的数据传递。
    """
    email: EmailInput
    semantic: Optional[SemanticResult] = None
    detection: Optional[DetectionResult] = None
    risk: Optional[RiskResult] = None
    response: Optional[ResponseResult] = None
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    workflow_log: list[str] = Field(default_factory=list)
    is_phishing: bool = False  # 最终判定结果

    class Config:
        arbitrary_types_allowed = True
