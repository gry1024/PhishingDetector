"""
LangGraph 工作流定义
====================
使用 LangGraph 构建有向图状态机，编排 4 个 Agent 的执行顺序。

工作流拓扑：
    START → semantic_analysis → multi_detection → risk_assessment → response → END

每个节点是一个 Agent，读取并更新 WorkflowState。
支持流式输出每个节点的执行日志。
"""

from typing import TypedDict, Optional, Annotated
from langgraph.graph import StateGraph, START, END

from src.models import (
    EmailInput, SemanticResult, DetectionResult,
    RiskResult, ResponseResult,
)
from src.agents.semantic import SemanticAgent
from src.agents.detector import DetectorAgent
from src.agents.risk import RiskAgent
from src.agents.response import ResponseAgent


class PhishingState(TypedDict):
    """
    LangGraph 状态类型定义
    
    使用 TypedDict 而非 Pydantic，因为 LangGraph 原生支持 TypedDict 状态。
    每个节点函数接收此状态并返回需要更新的字段。
    """
    # 输入
    email: dict                  # EmailInput 的字典形式
    # Agent #1 输出
    semantic: Optional[dict]     # SemanticResult 的字典形式
    # Agent #2 输出
    detection: Optional[dict]    # DetectionResult 的字典形式
    # Agent #3 输出
    risk: Optional[dict]         # RiskResult 的字典形式
    # Agent #4 输出
    response: Optional[dict]     # ResponseResult 的字典形式
    # 流程控制
    is_phishing: bool            # 最终判定
    workflow_log: list[str]      # 全流程日志（用于流式输出）


# ---- Agent 实例（模块级单例） ----
_semantic_agent = SemanticAgent()
_detector_agent = DetectorAgent()
_risk_agent = RiskAgent()
_response_agent = ResponseAgent()


def semantic_node(state: PhishingState) -> dict:
    """
    节点 #1：语义意图分析
    
    读取邮件输入，调用语义分析 Agent，
    返回意图分析结果和流程日志。
    """
    email = EmailInput(**state["email"])
    result = _semantic_agent.analyze(email)
    return {
        "semantic": result["semantic"].model_dump(),
        "workflow_log": state.get("workflow_log", []) + result["workflow_log"],
    }


def detection_node(state: PhishingState) -> dict:
    """
    节点 #2：多维关联检测
    
    读取邮件输入和语义分析结果，
    执行规则扫描 + LLM 深度分析。
    """
    email = EmailInput(**state["email"])
    semantic = SemanticResult(**state["semantic"]) if state.get("semantic") else None
    result = _detector_agent.analyze(email, semantic_result=semantic)
    return {
        "detection": result["detection"].model_dump(),
        "workflow_log": state.get("workflow_log", []) + result["workflow_log"],
    }


def risk_node(state: PhishingState) -> dict:
    """
    节点 #3：风险研判
    
    综合语义分析和多维检测结果，
    进行最终风险评估。
    """
    email = EmailInput(**state["email"])
    semantic = SemanticResult(**state["semantic"])
    detection = DetectionResult(**state["detection"])
    result = _risk_agent.analyze(email, semantic, detection)
    return {
        "risk": result["risk"].model_dump(),
        "is_phishing": result["is_phishing"],
        "workflow_log": state.get("workflow_log", []) + result["workflow_log"],
    }


def response_node(state: PhishingState) -> dict:
    """
    节点 #4：自主响应
    
    根据风险等级决定处置动作，
    生成告警消息和溯源报告。
    """
    email = EmailInput(**state["email"])
    semantic = SemanticResult(**state["semantic"])
    detection = DetectionResult(**state["detection"])
    risk = RiskResult(**state["risk"])
    result = _response_agent.analyze(email, semantic, detection, risk)
    return {
        "response": result["response"].model_dump(),
        "workflow_log": state.get("workflow_log", []) + result["workflow_log"],
    }


def build_workflow() -> StateGraph:
    """
    构建并编译检测工作流图
    
    返回编译后的 LangGraph CompiledGraph 实例，
    可直接调用 invoke() 或 stream() 执行检测。
    
    使用方式:
        graph = build_workflow()
        result = graph.invoke({"email": email_dict})
        # 或流式执行
        for chunk in graph.stream({"email": email_dict}):
            print(chunk)
    """
    # 创建状态图
    graph = StateGraph(PhishingState)

    # 添加 4 个 Agent 节点
    graph.add_node("semantic_analysis", semantic_node)
    graph.add_node("multi_detection", detection_node)
    graph.add_node("risk_assessment", risk_node)
    graph.add_node("response", response_node)

    # 定义边：串行流水线
    graph.add_edge(START, "semantic_analysis")
    graph.add_edge("semantic_analysis", "multi_detection")
    graph.add_edge("multi_detection", "risk_assessment")
    graph.add_edge("risk_assessment", "response")
    graph.add_edge("response", END)

    # 编译图
    return graph.compile()
