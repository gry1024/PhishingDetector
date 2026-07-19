"""
FastAPI 路由定义
================
提供 REST API 接口：
- POST /api/analyze: 分析邮件（支持 SSE 流式响应）
- GET  /api/emails: 获取历史邮件列表
- GET  /api/reports: 获取历史报告列表
- GET  /api/stats: 获取统计概览
"""

import json
import asyncio
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.workflow.graph import build_workflow
from src.models import EmailInput
from src import database as db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


class AnalyzeRequest(BaseModel):
    """邮件分析请求体"""
    subject: str = ""
    sender: str = ""
    recipients: str = ""
    body: str
    urls: list[str] = []
    headers: dict = {}
    has_attachment: bool = False
    raw_text: str = ""


class AnalyzeResponse(BaseModel):
    """邮件分析响应体"""
    email_id: int
    report_id: int
    is_phishing: bool
    risk_score: float
    risk_level: str
    semantic: dict
    detection: dict
    risk: dict
    response: dict
    workflow_log: list[str]


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(req: AnalyzeRequest):
    """
    分析邮件（同步模式）
    
    将邮件发送到 4-Agent 检测工作流，等待全部完成后返回完整报告。
    适用于需要一次性获取完整结果的场景。
    """
    # 构造邮件输入
    email = EmailInput(
        subject=req.subject,
        sender=req.sender,
        recipients=req.recipients,
        body=req.body,
        urls=req.urls,
        headers=req.headers,
        has_attachment=req.has_attachment,
        raw_text=req.raw_text,
    )

    # 保存到数据库
    email_id = db.save_email(email.model_dump())

    # 执行工作流
    graph = build_workflow()
    initial_state = {
        "email": email.model_dump(),
        "workflow_log": [],
    }

    try:
        result = graph.invoke(initial_state)
    except Exception as e:
        logger.error(f"工作流执行失败: {e}")
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")

    # 保存报告
    report_data = {
        "is_phishing": result.get("is_phishing", False),
        "risk_score": result.get("risk", {}).get("risk_score", 0),
        "risk_level": result.get("risk", {}).get("risk_level", "unknown"),
        "semantic_result": result.get("semantic", {}),
        "detection_result": result.get("detection", {}),
        "risk_result": result.get("risk", {}),
        "response_result": result.get("response", {}),
        "workflow_log": result.get("workflow_log", []),
    }
    report_id = db.save_report(email_id, report_data)

    return AnalyzeResponse(
        email_id=email_id,
        report_id=report_id,
        is_phishing=result.get("is_phishing", False),
        risk_score=result.get("risk", {}).get("risk_score", 0),
        risk_level=result.get("risk", {}).get("risk_level", "unknown"),
        semantic=result.get("semantic", {}),
        detection=result.get("detection", {}),
        risk=result.get("risk", {}),
        response=result.get("response", {}),
        workflow_log=result.get("workflow_log", []),
    )


@router.post("/analyze/stream")
async def analyze_email_stream(req: AnalyzeRequest):
    """
    分析邮件（SSE 流式模式）
    
    使用 Server-Sent Events 逐步返回每个 Agent 的执行结果，
    适用于 UI 实时展示工作流执行过程。
    
    事件类型：
    - agent_start: Agent 开始执行
    - agent_log: Agent 执行日志
    - agent_done: Agent 完成，附带结果
    - complete: 全部完成，附带最终报告
    - error: 执行出错
    """
    email = EmailInput(
        subject=req.subject,
        sender=req.sender,
        recipients=req.recipients,
        body=req.body,
        urls=req.urls,
        headers=req.headers,
        has_attachment=req.has_attachment,
        raw_text=req.raw_text,
    )
    email_id = db.save_email(email.model_dump())

    async def event_generator() -> AsyncGenerator[str, None]:
        """SSE 事件生成器"""
        graph = build_workflow()
        initial_state = {
            "email": email.model_dump(),
            "workflow_log": [],
        }

        try:
            # 使用 LangGraph stream 模式逐节点执行
            final_state = initial_state.copy()
            for chunk in graph.stream(initial_state, stream_mode="updates"):
                # chunk 是 {node_name: state_updates} 的字典
                for node_name, updates in chunk.items():
                    # 发送 Agent 开始事件
                    yield _sse_event("agent_start", {"node": node_name})
                    await asyncio.sleep(0)

                    # 发送日志事件
                    new_logs = updates.get("workflow_log", [])
                    for log_line in new_logs:
                        if log_line not in final_state.get("workflow_log", []):
                            yield _sse_event("agent_log", {
                                "node": node_name,
                                "message": log_line,
                            })
                    
                    # 更新最终状态
                    final_state.update(updates)

                    # 发送 Agent 完成事件
                    yield _sse_event("agent_done", {
                        "node": node_name,
                        "result": {k: v for k, v in updates.items() if k != "workflow_log"},
                    })

            # 保存报告
            report_data = {
                "is_phishing": final_state.get("is_phishing", False),
                "risk_score": final_state.get("risk", {}).get("risk_score", 0) if isinstance(final_state.get("risk"), dict) else 0,
                "risk_level": final_state.get("risk", {}).get("risk_level", "unknown") if isinstance(final_state.get("risk"), dict) else "unknown",
                "semantic_result": final_state.get("semantic", {}),
                "detection_result": final_state.get("detection", {}),
                "risk_result": final_state.get("risk", {}),
                "response_result": final_state.get("response", {}),
                "workflow_log": final_state.get("workflow_log", []),
            }
            report_id = db.save_report(email_id, report_data)

            # 发送完成事件
            yield _sse_event("complete", {
                "email_id": email_id,
                "report_id": report_id,
                **report_data,
            })

        except Exception as e:
            logger.error(f"流式分析失败: {e}")
            yield _sse_event("error", {"message": str(e)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/emails")
async def list_emails(limit: int = 50):
    """获取历史邮件列表"""
    return db.get_recent_emails(limit)


@router.get("/reports")
async def list_reports(limit: int = 50):
    """获取历史报告列表"""
    return db.get_recent_reports(limit)


@router.get("/stats")
async def get_stats():
    """获取统计概览"""
    return db.get_stats()


def _sse_event(event_type: str, data: dict) -> str:
    """格式化 SSE 事件"""
    return f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
