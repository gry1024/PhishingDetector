"""
FastAPI 路由
============
API 端点：
- POST /api/analyze/stream: 流式分析邮件（JSON Lines SSE）
- POST /api/analyze: 同步分析邮件
- GET  /api/emails: 历史邮件列表
- GET  /api/reports: 历史报告列表
- GET  /api/stats: 统计概览
"""

import json
import logging
from queue import Queue
from threading import Thread
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.models import EmailInput
from src.workflow.graph import run_analysis, AGENT_PIPELINE
from src import database as db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


class AnalyzeRequest(BaseModel):
    """邮件分析请求"""
    subject: str = ""
    sender: str = ""
    recipients: str = ""
    body: str = ""
    urls: list[str] = []
    headers: dict = {}
    has_attachment: bool = False
    raw_text: str = ""


@router.post("/analyze/stream")
async def analyze_stream(req: AnalyzeRequest):
    """
    流式分析邮件（JSON Lines 格式）

    每行一个 JSON 对象：{"type": "EVENT_TYPE", "data": {...}}

    事件类型：
    - agent_start: Agent 开始执行
    - thinking: Agent 思考过程（LLM 输出）
    - tool_call: 工具调用结果
    - agent_done: Agent 完成
    - complete: 全流程完成，附带完整报告
    - error: 执行出错
    """
    email = EmailInput(
        subject=req.subject,
        sender=req.sender,
        recipients=req.recipients,
        body=req.body or req.raw_text,
        urls=req.urls,
        headers=req.headers,
        has_attachment=req.has_attachment,
        raw_text=req.raw_text,
    )

    # 保存邮件到数据库
    email_id = db.save_email(email.model_dump())

    def event_generator() -> AsyncGenerator[str, None]:
        """在后台线程中运行分析，通过队列传递事件"""
        event_queue = Queue()

        def callback(event: dict):
            """Agent 回调：将事件放入队列"""
            event_queue.put(event)

        def run_in_thread():
            """后台线程：执行工作流"""
            try:
                report = run_analysis(email, callback=callback)
                # 保存报告
                if "error" not in report:
                    report["email_id"] = email_id
                    report_id = db.save_report(email_id, {
                        "is_phishing": report.get("is_phishing", False),
                        "risk_score": report.get("risk_score", 0),
                        "risk_level": report.get("risk_level", "unknown"),
                        "semantic_result": report.get("semantic", {}),
                        "detection_result": report.get("detection", {}),
                        "risk_result": report.get("risk", {}),
                        "response_result": report.get("response", {}),
                    })
            except Exception as e:
                event_queue.put({"type": "error", "data": {"message": str(e)}})
            finally:
                event_queue.put(None)  # 结束信号

        thread = Thread(target=run_in_thread, daemon=True)
        thread.start()

        # 从队列中读取事件并输出 JSON Lines
        while True:
            event = event_queue.get()
            if event is None:
                break
            yield json.dumps(event, ensure_ascii=False) + "\n"

    return StreamingResponse(
        event_generator(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/analyze")
async def analyze_sync(req: AnalyzeRequest):
    """同步分析邮件（等待全部完成后返回）"""
    email = EmailInput(
        subject=req.subject,
        sender=req.sender,
        recipients=req.recipients,
        body=req.body or req.raw_text,
        urls=req.urls,
        headers=req.headers,
        has_attachment=req.has_attachment,
        raw_text=req.raw_text,
    )

    email_id = db.save_email(email.model_dump())

    try:
        report = run_analysis(email)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if "error" in report:
        raise HTTPException(status_code=500, detail=report["error"])

    report_id = db.save_report(email_id, {
        "is_phishing": report.get("is_phishing", False),
        "risk_score": report.get("risk_score", 0),
        "risk_level": report.get("risk_level", "unknown"),
        "semantic_result": report.get("semantic", {}),
        "detection_result": report.get("detection", {}),
        "risk_result": report.get("risk", {}),
        "response_result": report.get("response", {}),
    })

    report["email_id"] = email_id
    report["report_id"] = report_id
    return report


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


@router.get("/pipeline")
async def get_pipeline():
    """获取工作流 Agent 列表（供前端渲染）"""
    return AGENT_PIPELINE
