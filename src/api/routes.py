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
import uuid
import time
from datetime import datetime, timezone
from queue import Queue
from threading import Thread
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.config import settings
from src.llm import get_llm
from src.models import EmailInput
from src.workflow.graph import run_analysis, AGENT_PIPELINE
from src import database as db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

STEP_IDS = {
    "语义意图分析": "semantic",
    "多维关联检测": "detector",
    "风险研判": "risk",
    "响应处置": "response",
}


def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _v2_event(
    event_type: str,
    run_id: str,
    step_id: str | None = None,
    step_name: str | None = None,
    status: str | None = None,
    payload: dict | None = None,
) -> dict:
    return {
        "event": event_type,
        "run_id": run_id,
        "step_id": step_id,
        "step_name": step_name,
        "status": status,
        "ts": _utc_ts(),
        "payload": payload or {},
    }


def _mask_key(raw_key: str) -> str:
    if not raw_key:
        return ""
    if len(raw_key) <= 12:
        return raw_key[:2] + "***"
    return f"{raw_key[:6]}***{raw_key[-6:]}"


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
    selected_steps: list[str] = []
    strict_llm: bool = True
    execution_mode: str = "serial"


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
                report = run_analysis(
                    email,
                    callback=callback,
                    selected_steps=req.selected_steps,
                    execution_mode=req.execution_mode,
                )
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

        # 从队列中读取事件并输出标准 SSE 格式
        while True:
            event = event_queue.get()
            if event is None:
                break
            event_type = event.get("type", "message")
            event_data = event.get("data", {})
            yield f"event: {event_type}\n"
            yield f"data: {json.dumps(event_data, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/v2/runs/stream")
async def analyze_stream_v2(req: AnalyzeRequest):
    """统一事件协议的流式分析接口（SSE）。"""
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
    run_id = str(uuid.uuid4())
    selected_steps = req.selected_steps or [item["id"] for item in AGENT_PIPELINE]
    strict_llm = req.strict_llm
    execution_mode = req.execution_mode

    def event_generator() -> AsyncGenerator[str, None]:
        event_queue = Queue()
        current_step_name = {"value": None}
        current_step_id = {"value": None}

        def emit_v2(event_obj: dict):
            event_queue.put({"type": event_obj.get("event", "message"), "data": event_obj})

        def callback(event: dict):
            source_type = event.get("type")
            source_data = event.get("data", {})

            if source_type == "agent_start":
                step_name = source_data.get("agent", "unknown")
                step_id = STEP_IDS.get(step_name, "unknown")
                current_step_name["value"] = step_name
                current_step_id["value"] = step_id
                emit_v2(_v2_event(
                    event_type="step_started",
                    run_id=run_id,
                    step_id=step_id,
                    step_name=step_name,
                    status="running",
                    payload={"index": source_data.get("index", -1), "icon": source_data.get("icon", "")},
                ))
                return

            if source_type in {"thinking", "llm_chunk"}:
                message = source_data.get("chunk", "")
                llm_failure_hints = (
                    "鉴权失败",
                    "invalid api key",
                    "authorized_error",
                    "401",
                    "timed out",
                    "connection",
                    "network",
                )
                if strict_llm and any(hint in message for hint in llm_failure_hints):
                    emit_v2(_v2_event(
                        event_type="llm_failed",
                        run_id=run_id,
                        step_id=current_step_id["value"],
                        step_name=current_step_name["value"],
                        status="failed",
                        payload={
                            "message": message.strip() or "LLM 调用失败",
                            "strict_llm": True,
                        },
                    ))
                    raise RuntimeError("strict_llm 模式下检测到 LLM 调用失败，已终止运行。")

                emit_v2(_v2_event(
                    event_type="step_progress",
                    run_id=run_id,
                    step_id=current_step_id["value"],
                    step_name=current_step_name["value"],
                    status="running",
                    payload={
                        "channel": source_type,
                        "message": message,
                        "agent": source_data.get("agent", current_step_name["value"]),
                    },
                ))
                return

            if source_type == "tool_call":
                emit_v2(_v2_event(
                    event_type="tool_finished",
                    run_id=run_id,
                    step_id=current_step_id["value"],
                    step_name=current_step_name["value"],
                    status="done",
                    payload={
                        "tool": source_data.get("tool", "unknown_tool"),
                        "input": source_data.get("input", ""),
                        "output": source_data.get("output", ""),
                        "duration_ms": source_data.get("duration_ms", 0),
                    },
                ))
                return

            if source_type == "agent_done":
                step_name = source_data.get("agent", current_step_name["value"])
                step_id = STEP_IDS.get(step_name, current_step_id["value"] or "unknown")
                emit_v2(_v2_event(
                    event_type="step_finished",
                    run_id=run_id,
                    step_id=step_id,
                    step_name=step_name,
                    status="done",
                    payload={"result": source_data.get("result", {})},
                ))
                return

            if source_type == "error":
                emit_v2(_v2_event(
                    event_type="run_failed",
                    run_id=run_id,
                    step_id=current_step_id["value"],
                    step_name=current_step_name["value"],
                    status="failed",
                    payload={"message": source_data.get("message", "unknown error")},
                ))

        def run_in_thread():
            try:
                emit_v2(_v2_event(
                    event_type="run_started",
                    run_id=run_id,
                    status="running",
                    payload={
                        "email_id": email_id,
                        "selected_steps": selected_steps,
                        "strict_llm": strict_llm,
                        "execution_mode": execution_mode,
                    },
                ))

                report = run_analysis(
                    email,
                    callback=callback,
                    selected_steps=selected_steps,
                    execution_mode=execution_mode,
                )
                if "error" not in report:
                    report_id = db.save_report(email_id, {
                        "is_phishing": report.get("is_phishing", False),
                        "risk_score": report.get("risk_score", 0),
                        "risk_level": report.get("risk_level", "unknown"),
                        "semantic_result": report.get("semantic", {}),
                        "detection_result": report.get("detection", {}),
                        "risk_result": report.get("risk", {}),
                        "response_result": report.get("response", {}),
                    })
                    emit_v2(_v2_event(
                        event_type="run_finished",
                        run_id=run_id,
                        status="done",
                        payload={
                            "email_id": email_id,
                            "report_id": report_id,
                            "result": report,
                        },
                    ))
                else:
                    emit_v2(_v2_event(
                        event_type="run_failed",
                        run_id=run_id,
                        status="failed",
                        payload={"message": report.get("error", "analysis failed")},
                    ))
            except Exception as e:
                emit_v2(_v2_event(
                    event_type="run_failed",
                    run_id=run_id,
                    status="failed",
                    payload={"message": str(e)},
                ))
            finally:
                event_queue.put(None)

        thread = Thread(target=run_in_thread, daemon=True)
        thread.start()

        while True:
            event = event_queue.get()
            if event is None:
                break
            event_type = event.get("type", "message")
            event_data = event.get("data", {})
            yield f"event: {event_type}\n"
            yield f"data: {json.dumps(event_data, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
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
        report = run_analysis(
            email,
            selected_steps=req.selected_steps,
            execution_mode=req.execution_mode,
        )
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


@router.get("/kb/entries")
async def list_kb_entries(limit: int = 50):
    """获取知识库条目列表（MVP 只读）。"""
    return db.list_kb_entries(limit=limit)


@router.get("/kb/search")
async def search_kb(q: str, limit: int = 5):
    """关键词检索知识库条目。"""
    query = (q or "").strip()
    if not query:
        return []
    return db.search_kb(query, limit=limit)


@router.get("/health/llm")
async def health_llm(request: Request, probe: bool = True):
    """环境自检：LLM 配置、可调用性、新版服务签名。"""
    llm_cfg = settings.llm
    api_key = llm_cfg.api_key or ""

    openapi_paths = set(request.app.openapi().get("paths", {}).keys())
    has_studio_page = "/studio" in openapi_paths
    has_v2_stream = "/api/v2/runs/stream" in openapi_paths
    has_legacy_analyze = "/analyze" in openapi_paths

    service_signature = {
        "has_studio_page": has_studio_page,
        "has_v2_stream": has_v2_stream,
        "legacy_analyze_removed": not has_legacy_analyze,
    }

    probe_result = {
        "attempted": False,
        "success": False,
        "latency_ms": None,
        "error_type": "",
        "error_message": "",
        "sample_response": "",
    }

    if probe and api_key:
        start = time.perf_counter()
        try:
            llm = get_llm()
            answer = llm.chat(
                system_prompt="You are a health checker.",
                user_prompt="Reply with OK only.",
                temperature=0,
            )
            latency = int((time.perf_counter() - start) * 1000)
            probe_result.update({
                "attempted": True,
                "success": True,
                "latency_ms": latency,
                "sample_response": (answer or "")[:80],
            })
        except Exception as e:
            latency = int((time.perf_counter() - start) * 1000)
            probe_result.update({
                "attempted": True,
                "success": False,
                "latency_ms": latency,
                "error_type": type(e).__name__,
                "error_message": str(e)[:240],
            })

    if not api_key:
        status = "fail"
    elif probe and not probe_result["success"]:
        status = "degraded"
    else:
        status = "ok"

    return {
        "status": status,
        "checked_at": _utc_ts(),
        "service": {
            "name": "PhishingDetector",
            "build": "kimi-style-demo-v2",
            "signature": service_signature,
        },
        "llm": {
            "provider": llm_cfg.provider,
            "base_url": llm_cfg.base_url,
            "model": llm_cfg.model,
            "api_key_present": bool(api_key),
            "api_key_length": len(api_key),
            "api_key_masked": _mask_key(api_key),
            "probe": probe_result,
        },
    }
