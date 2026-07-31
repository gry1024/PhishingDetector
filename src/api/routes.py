"""
FastAPI 路由 — Orchestrator 模式
=================================
API 端点：
- POST /api/analyze/stream: 流式分析邮件（JSON Lines SSE）
- POST /api/v2/runs/stream: SSE 流式分析（统一事件协议）
- POST /api/analyze: 同步分析邮件
- GET  /api/emails: 历史邮件列表
- GET  /api/reports: 历史报告列表
- GET  /api/stats: 统计概览
- GET  /api/health/llm: LLM 健康检查

事件协议 v2（Orchestrator 模式新增事件）：
- run_started: 运行开始
- orchestrator_start: 编排器启动
- orchestrator_thinking: 编排器思考叙事
- agent_call: 编排器调用子 Agent
- agent_result: 子 Agent 返回结果
- step_progress: 子 Agent 内部进度（thinking/sub_step/llm_chunk）
- tool_finished: 工具调用完成
- report: 最终报告
- orchestrator_done: 编排器完成
- run_finished: 运行完成
- run_failed: 运行失败
"""

import json
import logging
import uuid
import time
import csv
import io
import urllib.request
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

# GitHub 钓鱼邮件数据集配置（供前端示例/测试使用）
DATASET_SOURCES = {
    "sunny_phishing_benign": {
        "name": "Phishing & Benign Emails (JSONL)",
        "source": "SunnyThakur25/Phishing-Benign-Email-Dataset-Short-Version-",
        "url": "https://raw.githubusercontent.com/SunnyThakur25/Phishing-Benign-Email-Dataset-Short-Version-/main/phishing%20and%20benign%20email%20dataset.jsonl",
        "format": "jsonl",
        "fields": {"subject": "subject", "sender": "spoofed_sender", "body": "body", "label": "label"},
    },
    "rokibul_phishing": {
        "name": "Phishing Email Dataset (CSV)",
        "source": "rokibulroni/Phishing-Email-Dataset",
        "url": "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main/PhishingEmailData.csv",
        "format": "csv",
        "fields": {"subject": "Email_Subject", "sender": "Sender_Email", "body": "Email_Content", "label": "__default_phishing__"},
    },
}

_dataset_cache = {}


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

STEP_IDS = {
    "发件人画像分析": "sender_profiler",
    "邮件头取证分析": "header_forensics",
    "语义意图分析": "semantic",
    "威胁情报关联": "threat_intel",
    "多维关联检测": "detector",
    "风险研判": "risk",
    "响应处置": "response",
    "钓鱼检测编排器": "orchestrator",
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

    email_id = db.save_email(email.model_dump())

    def event_generator() -> AsyncGenerator[str, None]:
        event_queue = Queue()

        def callback(event: dict):
            event_queue.put(event)

        def run_in_thread():
            try:
                report = run_analysis(
                    email,
                    callback=callback,
                    selected_steps=req.selected_steps,
                    execution_mode=req.execution_mode,
                )
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
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/v2/runs/stream")
async def analyze_stream_v2(req: AnalyzeRequest):
    """统一事件协议的流式分析接口（SSE，Orchestrator 模式）。"""
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

    def event_generator() -> AsyncGenerator[str, None]:
        event_queue = Queue()
        # 当前活跃的子 Agent（用于 sub_step 等事件的归属）
        current_agent_key = {"value": None}
        current_agent_name = {"value": None}

        def emit_v2(event_obj: dict):
            event_queue.put({"type": event_obj.get("event", "message"), "data": event_obj})

        def callback(event: dict):
            source_type = event.get("type")
            source_data = event.get("data", {})

            # ---- Orchestrator 事件 ----
            if source_type == "orchestrator_start":
                emit_v2(_v2_event(
                    event_type="orchestrator_start",
                    run_id=run_id,
                    step_id="orchestrator",
                    step_name=source_data.get("agent", "编排器"),
                    status="running",
                    payload={"icon": source_data.get("icon", "🎯")},
                ))
                return

            if source_type == "orchestrator_thinking":
                message = source_data.get("chunk", "")
                if not message.strip():
                    return
                emit_v2(_v2_event(
                    event_type="orchestrator_thinking",
                    run_id=run_id,
                    step_id="orchestrator",
                    step_name="编排器",
                    status="running",
                    payload={"message": message},
                ))
                return

            if source_type == "orchestrator_done":
                emit_v2(_v2_event(
                    event_type="orchestrator_done",
                    run_id=run_id,
                    step_id="orchestrator",
                    step_name=source_data.get("agent", "编排器"),
                    status="done",
                    payload={
                        "is_phishing": source_data.get("is_phishing", False),
                        "risk_level": source_data.get("risk_level", "unknown"),
                        "risk_score": source_data.get("risk_score", 0),
                    },
                ))
                return

            # ---- 子 Agent 调用事件 ----
            if source_type == "agent_call":
                agent_key = source_data.get("agent_key", "unknown")
                current_agent_key["value"] = agent_key
                current_agent_name["value"] = source_data.get("agent_name", "unknown")
                emit_v2(_v2_event(
                    event_type="agent_call",
                    run_id=run_id,
                    step_id=agent_key,
                    step_name=source_data.get("agent_name", "unknown"),
                    status="running",
                    payload={
                        "agent_key": agent_key,
                        "agent_name": source_data.get("agent_name", ""),
                        "agent_icon": source_data.get("agent_icon", ""),
                        "agent_desc": source_data.get("agent_desc", ""),
                    },
                ))
                return

            if source_type == "agent_result":
                emit_v2(_v2_event(
                    event_type="agent_result",
                    run_id=run_id,
                    step_id=source_data.get("agent_key", current_agent_key["value"]),
                    step_name=source_data.get("agent_name", current_agent_name["value"]),
                    status="done",
                    payload={
                        "agent_key": source_data.get("agent_key", ""),
                        "agent_name": source_data.get("agent_name", ""),
                        "agent_icon": source_data.get("agent_icon", ""),
                        "result_summary": source_data.get("result_summary", {}),
                    },
                ))
                # 清除当前 Agent 标记
                current_agent_key["value"] = None
                current_agent_name["value"] = None
                return

            # ---- 报告事件 ----
            if source_type == "report":
                emit_v2(_v2_event(
                    event_type="report",
                    run_id=run_id,
                    step_id="orchestrator",
                    step_name="编排器",
                    status="done",
                    payload=source_data,
                ))
                return

            # ---- 子 Agent 内部事件（thinking/sub_step/llm_chunk/tool_call） ----
            if source_type == "agent_start":
                # 子 Agent 的 agent_start 事件：记录当前 Agent
                agent_name = source_data.get("agent", "unknown")
                step_id = STEP_IDS.get(agent_name, current_agent_key["value"] or "unknown")
                current_agent_key["value"] = step_id
                current_agent_name["value"] = agent_name
                emit_v2(_v2_event(
                    event_type="step_started",
                    run_id=run_id,
                    step_id=step_id,
                    step_name=agent_name,
                    status="running",
                    payload={
                        "index": source_data.get("index", -1),
                        "icon": source_data.get("icon", ""),
                    },
                ))
                return

            if source_type in {"thinking", "llm_chunk", "sub_step"}:
                message = source_data.get("chunk", "") or source_data.get("text", "")
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
                        step_id=current_agent_key["value"],
                        step_name=current_agent_name["value"],
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
                    step_id=current_agent_key["value"],
                    step_name=current_agent_name["value"],
                    status="running",
                    payload={
                        "channel": source_type,
                        "message": message,
                        "agent": source_data.get("agent", current_agent_name["value"]),
                        "sub_step_status": source_data.get("status", "running") if source_type == "sub_step" else None,
                    },
                ))
                return

            if source_type == "tool_call":
                emit_v2(_v2_event(
                    event_type="tool_finished",
                    run_id=run_id,
                    step_id=current_agent_key["value"],
                    step_name=current_agent_name["value"],
                    status="done",
                    payload={
                        "tool": source_data.get("tool", "unknown_tool"),
                        "input": source_data.get("input", ""),
                        "output": source_data.get("output", ""),
                        "duration_ms": source_data.get("duration_ms", 0),
                    },
                ))
                return

            if source_type == "data_flow":
                emit_v2(_v2_event(
                    event_type="data_flow",
                    run_id=run_id,
                    step_id=current_agent_key["value"],
                    step_name=current_agent_name["value"],
                    status="running",
                    payload={
                        "from": source_data.get("from", ""),
                        "to": source_data.get("to", ""),
                        "data": source_data.get("data", ""),
                    },
                ))
                return

            if source_type == "agent_done":
                step_name = source_data.get("agent", current_agent_name["value"])
                step_id = STEP_IDS.get(step_name, current_agent_key["value"] or "unknown")
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
                    step_id=current_agent_key["value"],
                    step_name=current_agent_name["value"],
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
                        "execution_mode": "orchestrator",
                    },
                ))

                report = run_analysis(
                    email,
                    callback=callback,
                    selected_steps=selected_steps,
                    execution_mode="serial",
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


@router.get("/datasets")
async def list_datasets():
    """列出可用的 GitHub 示例邮件数据集"""
    return [
        {"id": k, "name": v["name"], "source": v["source"], "format": v["format"]}
        for k, v in DATASET_SOURCES.items()
    ]


@router.get("/datasets/{dataset_id}")
async def get_dataset(dataset_id: str, q: str = "", label: str = "", limit: int = 50):
    """
    获取指定数据集的邮件样本。
    首次请求会从 GitHub raw 拉取并缓存；支持按主题/正文关键词搜索和标签筛选。
    """
    cfg = DATASET_SOURCES.get(dataset_id)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"未知数据集: {dataset_id}")

    cache_key = dataset_id
    if cache_key not in _dataset_cache:
        try:
            req = urllib.request.Request(
                cfg["url"],
                headers={"User-Agent": "PhishingDetector-Studio/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            logger.error(f"拉取数据集 {dataset_id} 失败: {e}")
            raise HTTPException(status_code=502, detail=f"无法从 GitHub 拉取数据集: {e}")

        items = []
        field_map = cfg["fields"]
        fmt = cfg["format"]

        if fmt == "jsonl":
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                items.append(_normalize_dataset_item(obj, field_map))
        elif fmt == "csv":
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                # CSV 列名常有前后空格，需要 strip
                stripped_row = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
                items.append(_normalize_dataset_item(stripped_row, field_map))

        _dataset_cache[cache_key] = items

    items = _dataset_cache[cache_key]

    if label:
        items = [it for it in items if (it.get("label") or "").lower() == label.lower()]

    if q:
        qlower = q.lower()
        items = [
            it for it in items
            if qlower in (it.get("subject") or "").lower()
            or qlower in (it.get("body") or "").lower()
        ]

    total = len(items)
    items = items[:limit]

    return {"dataset_id": dataset_id, "total": total, "limit": limit, "items": items}


def _normalize_dataset_item(obj: dict, field_map: dict) -> dict:
    """将不同数据集的字段统一为标准格式"""
    # 处理 label 字段：如果映射值以 __default_ 开头，直接使用默认值而非从数据中读取
    label_field = field_map.get("label", "label")
    if label_field.startswith("__default_"):
        label_value = label_field.replace("__default_", "").replace("__", "")
    else:
        label_value = str(obj.get(label_field, "") or "").strip().lower()

    # 处理 sender 字段：优先使用映射列名，如果没有则尝试常见变体
    sender_field = field_map.get("sender", "sender")
    sender_value = str(obj.get(sender_field, "") or "").strip()
    if not sender_value:
        # 尝试常见变体
        for alt in ["Sender_Email", "Sender_Name", "from", "spoofed_sender"]:
            alt_val = str(obj.get(alt, "") or "").strip()
            if alt_val:
                sender_value = alt_val
                break

    return {
        "id": obj.get("id", ""),
        "subject": str(obj.get(field_map.get("subject", "subject"), "") or "").strip(),
        "sender": sender_value,
        "body": str(obj.get(field_map.get("body", "body"), "") or "").strip(),
        "label": label_value,
        "intent": obj.get("intent", ""),
        "technique": obj.get("technique", ""),
        "target": obj.get("target", ""),
    }


@router.get("/pipeline")
async def get_pipeline():
    """获取工作流 Agent 列表（供前端渲染）"""
    return AGENT_PIPELINE


@router.get("/kb/entries")
async def list_kb_entries(limit: int = 50):
    """获取知识库条目列表"""
    return db.list_kb_entries(limit=limit)


@router.get("/kb/search")
async def search_kb(q: str, limit: int = 5):
    """关键词检索知识库条目"""
    query = (q or "").strip()
    if not query:
        return []
    return db.search_kb(query, limit=limit)


@router.get("/health/llm")
async def health_llm(request: Request, probe: bool = True):
    """环境自检：LLM 配置、可调用性"""
    llm_cfg = settings.llm
    api_key = llm_cfg.api_key or ""

    openapi_paths = set(request.app.openapi().get("paths", {}).keys())
    has_studio_page = "/studio" in openapi_paths
    has_v2_stream = "/api/v2/runs/stream" in openapi_paths

    service_signature = {
        "has_studio_page": has_studio_page,
        "has_v2_stream": has_v2_stream,
        "architecture": "orchestrator",
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
            "build": "orchestrator-v1",
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
