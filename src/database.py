"""
数据库层
========
基于 SQLite 的轻量存储，管理邮件输入和分析结果。
使用 sqlite3 标准库，无需额外 ORM 依赖。
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.config import settings

logger = logging.getLogger(__name__)

# 数据库文件路径
DB_PATH = Path(settings.data_dir).parent / "phishing_detector.db"


def get_connection() -> sqlite3.Connection:
    """获取数据库连接（启用 WAL 模式提升并发性能）"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """
    初始化数据库表结构
    
    创建 emails 表（存储待分析邮件）和
    reports 表（存储分析报告）。
    可安全重复调用（IF NOT EXISTS）。
    """
    conn = get_connection()
    try:
        conn.executescript("""
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
        """)
        conn.commit()
        logger.info(f"数据库初始化完成: {DB_PATH}")
    finally:
        conn.close()


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
