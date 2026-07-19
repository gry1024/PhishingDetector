"""
Gradio Web UI
=============
提供简洁美观的检测界面，参考 TREEHOLE 项目的浅系设计风格。

功能：
- 手动输入邮件进行分析
- 从数据库拉取历史邮件重新分析
- 实时展示工作流执行过程（流式日志）
- 展示完整分析报告
"""

import json
import gradio as gr
import requests

from src.config import settings

# API 基地址
API_BASE = f"http://localhost:{settings.api.port}"


def analyze_email(
    raw_text: str,
    subject: str,
    sender: str,
    body: str,
) -> tuple[str, str, str]:
    """
    分析邮件并返回结果
    
    返回三元组：(工作流日志, 分析报告, 风险等级标签)
    使用 SSE 流式接口，实时获取 Agent 执行进度。
    """
    # 构造请求体
    payload = {
        "subject": subject,
        "sender": sender,
        "body": body or raw_text,
        "raw_text": raw_text,
    }

    # 收集流式日志
    logs = []
    final_result = None

    try:
        # 使用 SSE 流式接口
        resp = requests.post(
            f"{API_BASE}/api/analyze/stream",
            json=payload,
            stream=True,
            timeout=120,
        )
        resp.raise_for_status()

        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            if line.startswith("event: "):
                event_type = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
                if event_type == "agent_log":
                    logs.append(data.get("message", ""))
                elif event_type == "complete":
                    final_result = data
                elif event_type == "error":
                    logs.append(f"[错误] {data.get('message', '未知错误')}")

    except requests.exceptions.ConnectionError:
        logs.append("[错误] 无法连接到后端 API，请确认 FastAPI 服务已启动")
        return "\n".join(logs), "后端未启动", "❌ 连接失败"
    except Exception as e:
        logs.append(f"[错误] {str(e)}")
        return "\n".join(logs), f"分析失败: {str(e)}", "❌ 错误"

    if not final_result:
        return "\n".join(logs), "未获取到分析结果", "⚠️ 无结果"

    # 格式化分析报告
    report = _format_report(final_result)
    risk_level = final_result.get("risk_level", "unknown")
    is_phishing = final_result.get("is_phishing", False)

    # 风险等级标签
    level_labels = {
        "critical": "🔴 极高风险",
        "high": "🟠 高风险",
        "medium": "🟡 中风险",
        "low": "🔵 低风险",
        "safe": "🟢 安全",
    }
    label = level_labels.get(risk_level, "⚪ 未知")
    if is_phishing:
        label += " (钓鱼邮件)"

    return "\n".join(logs), report, label


def load_from_db(email_id: int):
    """从数据库加载邮件内容"""
    try:
        resp = requests.get(f"{API_BASE}/api/emails", timeout=10)
        emails = resp.json()
        for email in emails:
            if email["id"] == email_id:
                raw = email.get("raw_text", "") or email.get("body", "")
                return (
                    raw,
                    email.get("subject", ""),
                    email.get("sender", ""),
                    email.get("body", ""),
                )
    except Exception:
        pass
    return "", "", "", ""


def get_db_email_list():
    """获取数据库中的邮件列表供选择"""
    try:
        resp = requests.get(f"{API_BASE}/api/emails", params={"limit": 20}, timeout=10)
        emails = resp.json()
        choices = []
        for e in emails:
            label = f"#{e['id']} | {e.get('subject', '(无主题)')[:30]} | {e.get('sender', '')[:25]}"
            choices.append((label, e["id"]))
        return gr.update(choices=choices) if choices else gr.update(choices=[])
    except Exception:
        return gr.update(choices=[])


def _format_report(result: dict) -> str:
    """将分析结果格式化为可读报告"""
    lines = []

    # --- 风险概览 ---
    risk = result.get("risk_result", {})
    lines.append(f"## 风险评分: {risk.get('risk_score', 0)}/100")
    lines.append(f"**风险等级**: {risk.get('risk_level', 'unknown').upper()}")
    if risk.get("attack_techniques"):
        lines.append(f"**ATT&CK 映射**: {', '.join(risk['attack_techniques'])}")
    lines.append("")

    # --- 语义分析 ---
    semantic = result.get("semantic_result", {})
    if semantic:
        lines.append("### 语义意图分析")
        lines.append(f"- **意图**: {semantic.get('intent', 'N/A')}")
        lines.append(f"- **置信度**: {semantic.get('confidence', 0):.0%}")
        techniques = semantic.get("persuasion_techniques", [])
        if techniques:
            lines.append(f"- **社会工程话术**: {', '.join(techniques)}")
        lines.append(f"- **分析**: {semantic.get('explanation', '')}")
        lines.append("")

    # --- 多维检测 ---
    detection = result.get("detection_result", {})
    if detection:
        lines.append("### 多维关联检测")
        lines.append(f"- **发件人可信度**: {detection.get('sender_score', 0):.2f}")
        lines.append(f"- **URL安全评分**: {detection.get('url_score', 0):.2f}")
        flags = detection.get("content_flags", [])
        if flags:
            lines.append(f"- **内容标记**: {', '.join(flags)}")
        lines.append(f"- **分析**: {detection.get('explanation', '')}")
        lines.append("")

    # --- 风险研判 ---
    if risk.get("explanation"):
        lines.append("### 风险研判")
        lines.append(risk["explanation"])
        lines.append("")

    # --- 响应处置 ---
    response = result.get("response_result", {})
    if response:
        lines.append("### 处置建议")
        lines.append(f"- **动作**: {response.get('action', 'N/A')}")
        if response.get("alert_message"):
            lines.append(f"- **告警**: {response['alert_message']}")
        if response.get("recommendation"):
            lines.append(f"- **建议**: {response['recommendation']}")
        if response.get("trace_report"):
            lines.append(f"- **溯源**: {response['trace_report']}")

    return "\n".join(lines)


def create_ui() -> gr.Blocks:
    """
    创建 Gradio UI 界面
    
    设计参考 TREEHOLE 项目的浅系风格：
    - 浅色背景 (#F5F5F7)
    - 简洁排版
    - 无多余装饰
    """
    # TREEHOLE 风格自定义 CSS
    custom_css = """
    :root {
        --bg: #F5F5F7;
        --fg: #1D1D1F;
        --accent: #0071E3;
        --danger: #FF3B30;
        --success: #34C759;
    }
    .gradio-container {
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display",
                     "PingFang SC", "Noto Sans SC", sans-serif !important;
        background: var(--bg) !important;
        color: var(--fg) !important;
        max-width: 1100px !important;
        margin: 0 auto !important;
    }
    .gradio-container h1 {
        font-size: 28px;
        font-weight: 600;
        letter-spacing: -0.02em;
        color: var(--fg);
        margin-bottom: 4px;
    }
    .gradio-container h2 {
        font-size: 18px;
        font-weight: 600;
        letter-spacing: -0.01em;
    }
    .gradio-container .secondary {
        color: #6E6E73;
        font-size: 13px;
    }
    .workflow-log {
        font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
        font-size: 13px;
        line-height: 1.8;
        background: #FFFFFF;
        border: 1px solid #E8E8ED;
        border-radius: 6px;
        padding: 16px;
    }
    .report-output {
        background: #FFFFFF;
        border: 1px solid #E8E8ED;
        border-radius: 6px;
        padding: 20px;
    }
    .risk-label {
        font-size: 20px;
        font-weight: 600;
        text-align: center;
        padding: 12px;
        border-radius: 6px;
    }
    """

    with gr.Blocks(
        css=custom_css,
        title="PhishingDetector - AI钓鱼邮件检测",
        theme=gr.themes.Default(
            primary_hue="blue",
            neutral_hue="slate",
            font=[gr.themes.GoogleFont("Noto Sans SC"), "sans-serif"],
        ),
    ) as app:
        # 标题
        gr.Markdown("# PhishingDetector")
        gr.Markdown("AI 驱动的钓鱼邮件智能检测系统 — 多 Agent 协作工作流")

        with gr.Tabs():
            # ---- Tab 1: 邮件分析 ----
            with gr.Tab("邮件分析", id="analyze"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("### 输入邮件")
                        raw_input = gr.Textbox(
                            label="直接粘贴邮件内容",
                            placeholder="在此粘贴完整的邮件内容（包括头部、主题、正文）...",
                            lines=10,
                        )
                        with gr.Accordion("或填写结构化字段", open=False):
                            subject_input = gr.Textbox(label="主题", placeholder="邮件主题")
                            sender_input = gr.Textbox(label="发件人", placeholder="sender@example.com")
                            body_input = gr.Textbox(
                                label="正文",
                                placeholder="邮件正文内容...",
                                lines=6,
                            )
                        analyze_btn = gr.Button(
                            "开始分析",
                            variant="primary",
                            size="lg",
                        )

                    with gr.Column(scale=1):
                        gr.Markdown("### 分析结果")
                        risk_label = gr.Textbox(
                            label="风险等级",
                            interactive=False,
                            elem_classes=["risk-label"],
                        )
                        report_output = gr.Markdown(
                            value="*等待分析...*",
                            elem_classes=["report-output"],
                        )

                gr.Markdown("### 工作流执行日志")
                workflow_log = gr.Textbox(
                    label="实时日志",
                    interactive=False,
                    lines=12,
                    elem_classes=["workflow-log"],
                    show_copy_button=True,
                )

                # 绑定分析按钮
                analyze_btn.click(
                    fn=analyze_email,
                    inputs=[raw_input, subject_input, sender_input, body_input],
                    outputs=[workflow_log, report_output, risk_label],
                )

            # ---- Tab 2: 历史记录 ----
            with gr.Tab("历史记录", id="history"):
                gr.Markdown("### 从数据库加载历史邮件")
                with gr.Row():
                    email_selector = gr.Dropdown(
                        label="选择邮件",
                        choices=[],
                        interactive=True,
                        scale=3,
                    )
                    refresh_btn = gr.Button("刷新列表", scale=1)
                    load_btn = gr.Button("加载并分析", variant="primary", scale=1)

                history_raw = gr.Textbox(label="邮件内容", interactive=True, lines=8)
                history_subject = gr.Textbox(label="主题")
                history_sender = gr.Textbox(label="发件人")
                history_body = gr.Textbox(label="正文", lines=6)

                gr.Markdown("### 分析结果")
                history_log = gr.Textbox(
                    label="工作流日志",
                    interactive=False,
                    lines=8,
                    elem_classes=["workflow-log"],
                )
                history_report = gr.Markdown(elem_classes=["report-output"])
                history_risk = gr.Textbox(label="风险等级", interactive=False)

                # 绑定事件
                refresh_btn.click(fn=get_db_email_list, outputs=[email_selector])

                def on_select(email_id):
                    if email_id is not None:
                        return load_from_db(email_id)
                    return "", "", "", ""

                email_selector.change(
                    fn=on_select,
                    inputs=[email_selector],
                    outputs=[history_raw, history_subject, history_sender, history_body],
                )

                load_btn.click(
                    fn=analyze_email,
                    inputs=[history_raw, history_subject, history_sender, history_body],
                    outputs=[history_log, history_report, history_risk],
                )

    return app


def launch_ui(share: bool = False):
    """启动 Gradio UI 服务"""
    app = create_ui()
    app.launch(
        server_port=7860,
        share=share,
        show_error=True,
    )
