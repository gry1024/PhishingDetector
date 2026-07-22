"""
Agent 基类
===========
所有检测 Agent 的公共基类。

核心特性：
- 支持工具调用（tools），调用结果自动记录
- 支持流式回调（callback），实时推送思考过程到前端
- 统一的 JSON 解析和错误处理
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Callable, Optional

from src.llm import get_llm, LLMClient
from src.models import EmailInput
from src.tools import ToolResult


# 回调函数类型：接收事件字典
EventCallback = Callable[[dict], None]


class BaseAgent(ABC):
    """
    Agent 抽象基类

    属性:
        name: Agent 名称（中文，用于前端显示）
        icon: Agent 图标 emoji
        tools: 可用工具字典 {name: function}
    """

    name: str = "BaseAgent"
    icon: str = "🤖"
    tools: dict = {}

    def __init__(self):
        self.logger = logging.getLogger(f"agent.{self.name}")

    @property
    def llm(self) -> LLMClient:
        """获取全局 LLM 客户端"""
        return get_llm()

    def call_tool(self, tool_name: str, *args, callback: EventCallback = None) -> ToolResult:
        """
        调用工具函数并记录结果

        Args:
            tool_name: 工具名称（需在 self.tools 中注册）
            *args: 传给工具函数的参数
            callback: 事件回调，用于推送工具调用到前端

        Returns:
            ToolResult 工具执行结果
        """
        if tool_name not in self.tools:
            raise ValueError(f"工具 '{tool_name}' 不存在于 {self.name} 的工具集中")

        tool_fn = self.tools[tool_name]
        result = tool_fn(*args)

        # 推送工具调用事件到前端
        if callback:
            callback({
                "type": "tool_call",
                "data": {
                    "agent": self.name,
                    "tool": result.tool_name,
                    "input": result.input_summary,
                    "output": result.output,
                    "duration_ms": result.duration_ms,
                }
            })

        self.logger.info(f"工具调用: {result.tool_name} → {result.output[:100]}")
        return result

    def emit_thinking(self, text: str, callback: EventCallback = None):
        """推送思考过程到前端"""
        if callback:
            callback({
                "type": "thinking",
                "data": {"agent": self.name, "chunk": text}
            })

    def emit_llm_chunk(self, text: str, callback: EventCallback = None):
        """推送 LLM 流式输出的单个 token 到前端"""
        if callback:
            callback({
                "type": "llm_chunk",
                "data": {"agent": self.name, "chunk": text}
            })

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        callback: EventCallback = None,
    ) -> dict:
        """
        调用 LLM 并解析 JSON 响应（真实流式输出）

        使用 chat_stream() 获取逐 token 的实时输出：
        - <<<JSON>>> 分隔符之前的自然语言分析 → 实时推送到前端（真实逐字效果）
        - 分隔符之后的 JSON → 累积解析，不推送到前端

        这样 token 从 API 一个个返回，前端看到的是真正的逐字输出，
        而非全部拿到后再假装打字。后端自然阻塞到流结束才返回，
        下一个 agent 不会提前启动。
        """
        self.emit_thinking("⏳ 正在调用 LLM 深度分析...\n", callback)

        json_buffer = ""
        in_json = False
        delimiter = "<<<JSON>>>"
        # pending 缓存未发射的文本，防止分隔符被拆分到多个 token 中
        pending = ""

        try:
            for token in self.llm.chat_stream(system_prompt, user_prompt):
                if in_json:
                    json_buffer += token
                    continue

                pending += token

                if delimiter in pending:
                    # 检测到分隔符 — 发射之前的文本，切换到 JSON 模式
                    idx = pending.index(delimiter)
                    before = pending[:idx]
                    if before:
                        self.emit_llm_chunk(before, callback)
                    json_buffer = pending[idx + len(delimiter):]
                    in_json = True
                    pending = ""
                elif len(pending) > len(delimiter):
                    # 保留末尾 len(delimiter) 个字符防止分隔符被拆分
                    safe = pending[:-len(delimiter)]
                    if safe:
                        self.emit_llm_chunk(safe, callback)
                    pending = pending[-len(delimiter):]

            # 流结束后处理剩余 pending
            if not in_json:
                if delimiter in pending:
                    idx = pending.index(delimiter)
                    before = pending[:idx]
                    if before:
                        self.emit_llm_chunk(before, callback)
                    json_buffer = pending[idx + len(delimiter):]
                elif pending.strip().startswith("{"):
                    # 没有分隔符但输出看起来是 JSON — 不发射，直接解析
                    json_buffer = pending
                else:
                    # 没有分隔符，输出是纯文本 — 发射并尝试从全文提取 JSON
                    if pending:
                        self.emit_llm_chunk(pending, callback)
                    json_buffer = pending

        except Exception as e:
            # 流式失败 — 回退到同步模式
            self.logger.warning(f"LLM 流式调用失败: {e}，回退到同步模式")
            self.emit_thinking("⚠️ 流式不可用，切换同步模式...\n", callback)
            raw = self.llm.chat(system_prompt=system_prompt, user_prompt=user_prompt)
            if delimiter in raw:
                idx = raw.index(delimiter)
                text_part = raw[:idx]
                if text_part.strip():
                    self.emit_llm_chunk(text_part, callback)
                json_buffer = raw[idx + len(delimiter):]
            else:
                json_buffer = raw

        self.emit_thinking("✅ LLM 分析完成\n", callback)

        # 解析 JSON
        json_str = json_buffer.strip()
        # 去除可能的 markdown 代码围栏
        if json_str.startswith("```"):
            lines = json_str.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            json_str = "\n".join(lines).strip()

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # 尝试从 markdown 代码块提取
            if "```json" in json_str:
                start = json_str.index("```json") + 7
                end = json_str.index("```", start)
                return json.loads(json_str[start:end].strip())
            elif "```" in json_str:
                start = json_str.index("```") + 3
                end = json_str.index("```", start)
                return json.loads(json_str[start:end].strip())
            raise ValueError(f"LLM JSON 解析失败: {json_str[:300]}")

    def _extract_analysis_text(self, result: dict) -> str:
        """从 LLM 返回的 JSON 中提取可读的分析说明文本，去除结构化代码。"""
        text_fields = []

        # 常见分析说明字段
        for key in ("explanation", "sender_analysis", "url_analysis",
                     "alert_message", "trace_report", "recommendation"):
            val = result.get(key, "")
            if val and isinstance(val, str) and len(val) > 5:
                # 跳过纯数字或短标签
                text_fields.append(val)

        if not text_fields:
            return ""

        # 用换行分隔多个字段
        return "\n\n".join(text_fields)

    @abstractmethod
    def analyze(self, email: EmailInput, callback: EventCallback = None, **kwargs) -> dict:
        """
        分析邮件，返回结果字典

        Args:
            email: 待分析邮件
            callback: 事件回调函数

        Returns:
            分析结果字典，包含 agent 特定的输出字段
        """
        ...
