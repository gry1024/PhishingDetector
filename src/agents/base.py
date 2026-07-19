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

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        callback: EventCallback = None,
    ) -> dict:
        """
        调用 LLM 并解析 JSON 响应

        自动处理 JSON 解析失败的情况，
        推送流式思考过程到前端。
        """
        self.emit_thinking("正在调用 LLM 分析...", callback)

        raw = self.llm.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format="json",
        )

        # 推送原始 LLM 响应
        self.emit_thinking(raw, callback)

        # 解析 JSON
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # 尝试从 markdown 代码块提取
            if "```json" in raw:
                start = raw.index("```json") + 7
                end = raw.index("```", start)
                return json.loads(raw[start:end].strip())
            elif "```" in raw:
                start = raw.index("```") + 3
                end = raw.index("```", start)
                return json.loads(raw[start:end].strip())
            raise ValueError(f"LLM JSON 解析失败: {raw[:300]}")

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
