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
import re
from abc import ABC, abstractmethod
from typing import Callable, Optional

from src.llm import get_llm, is_llm_available, LLMClient, LLMUnavailableError
from src.models import EmailInput
from src.tools import ToolResult


# 回调函数类型：接收事件字典
EventCallback = Callable[[dict], None]


def _repair_truncated_json(raw: str) -> list[str]:
    """对被 max_tokens 截断的 JSON 构造机械修复候选（只截断与补全，不猜测内容）。

    候选 1：补全未闭合的字符串与括号（保留被截断的尾部字符串字段）；
    候选 2：截到根对象第一层最近一个完整字段边界（丢弃不完整尾字段）再补全。
    无法构造候选时返回空列表。
    """
    s = (raw or "").strip()
    start = s.find("{")
    if start < 0:
        return []
    s = s[start:]
    closers = {"{": "}", "[": "]"}

    def _scan(text: str):
        in_str = False
        escaped = False
        stack = []
        for ch in text:
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch in "{[":
                stack.append(ch)
            elif ch in "}]" and stack:
                stack.pop()
        return in_str, stack

    def _close(text: str, in_str: bool, stack: list) -> str:
        suffix = '"' if in_str else ""
        suffix += "".join(closers[c] for c in reversed(stack))
        return text + suffix

    candidates = []

    # 候选 1：直接补全未闭合结构
    in_str, stack = _scan(s)
    if in_str or stack:
        candidates.append(_close(s, in_str, stack))

    # 候选 2：截到根对象第一层最近一个完整字段（逗号）边界再补全
    in_str = False
    escaped = False
    depth = 0
    last_field_comma = -1
    for i, ch in enumerate(s):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == "," and depth == 1:
            last_field_comma = i
    if last_field_comma > 0:
        truncated = s[:last_field_comma]
        in_str2, stack2 = _scan(truncated)
        candidates.append(_close(truncated, in_str2, stack2))

    return candidates


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

    def emit_tool_finished(
        self,
        tool_name: str,
        input_summary: str,
        output: str,
        duration_ms: int,
        callback: EventCallback = None,
    ):
        """推送结构化工具完成事件（与 call_tool 的事件同构）。

        用于未注册进工具表的内部调用（如 KB 混合检索），
        让前端能以结构化方式感知这类关键子步骤。
        """
        if callback:
            callback({
                "type": "tool_call",
                "data": {
                    "agent": self.name,
                    "tool": tool_name,
                    "input": input_summary,
                    "output": output,
                    "duration_ms": duration_ms,
                }
            })

    def emit_thinking(self, text: str, callback: EventCallback = None):
        """推送思考过程到前端"""
        if callback:
            callback({
                "type": "thinking",
                "data": {"agent": self.name, "chunk": text}
            })

    def emit_sub_step(self, text: str, status: str = "running", callback: EventCallback = None):
        """推送 Agent 内部工作流子步骤到前端"""
        if callback:
            callback({
                "type": "sub_step",
                "data": {"agent": self.name, "text": text, "status": status}
            })

    def emit_llm_chunk(self, text: str, callback: EventCallback = None):
        """推送 LLM 流式输出的单个 token 到前端"""
        if callback:
            callback({
                "type": "llm_chunk",
                "data": {"agent": self.name, "chunk": text}
            })

    def emit_llm_fallback(self, error: Exception, callback: EventCallback = None) -> str:
        """推送规则兜底事件并返回兜底原因（结构化，供前端徽章与 strict 模式判定）。

        原因枚举：
        - unavailable: LLM 连接/鉴权/超时失败（真不可用）
        - parse_error: LLM 有响应但 JSON 解析最终失败
        """
        reason = "parse_error" if isinstance(error, ValueError) else "unavailable"
        if reason == "parse_error":
            message = "LLM 输出解析失败，已启用规则化研判"
        else:
            message = f"LLM 不可用（{type(error).__name__}），已启用规则化研判"
        if callback:
            callback({
                "type": "llm_fallback",
                "data": {"agent": self.name, "fallback_reason": reason, "message": message},
            })
        return reason

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
        - 模型未输出分隔符时 → 用全量文本走解析链（裸 JSON/围栏/内嵌对象均可被识别）

        这样 token 从 API 一个个返回，前端看到的是真正的逐字输出，
        而非全部拿到后再假装打字。后端自然阻塞到流结束才返回，
        下一个 agent 不会提前启动。
        """
        # 前置检查：LLM 未配置时直接抛出，跳过 stream→sync→fail 三步链
        if not is_llm_available():
            raise LLMUnavailableError("LLM 未配置 API Key，已跳过 LLM 分析")

        self.emit_thinking("⏳ 正在调用 LLM 深度分析...\n", callback)

        json_buffer = ""
        # 全量输出累积：模型未输出分隔符时用全文走解析链，
        # 否则 json_buffer 只剩 pending 末尾几个字符，必然解析失败误入规则兜底
        text_buffer = ""
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
                        text_buffer += before
                    json_buffer = pending[idx + len(delimiter):]
                    in_json = True
                    pending = ""
                elif len(pending) > len(delimiter):
                    # 保留末尾 len(delimiter) 个字符防止分隔符被拆分
                    safe = pending[:-len(delimiter)]
                    if safe:
                        self.emit_llm_chunk(safe, callback)
                        text_buffer += safe
                    pending = pending[-len(delimiter):]

            # 流结束后处理剩余 pending
            if not in_json:
                if delimiter in pending:
                    idx = pending.index(delimiter)
                    before = pending[:idx]
                    if before:
                        self.emit_llm_chunk(before, callback)
                    json_buffer = pending[idx + len(delimiter):]
                else:
                    # 模型未输出分隔符：全量文本（叙事+可能内嵌的 JSON）交给解析链
                    if pending:
                        self.emit_llm_chunk(pending, callback)
                    json_buffer = text_buffer + pending

        except Exception as e:
            err_text = str(e).lower()
            is_auth_error = (
                "401" in err_text
                or "authorized_error" in err_text
                or "invalid api key" in err_text
                or "未设置" in str(e)
                or "not set" in err_text
                or "not configured" in err_text
                or "llm unavailable" in err_text
            )

            if is_auth_error:
                # 鉴权失败时不要再次回退到同步调用，避免重复无效请求。
                self.logger.warning(f"LLM 鉴权失败，跳过同步重试: {e}")
                raise

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

        self.emit_thinking("📦 LLM 输出接收完成，正在解析结构化结果...\n", callback)

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

        def _try_parse(raw: str) -> dict:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            raise ValueError("LLM JSON 根对象不是 object")

        def _sanitize(raw: str) -> str:
            return (raw or "").replace("\ufeff", "").strip()

        def _remove_trailing_commas(raw: str) -> str:
            return re.sub(r",\s*([}\]])", r"\1", raw)

        def _extract_balanced_object(raw: str) -> str:
            """提取首个平衡的 JSON 对象片段，忽略对象外的噪声文本。"""
            start = raw.find("{")
            if start < 0:
                return ""
            depth = 0
            in_str = False
            escaped = False
            for i in range(start, len(raw)):
                ch = raw[i]
                if in_str:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return raw[start:i + 1]
            return ""

        def _attempt_parse(raw: str) -> dict:
            candidate = _sanitize(raw)
            variants = []

            # 原文与去尾逗号版本
            if candidate:
                variants.append(candidate)
                variants.append(_remove_trailing_commas(candidate))

            # 若存在对象外噪声，提取平衡对象后再试
            balanced = _extract_balanced_object(candidate)
            if balanced:
                variants.append(balanced)
                variants.append(_remove_trailing_commas(balanced))

            seen = set()
            for v in variants:
                if not v or v in seen:
                    continue
                seen.add(v)
                try:
                    return _try_parse(v)
                except Exception:
                    continue
            raise ValueError(f"LLM JSON 解析失败: {candidate[:300]}")

        # 1) 直接解析（含容错）
        try:
            parsed = _attempt_parse(json_str)
            self.emit_thinking("✅ LLM 结构化解析成功\n", callback)
            return parsed
        except Exception:
            pass

        # 2) 尝试从 markdown 代码块提取
        try:
            if "```json" in json_str:
                start = json_str.index("```json") + 7
                end = json_str.index("```", start)
                parsed = _attempt_parse(json_str[start:end])
                self.emit_thinking("✅ LLM 结构化解析成功\n", callback)
                return parsed
            if "```" in json_str:
                start = json_str.index("```") + 3
                end = json_str.index("```", start)
                parsed = _attempt_parse(json_str[start:end])
                self.emit_thinking("✅ LLM 结构化解析成功\n", callback)
                return parsed
        except Exception:
            pass

        # 3) 最后兜底：首个平衡对象提取
        try:
            balanced = _extract_balanced_object(json_str)
            if balanced:
                parsed = _attempt_parse(balanced)
                self.emit_thinking("✅ LLM 结构化解析成功\n", callback)
                return parsed
        except Exception:
            pass

        # 4) 截断修复：输出被 max_tokens 截断时的机械修复（不猜测内容）
        for repaired in _repair_truncated_json(json_str):
            try:
                parsed = _attempt_parse(repaired)
                self.emit_thinking("✅ LLM 结构化解析成功（截断修复）\n", callback)
                return parsed
            except Exception:
                continue

        # 全部失败：留痕（环节名 + 原始输出前 300 字符）后走规则兜底
        self.logger.warning(
            "LLM JSON 解析最终失败（环节: %s），原始输出前300字符: %s",
            self.name,
            json_str[:300],
        )
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
