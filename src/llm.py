"""
LLM 客户端模块
==============
封装 Minimax M3 API 调用，提供统一的 LLM 接口。
使用 OpenAI SDK 兼容模式，支持同步和流式调用。
"""

import json
import logging
from typing import Generator

from openai import OpenAI

from src.config import settings

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Minimax M3 LLM 客户端
    
    使用 OpenAI 兼容接口调用 Minimax API，
    封装同步调用和流式调用两种模式。
    """

    def __init__(self):
        """初始化 OpenAI 兼容客户端"""
        cfg = settings.llm
        if not cfg.api_key:
            raise ValueError(
                "MINIMAX_API_KEY 未设置，请在 .env 文件中配置。"
                "参考 .env.example"
            )
        self.client = OpenAI(
            api_key=cfg.api_key,
            base_url=cfg.base_url,
        )
        self.model = cfg.model
        self.temperature = cfg.temperature
        self.max_tokens = cfg.max_tokens

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float | None = None,
        response_format: str = "text",
    ) -> str:
        """
        同步 LLM 调用
        
        Args:
            system_prompt: 系统提示词，定义 Agent 角色和行为
            user_prompt: 用户输入，即待分析的邮件内容
            temperature: 温度参数，覆盖默认值
            response_format: 响应格式，"json" 时要求 JSON 输出
        
        Returns:
            LLM 生成的文本响应
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature or self.temperature,
            "max_tokens": self.max_tokens,
        }

        # 请求 JSON 格式输出时添加 response_format
        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self.client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content
            logger.debug(f"LLM 响应: {content[:200]}...")
            return content
        except Exception as e:
            logger.error(f"LLM 调用失败: {e}")
            raise

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict:
        """
        LLM 调用并解析 JSON 响应
        
        在 prompt 中明确要求 JSON 输出，并解析返回结果。
        如果解析失败，尝试从文本中提取 JSON 块。
        """
        raw = self.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format="json",
        )
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # 尝试从 markdown 代码块中提取 JSON
            if "```json" in raw:
                start = raw.index("```json") + 7
                end = raw.index("```", start)
                return json.loads(raw[start:end].strip())
            elif "```" in raw:
                start = raw.index("```") + 3
                end = raw.index("```", start)
                return json.loads(raw[start:end].strip())
            raise ValueError(f"无法解析 LLM 返回的 JSON: {raw[:500]}")

    def chat_stream(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Generator[str, None, None]:
        """
        流式 LLM 调用
        
        逐 token 返回，用于 UI 实时展示分析过程。
        
        Yields:
            每个 chunk 的文本内容
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
            )
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"LLM 流式调用失败: {e}")
            raise


# 全局 LLM 客户端单例
llm_client = None


def get_llm() -> LLMClient:
    """获取全局 LLM 客户端实例（懒加载单例）"""
    global llm_client
    if llm_client is None:
        llm_client = LLMClient()
    return llm_client
