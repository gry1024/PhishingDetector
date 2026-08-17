"""
LLM 客户端模块
==============
统一的 LLM 调用接口，通过 LLM_PROVIDER 环境变量
在 Minimax / Qwen（通义千问）之间切换。
使用 OpenAI SDK 兼容模式，支持同步和流式调用。
"""

import contextvars
import json
import logging
from typing import Generator

from openai import OpenAI
import requests

from src.config import settings

logger = logging.getLogger(__name__)

# 显式 LLM 禁用开关（ContextVar，按线程/上下文隔离）：
# 批量评测等纯规则场景使用，不影响其他并发请求/线程的 LLM 可用性
_llm_disabled: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "llm_disabled", default=False
)


def set_llm_disabled(disabled: bool = True) -> contextvars.Token:
    """在当前上下文中显式禁用/恢复 LLM，返回 token 供 reset_llm_disabled 复位。"""
    return _llm_disabled.set(disabled)


def reset_llm_disabled(token: contextvars.Token) -> None:
    """按 token 复位 LLM 禁用状态。"""
    _llm_disabled.reset(token)


class LLMUnavailableError(RuntimeError):
    """LLM 服务不可用时的兜底异常类型。"""


class EmbeddingUnavailableError(RuntimeError):
    """知识库向量嵌入不可用时抛出。"""


class LLMClient:
    """
    LLM 客户端（支持 Minimax / 通义千问）

    通过 .env 中 LLM_PROVIDER 切换后端，
    使用 OpenAI 兼容接口统一调用。
    """

    def __init__(self):
        """初始化 OpenAI 兼容客户端"""
        cfg = settings.llm
        if not cfg.api_key:
            raise ValueError(
                f"LLM ({cfg.provider}) API Key 未设置，请在 .env 文件中配置。"
                "参考 .env.example"
            )
        self.client = OpenAI(
            api_key=cfg.api_key,
            base_url=cfg.base_url,
        )
        self.model = cfg.model
        self.temperature = cfg.temperature
        self.max_tokens = cfg.max_tokens
        self.persistent_error = False

    @staticmethod
    def _is_persistent_error(error: Exception) -> bool:
        """判断是否为不可恢复的错误（鉴权失败/额度用尽），避免重复无效重试。"""
        message = str(error).lower()
        # 鉴权类错误
        if (
            "401" in message
            or "authorized_error" in message
            or "invalid api key" in message
            or ("api key" in message and "invalid" in message)
        ):
            return True
        # 额度/配额类错误（429 rate_limit / quota exceeded）
        if (
            "429" in message
            or "rate_limit" in message
            or "quota" in message
            or "用量上限" in message
            or "额度" in message
            or "insufficient" in message
        ):
            return True
        return False

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
        if self.persistent_error:
            raise LLMUnavailableError("LLM 不可用（鉴权失败或额度用尽），已跳过重复调用。")

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

        # Qwen 支持原生 JSON 模式；Minimax 不支持，通过 prompt 要求 JSON

        try:
            response = self.client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content
            logger.debug(f"LLM 响应: {content[:200]}...")
            return content
        except Exception as e:
            if self._is_persistent_error(e):
                self.persistent_error = True
            logger.error(f"LLM 调用失败: {e}")
            raise LLMUnavailableError(str(e)) from e

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
        if self.persistent_error:
            raise LLMUnavailableError("LLM 不可用（鉴权失败或额度用尽），已跳过重复流式调用。")

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
            if self._is_persistent_error(e):
                self.persistent_error = True
            logger.error(f"LLM 流式调用失败: {e}")
            raise LLMUnavailableError(str(e)) from e


# 全局 LLM 客户端单例
llm_client = None
_llm_init_failed = False
_llm_init_error = ""


def get_llm() -> LLMClient:
    """获取全局 LLM 客户端实例（懒加载单例）

    首次初始化失败后会缓存失败状态，后续调用直接抛出，
    避免每个 Agent 都重复尝试构建客户端。
    """
    global llm_client, _llm_init_failed, _llm_init_error
    if _llm_init_failed:
        raise LLMUnavailableError(_llm_init_error)
    if llm_client is None:
        try:
            llm_client = LLMClient()
        except (ValueError, Exception) as e:
            _llm_init_failed = True
            _llm_init_error = str(e)
            raise LLMUnavailableError(str(e)) from e
    return llm_client


def is_llm_available() -> bool:
    """检查 LLM 是否可用（不抛异常）。"""
    if _llm_disabled.get():
        return False
    try:
        get_llm()
        return True
    except LLMUnavailableError:
        return False


def embed(texts: list[str], emb_type: str = "db") -> list[list[float]]:
    """调用 MiniMax 原生 embeddings 接口，返回向量列表。"""
    if not texts:
        return []

    if emb_type not in {"db", "query"}:
        raise EmbeddingUnavailableError(f"不支持的 embedding type: {emb_type}")

    if not settings.embedding_model:
        raise EmbeddingUnavailableError("EMBEDDING_MODEL 未配置")
    if not settings.minimax_group_id:
        raise EmbeddingUnavailableError("MINIMAX_GROUP_ID 未配置")
    if not settings.minimax_api_key:
        raise EmbeddingUnavailableError("MINIMAX_API_KEY 未配置")
    if not settings.minimax_base_url:
        raise EmbeddingUnavailableError("MINIMAX_BASE_URL 未配置")

    endpoint = settings.minimax_base_url.rstrip("/") + "/embeddings"
    payload = {
        "model": settings.embedding_model,
        "texts": texts,
        "type": emb_type,
    }
    headers = {
        "Authorization": f"Bearer {settings.minimax_api_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            endpoint,
            params={"GroupId": settings.minimax_group_id},
            json=payload,
            headers=headers,
            timeout=60,
        )
        response.raise_for_status()
        body = response.json()
    except requests.RequestException as exc:
        logger.error(f"Embedding 请求失败: {exc}")
        raise EmbeddingUnavailableError(str(exc)) from exc
    except ValueError as exc:
        logger.error(f"Embedding 响应解析失败: {exc}")
        raise EmbeddingUnavailableError("embedding 服务返回非 JSON 响应") from exc

    base_resp = body.get("base_resp") or {}
    status_code = base_resp.get("status_code")
    if status_code != 0:
        status_msg = base_resp.get("status_msg") or "embedding 服务业务失败"
        raise EmbeddingUnavailableError(str(status_msg))

    vectors_raw = body.get("vectors")
    if not isinstance(vectors_raw, list):
        raise EmbeddingUnavailableError("embedding 服务返回结构异常")

    vectors: list[list[float]] = []
    for vector_raw in vectors_raw:
        if not isinstance(vector_raw, list):
            raise EmbeddingUnavailableError("embedding 向量格式异常")
        try:
            vector = [float(value) for value in vector_raw]
        except (TypeError, ValueError) as exc:
            raise EmbeddingUnavailableError("embedding 向量格式异常") from exc
        if len(vector) != settings.embedding_dim:
            raise EmbeddingUnavailableError(
                f"embedding 维度异常: 期望 {settings.embedding_dim}，实际 {len(vector)}"
            )
        vectors.append(vector)

    if len(vectors) != len(texts):
        raise EmbeddingUnavailableError("embedding 返回向量数量与输入不一致")

    return vectors
