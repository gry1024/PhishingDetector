"""
全局配置模块
============
从 .env 文件和环境变量加载配置，使用 Pydantic 进行类型校验。
所有 API Key 和敏感信息通过环境变量管理，不硬编码。
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from pydantic import BaseModel

# 加载项目根目录的 .env 文件
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")


class LLMConfig(BaseModel):
    """LLM API 配置 — 通过 LLM_PROVIDER 切换 minimax / qwen"""
    provider: str = os.getenv("LLM_PROVIDER", "minimax")
    api_key: str = ""
    base_url: str = "https://api.minimax.chat/v1"
    model: str = "MiniMax-Text-01"
    temperature: float = 0.1  # 检测任务需要低温度保证一致性
    # 默认 4096：2048 曾被长解释字段顶满，JSON 尾部被截断导致解析失败误入规则兜底
    max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "4096"))

    def model_post_init(self, __context):
        if self.provider == "qwen":
            self.api_key = os.getenv("QWEN_API_KEY", "")
            self.base_url = os.getenv(
                "QWEN_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1",
            )
            self.model = os.getenv("QWEN_MODEL", "qwen-plus")
        else:
            self.api_key = os.getenv("MINIMAX_API_KEY", "")
            self.base_url = os.getenv("MINIMAX_BASE_URL", "https://api.minimax.chat/v1")
            self.model = os.getenv("MINIMAX_MODEL", "MiniMax-Text-01")


class APIConfig(BaseModel):
    """FastAPI 服务配置"""
    host: str = os.getenv("API_HOST", "0.0.0.0")
    port: int = int(os.getenv("API_PORT", "8000"))


class DatabaseConfig(BaseModel):
    """数据库配置"""
    url: str = os.getenv("DATABASE_URL", f"sqlite:///{ROOT_DIR}/phishing_detector.db")


class Settings(BaseModel):
    """应用全局配置"""
    llm: LLMConfig = LLMConfig()
    api: APIConfig = APIConfig()
    db: DatabaseConfig = DatabaseConfig()
    minimax_api_key: str = os.getenv("MINIMAX_API_KEY", "")
    minimax_base_url: str = os.getenv("MINIMAX_BASE_URL", "https://api.minimax.chat/v1")
    minimax_group_id: str = os.getenv("MINIMAX_GROUP_ID", "")
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "")
    embedding_dim: int = int(os.getenv("EMBEDDING_DIM", "1536"))
    data_dir: str = os.getenv("DATA_DIR", str(ROOT_DIR / "data"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


# 全局单例配置
settings = Settings()
