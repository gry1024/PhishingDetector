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

    @property
    def api_key(self) -> str:
        if self.provider == "qwen":
            return os.getenv("QWEN_API_KEY", "")
        return os.getenv("MINIMAX_API_KEY", "")

    @property
    def base_url(self) -> str:
        if self.provider == "qwen":
            return os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        return os.getenv("MINIMAX_BASE_URL", "https://api.minimax.chat/v1")

    @property
    def model(self) -> str:
        if self.provider == "qwen":
            return os.getenv("QWEN_MODEL", "qwen-plus")
        return os.getenv("MINIMAX_MODEL", "MiniMax-Text-01")

    temperature: float = 0.1  # 检测任务需要低温度保证一致性
    max_tokens: int = 2048


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
    data_dir: str = os.getenv("DATA_DIR", str(ROOT_DIR / "data"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


# 全局单例配置
settings = Settings()
