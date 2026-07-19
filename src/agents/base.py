"""
Agent 基类
===========
所有检测 Agent 的公共基类，提供统一的接口和日志记录。
每个 Agent 继承此基类并实现 analyze() 方法。
"""

import logging
from abc import ABC, abstractmethod

from src.llm import get_llm, LLMClient
from src.models import EmailInput


class BaseAgent(ABC):
    """
    Agent 抽象基类
    
    属性:
        name: Agent 名称，用于日志和流式输出标识
        llm: LLM 客户端实例
    
    子类需实现:
        analyze(email) -> dict: 分析邮件并返回结果字典
    """

    name: str = "BaseAgent"

    def __init__(self):
        self.logger = logging.getLogger(f"agent.{self.name}")

    @property
    def llm(self) -> LLMClient:
        """获取全局 LLM 客户端"""
        return get_llm()

    @abstractmethod
    def analyze(self, email: EmailInput) -> dict:
        """
        分析邮件输入，返回结果字典
        
        Args:
            email: 待分析的邮件数据
        
        Returns:
            分析结果字典，具体结构由各 Agent 定义
        """
        ...

    def log_step(self, message: str) -> str:
        """
        生成带 Agent 名称的日志消息
        
        同时记录到 logger 和返回格式化字符串，
        后者用于工作流日志的流式输出。
        """
        formatted = f"[{self.name}] {message}"
        self.logger.info(message)
        return formatted
