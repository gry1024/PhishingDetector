"""
FastAPI 应用实例
================
创建并配置 FastAPI 应用，挂载路由和中间件。
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router

app = FastAPI(
    title="PhishingDetector API",
    description="AI 驱动的钓鱼邮件智能检测系统 REST API",
    version="0.1.0",
)

# CORS 中间件：允许 Gradio UI 跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载路由
app.include_router(router)


@app.get("/")
async def root():
    """健康检查端点"""
    return {
        "service": "PhishingDetector API",
        "version": "0.1.0",
        "status": "running",
    }
