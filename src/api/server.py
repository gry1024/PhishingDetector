"""
FastAPI 应用
============
创建 FastAPI 实例，挂载路由和静态文件服务。
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import router

# 静态文件目录
STATIC_DIR = Path(__file__).parent.parent / "static"

app = FastAPI(
    title="PhishingDetector API",
    description="AI 钓鱼邮件智能检测系统",
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API 路由
app.include_router(router)

# 静态文件
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    """首页：返回 UI 页面"""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"service": "PhishingDetector API", "version": "1.0.0", "status": "running"}
