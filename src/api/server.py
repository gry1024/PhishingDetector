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
PAGES_DIR = STATIC_DIR / "pages"

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


NOCACHE = {"Cache-Control": "no-cache, no-store, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0"}


@app.get("/")
async def root():
    """首页：品牌封面页。"""
    return FileResponse(str(PAGES_DIR / "landing.html"), headers=NOCACHE)


@app.get("/landing")
async def landing_page():
    """Landing 页：封面与能力展示。"""
    return FileResponse(str(PAGES_DIR / "landing.html"), headers=NOCACHE)


@app.get("/studio")
async def studio_page():
    """Studio 页：可视化编排与运行状态演示页"""
    return FileResponse(str(PAGES_DIR / "studio.html"), headers=NOCACHE)
