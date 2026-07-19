"""
PhishingDetector 主入口
=======================
支持三种启动模式：
    1. API 模式：启动 FastAPI 后端服务
    2. UI 模式：启动 Gradio Web 界面
    3. 全栈模式：同时启动 API + UI（默认）

使用方式：
    python main.py              # 全栈模式
    python main.py --api        # 仅 API
    python main.py --ui         # 仅 UI
    python main.py --test       # 运行测试样例
"""

import sys
import argparse
import logging
import threading
import uvicorn

from src.config import settings
from src.database import init_db


def setup_logging():
    """配置全局日志"""
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def start_api():
    """启动 FastAPI 后端服务"""
    from src.api.server import app
    uvicorn.run(
        app,
        host=settings.api.host,
        port=settings.api.port,
        log_level=settings.log_level.lower(),
    )


def start_ui():
    """启动 Gradio Web UI"""
    from src.web.ui import launch_ui
    launch_ui()


def main():
    parser = argparse.ArgumentParser(description="PhishingDetector - AI钓鱼邮件检测系统")
    parser.add_argument("--api", action="store_true", help="仅启动 API 服务")
    parser.add_argument("--ui", action="store_true", help="仅启动 UI 服务")
    parser.add_argument("--test", action="store_true", help="运行测试样例")
    parser.add_argument("--share", action="store_true", help="UI 使用 Gradio share 链接")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("main")

    # 初始化数据库
    init_db()
    logger.info("数据库初始化完成")

    if args.test:
        # 运行测试
        from scripts.run_test import run_test
        run_test()
        return

    if args.api:
        # 仅 API 模式
        logger.info(f"启动 API 服务: http://{settings.api.host}:{settings.api.port}")
        start_api()
    elif args.ui:
        # 仅 UI 模式
        logger.info("启动 UI 服务 (需要 API 已运行)")
        start_ui()
    else:
        # 全栈模式：API 在后台线程运行，UI 在前台
        logger.info("全栈模式启动")
        logger.info(f"  API: http://localhost:{settings.api.port}")
        logger.info(f"  UI:  http://localhost:7860")

        # 后台启动 API
        api_thread = threading.Thread(target=start_api, daemon=True)
        api_thread.start()

        # 前台启动 UI（阻塞主线程）
        start_ui()


if __name__ == "__main__":
    main()
