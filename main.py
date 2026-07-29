"""
PhishingDetector 主入口
=======================
启动方式：
    python main.py          # 启动服务（API + UI）
    python main.py --test   # 运行测试样例
"""

import argparse
import logging
import uvicorn

from src.config import settings
from src.database import init_db


def setup_logging():
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(description="PhishingDetector")
    parser.add_argument("--test", action="store_true", help="运行测试样例")
    parser.add_argument("--port", type=int, default=settings.api.port, help="API端口")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("main")

    # 初始化数据库
    init_db()

    if args.test:
        from scripts.run_test import run_test
        run_test()
        return

    # 启动 FastAPI 服务
    logger.info(f"PhishingDetector 启动")
    logger.info(f"  API:  http://localhost:{args.port}")
    logger.info(f"  UI:   http://localhost:{args.port}/")
    logger.info(f"  Docs: http://localhost:{args.port}/docs")

    uvicorn.run(
        "src.api.server:app",
        host=settings.api.host,
        port=args.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
