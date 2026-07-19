"""
数据集下载脚本
==============
从 HuggingFace 和 GitHub 获取钓鱼邮件数据集。
数据集不上传到 GitHub，仅存放在本地 data/ 目录。

使用方式：
    python scripts/download_datasets.py

数据来源（参考项目设计文档）：
    1. PhishFuzzer (GitHub) — 23,100 封 LLM 生成的钓鱼/垃圾/正常邮件
    2. HuggingFace 钓鱼邮件数据集 — 约 20 万封
"""

import os
import sys
import json
import logging
from pathlib import Path

# 将项目根目录加入 Python 路径
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import requests
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# 数据存放目录
RAW_DIR = ROOT_DIR / "data" / "raw"
PROCESSED_DIR = ROOT_DIR / "data" / "processed"
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def download_huggingface_dataset():
    """
    从 HuggingFace 下载钓鱼邮件数据集
    
    优先使用 cybersectony/PhishingEmailDetectionv2.0（20万封，质量较好），
    备选 drorrabin/phishing_emails-data（3万封，较轻量）。
    """
    logger.info("=" * 60)
    logger.info("开始下载 HuggingFace 钓鱼邮件数据集...")
    logger.info("=" * 60)

    try:
        from datasets import load_dataset
    except ImportError:
        logger.error("请先安装 datasets 库: pip install datasets")
        return

    # 数据集列表（按优先级排序）
    datasets_config = [
        {
            "name": "cybersectony/PhishingEmailDetectionv2.0",
            "desc": "PhishingEmailDetection v2.0 (约20万封)",
            "split": "train",
            "save_name": "hf_phishing_v2",
        },
        {
            "name": "drorrabin/phishing_emails-data",
            "desc": "Phishing Emails Data (约3万封)",
            "split": "train",
            "save_name": "hf_phishing_drorrabin",
        },
    ]

    for cfg in datasets_config:
        try:
            logger.info(f"下载: {cfg['desc']}")
            logger.info(f"  仓库: {cfg['name']}")

            ds = load_dataset(cfg["name"], split=cfg["split"])
            logger.info(f"  记录数: {len(ds)}")

            # 转换为 DataFrame 并保存
            df = pd.DataFrame(ds)
            save_path = RAW_DIR / f"{cfg['save_name']}.csv"
            df.to_csv(save_path, index=False)
            logger.info(f"  已保存到: {save_path}")

            # 同时保存一份精简的 JSON 格式（方便测试使用）
            sample = df.head(100)
            json_path = PROCESSED_DIR / f"{cfg['save_name']}_sample_100.json"
            sample.to_json(json_path, orient="records", force_ascii=False, indent=2)
            logger.info(f"  样本已保存到: {json_path}")

        except Exception as e:
            logger.warning(f"  下载失败: {e}")
            logger.info("  尝试下一个数据集...")


def download_phishfuzzer():
    """
    从 GitHub 下载 PhishFuzzer 数据集
    
    PhishFuzzer 是 2025 年发布的 LLM 生成钓鱼邮件数据集，
    包含 23,100 封三分类邮件（钓鱼/垃圾/正常），含 URL 和附件元数据。
    
    GitHub 仓库: https://github.com/josephdouglass/PhishFuzzer
    """
    logger.info("=" * 60)
    logger.info("开始下载 PhishFuzzer 数据集...")
    logger.info("=" * 60)

    # PhishFuzzer 数据 URL（GitHub raw 链接）
    # 注意：实际链接需要根据仓库结构调整
    urls = [
        {
            "url": "https://raw.githubusercontent.com/josephdouglass/PhishFuzzer/main/data/phishing_emails.csv",
            "name": "phishfuzzer_phishing.csv",
            "desc": "PhishFuzzer 钓鱼邮件",
        },
        {
            "url": "https://raw.githubusercontent.com/josephdouglass/PhishFuzzer/main/data/legitimate_emails.csv",
            "name": "phishfuzzer_legitimate.csv",
            "desc": "PhishFuzzer 正常邮件",
        },
        {
            "url": "https://raw.githubusercontent.com/josephdouglass/PhishFuzzer/main/data/spam_emails.csv",
            "name": "phishfuzzer_spam.csv",
            "desc": "PhishFuzzer 垃圾邮件",
        },
    ]

    for item in urls:
        try:
            logger.info(f"下载: {item['desc']}")
            save_path = RAW_DIR / item["name"]

            if save_path.exists():
                logger.info(f"  文件已存在，跳过: {save_path}")
                continue

            resp = requests.get(item["url"], stream=True, timeout=60)
            resp.raise_for_status()

            with open(save_path, "wb") as f:
                total = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
                    total += len(chunk)
            logger.info(f"  已下载 {total / 1024 / 1024:.1f} MB → {save_path}")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"  文件不存在 (404)，可能仓库路径已变更: {item['url']}")
                logger.info(f"  请手动从 GitHub 仓库下载: https://github.com/josephdouglass/PhishFuzzer")
            else:
                logger.warning(f"  下载失败: {e}")
        except Exception as e:
            logger.warning(f"  下载失败: {e}")


def process_datasets():
    """
    处理原始数据集，生成统一格式的训练数据
    
    统一格式：
    {
        "text": "邮件全文",
        "label": 0(正常) / 1(钓鱼),
        "source": "数据集来源",
        "metadata": {}
    }
    """
    logger.info("=" * 60)
    logger.info("处理数据集为统一格式...")
    logger.info("=" * 60)

    all_records = []

    # 处理 HuggingFace 数据集
    for csv_file in RAW_DIR.glob("hf_phishing_*.csv"):
        try:
            df = pd.read_csv(csv_file)
            logger.info(f"处理 {csv_file.name}: {len(df)} 条记录")

            # 尝试自动识别文本列和标签列
            text_col = None
            label_col = None
            for col in df.columns:
                if col.lower() in ("text", "email", "content", "body", "email_text"):
                    text_col = col
                if col.lower() in ("label", "is_phishing", "phishing", "class"):
                    label_col = col

            if text_col and label_col:
                for _, row in df.iterrows():
                    all_records.append({
                        "text": str(row[text_col]),
                        "label": int(row[label_col]),
                        "source": csv_file.stem,
                    })
                logger.info(f"  已提取 {len(df)} 条记录")
            else:
                logger.warning(f"  无法识别文本列和标签列，列名: {list(df.columns)}")
        except Exception as e:
            logger.warning(f"  处理失败: {e}")

    # 处理 PhishFuzzer 数据集
    for csv_file in RAW_DIR.glob("phishfuzzer_*.csv"):
        try:
            df = pd.read_csv(csv_file)
            logger.info(f"处理 {csv_file.name}: {len(df)} 条记录")

            # PhishFuzzer 格式推断
            text_col = None
            for col in df.columns:
                if col.lower() in ("text", "email", "content", "body"):
                    text_col = col
                    break

            if text_col:
                label = 1 if "phishing" in csv_file.name else 0
                for _, row in df.iterrows():
                    all_records.append({
                        "text": str(row[text_col]),
                        "label": label,
                        "source": csv_file.stem,
                    })
        except Exception as e:
            logger.warning(f"  处理失败: {e}")

    if all_records:
        # 保存统一格式数据集
        output_path = PROCESSED_DIR / "unified_dataset.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_records, f, ensure_ascii=False, indent=2)
        logger.info(f"统一数据集已保存: {output_path} ({len(all_records)} 条)")

        # 保存 CSV 格式
        df_unified = pd.DataFrame(all_records)
        csv_path = PROCESSED_DIR / "unified_dataset.csv"
        df_unified.to_csv(csv_path, index=False)
        logger.info(f"CSV 格式已保存: {csv_path}")
    else:
        logger.warning("未提取到任何记录，请先确保数据集已下载")


if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════╗
    ║   PhishingDetector 数据集下载工具               ║
    ║                                                  ║
    ║   1. 下载 HuggingFace 数据集                    ║
    ║   2. 下载 PhishFuzzer 数据集                    ║
    ║   3. 全部下载                                    ║
    ║   4. 仅处理已有数据集                            ║
    ╚══════════════════════════════════════════════════╝
    """)

    choice = input("请选择操作 [1/2/3/4] (默认3): ").strip() or "3"

    if choice in ("1", "3"):
        download_huggingface_dataset()
    if choice in ("2", "3"):
        download_phishfuzzer()
    if choice in ("1", "2", "3", "4"):
        process_datasets()

    logger.info("完成！")
