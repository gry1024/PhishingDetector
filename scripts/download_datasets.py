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
                if col.lower() in ("label", "is_phishing", "phishing", "class", "email_type", "type"):
                    label_col = col

            # 字符串标签到整数的映射（phishing=1, 正常=0）
            label_map = {
                "phishing": 1, "spam": 1, "1": 1, 1: 1, 1.0: 1, True: 1,
                "legitimate": 0, "ham": 0, "safe": 0, "normal": 0, "0": 0, 0: 0, 0.0: 0, False: 0,
            }

            if text_col and label_col:
                for _, row in df.iterrows():
                    raw_label = row[label_col]
                    # 统一转换为 0/1 整数
                    label_val = label_map.get(raw_label, label_map.get(str(raw_label).lower().strip(), 0))
                    all_records.append({
                        "text": str(row[text_col]),
                        "label": int(label_val),
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


# ============================================================
# 真实中文邮件数据集接入（批次 5：DataCon2023 钓鱼 + TREC06c ham）
# ============================================================
# 数据源（2026-08 实测可用镜像；官方 uwaterloo 下载页已 404，勿再尝试）：
# - TREC06c：CDN 镜像 https://cdn.aibydoing.com/aibydoing/files/trec06c.zip（95.9MB）
#   full/index 共 64,620 行：ham 21,766 / spam 42,854（与官方公布一致）
# - DataCon2023：PhishMMF 仓库 datacon2023_1/2.zip（GitHub，共约 26.6MB / 2998 条）
import random
import zipfile
from email.parser import BytesParser
from email.header import decode_header

TREC06C_ZIP_URL = "https://cdn.aibydoing.com/aibydoing/files/trec06c.zip"
DATACON2023_URLS = [
    "https://raw.githubusercontent.com/12345677876/PhishMMF/main/datacon2023_1.zip",
    "https://raw.githubusercontent.com/12345677876/PhishMMF/main/datacon2023_2.zip",
]
DATASETS_DIR = ROOT_DIR / "datasets"
TEST_SET_PATH = DATASETS_DIR / "test_set.jsonl"
# 固定随机种子：保证 test_set 抽样可复现（改动需同步留档说明）
TEST_SET_SEED = 20260818
TEST_SET_PHISHING_N = 200
TEST_SET_BENIGN_N = 200
BODY_MAX_CHARS = 2000


def _download_file(url: str, save_path: Path):
    """下载文件（已存在则跳过），返回路径。"""
    if save_path.exists():
        logger.info(f"  文件已存在，跳过: {save_path.name}")
        return save_path
    logger.info(f"  下载: {url}")
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()
    with open(save_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1024 * 1024):
            f.write(chunk)
    logger.info(f"  已保存 {save_path.stat().st_size / 1024 / 1024:.1f} MB → {save_path}")
    return save_path


def download_real_email_datasets():
    """下载并解压 DataCon2023 钓鱼邮件与 TREC06c 中文语料。"""
    logger.info("=" * 60)
    logger.info("下载真实中文邮件数据集（DataCon2023 + TREC06c）...")
    logger.info("=" * 60)

    trec_zip = _download_file(TREC06C_ZIP_URL, RAW_DIR / "trec06c.zip")
    with zipfile.ZipFile(trec_zip) as zf:
        zf.extractall(RAW_DIR / "trec06c")
    logger.info("  TREC06c 解压完成 → data/raw/trec06c/")

    for url in DATACON2023_URLS:
        zip_path = _download_file(url, RAW_DIR / Path(url).name)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(RAW_DIR)
    logger.info("  DataCon2023 解压完成 → data/raw/")


def _decode_header_str(raw: str) -> str:
    """解码 RFC822 编码头（=?gb2312?B?...?= 等），统一为可读文本。"""
    if not raw:
        return ""
    out = []
    for text, charset in decode_header(raw):
        if isinstance(text, bytes):
            for enc in (charset or "gb18030", "gb18030", "utf-8", "latin-1"):
                try:
                    out.append(text.decode(enc, errors="ignore"))
                    break
                except (LookupError, UnicodeDecodeError):
                    continue
        else:
            out.append(text)
    return "".join(out)


def _looks_like_text(text: str) -> bool:
    """启发式校验解码结果：控制字符/私用区占比过高即判定为错误解码。"""
    if not text:
        return False
    sample = text[:500]
    bad = sum(
        1 for ch in sample
        if (ord(ch) < 32 and ch not in "\r\n\t") or 0xE000 <= ord(ch) <= 0xF8FF
    )
    return bad / max(len(sample), 1) < 0.02


def _extract_text_body(msg) -> str:
    """提取 text/plain 正文（截断 BODY_MAX_CHARS）。

    兼容两类真实语料问题：
    - 头部声明与实际不符（如声明 base64 实为纯文本，TREC06c 中实测存在）：
      严格解码失败或校验为乱码时，回退使用原始 payload 字符串；
    - 中文多编码：依次尝试声明 charset / gb18030 / utf-8。
    """
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        raw_payload = part.get_payload(decode=False)
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            continue
        charset = part.get_content_charset() or "gb18030"
        payload_bytes = part.get_payload(decode=True)
        if payload_bytes:
            for enc in (charset, "gb18030", "utf-8"):
                try:
                    text = payload_bytes.decode(enc)  # 严格解码，错误编码会抛异常
                except (LookupError, UnicodeDecodeError):
                    continue
                if _looks_like_text(text):
                    return text.strip()[:BODY_MAX_CHARS]
        # CTE 声明与实际不符：直接使用原始 payload
        text = raw_payload.strip()
        if _looks_like_text(text):
            return text[:BODY_MAX_CHARS]
    # 终极兜底：multipart 边界损坏无法拆分子部件时（TREC06c 中实测存在），
    # 用最外层容器的原始 payload（报文头/体切分后的全部正文段）
    if parts:
        raw_payload = parts[0].get_payload(decode=False)
        if isinstance(raw_payload, str):
            text = raw_payload.strip()
            if _looks_like_text(text):
                return text[:BODY_MAX_CHARS]
    return ""


def parse_datacon2023_phishing() -> list[dict]:
    """解析 DataCon2023 jsonl → [{subject, sender, body, label: phishing}]。"""
    records = []
    for name in ("datacon2023_1.jsonl", "datacon2023_2.jsonl"):
        path = RAW_DIR / name
        if not path.exists():
            logger.warning(f"  缺少文件，跳过: {path}")
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                meta = rec.get("Metadata") or {}
                body_obj = rec.get("Body") or {}
                body = (body_obj.get("text") or "").strip()
                if not body:
                    body = ((body_obj.get("html") or {}).get("text") or "").strip()
                records.append({
                    "subject": (meta.get("Subject") or "").strip(),
                    "sender": (meta.get("From") or "").strip(),
                    "body": body[:BODY_MAX_CHARS],
                    "label": "phishing",
                })
    logger.info(f"DataCon2023 解析完成: {len(records)} 条钓鱼邮件")
    return records


def sample_trec06c_ham(n: int, seed: int) -> list[dict]:
    """从 TREC06c full/index 的 ham 部分按固定种子抽样 n 条并解析。

    红线：只取 ham 开头的行（label=benign）；spam 行一律跳过——
    垃圾邮件 ≠ 钓鱼邮件，混入会使评测指标失真。
    """
    root = RAW_DIR / "trec06c" / "trec06c"
    index_path = root / "full" / "index"
    ham_paths = []
    with open(index_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("ham "):
                ham_paths.append(line.split(None, 1)[1])
    logger.info(f"TREC06c ham 总数: {len(ham_paths)}（官方公布 21,766）")

    rng = random.Random(seed)
    rng.shuffle(ham_paths)
    picked = ham_paths[:n]

    records = []
    for rel in picked:
        # index 路径形如 ../data/NNN/MMM，相对于 full/ 目录
        email_path = root / "full" / rel
        if not email_path.exists():
            continue
        try:
            with open(email_path, "rb") as f:
                msg = BytesParser().parse(f)
            records.append({
                "subject": _decode_header_str(msg.get("Subject", "")).strip(),
                "sender": _decode_header_str(msg.get("From", "")).strip(),
                "body": _extract_text_body(msg),
                "label": "benign",
            })
        except Exception as exc:
            logger.warning(f"  解析失败跳过 {rel}: {exc}")
    logger.info(f"TREC06c ham 抽样完成: {len(records)}/{n} 条（种子 {seed}）")
    return records


def build_test_set():
    """生成 datasets/test_set.jsonl：phishing 200 + benign 200（固定种子）。"""
    logger.info("=" * 60)
    logger.info(f"生成 test_set（种子 {TEST_SET_SEED}）...")
    logger.info("=" * 60)

    phishing_pool = parse_datacon2023_phishing()
    benign_pool = sample_trec06c_ham(TEST_SET_BENIGN_N, TEST_SET_SEED)

    rng = random.Random(TEST_SET_SEED)
    rng.shuffle(phishing_pool)
    picked = phishing_pool[:TEST_SET_PHISHING_N] + benign_pool
    rng.shuffle(picked)

    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    with open(TEST_SET_PATH, "w", encoding="utf-8") as f:
        for rec in picked:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    n_phish = sum(1 for r in picked if r["label"] == "phishing")
    n_benign = sum(1 for r in picked if r["label"] == "benign")
    logger.info(
        f"test_set 已生成: {TEST_SET_PATH}（共 {len(picked)} 条："
        f"钓鱼 {n_phish} / 正常 {n_benign}，种子 {TEST_SET_SEED}）"
    )


if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════╗
    ║   PhishingDetector 数据集下载工具               ║
    ║                                                  ║
    ║   1. 下载 HuggingFace 数据集                    ║
    ║   2. 下载 PhishFuzzer 数据集                    ║
    ║   3. 全部下载                                    ║
    ║   4. 仅处理已有数据集                            ║
    ║   5. 真实中文邮件集（DataCon2023+TREC06c）       ║
    ║      并生成 datasets/test_set.jsonl              ║
    ╚══════════════════════════════════════════════════╝
    """)

    choice = input("请选择操作 [1/2/3/4/5] (默认3): ").strip() or "3"

    if choice == "5":
        download_real_email_datasets()
        build_test_set()
    else:
        if choice in ("1", "3"):
            download_huggingface_dataset()
        if choice in ("2", "3"):
            download_phishfuzzer()
        if choice in ("1", "2", "3", "4"):
            process_datasets()

    logger.info("完成！")
