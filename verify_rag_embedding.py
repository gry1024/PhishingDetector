#!/usr/bin/env python3
"""
RAG 嵌入质量专项验收脚本
========================
放在项目根目录运行：python verify_rag_embedding.py [--clear-embeddings]

支持两种 provider：
- minimax：MiniMax 原生嵌入接口（embo-01，1536 维，
  POST {base_url}/embeddings?GroupId=xxx，body 用 texts + type=db/query）
- qwen：OpenAI 兼容接口（text-embedding-v3，1024 维，body 用 input）

做三件事：
1. 查库：kb_entries 里 embedding 的维度分布与 embedding_model 记录
2. 直连嵌入 API 探针：验证模型/密钥/端点真实可用，输出相似度余弦矩阵
3. 给出结论与修复指令

--clear-embeddings：清空库中全部 embedding（确认是假向量后使用）。
"""

import json
import math
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


# ---------- 配置读取 ----------

def load_config() -> dict:
    env = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    env.update({k: v for k, v in os.environ.items()})

    provider = env.get("LLM_PROVIDER", "minimax").lower()
    is_qwen = provider == "qwen"
    return {
        "provider": provider,
        "model": env.get("EMBEDDING_MODEL", ""),
        "api_key": env.get("EMBEDDING_API_KEY")
                   or (env.get("QWEN_API_KEY") if is_qwen else env.get("MINIMAX_API_KEY"))
                   or "",
        "base_url": env.get("EMBEDDING_BASE_URL")
                    or (env.get("QWEN_BASE_URL") if is_qwen else env.get("MINIMAX_BASE_URL"))
                    or ("https://dashscope.aliyuncs.com/compatible-mode/v1" if is_qwen
                        else "https://api.minimax.chat/v1"),
        "group_id": env.get("MINIMAX_GROUP_ID") or env.get("MINIMAX_GROUPID") or "",
        "expect_dim": int(env.get("EMBEDDING_DIM", "1536" if not is_qwen else "1024")),
        "db_path": (env.get("DATABASE_URL", "").replace("sqlite:///", "")
                    or str(ROOT / "phishing_detector.db")),
    }


# ---------- 第一步：查库 ----------

def check_database(db_path: str) -> dict:
    print("=" * 60)
    print("第一步：检查数据库中的 embedding")
    print("=" * 60)
    if not Path(db_path).exists():
        print(f"[跳过] 数据库文件不存在: {db_path}")
        return {"exists": False}

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(kb_entries)").fetchall()}
    print(f"kb_entries 列: {sorted(cols)}")

    result = {"exists": True, "has_model_col": "embedding_model" in cols}
    if "embedding" not in cols:
        print("[失败] 连 embedding 列都不存在 —— 第一步嵌入基建的迁移根本没有生效")
        conn.close()
        result.update({"total": 0, "with_emb": 0, "dims": [], "models": []})
        return result

    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM kb_entries WHERE enabled=1").fetchone()[0]
        with_emb = conn.execute(
            "SELECT COUNT(*) FROM kb_entries WHERE enabled=1 "
            "AND embedding IS NOT NULL AND embedding != ''").fetchone()[0]
        samples = conn.execute(
            "SELECT title, embedding FROM kb_entries WHERE enabled=1 "
            "AND embedding IS NOT NULL AND embedding != '' LIMIT 5").fetchall()
        models = ([m[0] for m in conn.execute(
            "SELECT DISTINCT embedding_model FROM kb_entries WHERE enabled=1"
        ).fetchall()] if result["has_model_col"] else "列不存在")
    except sqlite3.OperationalError as e:
        print(f"[失败] 读表出错: {e}")
        conn.close()
        result.update({"error": str(e), "total": 0, "with_emb": 0, "dims": [], "models": []})
        return result
    conn.close()

    dims = []
    for title, emb in samples:
        try:
            dims.append(len(json.loads(emb)))
        except (json.JSONDecodeError, TypeError):
            dims.append(-1)

    print(f"启用条目总数: {total}")
    print(f"含 embedding: {with_emb}")
    print(f"embedding_model 记录: {models}")
    print(f"抽样维度（前5条）: {dims}")
    result.update({"total": total, "with_emb": with_emb, "dims": dims,
                   "models": models})
    return result


# ---------- 第二步：API 探针 ----------

# A 模拟"检索查询"（改写措辞的钓鱼话术），B/C 模拟"被检索的知识库文本"
TEXT_QUERY = "您的账户需要重新认证，否则将被冻结"
TEXT_DB_RELATED = "凭证钓鱼：仿冒登录页骗取账号密码"
TEXT_DB_UNRELATED = "今天下午天气晴朗，适合出门散步"


def cosine(a: list, b: list) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def _post(url: str, headers: dict, payload: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def probe_minimax(cfg: dict) -> dict:
    """MiniMax 原生格式：texts + type=db/query，GroupId 在 URL 上。"""
    if not cfg["group_id"]:
        print("[未配置] MINIMAX_GROUP_ID 未设置")
        print("       在 MiniMax 开放平台用户中心 → 基本信息 里复制 GroupId，")
        print("       写入 .env：MINIMAX_GROUP_ID=你的组ID")
        return {"configured": True, "api_ok": False, "reason": "no_group_id"}

    url = cfg["base_url"].rstrip("/") + f"/embeddings?GroupId={cfg['group_id']}"
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {cfg['api_key']}"}
    print(f"endpoint={url.split('?')[0]}?GroupId={cfg['group_id'][:4]}***")

    try:
        # 知识库文本用 type=db，检索查询用 type=query（MiniMax 双塔算法要求）
        db_resp = _post(url, headers, {
            "model": cfg["model"],
            "texts": [TEXT_DB_RELATED, TEXT_DB_UNRELATED],
            "type": "db",
        })
        q_resp = _post(url, headers, {
            "model": cfg["model"],
            "texts": [TEXT_QUERY],
            "type": "query",
        })
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        print(f"[API 失败] HTTP {e.code}: {detail}")
        return {"configured": True, "api_ok": False, "reason": f"http_{e.code}"}
    except Exception as e:
        print(f"[API 失败] {type(e).__name__}: {e}")
        return {"configured": True, "api_ok": False, "reason": str(e)}

    for name, resp in (("db", db_resp), ("query", q_resp)):
        base_resp = resp.get("base_resp") or {}
        if base_resp.get("status_code", 0) != 0:
            print(f"[API 失败] {name} 调用返回错误: "
                  f"{base_resp.get('status_code')} {base_resp.get('status_msg')}")
            return {"configured": True, "api_ok": False,
                    "reason": f"status_{base_resp.get('status_code')}"}

    vec_related = db_resp["vectors"][0]
    vec_unrelated = db_resp["vectors"][1]
    vec_query = q_resp["vectors"][0]
    return {
        "configured": True, "api_ok": True,
        "dim": len(vec_query),
        "sim_ab": cosine(vec_query, vec_related),
        "sim_ac": cosine(vec_query, vec_unrelated),
    }


def probe_openai(cfg: dict) -> dict:
    """OpenAI 兼容格式（Qwen/DashScope）：input + data[].embedding。"""
    url = cfg["base_url"].rstrip("/") + "/embeddings"
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {cfg['api_key']}"}
    print(f"endpoint={url}")
    try:
        resp = _post(url, headers, {
            "model": cfg["model"],
            "input": [TEXT_QUERY, TEXT_DB_RELATED, TEXT_DB_UNRELATED],
        })
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        print(f"[API 失败] HTTP {e.code}: {detail}")
        return {"configured": True, "api_ok": False, "reason": f"http_{e.code}"}
    except Exception as e:
        print(f"[API 失败] {type(e).__name__}: {e}")
        return {"configured": True, "api_ok": False, "reason": str(e)}

    vectors = [d["embedding"] for d in resp.get("data", [])]
    if not vectors:
        print(f"[API 异常] 响应中没有 data 数组: {str(resp)[:300]}")
        return {"configured": True, "api_ok": False, "reason": "empty_data"}
    return {
        "configured": True, "api_ok": True,
        "dim": len(vectors[0]),
        "sim_ab": cosine(vectors[0], vectors[1]),
        "sim_ac": cosine(vectors[0], vectors[2]),
    }


def probe_api(cfg: dict) -> dict:
    print()
    print("=" * 60)
    print("第二步：直连嵌入 API 探针")
    print("=" * 60)
    if not cfg["model"]:
        print("[未配置] EMBEDDING_MODEL 未设置 —— 嵌入功能处于关闭状态")
        if cfg["provider"] == "minimax":
            print("       MiniMax 请配置：EMBEDDING_MODEL=embo-01")
        else:
            print("       Qwen 请配置：EMBEDDING_MODEL=text-embedding-v3")
        return {"configured": False}
    if not cfg["api_key"]:
        print("[未配置] 未找到 API Key")
        return {"configured": True, "api_ok": False, "reason": "no_api_key"}

    masked = cfg["api_key"][:6] + "***" if len(cfg["api_key"]) > 6 else "***"
    print(f"provider={cfg['provider']}  model={cfg['model']}  key={masked}")

    if cfg["provider"] == "minimax":
        info = probe_minimax(cfg)
    else:
        info = probe_openai(cfg)

    if info.get("api_ok"):
        print(f"返回维度: {info['dim']}（期望 {cfg['expect_dim']}）")
        print(f"余弦相似度  钓鱼查询↔凭证钓鱼条目: {info['sim_ab']:.3f}")
        print(f"余弦相似度  钓鱼查询↔无关天气文本: {info['sim_ac']:.3f}")
    return info


# ---------- 第三步：结论 ----------

def verdict(db: dict, api: dict, cfg: dict):
    print()
    print("=" * 60)
    print("结论")
    print("=" * 60)

    if db.get("exists") and not db.get("has_model_col"):
        print("[结构问题] kb_entries 缺 embedding_model 列 —— "
              "第一步迁移不完整，先让 Copilot 补迁移再谈验收。")

    if not api.get("configured"):
        print("状态：【未配置】嵌入功能关闭，系统运行在纯关键词模式。")
        print("行动：配置 EMBEDDING_MODEL（MiniMax 用 embo-01）后重跑本脚本。")
        return
    if not api.get("api_ok"):
        print("状态：【API 不通】嵌入服务调用失败，系统实际运行在关键词回退模式。")
        print("行动：按上方错误信息修复后，--clear-embeddings 并重启重算。")
        return

    dim_ok = api["dim"] >= 256
    dim_match = api["dim"] == cfg["expect_dim"]
    # 语义区分度判据（按 embo-01 实测标定）：相对分离 >= 0.2 且相关对 >= 0.4。
    # 标定依据：embo-01 实测 相关对 0.494 / 无关对 0.021（23 倍分离）；
    # 此前的 0.6 绝对阈值系按其他模型设定的经验值，不适用于本模型。
    sem_ok = api["sim_ab"] >= 0.4 and api["sim_ab"] - api["sim_ac"] >= 0.2
    print(f"API 维度 {api['dim']}：{'正常' if dim_ok else '异常（<256，疑似伪嵌入）'}"
          f"{'，与 EMBEDDING_DIM 一致' if dim_match else '，与 EMBEDDING_DIM=%d 不一致！' % cfg['expect_dim']}")
    print(f"语义区分度：{'正常' if sem_ok else '不足（相似对未显著高于无关对）'}")

    db_dims = set(db.get("dims", [])) if db.get("exists") else set()
    db_dim = db_dims.pop() if len(db_dims) == 1 else None
    if db.get("exists") and db.get("with_emb", 0) > 0:
        if db_dim is not None and db_dim != api["dim"]:
            print()
            print(f"状态：【假向量】库中 embedding 维度为 {db_dim}，"
                  f"与 API 真实维度 {api['dim']} 不一致。")
            print("行动：python verify_rag_embedding.py --clear-embeddings")
            print("      然后重启服务让 init_db 按正确配置重算，最后重跑本脚本确认。")
            return

    if dim_ok and dim_match and sem_ok:
        print()
        print("状态：【API 验收通过】嵌入服务真实可用且语义区分度正常。")
        if not db.get("exists") or db.get("with_emb", 0) == 0:
            print("下一步：重启服务让 init_db 生成真实向量，重跑本脚本确认维度一致。")
        else:
            print("下一步：跑混合检索冒烟——'我的账户需要重新认证否则冻结'")
            print("应命中凭证钓鱼条目，match_type 应为 semantic 或 hybrid。")
            print("此时才能宣称语义检索已验收。")
    else:
        print()
        print("状态：【配置待修】维度或语义区分度不达标，检查 EMBEDDING_DIM "
              "与实际模型是否匹配后重试。")


def clear_embeddings(db_path: str):
    conn = sqlite3.connect(db_path)
    n = conn.execute(
        "UPDATE kb_entries SET embedding='', embedding_model=''").rowcount
    conn.commit()
    conn.close()
    print(f"已清空 {n} 条 embedding。重启服务后 init_db 会自动重算。")


if __name__ == "__main__":
    cfg = load_config()
    if "--clear-embeddings" in sys.argv:
        clear_embeddings(cfg["db_path"])
        sys.exit(0)
    db_info = check_database(cfg["db_path"])
    api_info = probe_api(cfg)
    verdict(db_info, api_info, cfg)