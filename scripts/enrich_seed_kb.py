"""
扩写 src/database.py 中的 KB_SEED_ENTRIES 短文条目（content < 200 字）。
策略：先找到每个 _kb(...) 调用块，再定位块内的 title / content / recommendation 字段；
逐块改写以避免前一个字段写错后导致后续字段失败。
数据来自 data/seed_enrich.json。
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_FILE = ROOT / "src" / "database.py"
DATA_FILE = ROOT / "data" / "seed_enrich.json"


def replace_in_file():
    enrich = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    src = DB_FILE.read_text(encoding="utf-8")

    # 找出每个 _kb(...) 的 span（按括号深度匹配）
    spans: list[tuple[int, int, str]] = []  # (title_start, end, title)
    i = 0
    while True:
        m = re.search(r'_kb\(\s*\n\s*title="(?P<t>[^"]+)"', src[i:])
        if not m:
            break
        title = m.group("t")
        # 找到这个 _kb( 之后到 ... ) 完整结束（按括号配平）
        start = i + m.start()  # _kb( 起点
        depth = 0
        j = start
        while j < len(src):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
                if depth == 0:
                    spans.append((start, j + 1, title))
                    break
            j += 1
        else:
            break
        i = j + 1

    if not spans:
        print("No _kb() entries found.")
        return

    print(f"Detected {len(spans)} _kb() blocks.")

    # 从后往前替换，避免索引漂移
    new_src = src
    n_content = 0
    n_reco = 0
    for start, end, title in reversed(spans):
        if title not in enrich:
            continue
        block = new_src[start:end]
        # 在 block 内替换 content
        pat_c = re.compile(r'(\n\s*content=")([^"]*)(")')
        def _rep_c(m, _new=enrich[title]["content"]):
            esc = _new.replace('"', '\\"')
            return f"{m.group(1)}{esc}{m.group(3)}"
        new_block, nc = pat_c.subn(_rep_c, block, count=1)
        n_content += nc
        # 在原 block 上替换 recommendation（基于 original block 以避免被改过的 block 干扰）
        pat_r = re.compile(r'(\n\s*recommendation=")([^"]*)(")')
        def _rep_r(m, _new=enrich[title]["recommendation"]):
            esc = _new.replace('"', '\\"')
            return f"{m.group(1)}{esc}{m.group(3)}"
        final_block, nr = pat_r.subn(_rep_r, new_block, count=1)
        n_reco += nr
        new_src = new_src[:start] + final_block + new_src[end:]

    if new_src != src:
        DB_FILE.write_text(new_src, encoding="utf-8")

    print(f"content replacements: {n_content}")
    print(f"recommendation replacements: {n_reco}")

    # 验证
    check_pat = re.compile(r'_kb\(\s*\n\s*title="([^"]+)"[^)]*?content="([^"]*)"', re.DOTALL)
    checked = check_pat.findall(new_src)
    short = [(t, len(c)) for t, c in checked if len(c) < 200]
    print(f"\nseed _kb() total: {len(checked)}; still < 200 chars: {len(short)}")
    for t, c in checked:
        marker = "OK" if len(c) >= 200 else "!!"
        print(f"  [{marker}] {len(c):5d} - {t}")


if __name__ == "__main__":
    replace_in_file()
