import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database import DB_PATH, init_db, list_kb_entries, search_kb


def main() -> None:
    init_db()
    init_db()

    before_entries = list_kb_entries(500)
    before_count = len(before_entries)
    before_unique = len({item.get("title") for item in before_entries})
    required_fields_count = sum(
        1
        for item in before_entries
        if item.get("summary") and item.get("category") and item.get("keywords")
    )

    print("A_COUNT", before_count)
    print("A_UNIQ", before_unique)
    print("A_GE_30", before_count >= 30)
    print("A_REQUIRED_FIELDS", f"{required_fields_count}/{before_count}")

    query1 = search_kb("ip direct login page", limit=5)
    query2 = search_kb("m365 credential phishing", limit=5)
    print("Q1_TOP3", [item.get("title") for item in query1[:3]])
    print("Q2_TOP3", [item.get("title") for item in query2[:3]])

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    init_db()
    after_entries = list_kb_entries(500)
    after_count = len(after_entries)

    print("B_REBUILD_COUNT", after_count)
    print("B_MATCH", before_count == after_count)


if __name__ == "__main__":
    main()
