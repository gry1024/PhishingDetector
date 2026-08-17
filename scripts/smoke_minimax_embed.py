import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.llm import embed

vectors = embed(["smoke test for minimax embedding"], "query")
print(len(vectors))
print(len(vectors[0]))
