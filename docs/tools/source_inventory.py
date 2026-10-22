#!/usr/bin/env python3
from pathlib import Path
import ast, hashlib
root = Path(__file__).resolve().parents[2]
for file in sorted((root / "app").rglob("*.py")):
    ast.parse(file.read_text(encoding="utf-8"))
    print(f"{file.relative_to(root)}: {len(file.read_text().splitlines())} lines")
print("Root:", root)
