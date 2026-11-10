"""Compute source digests for evaluation provenance checks."""
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(root=None):
    root = ROOT if root is None else root
    paths = []
    for name in ("backend", "adapters", "sandbox", "scripts", "frontend/src", "evals/promptfoo"):
        for directory, dirs, files in os.walk(root / name):
            dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__'}]
            paths.extend(Path(directory) / f for f in files if Path(f).suffix in {'.py', '.mjs', '.js', '.ts', '.tsx', '.json', '.css', '.yaml'})
    paths += [root / p for p in ("requirements.txt", "requirements.lock.txt", "evals/requirements.txt", "frontend/package.json", "frontend/package-lock.json", "Dockerfile", "sandbox/Dockerfile", "assets/tokenizer/manifest.json", "compose.infrastructure.yaml") if (root / p).is_file()]
    return {p.relative_to(root).as_posix(): sha(p.read_bytes()) for p in sorted(set(paths))}
