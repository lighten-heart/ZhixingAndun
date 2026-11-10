"""Exact offsets from a pinned audit tokenizer, never provider token estimates."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "assets" / "tokenizer"


@lru_cache(maxsize=1)
def load_tokenizer():
    from tokenizers import Tokenizer
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    raw = (ROOT / "tokenizer.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
        raise ValueError("tokenizer hash mismatch")
    return Tokenizer.from_str(raw.decode()), manifest


def locate(content, start=0, end=None):
    end = len(content) if end is None else end
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= len(content):
        raise ValueError("invalid codepoint range")
    tokenizer, manifest = load_tokenizer()
    encoded = tokenizer.encode(content, add_special_tokens=False)
    # A full lossless round trip is required before exposing a verified mapping.
    if tokenizer.decode(encoded.ids, skip_special_tokens=False) != content:
        raise ValueError("tokenizer round trip does not preserve source")
    positions = [{"index": i, "id": identifier, "start": a, "end": b}
                 for i, (identifier, (a, b)) in enumerate(zip(encoded.ids, encoded.offsets)) if a < end and b > start]
    return {"tokenizer": manifest, "scope": "source_snapshot_audit_tokenizer",
            "provider_prompt_tokenization_verified": False, "offset_unit": "unicode_codepoint",
            "content_sha256": hashlib.sha256(content.encode()).hexdigest(), "token_count": len(encoded.ids),
            "verified_roundtrip": True, "range": {"start": start, "end": end}, "tokens": positions}
