"""Trusted data records, verified transformations and purpose/recipient permissions."""
import base64
import hashlib
from fastapi import HTTPException


def content_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def transform(parents, operation, options):
    """Only program-produced outputs can claim exact derivation. No model rewrites."""
    spans = []
    if operation == "concat":
        result = ""
        for parent in parents:
            start = len(result)
            result += parent["content"]
            spans.append({"data_id": parent["id"], "version": parent["version"], "input_start": 0,
                          "input_end": len(parent["content"]), "output_start": start, "output_end": len(result), "mapping": "exact"})
    else:
        if len(parents) != 1:
            raise HTTPException(422, "此变换必须有且只有一个输入")
        parent = parents[0]
        text = parent["content"]
        start, end = 0, len(text)
        if operation == "slice":
            start, end = options.get("start"), options.get("end")
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
                raise HTTPException(422, "截取位置无效")
            result = text[start:end]
        elif operation == "copy":
            result = text
        elif operation == "base64":
            result = base64.b64encode(text.encode()).decode("ascii")
        else:
            raise HTTPException(422, "不支持或不可核验的变换")
        spans.append({"data_id": parent["id"], "version": parent["version"], "input_start": start,
                      "input_end": end, "output_start": 0, "output_end": len(result),
                      "mapping": "encoded_range" if operation == "base64" else "exact"})
    if not result or len(result) > 200000:
        raise HTTPException(422, "派生结果为空或超过限制")
    return result, spans


def intersect(parents, field):
    permitted = set(parents[0][field])
    for parent in parents[1:]:
        permitted.intersection_update(parent[field])
    return sorted(permitted)


def check_use(data, purpose, recipient):
    return purpose in data["allowed_purposes"] and recipient in data["allowed_recipients"]


def field_value(value, pointer):
    """RFC 6901 pointer into actual candidate arguments; no eval or dot ambiguity."""
    if not pointer.startswith("/"):
        raise ValueError("field must be a JSON pointer")
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            value = value[int(part)]
        else:
            value = value[part]
    return value
