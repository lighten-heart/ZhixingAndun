"""Receipt hook for an instrumented inference provider (not a cloud API proxy).

Call AFTER the provider has captured the actual input tensor and chat rendering.
Pass input_token_ids from the inference engine, never from an audit estimate.
The configured provider and guard share a dedicated >=32-character HMAC secret.
"""
import hashlib
import hmac
import json
import time


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def issue_receipt(*, request_record, rendered_prompt, actual_input_token_ids,
                  tokenizer_sha256, template_sha256, source_spans, key):
    if not isinstance(key, str) or len(key) < 32:
        raise ValueError("A dedicated provider receipt secret is required")
    if not isinstance(actual_input_token_ids, list) or not actual_input_token_ids or any(type(i) is not int or i < 0 for i in actual_input_token_ids):
        raise ValueError("Actual input tensor token IDs are required")
    body = {"schema": 1, "request_id": request_record["id"],
        **{name: request_record[name] for name in ("request_sha256", "nonce", "provider", "model")},
        "issued_at": time.time(), "rendered_prompt": rendered_prompt,
        "input_token_ids": actual_input_token_ids,
        "inference_input_sha256": hashlib.sha256(canonical(actual_input_token_ids)).hexdigest(),
        "tokenizer_sha256": tokenizer_sha256, "template_sha256": template_sha256,
        "source_spans": source_spans}
    return {**body, "signature": hmac.new(key.encode(), canonical(body), hashlib.sha256).hexdigest()}
