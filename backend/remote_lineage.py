"""Model request/source chains and an authenticated inference-receipt contract.

Opaque cloud providers stay unverified. A signed receipt is accepted only from
an explicitly configured provider, with the exact request nonce and input IDs.
It describes input provenance, never causal attribution of generated output.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from fastapi import HTTPException
from .token_mapping import load_tokenizer


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def hash_json(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strings(value, pointer=""):
    if isinstance(value, str):
        yield pointer, value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, pointer + "/" + str(index))
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(item, pointer + "/" + key.replace("~", "~0").replace("/", "~1"))


class RemoteLineage:
    def __init__(self, service):
        self.service = service

    def record(self, session_id, data):
        from .service import ident, now, digest
        service = self.service
        service.require("session", session_id)
        if len(canonical(data["request"])) > 500000:
            raise HTTPException(422, "模型请求快照超过 500 KB")
        if data["request"].get("provider") != data["provider"] or data["request"].get("model") != data["model"]:
            raise HTTPException(422, "请求与模型路由不一致")
        fields = list(strings(data["request"]))
        bindings, unmatched = [], []
        for sid in dict.fromkeys(data["source_ids"]):
            source = service.require("source", sid)
            if source["session_id"] != session_id or digest(source["content"]) != source["_content_hash"]:
                raise HTTPException(422, "来源会话或快照哈希不一致")
            candidates = [(source["content"], 0, len(source["content"]), "verified_exact_copy")]
            # Harness snapshots include JSON content blocks. Decode only strings
            # whose raw escape spans can be traced back to the immutable snapshot.
            try:
                from .excerpts import locate_excerpt
                decoded = json.loads(source["content"])
                if isinstance(decoded, (list, dict)):
                    for _, value in strings(decoded):
                        if len(value) < 8: continue
                        location = locate_excerpt(source["content"], value)
                        if location:
                            candidates.append((value, location[0], location[1], "verified_json_string_copy"))
            except ValueError:
                pass
            found, seen = False, set()
            for content, source_start, source_end, relation in candidates:
                for pointer, text in fields:
                    offset = text.find(content)
                    while offset >= 0:
                        marker = (pointer, offset, source_start, source_end)
                        if marker not in seen:
                            seen.add(marker)
                            found = True
                            bindings.append({"id": f"binding-{len(bindings)}", "source_id": sid, "version": source["version"],
                                "content_hash": source["_content_hash"], "pointer": pointer,
                                "field_start": offset, "field_end": offset + len(content),
                                "source_start": source_start, "source_end": source_end, "relation": relation})
                            if len(bindings) > 2000:
                                raise HTTPException(422, "来源映射数量超限")
                        offset = text.find(content, offset + len(content))
            if not found:
                unmatched.append(sid)
        record = {"id": ident("llm"), "session_id": session_id, "created_at": now(),
            "provider": data["provider"], "model": data["model"], "agent_id": data["agent_id"],
            "host_session_id": data.get("host_session_id", ""), "parent_agent_id": data.get("parent_agent_id"),
            "request_sha256": hash_json(data["request"]), "_request": data["request"],
            "nonce": secrets.token_hex(24), "bindings": bindings, "unmapped_source_ids": unmatched,
            "scope": "harness_pre_provider_request", "provider_prompt_tokenization_verified": False,
            "provider_receipt_status": "awaiting_provider_evidence", "created_epoch": time.time()}
        with service.store.transaction():
            service.store.put("model_request", record)
            service.event(session_id, "model.request_recorded", "登记实际宿主模型请求与已核验的来源复制关系", details={"request_id": record["id"], "agent_id": record["agent_id"], "request_sha256": record["request_sha256"]})
        return service.public_view(record)

    def complete(self, request_id, data):
        service = self.service
        with service.store.transaction():
            record = service.require("model_request", request_id)
            if record.get("completion"):
                if record["completion"] != data:
                    raise HTTPException(409, "同一请求的完成回执不可改写")
                return service.public_view(record)
            record["completion"] = data
            service.store.put("model_request", record)
            from .usage import record as record_usage
            record_usage(service.store, record['session_id'], 'usage_' + request_id,
                         {'provider': record['provider'], 'model': record['model']}, data.get('usage'),
                         phase='business_model', status='completed' if data.get('finish') else 'failed')
        return service.public_view(record)

    def accept_receipt(self, request_id, receipt):
        service = self.service
        record = service.require("model_request", request_id)
        keys = json.loads(os.getenv("GUARD_TOKEN_RECEIPT_KEYS", "{}"))
        key = keys.get(record["provider"])
        if not isinstance(key, str) or len(key) < 32:
            raise HTTPException(503, "该提供方未配置可信推理回执密钥，不能确认远端 token")
        try:
            signature = receipt["signature"]
            body = {k: v for k, v in receipt.items() if k != "signature"}
            expected = hmac.new(key.encode(), canonical(body), hashlib.sha256).hexdigest()
            if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
                raise ValueError("invalid signature")
            for field in ("provider", "model", "request_sha256", "nonce"):
                if body[field] != record[field]: raise ValueError("request mismatch")
            if body["request_id"] != request_id or body["schema"] != 1:
                raise ValueError("identity mismatch")
            if not record["created_epoch"] - 10 <= body["issued_at"] <= time.time() + 10 or time.time() - body["issued_at"] > 600:
                raise ValueError("expired receipt")
            tokenizer, manifest = load_tokenizer()
            if body["tokenizer_sha256"] != manifest["sha256"]:
                raise ValueError("unsupported tokenizer version")
            prompt, ids = body["rendered_prompt"], body["input_token_ids"]
            if not isinstance(prompt, str) or len(prompt) > 500000 or not isinstance(ids, list) or len(ids) > 200000:
                raise ValueError("invalid prompt size")
            if any(type(i) is not int or i < 0 for i in ids): raise ValueError("invalid token IDs")
            encoded = tokenizer.encode(prompt, add_special_tokens=False)
            if encoded.ids != ids or tokenizer.decode(ids, skip_special_tokens=False) != prompt:
                raise ValueError("input tokens do not reproduce prompt")
            if hash_json(ids) != body["inference_input_sha256"]:
                raise ValueError("inference tensor checksum mismatch")
            if not isinstance(body["template_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", body["template_sha256"]):
                raise ValueError("missing template identity")
            mappings = {item["id"]: item for item in record["bindings"]}
            supplied = set()
            spans = []
            request_fields = dict(strings(record["_request"]))
            for span in body["source_spans"]:
                binding = mappings[span["binding_id"]]
                start, end = span["prompt_start"], span["prompt_end"]
                if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(prompt):
                    raise ValueError("invalid prompt span")
                original = request_fields[binding["pointer"]][binding["field_start"]:binding["field_end"]]
                source = service.require("source", binding["source_id"])
                if source["version"] != binding["version"] or source["_content_hash"] != binding["content_hash"]:
                    raise ValueError("stale source")
                if prompt[start:end] != original or span["binding_id"] in supplied:
                    raise ValueError("unverified or duplicate source span")
                supplied.add(span["binding_id"])
                spans.append({**binding, "prompt_start": start, "prompt_end": end,
                    "token_indices": [i for i, (a, b) in enumerate(encoded.offsets) if a < end and b > start]})
            if supplied != set(mappings): raise ValueError("incomplete source mapping")
            proof = {"receipt_sha256": hash_json(receipt), "input_token_count": len(ids),
                "tokenizer_sha256": manifest["sha256"], "template_sha256": body["template_sha256"],
                "inference_input_sha256": body["inference_input_sha256"], "source_token_spans": spans,
                "trust_basis": "configured_provider_authenticated_receipt", "causal_output_attribution": False}
        except (ValueError, KeyError, TypeError, OverflowError):
            raise HTTPException(422, "推理回执签名、请求、版本、完整性或 token 映射核验失败")
        with service.store.transaction():
            current = service.require("model_request", request_id)
            if current.get("provider_proof"):
                raise HTTPException(409, "提供方回执已登记，禁止重放或改写")
            current.update(provider_prompt_tokenization_verified=True, provider_receipt_status="verified",
                provider_proof=proof, _provider_receipt=receipt)
            service.store.put("model_request", current)
        return service.public_view(current)
