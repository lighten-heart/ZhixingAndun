# AUTO-GENERATED: docs/testing-plans/evidence-completion.md, S3
import copy
import hashlib
import hmac
import json
import time
import pytest
from fastapi import HTTPException
from backend.service import GuardService
from backend.remote_lineage import RemoteLineage, canonical, hash_json
from backend.token_mapping import load_tokenizer

KEY = "receipt-contract-test-only-32-characters"


def sign(body):
    return {**body, "signature": hmac.new(KEY.encode(), canonical(body), hashlib.sha256).hexdigest()}


@pytest.fixture
def lineage(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARD_TOKEN_RECEIPT_KEYS", json.dumps({"controlled-test": KEY}))
    service = GuardService(tmp_path)
    session = service.create_session({"title": "token evidence", "intent": "Explain project", "scope": "read_only", "agent_id": "main"})
    source = service.add_source(session["id"], {"type": "document", "content": "公开材料🙂测试"})
    recorder = RemoteLineage(service)
    request = {"provider": "controlled-test", "model": "contract-test", "messages": [{"role": "user", "content": source["content"]}]}
    record = recorder.record(session["id"], {"provider": "controlled-test", "model": "contract-test", "agent_id": "main", "request": request, "source_ids": [source["id"]]})
    prompt = "user\n" + source["content"] + "\nassistant\n"
    tokenizer, manifest = load_tokenizer()
    ids = tokenizer.encode(prompt, add_special_tokens=False).ids
    body = {"schema": 1, "request_id": record["id"], "request_sha256": record["request_sha256"],
        "nonce": record["nonce"], "provider": "controlled-test", "model": "contract-test", "issued_at": time.time(),
        "rendered_prompt": prompt, "input_token_ids": ids, "inference_input_sha256": hash_json(ids),
        "tokenizer_sha256": manifest["sha256"], "template_sha256": "a" * 64,
        "source_spans": [{"binding_id": record["bindings"][0]["id"], "prompt_start": 5, "prompt_end": 5 + len(source["content"])}]}
    yield recorder, record, body
    service.store.close()


def test_authenticated_contract_not_a_live_provider_measurement(lineage):
    recorder, record, body = lineage
    result = recorder.accept_receipt(record["id"], sign(body))
    assert result["provider_prompt_tokenization_verified"] is True
    assert result["provider_proof"]["source_token_spans"][0]["token_indices"]
    assert "_provider_receipt" not in result
    with pytest.raises(HTTPException) as error:
        recorder.accept_receipt(record["id"], sign(body))
    assert error.value.status_code == 409


@pytest.mark.parametrize("field", ["request_id", "request_sha256", "nonce", "provider", "model", "tokenizer_sha256", "inference_input_sha256", "input_token_ids", "source_spans", "issued_at", "signature"])
def test_tampered_receipt_rejected(lineage, field):
    recorder, record, body = lineage
    changed = copy.deepcopy(body)
    if field == "input_token_ids": changed[field][0] += 1
    elif field == "source_spans": changed[field] = []
    elif field == "issued_at": changed[field] = 1
    elif field != "signature": changed[field] = "tampered"
    receipt = sign(changed)
    if field == "signature": receipt[field] = "b" * 64
    with pytest.raises(HTTPException) as error:
        recorder.accept_receipt(record["id"], receipt)
    assert error.value.status_code == 422
    assert recorder.service.require("model_request", record["id"])["provider_prompt_tokenization_verified"] is False


def test_missing_provider_evidence_stays_unverified(lineage, monkeypatch):
    recorder, record, body = lineage
    monkeypatch.delenv("GUARD_TOKEN_RECEIPT_KEYS")
    with pytest.raises(HTTPException) as error:
        recorder.accept_receipt(record["id"], sign(body))
    assert error.value.status_code == 503


def test_json_source_exact_decode_mapping(lineage):
    recorder, record, _ = lineage
    text = '中文🙂 with "quoted" value\nand newline'
    source = recorder.service.add_source(record["session_id"], {"type": "document", "content": json.dumps([{"type": "text", "text": text}])})
    request = {"provider": "controlled-test", "model": "contract-test", "messages": [{"content": [{"type": "text", "text": text}]}]}
    result = recorder.record(record["session_id"], {"provider": "controlled-test", "model": "contract-test", "agent_id": "main", "request": request, "source_ids": [source["id"]]})
    assert not result["unmapped_source_ids"]
    assert result["bindings"][0]["relation"] == "verified_json_string_copy"
