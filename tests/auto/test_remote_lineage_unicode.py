"""S3 metamorphic contract tests; synthetic signed receipts, NOT cloud proof.

One hundred fixed seeds exercise the real source store, immutable request record,
fixed tokenizer, receipt issuer, signature validation, and token/source binding.
The independent oracle is that raw and JSON-escaped representations of the same
source must bind to identical rendered input token positions. Adversarial cases
are correctly re-signed, so rejection must depend on the semantic contract.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import random

import pytest
from fastapi import HTTPException

from adapters.inference_receipt import issue_receipt
from backend.remote_lineage import RemoteLineage
from backend.service import GuardService
from backend.token_mapping import load_tokenizer

KEY = "unicode-contract-fixture-only-key-32-plus-characters"
PROVIDER = "synthetic-unicode-contract"
TEMPLATE = "synthetic-unicode-contract-template-v1"


def corpus(seed):
    rng = random.Random(seed)
    required = ["中文边界", "🙂", "👩\u200d💻", "🇨🇳", "e\u0301", "a\u0308\u0323",
                '"quoted"', "\\literal\\u4e2d", "\nline\tcolumn\rreturn", "️", "\u200b"]
    optional = ["漢字かな", "한글", "é", "\U0002000b", "/~pointer", "<xml>&entity;", "\b\f", " " * 3]
    rng.shuffle(required)
    middle = "|".join(required + rng.sample(optional, 4))
    # Stable distinct first/last markers prevent a shifted interval from being
    # accidentally equivalent, including when nearby text contains repeats.
    text = f"⟦seed {seed:03d}⟧" + middle + f"⟦end {seed:03d}⟧"
    prefix = "入口🙂e\u0301\n" + " " * rng.randrange(4)
    suffix = "\n出口🧪"
    repetitions = 1 + seed % 2
    pieces, starts = [prefix], []
    for occurrence in range(repetitions):
        starts.append(sum(len(part) for part in pieces))
        pieces.append(text)
        if occurrence + 1 < repetitions:
            pieces.append("\n第二处🙂\n")
    pieces.append(suffix)
    return text, "".join(pieces), starts


@pytest.mark.parametrize("seed", range(100))
def test_unicode_source_representations_and_resigned_mutations(seed, tmp_path, monkeypatch):
    monkeypatch.setenv("GUARD_TOKEN_RECEIPT_KEYS", json.dumps({PROVIDER: KEY}))
    # Explicit isolation also protects this synthetic test when it is invoked
    # from an operator shell configured for the live PostgreSQL/Harness system.
    for name in ("GUARD_DATABASE_URL", "GUARD_MODEL_BACKEND", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_NAME", "GUARD_MODEL_KEY"):
        monkeypatch.setenv(name, "")
    text, request_content, occurrence_starts = corpus(seed)
    ensure_ascii = seed % 3 != 0
    snapshot = json.dumps({"blocks": [{"type": "text", "text": text}]}, ensure_ascii=ensure_ascii)
    serialized_text = json.dumps(text, ensure_ascii=ensure_ascii)[1:-1]
    expected_json_start = snapshot.index(serialized_text)
    service = GuardService(tmp_path)
    try:
        session = service.create_session({"title": f"Unicode receipt seed {seed}",
            "intent": "Read a synthetic public reference", "scope": "read_only", "agent_id": "main"})
        raw_source = service.add_source(session["id"], {"type": "document", "content": text})
        json_source = service.add_source(session["id"], {"type": "document", "content": snapshot})
        recorder = RemoteLineage(service)
        record = recorder.record(session["id"], {"provider": PROVIDER, "model": "contract-only-model",
            "agent_id": "main", "source_ids": [raw_source["id"], json_source["id"]],
            "request": {"provider": PROVIDER, "model": "contract-only-model",
                "messages": [{"role": "user", "content": request_content}]}})
        assert not record["unmapped_source_ids"]
        assert len(record["bindings"]) == 2 * len(occurrence_starts)
        for source in (raw_source, json_source):
            bindings = [item for item in record["bindings"] if item["source_id"] == source["id"]]
            assert sorted(item["field_start"] for item in bindings) == occurrence_starts
            for binding in bindings:
                assert binding["pointer"] == "/messages/0/content"
                assert binding["field_end"] == binding["field_start"] + len(text)
                source_fragment = source["content"][binding["source_start"]:binding["source_end"]]
                if source["id"] == raw_source["id"]:
                    assert binding["relation"] == "verified_exact_copy" and source_fragment == text
                    assert (binding["source_start"], binding["source_end"]) == (0, len(text))
                else:
                    assert binding["relation"] == "verified_json_string_copy"
                    assert binding["source_start"] == expected_json_start
                    assert binding["source_end"] == expected_json_start + len(serialized_text)
                    assert json.loads('"' + source_fragment + '"') == text

        header, footer = "系统🧪\n<user>\n", "\n</user>\n<assistant>"
        prompt = header + request_content + footer
        tokenizer, manifest = load_tokenizer()
        ids = tokenizer.encode(prompt, add_special_tokens=False).ids
        assert tokenizer.decode(ids, skip_special_tokens=False) == prompt
        expected_intervals = {start: (len(header) + start, len(header) + start + len(text))
                              for start in occurrence_starts}
        spans = [{"binding_id": binding["id"], "prompt_start": expected_intervals[binding["field_start"]][0],
                  "prompt_end": expected_intervals[binding["field_start"]][1]} for binding in record["bindings"]]
        for span in spans:
            assert prompt[span["prompt_start"]:span["prompt_end"]] == text

        def signed(rendered=prompt, token_ids=None, source_spans=None):
            return issue_receipt(request_record=record, rendered_prompt=rendered,
                actual_input_token_ids=ids if token_ids is None else token_ids,
                tokenizer_sha256=manifest["sha256"], template_sha256=hashlib.sha256(TEMPLATE.encode()).hexdigest(),
                source_spans=spans if source_spans is None else source_spans, key=KEY)

        changed_spans = copy.deepcopy(spans)
        changed_spans[0]["prompt_start"] += 1
        first = spans[0]["prompt_start"]
        changed_prompt = prompt[:first] + "改" + prompt[first + 1:]
        # The changed-content receipt carries the CORRECT token IDs and checksum
        # for its changed prompt. Only its immutable-source binding is false.
        changed_ids = tokenizer.encode(changed_prompt, add_special_tokens=False).ids
        assert tokenizer.decode(changed_ids, skip_special_tokens=False) == changed_prompt
        mutations = {
            "source_offset_shift": signed(source_spans=changed_spans),
            "input_token_truncation": signed(token_ids=ids[:-1]),
            "changed_content_with_correct_tokens": signed(rendered=changed_prompt, token_ids=changed_ids),
            "missing_binding": signed(source_spans=spans[:-1]),
        }
        rejected = {}
        for name, receipt in mutations.items():
            with pytest.raises(HTTPException) as failure:
                recorder.accept_receipt(record["id"], receipt)
            assert failure.value.status_code == 422, name
            assert service.require("model_request", record["id"])["provider_prompt_tokenization_verified"] is False
            rejected[name] = failure.value.status_code

        correct_receipt = signed()
        accepted = recorder.accept_receipt(record["id"], correct_receipt)
        assert accepted["provider_prompt_tokenization_verified"] is True
        proof = accepted["provider_proof"]
        assert proof["input_token_count"] == len(ids)
        assert proof["causal_output_attribution"] is False
        assert proof["trust_basis"] == "configured_provider_authenticated_receipt"
        assert "_provider_receipt" not in accepted
        for start in occurrence_starts:
            paired = [span for span in proof["source_token_spans"] if span["field_start"] == start]
            assert {span["source_id"] for span in paired} == {raw_source["id"], json_source["id"]}
            assert paired[0]["token_indices"] == paired[1]["token_indices"]
            assert paired[0]["token_indices"] and paired[0]["token_indices"] == sorted(set(paired[0]["token_indices"]))
            assert all(0 <= index < len(ids) for index in paired[0]["token_indices"])
            assert {(span["prompt_start"], span["prompt_end"]) for span in paired} == {expected_intervals[start]}
        with pytest.raises(HTTPException) as replay:
            recorder.accept_receipt(record["id"], correct_receipt)
        assert replay.value.status_code == 409

        if os.getenv("AEGIS_UNICODE_EVIDENCE_DIR"):
            evidence = Path(os.environ["AEGIS_UNICODE_EVIDENCE_DIR"])
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / f"seed-{seed:03d}.json").write_text(json.dumps({"seed": seed,
                "claim_scope": "synthetic_authenticated_receipt_contract_not_cloud_measurement",
                "ensure_ascii": ensure_ascii, "source_char_count": len(text), "prompt_char_count": len(prompt),
                "token_count": len(ids), "tokenizer_sha256": manifest["sha256"],
                "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                "binding_count": len(spans), "equivalent_representations": ["raw", "json"],
                "roundtrip": True, "accepted": True, "negative_rejections": rejected,
                "replay_status": replay.value.status_code}, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        service.store.close()
