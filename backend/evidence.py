"""Data and knowledge services mixed into the shared transactional guard."""
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import HTTPException
from . import provenance
from .detection import redact


def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex[:16]


class EvidenceServices:
    def source_labels(self, source):
        """Permissions follow recorded parents across memory/session boundaries."""
        from .excerpts import locate_excerpt
        ancestors, pending = set(), [source]
        while pending:
            item = pending.pop()
            if item["id"] in ancestors:
                continue
            ancestors.add(item["id"])
            parent_id = item.get("parent_source_id")
            metadata = item.get("metadata", {})
            revision = self.store.get("memory_revision", metadata.get("operator_review", ""))
            if revision and revision["snapshot"].get("source_id") == metadata.get("prior_source_id"):
                parent_id = metadata["prior_source_id"]
            if parent_id:
                parent = self.store.get("source", parent_id)
                if parent:
                    pending.append(parent)
        return [d for d in self.store.all("data") if d["source_id"] in ancestors
                or (len(d["content"]) >= 4 and locate_excerpt(source["content"], d["content"]))]

    def context_admission(self, session_id, data):
        with self.store.transaction():
            return self._context_admission(session_id, data)

    def _context_admission(self, session_id, data):
        from .service import digest
        source = self.require("source", data.source_id)
        if source["session_id"] != session_id:
            raise HTTPException(422, "上下文来源不属于当前任务")
        decision, gaps = source["decision"], []
        labels = self.source_labels(source)
        for label in labels:
            if not provenance.check_use(label, data.purpose, data.recipient):
                decision = "block"
                gaps.append("CONTEXT_RECIPIENT_NOT_AUTHORIZED")
        if source.get("sensitive") and not labels:
            decision = "block"
            gaps.append("SENSITIVE_CONTEXT_USE_UNCLASSIFIED")
        result = {"source_id": source["id"], "version": source["version"], "decision": decision,
                  "recipient": data.recipient, "purpose": data.purpose, "information_gaps": gaps,
                  "scope": "registered_data_and_credential_detection"}
        binding = self._admission_binding(source, labels)
        if binding:
            # Append distinct decisions; a later denial cannot erase a prior
            # permission. This attests the Guard decision, not remote delivery.
            record = {**result, **binding, "session_id": session_id,
                      "evidence_type": "guard_decision_bound_to_reported_receipt"}
            record["id"] = "admission_" + digest(record)
            if not self.store.get("context_admission", record["id"]):
                record["created_at"] = datetime.now(timezone.utc).isoformat()
                self.store.put("context_admission", record)
        self.event(session_id, "context.admitted", "检查业务模型上下文接收权限", source_id=source["id"], details=result)
        return result

    def _admission_binding(self, source, labels=None):
        """Only exact complete JSON results can establish tool-result provenance."""
        from .service import digest
        call_id = source.get("metadata", {}).get("call_id")
        call = self.store.get("call", call_id) if isinstance(call_id, str) else None
        if not call or call["session_id"] != source["session_id"]:
            return None
        receipt = call.get("receipt")
        if (not receipt or call["execution_status"] not in {"succeeded", "failed"}
                or receipt.get("status") != call["execution_status"]
                or not call.get("_receipt_fingerprint")):
            return None
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate result key")
                value[key] = item
            return value
        try:
            parsed = json.loads(source["content"], object_pairs_hook=unique_object)
            if digest(parsed) != digest(receipt["result"]):
                return None
            fingerprint = digest({key: receipt[key] for key in ("status", "detail", "result")})
            if fingerprint != call["_receipt_fingerprint"]:
                return None
        except (ValueError, TypeError, KeyError, RecursionError):
            return None
        return {"call_id": call_id, "source_hash": digest(source["content"]),
                "source_decision": source["decision"], "source_sensitive": source.get("sensitive", False),
                "receipt_fingerprint": fingerprint,
                "labels_hash": digest(self.source_labels(source) if labels is None else labels)}

    def review_history(self, session_id):
        """Expose only server-recorded admission facts, never raw result bodies."""
        calls = self.store.all("call", session_id)
        by_id = {call["id"]: call for call in calls}
        for record in self.store.all("context_admission", session_id):
            call = by_id.get(record["call_id"])
            source = self.store.get("source", record["source_id"])
            if call is None or source is None:
                continue
            binding = self._admission_binding(source)
            current = bool(binding and source["version"] == record["version"]
                           and all(record.get(k) == v for k, v in binding.items()))
            fact = {key: record[key] for key in ("source_id", "version", "decision",
                    "recipient", "purpose", "evidence_type")}
            fact["current"] = current
            call.setdefault("result_admissions", []).append(fact)
        return calls

    def control_receipt(self, call_id, data):
        with self.store.transaction():
            call = self.require("call", call_id)
            if call["parameter_hash"] != data.parameter_hash or call.get("execution_owner") != "adapter":
                raise HTTPException(409, "控制记录与实际调用绑定不一致")
            if call["decision"] == "allow" or call["execution_status"] not in {"pending", "not_executed"}:
                raise HTTPException(409, "已放行或已执行的调用不能声明执行前阻断")
            receipt = {"status": "withheld_before_execution", "boundary": data.boundary, "parameter_hash": data.parameter_hash,
                       "evidence_type": "trusted_adapter_control_report"}
            if call.get("control_receipt"):
                if call["control_receipt"] != receipt:
                    raise HTTPException(409, "执行控制记录冲突")
                return call
            call["control_receipt"] = receipt
            self.store.put("call", call)
            self.event(call["session_id"], "call.controlled", "适配器确认本次请求在执行入口被阻断", call_id=call_id, details=receipt)
            return call

    def ingest_event(self, session_id, data):
        from .service import digest
        self.require("session", session_id)
        payload = data.model_dump()
        identifier = "external_" + digest({"session_id": session_id, "component": data.component, "event_id": data.event_id})[:32]
        with self.store.transaction():
            previous = self.store.get("external_event", identifier)
            if previous:
                if previous["payload"] != payload:
                    raise HTTPException(409, "相同事件标识的内容冲突")
                return previous
            if any(e["payload"]["component"] == data.component and e["payload"]["sequence"] == data.sequence for e in self.store.all("external_event", session_id)):
                raise HTTPException(409, "同一组件顺序号已被另一事件使用")
            record = {"id": identifier, "session_id": session_id, "payload": payload,
                      "created_at": datetime.now(timezone.utc).isoformat(), "payload_hash": digest(payload)}
            self.store.put("external_event", record)
            self.event(session_id, "external.received", "接收并去重组件事件；引用按显式关系关联", details={"external_event_id": identifier, "component": data.component})
            return record

    def external_events(self, session_id):
        records = self.store.all("external_event", session_id)
        known = {e["payload"]["component"] + ":" + e["payload"]["event_id"]: e["id"] for e in records}
        result = []
        for record in records:
            references = record["payload"]["references"]
            missing = [ref for ref in references if ref not in known]
            result.append({**record, "links": [known[ref] for ref in references if ref in known],
                           "pending_references": missing, "link_status": "pending" if missing else "resolved"})
        return result

    def register_data(self, session_id, data):
        source = self.require("source", data.source_id)
        if source["session_id"] != session_id:
            raise HTTPException(422, "数据来源不属于当前任务")
        with self.store.transaction():
            if source.get("sensitive") and data.sensitivity != "credential":
                raise HTTPException(422, "凭据格式标记不能通过普通标签登记降级")
            record = {"id": new_id("data"), "session_id": session_id, "version": 1,
                      "created_at": datetime.now(timezone.utc).isoformat(), **data.model_dump(),
                      "content": source["content"], "content_hash": provenance.content_hash(source["content"]),
                      "label_basis": "trusted_operator_registration", "derivation": None}
            self.store.put("data", record)
            self.event(session_id, "data.registered", "登记可信数据标签、用途与接收方权限", source_id=source["id"], details={"data_id": record["id"]})
            return record

    def derive_data(self, session_id, data):
        parents = [self.require("data", i) for i in data.parent_ids]
        if any(p["session_id"] != session_id for p in parents):
            raise HTTPException(422, "变换输入不属于当前任务")
        content, spans = provenance.transform(parents, data.operation, data.options)
        # The new source is scanned again. ACL intersection cannot relax any parent.
        source = self.add_source(session_id, {"type": "document", "content": content,
                    "resource": "derived-data", "parent_source_id": parents[0]["source_id"]})
        levels = ["public", "internal", "confidential", "credential"]
        with self.store.transaction():
            record = {"id": new_id("data"), "session_id": session_id, "version": 1,
                      "created_at": datetime.now(timezone.utc).isoformat(), "source_id": source["id"],
                      "content": content, "content_hash": provenance.content_hash(content), "label": data.operation,
                      "sensitivity": max((p["sensitivity"] for p in parents), key=levels.index),
                      "allowed_purposes": provenance.intersect(parents, "allowed_purposes"),
                      "allowed_recipients": provenance.intersect(parents, "allowed_recipients"),
                      "label_basis": "verified_derivation", "derivation": {"operation": data.operation, "verified": True, "spans": spans}}
            self.store.put("data", record)
            self.event(session_id, "data.derived", "程序执行并核验派生关系；继承权限交集", source_id=source["id"], details={"data_id": record["id"], "derivation": record["derivation"]})
            return record

    def data_flow_errors(self, session_id, candidate):
        errors, used = [], {}
        for ref in candidate.get("data_references", []):
            try:
                data = self.require("data", ref["data_id"])
                if data["session_id"] != session_id or ref["version"] != data["version"]:
                    raise ValueError("version or session mismatch")
                value = provenance.field_value(candidate["args"], ref["field"])
                if value != data["content"]:
                    raise ValueError("field not bound to content")
                used[data["id"]] = data
            except (HTTPException, ValueError, TypeError, KeyError, IndexError):
                errors.append("DATA_REFERENCE_UNVERIFIED")
        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for key, item in value.items():
                    yield str(key)
                    yield from strings(item)
            elif isinstance(value, list):
                for item in value:
                    yield from strings(item)
        values = list(strings(candidate["args"]))
        for data in self.store.all("data"):
            if len(data["content"]) >= 4 and any(data["content"] in value for value in values):
                used[data["id"]] = data
        for source_id in candidate.get("source_ids", []):
            source = self.store.get("source", source_id)
            if source:
                for label in self.source_labels(source):
                    used[label["id"]] = label
        tool = candidate["tool"]
        recipients = ["local"]
        server = candidate.get("mcp_server", "local-fixture")
        if server not in {"local-fixture", "deepseek-harness/native"}:
            recipients = [server]  # Immediate MCP receiver always counts.
        if tool == "net.fetch":
            try:
                recipients.append(urlparse(candidate["args"].get("url", "")).hostname or "unknown")
            except ValueError:
                recipients.append("unknown")
        elif tool == "agent.delegate":
            recipients.append("child-agent")
        elif tool == 'git.push':
            recipients.append('git:' + str(candidate['args'].get('remote', 'unknown')))
        for data in used.values():
            if any(not provenance.check_use(data, candidate.get("purpose", "task"), r) for r in recipients):
                errors.append("DATA_USE_NOT_AUTHORIZED")
        return sorted(set(errors))

    def public_data(self, item):
        result = redact(item)
        if item["sensitivity"] != "public":
            result["content"] = "•" * len(item["content"])
        return result

    def public_view(self, value):
        from .detection import normalize
        contents = set()
        for item in self.store.all("data"):
            if item["sensitivity"] != "public":
                contents.add(item["content"])
                contents.add(normalize(item["content"])[0])
                # Harness/MCP text blocks may wrap JSON several times. Match
                # bounded escaped forms without decoding or changing originals.
                for ascii_only in (False, True):
                    escaped = item["content"]
                    for _ in range(4):
                        escaped = json.dumps(escaped, ensure_ascii=ascii_only)[1:-1]
                        contents.add(escaped)
                        contents.add(normalize(escaped)[0])
        texts = sorted((s for s in contents if s), key=len, reverse=True)
        def mask(v):
            if isinstance(v, str):
                for text in texts:
                    v = v.replace(text, "•" * len(text))
                return v
            if isinstance(v, dict):
                return {k if mask(str(k)) == str(k) else "[PRIVATE_KEY:" + provenance.content_hash(str(k))[:20] + "]": mask(x) for k, x in v.items()}
            if isinstance(v, list):
                return [mask(x) for x in v]
            return v
        return redact(mask(value))

    def index_knowledge(self, session_id, data):
        item = self.require("data", data.data_id)
        if item["session_id"] != session_id:
            raise HTTPException(422, "知识数据不属于当前任务")
        source = self.require("source", item["source_id"])
        segments = []
        # Lexical index has explicit original offsets, with overlap for boundary queries.
        for start in range(0, len(item["content"]), 800):
            end = min(len(item["content"]), start + 1000)
            segments.append({"start": start, "end": end, "content": item["content"][start:end]})
        record = {"id": new_id("kb"), "session_id": session_id, "version": 1, "title": data.title,
                  "data_id": item["id"], "data_version": item["version"], "source_id": source["id"],
                  "content_hash": item["content_hash"], "segments": segments,
                  "status": "active" if source["decision"] == "allow" else "quarantined",
                  "index_type": "sparse_tfidf_v1", "created_at": datetime.now(timezone.utc).isoformat()}
        self.store.put("knowledge", record)
        self.event(session_id, "knowledge.indexed", "知识文档分段索引已建立", source_id=source["id"], details={"document_id": record["id"], "segments": len(segments)})
        return record

    def query_knowledge(self, session_id, query):
        self.require("session", session_id)
        from .knowledge_vectors import rank
        results, excluded, quarantined = [], 0, []
        for document in self.store.all("knowledge", session_id):
            data = self.require("data", document["data_id"])
            origin = self.require("source", document["source_id"])
            if not provenance.check_use(data, query.purpose, query.recipient):
                excluded += 1
                continue
            if (document.get("status", "active") != "active" or origin["decision"] != "allow"
                    or data["content_hash"] != document["content_hash"]
                    or data["version"] != document["data_version"]):
                quarantined.append({"document_id": document["id"], "source_id": origin["id"],
                                    "segment": None, "decision": "block", "stage": "before_retrieval"})
                continue
            for index, segment in enumerate(document["segments"]):
                results.append({**segment, "document_id": document["id"], "version": document["version"],
                                "data_id": data["id"], "data_version": data["version"], "segment": index,
                                "source_id": document["source_id"], "title": document["title"]})
        admitted = []
        for result in rank(query.query, results)[:query.limit]:
            source = self.add_source(session_id, {"type": "knowledge", "content": result["content"],
                "resource": "knowledge://" + result["document_id"],
                "parent_source_id": result["source_id"],
                "metadata": {k: v for k, v in result.items() if k != "content"}})
            result["admission_source_id"] = source["id"]
            # Recheck mutable ACL/index state after model I/O and before returning text.
            with self.store.transaction():
                current = self.require("knowledge", result["document_id"])
                current_data = self.require("data", result["data_id"])
                if (source["decision"] == "allow" and current.get("status", "active") == "active"
                        and self.require("source", current["source_id"])["decision"] == "allow"
                        and current["version"] == result["version"] and current_data["version"] == result["data_version"]
                        and provenance.check_use(current_data, query.purpose, query.recipient)):
                    admitted.append(result)
                else:
                    source["decision"] = "block"
                    source["version"] += 1
                    source["detection"]["information_gaps"].append("KNOWLEDGE_ADMISSION_STATE_CHANGED")
                    self.store.put("source", source)
                    quarantined.append({"document_id": result["document_id"], "segment": result["segment"], "source_id": source["id"], "decision": "block"})
        self.event(session_id, "knowledge.retrieved", "按用途和接收方过滤后逐片段审查", details={"admitted": len(admitted), "quarantined": quarantined, "permission_filtered": excluded})
        return {"results": admitted, "quarantined": quarantined, "permission_filtered": excluded, "index_type": "sparse_tfidf_v1"}
