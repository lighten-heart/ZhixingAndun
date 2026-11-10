"""Operator-controlled changes; model text cannot change authorization or restore data."""
import copy
from fastapi import HTTPException


from .usage import audited

class Operations:
    def change_authorization(self, session_id, data, actor):
        from .service import ident, now
        if actor not in {"admin", "local-operator"}:
            raise HTTPException(403, "仅管理员可变更可信任务授权")
        with self.store.transaction():
            session = self.require("session", session_id)
            if session["authorization_version"] != data.expected_version:
                raise HTTPException(409, "任务授权版本已变化，请重新加载")
            if any(c["execution_status"] == "executing" for c in self.store.all("call", session_id)):
                raise HTTPException(409, "存在执行中调用，等待其回执后再变更授权")
            if any(r["session_id"] == session_id and r["status"] in {"starting", "running", "waiting_approval", "stopping"}
                   for r in self.store.all("harness_run")):
                raise HTTPException(409, "请先停止宿主任务，再修改任务授权并启动新任务")
            before = {k: session[k] for k in ("intent", "scope", "authorization_version")}
            session.setdefault("original_intent", session["intent"])
            session.setdefault("original_scope", session["scope"])
            session.update(intent=data.intent, scope=data.scope, authorization_version=data.expected_version + 1)
            entry = {"id": ident("auth"), "session_id": session_id, "actor": actor, "reason": data.reason,
                     "before": before, "after": {k: session[k] for k in before}, "created_at": now()}
            self.store.put("authorization", entry)
            self.store.put("session", session)
            for call in self.store.all("call", session_id):
                if call.get("_permit") and not call["_permit"]["used"]:
                    call["_permit"]["revoked"] = True
                    self.store.put("call", call)
            self.event(session_id, "authorization.changed", "经可信操作者变更任务范围；旧许可撤销，候选操作须重新审查", details=entry)
            return self.session_view(session)

    def memory_versions(self, memory_id):
        self.require("memory", memory_id)
        return sorted((r for r in self.store.all("memory_revision") if r["memory_id"] == memory_id),
                      key=lambda r: r["snapshot"]["version"])

    @audited('memory')
    def review_memory(self, memory_id, data, actor):
        from .service import ident, now, digest
        from .detection import detect, model_configured, normalize, sensitive
        if actor not in {"admin", "local-operator", "reviewer"}:
            raise HTTPException(403, "记忆复核需要操作者权限")
        old = self.require("memory", memory_id)
        if old["version"] != data.expected_version:
            raise HTTPException(409, "记忆版本已变化，请重新加载")
        session = self.require("session", old["source_session_id"])
        content = data.content if data.action == "revise" else old["content"]
        detection = None
        if data.action != "quarantine":
            detection = detect(content, "memory", session["intent"], model_redactor=self.public_view)
            if detection["risk_score"] >= 40 or (model_configured() and not detection.get("semantic_complete")):
                raise HTTPException(409, "记忆仍有风险或必要检查未完成，不能恢复；可提交修订后的内容重新复核")
        with self.store.transaction():
            current = self.require("memory", memory_id)
            if current != old or self.require("session", session["id"]) != session:
                raise HTTPException(409, "复核期间记忆或授权发生变化")
            revision = {"id": ident("mrev"), "memory_id": memory_id, "session_id": session["id"],
                        "snapshot": copy.deepcopy(current), "actor": actor, "action": data.action,
                        "reason": data.reason, "created_at": now()}
            self.store.put("memory_revision", revision)
            # Previously admitted versions stay blocked. A new read must review the new version.
            for source in self.store.all("source"):
                if source.get("metadata", {}).get("memory_id") == memory_id:
                    source["decision"] = "block"
                    source["version"] += 1
                    source["detection"].setdefault("information_gaps", []).append("MEMORY_VERSION_REVOKED")
                    self.store.put("source", source)
            current.update(version=current["version"] + 1, updated_at=now(),
                           status="quarantined" if data.action == "quarantine" else "active")
            if detection is not None:
                # Independently checked operator revision; it is not a model-asserted derivation.
                source = {"id": ident("src"), "session_id": session["id"], "type": "memory",
                          "resource": "memory-operator-review://" + memory_id, "content": content,
                          "normalized": normalize(content)[0], "version": 1, "created_at": now(), "decision": "allow",
                          "detection": detection, "sensitive": sensitive(content),
                          "metadata": {"operator_review": revision["id"], "prior_source_id": old["source_id"]},
                          "offset_unit": "unicode_codepoint", "_content_hash": digest(content)}
                self.store.put("source", source)
                current.update(content=content, detection=detection, source_id=source["id"])
            current["last_review"] = {"actor": actor, "reason": data.reason, "action": data.action, "at": now()}
            self.store.put("memory", current)
            self.event(session["id"], "memory.reviewed", "受控记忆复核完成；旧版本不自动恢复准入", source_id=current["source_id"],
                       details={"memory_id": memory_id, "version": current["version"], "action": data.action, "actor": actor, "reason": data.reason})
            return current

    def scan_memories(self):
        result = []
        for item in self.store.all("memory"):
            try:
                scanned = self.scan_memory(item["id"])
                result.append({"id": item["id"], "status": scanned["status"], "version": scanned["version"]})
            except HTTPException as error:
                result.append({"id": item["id"], "status": "review_conflict", "error": error.status_code})
        return {"records": result, "total": len(result), "scope": "records_present_when_scan_started"}

    @audited('knowledge')
    def review_knowledge(self, document_id, data, actor):
        from .service import now
        from .detection import detect, model_configured
        if actor not in {"admin", "local-operator", "reviewer"}:
            raise HTTPException(403, "知识复核需要操作者权限")
        original = self.require("knowledge", document_id)
        if original["version"] != data.expected_version:
            raise HTTPException(409, "知识版本已变化")
        item = self.require("data", original["data_id"])
        source = self.require("source", original["source_id"])
        session = self.require("session", original["session_id"])
        if data.action == "restore":
            if source["decision"] != "allow" or original["content_hash"] != item["content_hash"]:
                raise HTTPException(409, "原来源未获准或数据已变化，请登记新版本")
            detection = detect(item["content"], "knowledge", session["intent"], model_redactor=self.public_view)
            if detection["risk_score"] >= 40 or (model_configured() and not detection.get("semantic_complete")):
                raise HTTPException(409, "知识材料仍有风险或检查未完成，不能恢复")
        with self.store.transaction():
            if (self.require("knowledge", document_id) != original or self.require("data", item["id"]) != item
                    or self.require("source", source["id"]) != source or self.require("session", session["id"]) != session):
                raise HTTPException(409, "知识复核期间材料或授权变化")
            record = copy.deepcopy(original)
            record.update(version=record["version"] + 1, data_version=item["version"],
                          status="quarantined" if data.action == "quarantine" else "active")
            self.store.put("knowledge", record)
            for admitted in self.store.all("source"):
                if admitted.get("metadata", {}).get("document_id") == document_id:
                    admitted["decision"] = "block"
                    admitted["version"] += 1
                    admitted["detection"].setdefault("information_gaps", []).append("KNOWLEDGE_VERSION_REVOKED")
                    self.store.put("source", admitted)
            self.event(session["id"], "knowledge.reviewed", "知识索引状态变更", source_id=source["id"],
                       details={"document_id": document_id, "before_version": original["version"], "version": record["version"],
                                "action": data.action, "reason": data.reason, "actor": actor, "at": now()})
            return {k: v for k, v in record.items() if k != "segments"}
