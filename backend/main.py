"""Local API and production SPA server: uvicorn backend.main:app --host 127.0.0.1."""
import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .detection import model_configured, model_configuration_valid, redact
from .models import ApprovalInput, CallInput, ClaimInput, DelegatedSourceInput, DemoInput, Empty, ExecuteInput, MemoryInput, PolicyInput, ReceiptInput, SessionInput, SourceInput
from .scenarios import catalog, evaluate, run_scenario
from .service import GuardService, now
from .harness import HarnessManager, HarnessRunInput

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.0.0"

def create_app(data_dir=None):
    service = GuardService(data_dir or os.getenv("GUARD_DATA_DIR", str(PROJECT_ROOT / "data")))
    harness = HarnessManager(service)

    @asynccontextmanager
    async def lifespan(app):
        yield
        harness.close()
        service.store.close()

    app = FastAPI(title="智行安盾", version=VERSION, lifespan=lifespan,
                  description="Four-module guard API. Local fixture evidence is distinct from trusted adapter receipts.")
    app.state.service = service
    app.state.harness = harness
    from .forensics import Forensics
    forensics = Forensics(service)
    from .remote_lineage import RemoteLineage
    lineage = RemoteLineage(service)
    from .models import ModelRequestInput, ModelCompletionInput, TokenReceiptInput

    @app.post("/api/sessions/{session_id}/model-requests")
    def record_model_request(session_id: str, data: ModelRequestInput):
        return lineage.record(session_id, data.model_dump())

    @app.get("/api/sessions/{session_id}/model-requests")
    def model_requests(session_id: str):
        service.require("session", session_id)
        return service.public_view(service.store.all("model_request", session_id))

    @app.get("/api/sessions/{session_id}/model-usage")
    def model_usage(session_id: str):
        service.require("session", session_id)
        from .usage import summarize
        return service.public_view(summarize(service.store, session_id))

    @app.post("/api/model-requests/{request_id}/completion")
    def complete_model_request(request_id: str, data: ModelCompletionInput):
        return lineage.complete(request_id, data.model_dump())

    @app.post("/api/model-requests/{request_id}/provider-receipt")
    def provider_token_receipt(request_id: str, data: TokenReceiptInput):
        return lineage.accept_receipt(request_id, data.receipt)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.middleware("http")
    async def local_api_security(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            if origin:
                allowed = {"http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8765", "http://127.0.0.1:8765", "http://testserver"}
                if request.url.hostname in {"localhost", "127.0.0.1", "::1", "testserver"}:
                    allowed.add(f"{request.url.scheme}://{request.url.netloc}")
                try:
                    parsed = urlparse(origin)
                except ValueError:
                    return JSONResponse({"detail": "拒绝格式无效的前端来源"}, status_code=403)
                if origin not in allowed or parsed.username or parsed.password:
                    return JSONResponse({"detail": "拒绝非本机可信前端来源"}, status_code=403)
            from .access import role, allowed
            request.state.actor = role(request.headers.get("x-guard-token", ""))
            if request.url.path != "/api/health":
                if request.state.actor is None:
                    return JSONResponse({"detail": "缺少或无效的 X-Guard-Token"}, status_code=401)
                if not allowed(request.state.actor, request.method, request.url.path):
                    return JSONResponse({"detail": "当前角色没有执行此操作的权限"}, status_code=403)
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                length = request.headers.get("content-length")
                if length and (not length.isdigit() or int(length) > 1500000):
                    return JSONResponse({"detail": "请求体超过 1.5 MB 上限"}, status_code=413)
                chunks, total = [], 0
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > 1500000:
                        return JSONResponse({"detail": "请求体超过 1.5 MB 上限"}, status_code=413)
                    chunks.append(chunk)
                body = b"".join(chunks)
                # Starlette's cached request forwards this bounded body downstream.
                request._body = body
                if body:
                    try:
                        json.loads(body)
                    except (ValueError, UnicodeError, RecursionError):
                        return JSONResponse({"detail": "请求体不是有效或可处理的 JSON"}, status_code=422)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        errors = [".".join(str(x) for x in item["loc"]) + ": " + item["type"] for item in exc.errors()]
        return JSONResponse({"detail": "输入校验失败：" + "; ".join(errors[:10])}, status_code=422)

    from .models import DataInput, DerivationInput, KnowledgeInput, KnowledgeQuery
    from .models import ContextAdmissionInput

    @app.post("/api/sessions/{session_id}/context-admission")
    def context_admission(session_id: str, data: ContextAdmissionInput):
        return service.context_admission(session_id, data)

    @app.get("/api/sessions/{session_id}/data")
    def data_records(session_id: str):
        service.require("session", session_id)
        return [service.public_data(item) for item in service.store.all("data", session_id)]

    @app.post("/api/sessions/{session_id}/data")
    def register_data(session_id: str, data: DataInput):
        return service.public_data(service.register_data(session_id, data))

    @app.post("/api/sessions/{session_id}/data/derive")
    def derive_data(session_id: str, data: DerivationInput):
        return service.public_data(service.derive_data(session_id, data))

    @app.post("/api/sessions/{session_id}/knowledge")
    def index_knowledge(session_id: str, data: KnowledgeInput):
        record = service.index_knowledge(session_id, data)
        return {k: v for k, v in record.items() if k != "segments"}

    @app.post("/api/sessions/{session_id}/knowledge/search")
    def search_knowledge(session_id: str, data: KnowledgeQuery):
        return redact(service.query_knowledge(session_id, data))

    @app.get("/api/sources/{source_id}/tokens")
    def source_tokens(source_id: str, start: int = 0, end: int | None = None):
        from .excerpts import locate_excerpt
        from .token_mapping import locate
        from .service import digest
        source = service.require("source", source_id)
        if digest(source["content"]) != source["_content_hash"]:
            raise HTTPException(409, "来源快照哈希校验失败")
        try:
            mapping = locate(source["content"], start, end)
            # Token IDs can reconstruct secret text. Public evidence receives only offsets.
            if source.get("sensitive") or any((d["source_id"] == source_id or (len(d["content"]) >= 4 and locate_excerpt(source["content"], d["content"]))) and d["sensitivity"] != "public" for d in service.store.all("data", source["session_id"])):
                for token in mapping["tokens"]:
                    token.pop("id", None)
            return {"source_id": source_id, "version": source["version"], **mapping}
        except (FileNotFoundError, ImportError):
            raise HTTPException(503, "审计 tokenizer 未安装")
        except ValueError:
            raise HTTPException(422, "范围或 tokenizer 映射核验失败")

    @app.get("/api/health")
    def health():
        host = harness.status()
        host_status = "running" if host["active_run_ids"] else "ready" if host["ready"] else "not_ready"
        from .forensics import cached_status as sandbox_status
        sandbox = sandbox_status()
        return {"status": "ok", "version": VERSION, "instance_id": os.getenv("GUARD_INSTANCE_ID", ""), "process_id": os.getpid(), "mode": "local_fixture+adapter_api", "primary_host": "DeepSeek Harness", "harness_status": host_status, "model_configured": model_configured(), "model_configuration_valid": model_configuration_valid(), "hermes_status": "not_connected", "sandbox_available": sandbox["available"], "sandbox": sandbox, "storage": service.store.health(), "auth_required": __import__("backend.access", fromlist=["configured"]).configured(), "model_status": ("configured_not_health_checked" if model_configuration_valid() else "invalid_configuration") if model_configured() else "not_configured", "timestamp": now()}

    from .models import ScriptInput

    @app.post("/api/sessions/{session_id}/scripts")
    def register_script(session_id: str, data: ScriptInput):
        return forensics.register(session_id, data.code, data.label)

    @app.get("/api/sessions/{session_id}/scripts")
    def list_scripts(session_id: str):
        service.require("session", session_id)
        return service.public_view(service.store.all("script", session_id))

    @app.post("/api/calls/{call_id}/sandbox")
    def probe_script(call_id: str, data: Empty):
        return forensics.run(call_id)

    @app.get("/api/sandbox")
    def list_probes():
        return service.public_view(service.store.all("sandbox"))

    @app.get("/api/evaluations/blind")
    def blind_report():
        report = PROJECT_ROOT / "output/blind-latest.json"
        if not report.exists():
            return {"available": False}
        data = json.loads(report.read_text(encoding="utf-8"))
        from .code_fingerprint import fingerprint
        data["current_code_matches"] = data.get("code") == fingerprint() if "code" in data else None
        return data

    @app.get("/api/sandbox/{sandbox_id}")
    def get_probe(sandbox_id: str):
        return service.public_view(service.require("sandbox", sandbox_id))

    @app.get("/api/dashboard")
    def dashboard():
        data = service.dashboard()
        from .forensics import cached_status
        sandbox = cached_status()
        for component in data["components"]:
            if component["name"] == "证据溯源":
                component["detail"] = f"{service.store.health()['backend']} 持久化、显式引用与上下文关系、脱敏导出"
            if component["name"] == "动态沙箱":
                component.update(status="healthy" if sandbox["available"] else "unavailable",
                                 detail="Docker / strace 隔离取证已就绪" if sandbox["available"] else "Docker 取证尚未就绪，请检查基础设施状态")
        host = harness.status()
        data["components"] = [c for c in data["components"] if c["name"] != "Hermes 宿主接入"]
        data["components"].insert(4, {"name": "DeepSeek Harness 宿主", "status": "configured" if host["ready"] else "not_connected", "detail": "本机运行时已就绪；真实模型与防护结果请查看 Harness 宿主演示" if host["ready"] else "请安装受支持的 Harness 运行时并配置账号"})
        return service.public_view(data)

    @app.get("/api/harness/status")
    def harness_status():
        return harness.status()

    @app.get('/api/agent-comparisons')
    def agent_comparisons():
        from .code_fingerprint import fingerprint
        root = PROJECT_ROOT / 'output/agent-comparison'
        reports = []
        current = fingerprint()
        if root.exists():
            for path in sorted(root.glob('*/report.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:30]:
                if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or path.stat().st_size > 20000000:
                    continue
                try:
                    report = json.loads(path.read_text(encoding='utf-8'))
                    manifest_path = path.with_name('manifest.json')
                    if manifest_path.is_symlink() or manifest_path.stat().st_size > 1000000:
                        continue
                    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
                    import hashlib
                    if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != report.get('manifest_sha256'):
                        continue
                    reports.append({'id': path.parent.name, 'completed': report.get('completed', False),
                        'current_code_matches': manifest.get('code') == current, 'arms': report['arms'],
                        'scope': report['scope'], 'created_at': manifest['created_at'],
                        'runs': len(report['rows']), 'manifest_sha256': report['manifest_sha256']})
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        return service.public_view(reports)

    @app.get("/api/harness/runs")
    def harness_runs(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=1000000)):
        return harness.list_runs(limit, offset)

    @app.get("/api/harness/runs/{run_id}")
    def harness_run(run_id: str):
        return harness.get(run_id)

    @app.get("/api/harness/runs/{run_id}/lease")
    def harness_lease(run_id: str):
        return harness.lease(run_id)

    @app.post("/api/harness/runs")
    def harness_start(data: HarnessRunInput, request: Request):
        return harness.start(data, str(request.base_url))

    @app.post("/api/harness/runs/{run_id}/stop")
    def harness_stop(run_id: str, data: Empty):
        return harness.stop(run_id)

    @app.get("/api/sessions")
    def sessions():
        counts = service.store.call_counts()
        return service.public_view([{**s, **counts.get(s["id"], {"call_count": 0, "blocked_count": 0})}
                                    for s in service.store.all("session")])

    @app.post("/api/sessions")
    def create_session(data: SessionInput):
        return service.public_view(service.create_session(data))

    @app.get("/api/sessions/{session_id}")
    def session_detail(session_id: str):
        return service.public_view(service.detail(session_id))

    from .models import AuthorizationInput, MemoryReviewInput, KnowledgeReviewInput

    @app.post("/api/sessions/{session_id}/authorization-change")
    def change_authorization(session_id: str, data: AuthorizationInput, request: Request):
        return service.public_view(service.change_authorization(session_id, data, request.state.actor))

    @app.get("/api/sessions/{session_id}/authorization-history")
    def authorization_history(session_id: str):
        service.require("session", session_id)
        return service.public_view(service.store.all("authorization", session_id))

    @app.get("/api/sessions/{session_id}/knowledge")
    def knowledge_documents(session_id: str):
        service.require("session", session_id)
        return service.public_view([{k: v for k, v in d.items() if k != "segments"}
                                    for d in service.store.all("knowledge", session_id)])

    @app.post("/api/knowledge/{document_id}/review")
    def review_knowledge(document_id: str, data: KnowledgeReviewInput, request: Request):
        return service.public_view(service.review_knowledge(document_id, data, request.state.actor))

    @app.post("/api/sessions/{session_id}/delegated-sources")
    def delegated_source(session_id: str, data: DelegatedSourceInput):
        return service.public_view(service.add_delegated_source(session_id, data))

    @app.post("/api/sessions/{session_id}/sources")
    def add_source(session_id: str, data: SourceInput):
        return service.public_view(service.add_source(session_id, data))

    @app.post("/api/sessions/{session_id}/calls")
    def review_call(session_id: str, data: CallInput):
        return service.with_permit(service.review_call(session_id, data))

    @app.post("/api/calls/{call_id}/execute")
    def execute_call(call_id: str, data: ExecuteInput):
        return service.public_view(service.execute_fixture(call_id, data.permit))

    @app.post("/api/calls/{call_id}/recheck")
    def recheck_call(call_id: str, data: Empty):
        return service.with_permit(service.recheck(call_id))

    @app.post("/api/calls/{call_id}/claim")
    def claim_call(call_id: str, data: ClaimInput):
        claimed = service.claim(call_id, data.permit, data.parameter_hash)
        return {"claim_id": claimed["claim_id"], "call": service.public_view(claimed["call"])}

    @app.get("/api/calls/{call_id}/authorization")
    def call_authorization(call_id: str):
        return service.with_permit(service.require("call", call_id))

    @app.post("/api/calls/{call_id}/receipt")
    def receipt_call(call_id: str, data: ReceiptInput):
        return service.public_view(service.receipt(call_id, data.claim_id, data.status, data.detail, data.result))

    from .models import ControlInput, ExternalEventInput

    @app.post("/api/calls/{call_id}/control")
    def control_call(call_id: str, data: ControlInput):
        return service.public_view(service.control_receipt(call_id, data))

    @app.post("/api/sessions/{session_id}/external-events")
    def ingest_external(session_id: str, data: ExternalEventInput):
        return service.public_view(service.ingest_event(session_id, data))

    @app.get("/api/sessions/{session_id}/external-events")
    def external_events(session_id: str):
        service.require("session", session_id)
        return service.public_view(service.external_events(session_id))

    @app.get("/api/alerts")
    def alerts():
        return service.public_view([c for c in service.store.all("call") if c["decision"] in {"block", "confirm"}])

    @app.get("/api/approvals")
    def approvals():
        return service.public_view([c for c in service.store.all("call") if c["execution_status"] == "pending" and c["decision"] == "confirm" and not c.get("_superseded_by") and not c.get("_recheck_in_progress")])

    @app.post("/api/approvals/{call_id}")
    def approve(call_id: str, data: ApprovalInput, request: Request):
        return service.with_permit(service.approve(call_id, data.approved, data.comment, actor=request.state.actor))

    @app.get("/api/policies")
    def policy():
        return service.policy()

    @app.put("/api/policies")
    def update_policy(data: PolicyInput):
        return service.update_policy(data)

    @app.get("/api/memories")
    def memories():
        return service.public_view(service.store.all("memory"))

    @app.post("/api/memories")
    def create_memory(data: MemoryInput):
        return service.public_view(service.create_memory(data))

    @app.post("/api/memories/{memory_id}/scan")
    def scan_memory(memory_id: str, data: Empty):
        return service.public_view(service.scan_memory(memory_id))

    @app.post("/api/memories/scan-all")
    def scan_memories(data: Empty):
        return service.public_view(service.scan_memories())

    @app.post("/api/memories/{memory_id}/review")
    def review_memory(memory_id: str, data: MemoryReviewInput, request: Request):
        return service.public_view(service.review_memory(memory_id, data, request.state.actor))

    @app.get("/api/memories/{memory_id}/versions")
    def memory_versions(memory_id: str):
        return service.public_view(service.memory_versions(memory_id))

    @app.post("/api/sessions/{session_id}/memory/{memory_id}")
    def read_memory(session_id: str, memory_id: str, data: Empty):
        return service.public_view(service.read_memory(session_id, memory_id))

    @app.get("/api/scenarios")
    def scenarios():
        return catalog()

    @app.post("/api/demo/run")
    def demo(data: DemoInput):
        return service.public_view(run_scenario(service, data.scenario_id))

    @app.post("/api/evaluations/run")
    def evaluation_run(data: Empty):
        return service.public_view(evaluate(service))

    @app.get("/api/evaluations")
    def evaluations():
        return service.public_view(service.store.all("evaluation"))

    @app.get("/api/evaluations/campaigns")
    def saved_campaign_reports(limit: int = Query(default=20, ge=1, le=50)):
        from .campaign_reports import campaign_reports
        return campaign_reports(PROJECT_ROOT, limit=limit)

    @app.get("/api/evaluations/promptfoo")
    def promptfoo_reports():
        reports = []
        for suite in ("regression", "paired", "semantic", "harness"):
            path = PROJECT_ROOT / "output/promptfoo" / (suite + "-summary.json")
            if path.is_file():
                try:
                    item = json.loads(path.read_text(encoding="utf-8"))
                    reports.append({k: item[k] for k in ("suite", "passed", "duration_seconds", "stats") if k in item})
                except (OSError, ValueError, TypeError):
                    reports.append({"suite": suite, "passed": False, "duration_seconds": 0, "stats": {"errors": 1}})
        return {"suites": reports}

    @app.get("/api/sessions/{session_id}/export")
    def export(session_id: str):
        record = {"exported_at": now(), "version": VERSION, "offset_unit": "unicode_codepoint", "policy": service.policy(), "evidence": service.public_view(service.detail(session_id)), "limitations": ["正文、参数、回执已脱敏", "DAG 仅使用已登记引用与父子关系，不能证明未接入执行路径", "完整原文仅存在本机数据库；请使用操作系统用户权限保护数据目录"]}
        from .usage import summarize
        record['evidence']['model_usage'] = service.public_view(summarize(service.store, session_id))
        return JSONResponse(record, headers={"Content-Disposition": f'attachment; filename="aegisguard-{session_id}.json"'})

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(404, "API 不存在")
        dist = PROJECT_ROOT / "frontend" / "dist"
        target = (dist / path).resolve()
        if not target.is_relative_to(dist.resolve()):
            raise HTTPException(404, "文件不存在")
        if target.is_file():
            return FileResponse(target)
        if (dist / "index.html").is_file():
            return FileResponse(dist / "index.html")
        return JSONResponse({"detail": "后端已运行；前端尚未构建，请启动前端开发服务或构建 frontend/dist。", "api_docs": "/docs"}, status_code=200)

    return app

class LazyApplication:
    """Importing route factories must never recover an operator's live database.

    Uvicorn invokes this ASGI entry point with lifespan before serving requests.
    Tests and tooling can safely import create_app without opening the default DB.
    """
    def __init__(self):
        self.application = None

    async def __call__(self, scope, receive, send):
        if self.application is None:
            self.application = create_app()
        await self.application(scope, receive, send)


app = LazyApplication()
