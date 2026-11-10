"""Optional distinct operator, reviewer, adapter and viewer tokens for local deployment."""
import os
import secrets

TOKENS = {"admin": "GUARD_API_TOKEN", "reviewer": "GUARD_REVIEWER_TOKEN", "adapter": "GUARD_ADAPTER_TOKEN", "viewer": "GUARD_VIEWER_TOKEN"}


def configured():
    return any(os.getenv(name, "") for name in TOKENS.values())


def role(token):
    if not configured():
        return "local-operator"
    for label, name in TOKENS.items():
        value = os.getenv(name, "")
        if value and secrets.compare_digest(value, token):
            return label
    return None


def allowed(actor, method, path):
    if actor in {"admin", "local-operator"}:
        return True
    if path.endswith("/authorization-change"):
        return False
    if path.endswith("/authorization") or path.endswith("/lease"):
        return actor == "adapter"
    if method in {"GET", "HEAD", "OPTIONS"}:
        return actor in {"viewer", "reviewer", "adapter"}
    if path.startswith("/api/approvals/"):
        return actor == "reviewer"
    if path == "/api/memories/scan-all" or (path.startswith(("/api/memories/", "/api/knowledge/")) and path.endswith("/review")):
        return actor == "reviewer"
    if path.endswith("/scripts"):
        return False
    if path.endswith("/sandbox"):
        return actor in {"reviewer", "adapter"}
    if "/data" in path or path.endswith("/knowledge") or path == "/api/policies":
        return False
    if path.startswith("/api/harness/runs"):
        return actor == "reviewer"
    return actor == "adapter"
