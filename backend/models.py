"""Typed API inputs. Unknown fields are rejected rather than silently ignored."""
import math
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

Decision = Literal["allow", "confirm", "block"]
SourceType = Literal["user_input", "web", "document", "code", "email", "issue", "mcp_description", "mcp_result", "memory", "knowledge"]

class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False, allow_inf_nan=False)

    @model_validator(mode="after")
    def portable_json(self):
        def validate(value, depth=0):
            if depth > 40:
                raise ValueError("JSON nesting exceeds 40 levels")
            if isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise ValueError("Lone Unicode surrogate is not a valid text value")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("Non-finite JSON numbers are not supported")
            if isinstance(value, dict):
                for key, item in value.items():
                    validate(key, depth + 1)
                    validate(item, depth + 1)
            if isinstance(value, list):
                for item in value:
                    validate(item, depth + 1)
        for field in type(self).model_fields:
            validate(getattr(self, field))
        return self

class SessionInput(Input):
    title: str = Field(min_length=1, max_length=160)
    intent: str = Field(min_length=1, max_length=12000)
    scope: Literal["read_only", "development"] = "read_only"
    agent_id: str = Field(default="agent-main", min_length=1, max_length=120)

class SourceInput(Input):
    type: SourceType
    content: str = Field(min_length=1, max_length=200000)
    resource: str = Field(default="", max_length=2000)
    parent_source_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class AuthorizationInput(Input):
    expected_version: int = Field(ge=1)
    intent: str = Field(min_length=1, max_length=12000)
    scope: Literal["read_only", "development"]
    reason: str = Field(min_length=1, max_length=2000)

class DelegatedSourceInput(Input):
    call_id: str = Field(min_length=1, max_length=100)
    claim_id: str = Field(min_length=20, max_length=256)
    agent_id: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=200000)

class MemoryReviewInput(Input):
    expected_version: int = Field(ge=1)
    action: Literal["quarantine", "restore", "revise"]
    reason: str = Field(min_length=1, max_length=2000)
    content: str | None = Field(default=None, min_length=1, max_length=200000)

    @model_validator(mode="after")
    def revision_content(self):
        if (self.action == "revise") != (self.content is not None):
            raise ValueError("Only revise requires replacement content")
        return self

class KnowledgeReviewInput(Input):
    expected_version: int = Field(ge=1)
    action: Literal["quarantine", "restore"]
    reason: str = Field(min_length=1, max_length=2000)

class CallInput(Input):
    tool: str = Field(min_length=1, max_length=100)
    args: dict[str, Any] = Field(default_factory=dict)
    source_ids: list[str] = Field(default_factory=list, max_length=100)
    plan: str = Field(default="", max_length=12000)
    agent_id: str = Field(default="agent-main", min_length=1, max_length=120)
    parent_call_id: str | None = None
    mcp_server: str = Field(default="local-fixture", max_length=200)
    execution_owner: Literal["fixture", "adapter"] = "fixture"
    data_references: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    purpose: str = Field(default="task", max_length=100)
    resource_facts: dict[str, Any] = Field(default_factory=dict)

class ExecuteInput(Input):
    permit: str | None = None

class ClaimInput(ExecuteInput):
    permit: str = Field(min_length=20, max_length=256)
    parameter_hash: str

class ReceiptInput(Input):
    claim_id: str
    status: Literal["succeeded", "failed", "unknown"]
    detail: str = Field(default="", max_length=4000)
    result: Any = None

class ControlInput(Input):
    parameter_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    boundary: Literal["harness_tool_entry", "sdk_callback", "mcp_forwarder"]

class ExternalEventInput(Input):
    event_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    component: str = Field(min_length=1, max_length=100)
    sequence: int = Field(ge=0)
    type: str = Field(min_length=1, max_length=100)
    references: list[str] = Field(default_factory=list, max_length=100)
    details: dict[str, Any] = Field(default_factory=dict)

class ApprovalInput(Input):
    approved: bool
    comment: str = Field(default="", max_length=2000)

class Condition(Input):
    tools: list[str] | None = None
    scope: Literal["read_only", "development"] | None = None
    risk_min: float | None = Field(default=None, ge=0, le=100)
    path_prefixes: list[str] | None = None
    destinations: list[str] | None = None
    sensitive: bool | None = None
    parameters: list[dict[str, Any]] | None = Field(default=None, max_length=16)
    json_schema: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_parameters(self):
        from .policy import validate_parameter_conditions
        validate_parameter_conditions(self.parameters)
        if self.json_schema is not None:
            from .schema_policy import validate_schema
            validate_schema(self.json_schema)
        return self

class DataInput(Input):
    source_id: str
    label: str = Field(max_length=160)
    sensitivity: Literal["public", "internal", "confidential", "credential"]
    allowed_purposes: list[str] = Field(max_length=30)
    allowed_recipients: list[str] = Field(max_length=30)

class DerivationInput(Input):
    parent_ids: list[str] = Field(min_length=1, max_length=20)
    operation: Literal["copy", "slice", "concat", "base64"]
    options: dict[str, Any] = Field(default_factory=dict)

class KnowledgeInput(Input):
    data_id: str
    title: str = Field(min_length=1, max_length=160)

class KnowledgeQuery(Input):
    query: str = Field(min_length=1, max_length=2000)
    purpose: str = Field(default="task", max_length=100)
    recipient: str = Field(default="deepseek-account", max_length=200)
    limit: int = Field(default=5, ge=1, le=10)

class ContextAdmissionInput(Input):
    source_id: str
    purpose: str = Field(default="task", max_length=100)
    recipient: str = Field(default="deepseek-account", max_length=200)

class PolicyRule(Input):
    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    enabled: bool = True
    priority: int = Field(default=50, ge=0, le=1000)
    condition: Condition
    action: Decision
    mandatory: bool = False

class PolicyInput(Input):
    version: int = Field(ge=1)
    rules: list[PolicyRule] = Field(max_length=100)

class MemoryInput(Input):
    session_id: str
    content: str = Field(min_length=1, max_length=200000)
    label: str = Field(default="新记忆", max_length=160)

class DemoInput(Input):
    scenario_id: str

class Empty(Input):
    pass

class ScriptInput(Input):
    code: str = Field(min_length=1, max_length=20000)
    label: str = Field(min_length=1, max_length=160)

class ModelRequestInput(Input):
    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=100)
    agent_id: str = Field(min_length=1, max_length=200)
    parent_agent_id: str | None = Field(default=None, max_length=200)
    host_session_id: str = Field(default="", max_length=200)
    request: dict[str, Any]
    source_ids: list[str] = Field(default_factory=list, max_length=100)

class ModelCompletionInput(Input):
    output_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    chunk_count: int = Field(ge=0)
    usage: dict[str, Any] | None = None
    finish: dict[str, Any] | None = None
    observed_at: str = Field(max_length=100)

class TokenReceiptInput(Input):
    receipt: dict[str, Any]
