"""AgentCore Platform v1.0 — CMN-C1-653 AWSIAMPermissionAuditAgent state."""

# ADR-005: State must be a flat TypedDict — never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption.  Extend AgentState with agent-specific
# fields only.  Do NOT add credentials, secrets, or Pydantic models.

import json
from typing import Any, NotRequired, Optional

from framework.schemas.agent_state import AgentState


def to_json(value: Any) -> Optional[str]:
    """Serialize a list/dict State value to a compact JSON string (ADR-005, msgpack-safe).

    Returns None for None so the field stays a true Optional[str].
    """
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def from_json(value: Any, default: Any) -> Any:
    """Deserialize a JSON-string State value back to its list/dict form.

    Tolerant by design: None/empty -> default; an already-native list/dict (e.g. a value
    supplied directly in a unit test) passes through unchanged; a malformed string -> default.
    """
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class State(AgentState):
    """Agent state for the AWS IAM least-privilege + FISC/ISMAP audit agent.

    Add only fields specific to this agent below. All shared fields
    (user_input, status, session_id, node_history, error_log, hitl_*, etc.)
    are inherited from AgentState.

    All agent-specific fields are NotRequired (written mid-pipeline; absent
    from early checkpoints — C8). Nested dict/list step outputs are stored as
    JSON strings via to_json()/from_json() (ADR-005 / a review finding: deeply nested
    structures in state risk msgpack issues even when the top-level type is
    dict/list).

    Security note: `account_id` (raw AWS account id) is only ever held
    transiently inside node-local computation — it is intentionally NOT a
    state field. Only `account_id_hash` (the S-3-safe derived identifier)
    is persisted to state / checkpoint / output.
    """

    compliance_scope: NotRequired[str]  # "FISC" | "ISMAP" | "both"
    iam_policy_json: NotRequired[str]  # raw JSON string supplied by caller (pre-scan)
    account_id_hash: NotRequired[str]  # S-3-safe identifier — never the raw account_id
    # Step 2 output — JSON {statements: [...]} (ADR-005: JSON string, not a native dict).
    iam_policy_data: NotRequired[str | None]
    # Step 3 output — JSON list of least-privilege findings.
    over_permissive_findings: NotRequired[str | None]
    # Step 4 output — JSON list of FISC/ISMAP control-mapped findings.
    control_mapped_findings: NotRequired[str | None]
    remediation_report: NotRequired[str]  # Step 5 LLM-synthesised report body
    # Final validated output contract — JSON strings (ADR-005).
    violations: NotRequired[str | None]
    summary: NotRequired[str | None]
    audit_metadata: NotRequired[str | None]
