"""AgentCore Platform v1.0 — CMN-C1-653 InputValidate node (pre_process slot).

Step 1 of the design workflow: S-1 trust gate (INTERNAL) + S-2
deterministic credential scan (regex for AWS access keys / secret fields /
bearer tokens embedded in the caller-supplied IAM policy export). This is a
deterministic check, NOT an LLM judgment — SecurityViolationError-equivalent
behaviour is expressed as status=ERROR + error_log (raise-free per S-3 hook
contract; see _extra_security_gate_input()).
"""

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.service import hash_account_id, scan_for_embedded_credentials

_VALID_SCOPES = {"FISC", "ISMAP", "BOTH"}


class InputValidateNode(FunctionNode):
    """S-1 trust gate + S-2 deterministic credential scan on the policy export."""

    # S-1: this node gates access to a live IAM audit request —
    # only INTERNAL callers (cloud security engineers via the governed frontend)
    # may submit an audit. Not ANONYMOUS/VERIFIED_EXTERNAL — privileged operation.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Checking the request...",
            metadata={"step": "pre_process"},
        )
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})  # read-only [C1]

        iam_policy_json = input_context.get("iam_policy_json", "") or state.get("iam_policy_json", "")
        compliance_scope = str(input_context.get("compliance_scope", "both") or "both").upper()
        account_id = input_context.get("account_id", "")

        if not iam_policy_json:
            emit_trace_event("input_validate_rejected", {"reason": "missing_policy_export"}, state)
            return {
                "status": AgentStatus.ERROR,
                "error_log": ["InputValidateNode: iam_policy_json is required"],
            }

        if compliance_scope not in _VALID_SCOPES:
            emit_trace_event("input_validate_rejected", {"reason": "invalid_compliance_scope"}, state)
            return {
                "status": AgentStatus.ERROR,
                "error_log": [f"InputValidateNode: invalid compliance_scope '{compliance_scope}'"],
            }

        # S-2: deterministic regex scan for embedded AWS credentials — before
        # any Tool call touches this payload.
        violation = scan_for_embedded_credentials(iam_policy_json) or scan_for_embedded_credentials(user_input)
        if violation:
            emit_trace_event("input_validate_rejected", {"reason": "embedded_credential"}, state)
            return {
                "status": AgentStatus.ERROR,
                "error_log": [f"InputValidateNode: S-2 gate rejected input — {violation}"],
            }

        emit_trace_event(
            "input_validated",
            {"compliance_scope": compliance_scope, "has_account_id": bool(account_id)},
            state,
        )

        return {
            "validated_input": user_input.strip() if isinstance(user_input, str) else user_input,
            "iam_policy_json": iam_policy_json,
            "compliance_scope": compliance_scope,
            "account_id_hash": hash_account_id(account_id) if account_id else "",
            "status": AgentStatus.SUCCESS,
        }

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-2 domain hook: re-verify no embedded credential slipped through at the gate boundary."""
        payload = state.get("iam_policy_json") or state.get("validated_input") or ""
        if isinstance(payload, str):
            violation = scan_for_embedded_credentials(payload)
            if violation:
                return {
                    "status": AgentStatus.ERROR,
                    "error_log": [f"S-2 gate: {violation}"],
                }
        return state
