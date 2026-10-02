"""AgentCore Platform v1.0 — CMN-C1-653 OutputValidate node (post_process slot).

Step 6 of the design workflow: S-3 deterministic output gate
(preservation variant) — block raw ARNs / account IDs / internal policy
detail / access-key-ID patterns from the report while preserving violation
descriptions + control IDs + fix recommendations. On a redaction event this
drops/masks the offending substring and logs via emit_trace_event (no silent
suppression of the whole field).
"""

import json
from datetime import datetime, timezone
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json
from src.services.service import build_output_contract, redact_sensitive_identifiers


class OutputValidateNode(FunctionNode):
    """S-3 deterministic output gate: identifier redaction + output-contract assembly."""

    # S-1: explicit by design, not inherited implicitly.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # ADR-005 (a review finding): step outputs travel through state as JSON strings.
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Preparing the result...",
            metadata={"step": "post_process"},
        )
        control_mapped_findings = from_json(state.get("control_mapped_findings"), [])
        remediation_report = state.get("remediation_report", "")
        account_id_hash = state.get("account_id_hash", "")
        compliance_scope = state.get("compliance_scope", "BOTH")

        scan_ts = datetime.now(timezone.utc).isoformat()
        contract = build_output_contract(
            mapped_findings=control_mapped_findings,
            remediation_report=remediation_report,
            account_id_hash=account_id_hash,
            scan_ts=scan_ts,
            compliance_scope=compliance_scope,
        )

        emit_trace_event(
            "output_validated",
            {
                "account_scope": bool(account_id_hash),
                "compliance_scope": compliance_scope,
                "violation_count": contract["summary"]["total_violations"],
            },
            state,
        )

        # AgentBaseGraph.get_output() surfaces only `formatted_output`/`result`
        # to the caller (the locked output contract's violations/summary/
        # audit_metadata fields do not otherwise reach the API response) — so
        # the full contract is serialised as JSON into result/formatted_output.
        # `state["violations"/"summary"/"audit_metadata"]` remain available for
        # in-process callers / tests.
        output_payload = json.dumps(
            {
                "violations": contract["violations"],
                "summary": contract["summary"],
                "audit_metadata": contract["audit_metadata"],
                "report": contract["report"],
            }
        )

        return {
            # ADR-005 (a review finding): output-contract fields stored as JSON strings in state
            # (in-process callers/tests decode via from_json).
            "violations": to_json(contract["violations"]),
            "summary": to_json(contract["summary"]),
            "audit_metadata": to_json(contract["audit_metadata"]),
            "result": output_payload,
            "formatted_output": output_payload,
            "status": AgentStatus.SUCCESS,
        }

    def _extra_security_gate_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-3 domain hook: re-verify no raw ARN/account-ID/access-key slipped through."""
        report = state.get("result") or state.get("formatted_output") or ""
        if isinstance(report, str):
            redacted, was_redacted = redact_sensitive_identifiers(report)
            if was_redacted:
                emit_trace_event("output_gate_redacted", {"field": "result"}, state)
                new_state = dict(state)
                new_state["result"] = redacted
                new_state["formatted_output"] = redacted
                return new_state
        return state
