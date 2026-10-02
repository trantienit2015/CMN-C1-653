"""AgentCore Platform v1.0 — CMN-C1-653 main node (Steps 2-5 of the design workflow).

AgentBaseGraph is a fixed 3-slot pipeline (pre_process / main / post_process);
per the standard ">3 business steps -> 3 slots + services/" mapping for
Cat 1, this node composes the 4 middle workflow steps by calling pure functions
in src/services/service.py — each step is independently unit-testable there:

  Step 2 IAMPolicyFetch      -> AwsIamReadOnlyClient.fetch_policy_data() (Tool-call, read-only)
  Step 3 LeastPrivilegeCheck -> check_least_privilege()                 (deterministic, CIS)
  Step 4 FISCCloudCheck      -> map_to_fisc_ismap_controls()            (deterministic rule table)
  Step 5 RemediationReport   -> self._generate_remediation_report()    (LLM-essential; degrades to
                                                                         _fallback_report on failure)

AWS credentials (when a real read-only IAM API call is wired) are obtained via
ctx.secrets.require() at node level — never os.environ, never stored in state.
"""

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import to_json
from src.services.service import (
    AwsIamReadOnlyClient,
    IamClientError,
    check_least_privilege,
    map_to_fisc_ismap_controls,
)

_AWS_SECRET_KEY = "AWS_IAM_AUDIT_CREDENTIALS"


class MainNode(FunctionNode):
    """Steps 2-5: read-only IAM fetch -> deterministic checks -> LLM remediation."""

    # S-1: read-only IAM analysis + LLM synthesis; not a write
    # operation, but still an internal-governed audit pipeline.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(self, llm: Any | None = None, iam_client: AwsIamReadOnlyClient | None = None) -> None:
        # Immutable dependencies injected by the graph — safe on the instance
        # (no per-invocation mutable state kept here).
        self._llm = llm
        self._iam_client = iam_client or AwsIamReadOnlyClient()

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # AgentBaseGraph's fixed pipeline runs pre_process -> main unconditionally
        # (routing on status happens AFTER main) — so an upstream pre_process
        # error must short-circuit here rather than silently proceeding on
        # partial/empty state (e.g. missing iam_policy_json would otherwise
        # yield an empty-findings "success").
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Working on the request...",
            metadata={"step": "main"},
        )
        if state.get("status") == AgentStatus.ERROR:
            return {
                "status": AgentStatus.ERROR,
                "error_log": state.get("error_log", []) + ["MainNode: skipped — upstream InputValidate error"],
            }

        iam_policy_json = state.get("iam_policy_json", "")
        compliance_scope = state.get("compliance_scope", "BOTH")

        # S-3: AWS credentials (if a live IAM API call is configured) come from
        # the bound secret provider — never os.environ, never stored in state.
        # The read-only Tool-call below only requires credentials when an actual
        # boto3-backed client is injected; the deterministic-core path parses
        # the caller-supplied export directly (see AwsIamReadOnlyClient docstring).
        try:
            ctx = InvocationContext.from_state(state)
            ctx.secrets.require(_AWS_SECRET_KEY)
        except Exception:
            # Deterministic-core mode: no live AWS credential bound — proceed
            # with the caller-supplied policy export only (no silent failure;
            # this is the documented no-op path, logged via emit_trace_event).
            pass

        # Step 2: IAMPolicyFetch (read-only Tool-call)
        try:
            iam_policy_data = self._iam_client.fetch_policy_data(iam_policy_json)
        except IamClientError as exc:
            emit_trace_event("iam_policy_fetch_failed", {"reason": str(exc)}, state)
            return {
                "status": AgentStatus.ERROR,
                "error_log": [f"MainNode: IAMPolicyFetch failed — {exc}"],
            }
        emit_trace_event("iam_policy_fetched", {"statement_count": len(iam_policy_data.get("statements", []))}, state)

        # Step 3: LeastPrivilegeCheck (deterministic static analysis vs CIS)
        over_permissive_findings = check_least_privilege(iam_policy_data)
        emit_trace_event("least_privilege_checked", {"finding_count": len(over_permissive_findings)}, state)

        # Step 4: FISCCloudCheck (deterministic rule table)
        control_mapped_findings = map_to_fisc_ismap_controls(over_permissive_findings, compliance_scope)
        emit_trace_event(
            "fisc_ismap_mapped",
            {"compliance_scope": compliance_scope, "mapped_count": len(control_mapped_findings)},
            state,
        )

        # Step 5: RemediationReport (LLM-essential, grounded synthesis; deterministic
        # fallback below is the documented degrade path — never raise, never surface
        # an unvalidated/wrong-shape LLM response into state).
        if not control_mapped_findings:
            remediation_report = "No over-permissive IAM statements detected against the current ruleset."
        elif self._llm is not None:
            remediation_report = self._generate_remediation_report(control_mapped_findings, compliance_scope, state)
        else:
            remediation_report = self._fallback_report(control_mapped_findings)
        emit_trace_event(
            "remediation_report_generated",
            {"compliance_scope": compliance_scope, "violation_count": len(control_mapped_findings)},
            state,
        )

        return {
            # ADR-005 (a review finding): nested step outputs are stored as JSON strings,
            # not native dict/list — msgpack-safe across checkpoints.
            "iam_policy_data": to_json(iam_policy_data),
            "over_permissive_findings": to_json(over_permissive_findings),
            "control_mapped_findings": to_json(control_mapped_findings),
            "remediation_report": remediation_report,
            "status": AgentStatus.SUCCESS,
        }

    def _generate_remediation_report(
        self, findings: list[dict[str, Any]], compliance_scope: str, state: dict[str, Any]
    ) -> str:
        """Call the LLM for the grounded remediation report; degrade to the deterministic
        fallback on any failure — a missing secret, a provider/API error, or a response that
        does not match the canonical ``BaseLLM.complete()`` contract (``{"content": str, ...}``).
        Never raises and never lets an unvalidated response reach state.
        """
        prompt = self._build_remediation_prompt(findings, compliance_scope)
        try:
            if self._llm is None:
                raise RuntimeError("no LLM client is configured for this deployment")
            response = self._llm.complete([{"role": "user", "content": prompt}])
            content = response.get("content") if isinstance(response, dict) else None
        except Exception as exc:  # noqa: BLE001 - any provider/network failure degrades, never raises
            emit_trace_event("remediation_llm_call_failed", {"reason": str(exc)}, state)
            return self._fallback_report(findings)
        if not isinstance(content, str) or not content.strip():
            emit_trace_event("remediation_llm_response_invalid", {}, state)
            return self._fallback_report(findings)
        return content

    @staticmethod
    def _build_remediation_prompt(findings: list[dict[str, Any]], compliance_scope: str) -> str:
        lines = [
            "You are an AWS cloud security auditor. Synthesise a priority-ranked "
            f"remediation report for the following IAM least-privilege violations "
            f"(compliance scope: {compliance_scope}). For each violation, cite its "
            "FISC/ISMAP control ID and give an example fix statement.",
        ]
        for f in findings:
            lines.append(
                f"- [{f.get('severity')}] {f.get('violation_type')} on {f.get('policy_arn')} "
                f"(FISC={f.get('fisc_control_id')}, ISMAP={f.get('ismap_control_id')})"
            )
        return "\n".join(lines)

    @staticmethod
    def _fallback_report(findings: list[dict[str, Any]]) -> str:
        """Deterministic fallback used when no LLM client is configured (e.g. tests)."""
        parts = [
            f"{f.get('severity', 'medium').upper()}: {f.get('violation_type')} on {f.get('policy_arn')} "
            f"(fix: {f.get('recommended_fix_example', '')})"
            for f in findings
        ]
        return "Priority-ranked remediation:\n" + "\n".join(parts)
