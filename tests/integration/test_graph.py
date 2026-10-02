# CMN-C1-653 — Integration test: full graph compile + invoke

import json

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph

WILDCARD_POLICY = (
    '{"Statement": [{"Sid": "AdminAll", "Effect": "Allow", "Action": "*", "Resource": "*"}]}'
)


class FakeLLM:
    def complete(self, prompt: str) -> str:
        return "Remediation: scope down the admin-equivalent policy."


class TestAgentIntegration:
    def test_full_pipeline_success(self):
        agent = Graph(config={"llm": FakeLLM(), "max_retry": 1})
        agent.compile()

        ctx = InvocationContext(
            session_id="itest-1",
            caller_trust_level=TrustLevel.INTERNAL,
            caller_id="itest-caller",
        )
        result = agent.invoke(
            "audit account 123456789012",
            ctx=ctx,
            input_context={
                "account_id": "123456789012",
                "iam_policy_json": WILDCARD_POLICY,
                "compliance_scope": "both",
            },
        )

        assert result["status"] == "success"
        node_history = result.get("node_history", [])
        assert len(node_history) >= 5

        # AgentBaseGraph.get_output() surfaces only `output` (= formatted_output)
        # to the caller — OutputValidateNode serialises the locked output
        # contract (violations/summary/audit_metadata/report) as JSON into it.
        output = result.get("output", "")
        assert isinstance(output, str)
        payload = json.loads(output)
        assert len(payload["violations"]) == 1
        assert payload["violations"][0]["violation_type"] == "admin_equivalent"
        assert payload["summary"]["total_violations"] == 1
        assert "account_id_hash" in payload["audit_metadata"]
        assert "123456789012" not in output

    def test_missing_policy_export_yields_error_status(self):
        agent = Graph(config={"llm": FakeLLM(), "max_retry": 1})
        agent.compile()

        ctx = InvocationContext(
            session_id="itest-2",
            caller_trust_level=TrustLevel.INTERNAL,
            caller_id="itest-caller",
        )
        result = agent.invoke(
            "audit with no policy",
            ctx=ctx,
            input_context={"account_id": "123456789012", "compliance_scope": "both"},
        )
        assert result["status"] in ("error", "cancelled")

    def test_anonymous_caller_denied_by_trust_gate(self):
        agent = Graph(config={"llm": FakeLLM(), "max_retry": 1})
        agent.compile()

        ctx = InvocationContext(
            session_id="itest-3",
            caller_trust_level=TrustLevel.ANONYMOUS,
            caller_id="itest-caller",
        )
        result = agent.invoke(
            "audit account 123456789012",
            ctx=ctx,
            input_context={
                "account_id": "123456789012",
                "iam_policy_json": WILDCARD_POLICY,
                "compliance_scope": "both",
            },
        )
        assert result["status"] in ("error", "cancelled")
