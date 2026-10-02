# CMN-C1-653 — Unit Tests: MainNode (main slot, Steps 2-5)

import json

from framework.schemas.agent_status import AgentStatus

from src.nodes.main_node import MainNode
from src.schemas.state import from_json
from src.services.service import AwsIamReadOnlyClient, IamClientError


class FakeLLM:
    def complete(self, messages: list) -> dict:
        # Canonical BaseLLM.complete() contract: returns a dict, text under "content".
        prompt = messages[-1]["content"] if messages else ""
        return {"content": "FAKE-LLM-REPORT: " + prompt[:20]}


class MalformedLLM:
    """Returns a response missing the canonical "content" key."""

    def complete(self, messages: list) -> dict:
        return {"choices": ["not the canonical shape"]}


class RaisingLLM:
    """Simulates a provider/network failure at call time."""

    def complete(self, messages: list) -> dict:
        raise RuntimeError("simulated Azure OpenAI API failure")


class FailingIamClient(AwsIamReadOnlyClient):
    def fetch_policy_data(self, iam_policy_json: str) -> dict:
        raise IamClientError("simulated AWS IAM API failure")


WILDCARD_POLICY = json.dumps(
    {
        "Statement": [
            {"Sid": "AdminAll", "Effect": "Allow", "Action": "*", "Resource": "*"},
        ]
    }
)

CLEAN_POLICY = json.dumps(
    {
        "Statement": [
            {"Sid": "ReadOnly", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
        ]
    }
)


class TestMainNode:
    """Unit tests for Steps 2-5: IAMPolicyFetch -> LeastPrivilegeCheck -> FISCCloudCheck -> RemediationReport."""

    def setup_method(self):
        self.node = MainNode(llm=FakeLLM(), iam_client=AwsIamReadOnlyClient())

    def test_success_path_with_violation(self):
        """TC: over-permissive policy -> findings detected + control-mapped + LLM report."""
        state = {
            "iam_policy_json": WILDCARD_POLICY,
            "compliance_scope": "BOTH",
            "node_history": [],
            "error_log": [],
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert len(from_json(result["over_permissive_findings"], [])) == 1
        assert from_json(result["over_permissive_findings"], [])[0]["violation_type"] == "admin_equivalent"
        assert from_json(result["control_mapped_findings"], [])[0]["fisc_control_id"] is not None
        assert from_json(result["control_mapped_findings"], [])[0]["ismap_control_id"] is not None
        assert "FAKE-LLM-REPORT" in result["remediation_report"]

    def test_clean_policy_no_violations(self):
        """TC: least-privilege policy -> no findings, deterministic no-violation report."""
        state = {
            "iam_policy_json": CLEAN_POLICY,
            "compliance_scope": "BOTH",
            "node_history": [],
            "error_log": [],
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert from_json(result["over_permissive_findings"], None) == []
        assert "No over-permissive" in result["remediation_report"]

    def test_fisc_only_scope_omits_ismap(self):
        """TC: compliance_scope=FISC -> ismap_control_id is None, fisc_control_id set."""
        state = {
            "iam_policy_json": WILDCARD_POLICY,
            "compliance_scope": "FISC",
            "node_history": [],
            "error_log": [],
        }
        result = self.node.execute(state)
        f = from_json(result["control_mapped_findings"], [])[0]
        assert f["fisc_control_id"] is not None
        assert f["ismap_control_id"] is None

    def test_iam_fetch_failure_is_error(self):
        """TC: IAM client raises IamClientError -> status ERROR, no crash."""
        node = MainNode(llm=FakeLLM(), iam_client=FailingIamClient())
        state = {
            "iam_policy_json": CLEAN_POLICY,
            "compliance_scope": "BOTH",
            "node_history": [],
            "error_log": [],
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.ERROR
        assert any("IAMPolicyFetch" in e for e in result["error_log"])

    def test_no_llm_falls_back_deterministically(self):
        """TC: no LLM configured -> deterministic fallback report is still produced."""
        node = MainNode(llm=None, iam_client=AwsIamReadOnlyClient())
        state = {
            "iam_policy_json": WILDCARD_POLICY,
            "compliance_scope": "BOTH",
            "node_history": [],
            "error_log": [],
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert "Priority-ranked remediation" in result["remediation_report"]

    def test_llm_malformed_response_falls_back_deterministically(self):
        """TC: LLM returns a response missing the canonical "content" key -> deterministic
        fallback, never a raw dict/None surfacing into remediation_report."""
        node = MainNode(llm=MalformedLLM(), iam_client=AwsIamReadOnlyClient())
        state = {
            "iam_policy_json": WILDCARD_POLICY,
            "compliance_scope": "BOTH",
            "node_history": [],
            "error_log": [],
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert isinstance(result["remediation_report"], str)
        assert "Priority-ranked remediation" in result["remediation_report"]

    def test_llm_raising_falls_back_deterministically(self):
        """TC: LLM call raises (simulated provider/network failure) -> status stays SUCCESS,
        deterministic fallback report is produced, no exception escapes execute()."""
        node = MainNode(llm=RaisingLLM(), iam_client=AwsIamReadOnlyClient())
        state = {
            "iam_policy_json": WILDCARD_POLICY,
            "compliance_scope": "BOTH",
            "node_history": [],
            "error_log": [],
        }
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert "Priority-ranked remediation" in result["remediation_report"]
