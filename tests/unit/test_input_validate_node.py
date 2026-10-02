# CMN-C1-653 — Unit Tests: InputValidateNode (pre_process slot, Step 1)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.pre_process_node import InputValidateNode


class TestInputValidateNode:
    """Unit tests for Step 1 InputValidate (S-1 INTERNAL + S-2 credential scan)."""

    def setup_method(self):
        self.node = InputValidateNode()

    def _state(self, iam_policy_json="", compliance_scope="both", account_id="123456789012", user_input="audit"):
        return {
            "user_input": user_input,
            "input_context": {
                "iam_policy_json": iam_policy_json,
                "compliance_scope": compliance_scope,
                "account_id": account_id,
            },
            "node_history": [],
            "error_log": [],
        }

    def test_success_path(self):
        """TC: valid policy export + valid scope -> SUCCESS, account_id_hash set."""
        state = self._state(iam_policy_json='{"Statement": []}')
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["iam_policy_json"] == '{"Statement": []}'
        assert result["compliance_scope"] == "BOTH"
        assert result["account_id_hash"] != ""
        assert "123456789012" not in result["account_id_hash"]

    def test_missing_policy_export_is_error(self):
        """TC: empty iam_policy_json -> ERROR, no Tool call attempted."""
        state = self._state(iam_policy_json="")
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR
        assert any("iam_policy_json" in e for e in result["error_log"])

    def test_invalid_compliance_scope_is_error(self):
        """TC: unsupported compliance_scope value -> ERROR."""
        state = self._state(iam_policy_json='{"Statement": []}', compliance_scope="gdpr")
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR

    def test_embedded_aws_access_key_rejected(self):
        """TC: S-2 — embedded AWS access key in payload -> ERROR (deterministic, not LLM)."""
        state = self._state(iam_policy_json='{"note": "AKIAABCDEFGHIJKLMNOP"}')
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR
        assert any("S-2 gate" in e for e in result["error_log"])

    def test_embedded_secret_field_rejected(self):
        """TC: S-2 — aws_secret_access_key field in payload -> ERROR."""
        state = self._state(iam_policy_json='{"aws_secret_access_key": "abc123"}')
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR

    def test_trust_gate_denies_below_internal(self):
        """S-1: caller below INTERNAL is denied by the framework trust gate (via __call__)."""
        state = self._state(iam_policy_json='{"Statement": []}')
        state["caller_trust_level"] = TrustLevel.ANONYMOUS.value
        state["correlation_id"] = "test-corr"
        result = self.node(state)
        assert result["status"] == AgentStatus.ERROR.value
        assert any("trust gate" in e.lower() or "s-1" in e.lower() for e in result.get("error_log", []))

    def test_extra_security_gate_input_contract(self):
        """S-2 hook: _extra_security_gate_input must return a dict, never raise, never None."""
        clean_state = {"iam_policy_json": '{"Statement": []}'}
        out = self.node._extra_security_gate_input(clean_state)
        assert isinstance(out, dict)
        assert out is clean_state or out.get("status") != AgentStatus.ERROR

        dirty_state = {"iam_policy_json": "AKIAABCDEFGHIJKLMNOP"}
        out2 = self.node._extra_security_gate_input(dirty_state)
        assert isinstance(out2, dict)
        assert out2["status"] == AgentStatus.ERROR
