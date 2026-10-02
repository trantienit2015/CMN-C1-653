# CMN-C1-653 — Unit Tests: OutputValidateNode (post_process slot, Step 6)

from framework.schemas.agent_status import AgentStatus

from src.nodes.post_process_node import OutputValidateNode
from src.schemas.state import from_json


class TestOutputValidateNode:
    """Unit tests for Step 6 OutputValidate (S-3 identifier redaction + output contract)."""

    def setup_method(self):
        self.node = OutputValidateNode()

    def _state(self, findings=None, report="", account_id_hash="abc123", scope="BOTH"):
        return {
            "control_mapped_findings": findings or [],
            "remediation_report": report,
            "account_id_hash": account_id_hash,
            "compliance_scope": scope,
            "node_history": [],
            "error_log": [],
        }

    def test_success_path_builds_output_contract(self):
        """TC: findings -> violations[] with control IDs, summary, audit_metadata."""
        findings = [
            {
                "policy_arn": "arn:aws:iam::123456789012:policy/Admin",
                "statement_id": "AdminAll",
                "violation_type": "admin_equivalent",
                "severity": "critical",
                "fisc_control_id": "FISC-11-AC-01",
                "ismap_control_id": "ISMAP-AC-1.1",
                "recommended_fix_example": "Scope down the policy.",
            }
        ]
        state = self._state(findings=findings, report="Fix the admin policy.")
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert len(from_json(result["violations"], [])) == 1
        assert from_json(result["summary"], {})["total_violations"] == 1
        assert from_json(result["summary"], {})["critical_count"] == 1
        assert from_json(result["audit_metadata"], {})["account_id_hash"] == "abc123"
        assert "account_id_hash" in from_json(result["audit_metadata"], {})

    def test_raw_arn_redacted_from_report(self):
        """TC: S-3 — raw ARN in report text is redacted, description preserved (preservation variant)."""
        findings = []
        report = "See arn:aws:iam::123456789012:policy/Foo for the offending policy."
        state = self._state(findings=findings, report=report)
        result = self.node.execute(state)
        assert "arn:aws:iam::123456789012" not in result["result"]
        assert "[REDACTED_ARN]" in result["result"] or "[REDACTED_ACCOUNT_ID]" in result["result"]

    def test_no_violations_compliant_summary(self):
        """TC: empty findings -> compliant summary status."""
        state = self._state(findings=[])
        result = self.node.execute(state)
        assert from_json(result["summary"], {})["fisc_compliance_status"] == "compliant"
        assert from_json(result["summary"], {})["ismap_compliance_status"] == "compliant"

    def test_extra_security_gate_output_contract(self):
        """S-3 hook: _extra_security_gate_output must return a dict, never raise, never None."""
        clean_state = {"result": "no sensitive identifiers here"}
        out = self.node._extra_security_gate_output(clean_state)
        assert isinstance(out, dict)

        dirty_state = {"result": "account 123456789012 arn:aws:iam::123456789012:policy/X"}
        out2 = self.node._extra_security_gate_output(dirty_state)
        assert isinstance(out2, dict)
        assert "123456789012" not in out2["result"]
