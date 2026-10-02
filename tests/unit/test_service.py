# CMN-C1-653 — Unit Tests: domain service layer (src/services/service.py)

import json

import pytest

from src.services.service import (
    AwsIamReadOnlyClient,
    IamClientError,
    check_least_privilege,
    hash_account_id,
    map_to_fisc_ismap_controls,
    redact_sensitive_identifiers,
    scan_for_embedded_credentials,
)


class TestScanForEmbeddedCredentials:
    def test_clean_payload_returns_none(self):
        assert scan_for_embedded_credentials('{"Statement": []}') is None

    def test_access_key_detected(self):
        assert scan_for_embedded_credentials("AKIAABCDEFGHIJKLMNOP") is not None

    def test_secret_field_detected(self):
        assert scan_for_embedded_credentials('{"aws_secret_access_key": "x"}') is not None

    def test_empty_payload_returns_none(self):
        assert scan_for_embedded_credentials("") is None


class TestAwsIamReadOnlyClient:
    def test_fetch_parses_statements(self):
        client = AwsIamReadOnlyClient()
        data = client.fetch_policy_data(json.dumps({"Statement": [{"Sid": "A"}]}))
        assert len(data["statements"]) == 1

    def test_fetch_invalid_json_raises(self):
        client = AwsIamReadOnlyClient()
        with pytest.raises(IamClientError):
            client.fetch_policy_data("not json")

    def test_fetch_empty_string_returns_empty(self):
        client = AwsIamReadOnlyClient()
        data = client.fetch_policy_data("")
        assert data["statements"] == []


class TestCheckLeastPrivilege:
    def test_admin_equivalent_detected(self):
        data = {"statements": [{"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"}]}
        findings = check_least_privilege(data)
        assert len(findings) == 1
        assert findings[0]["violation_type"] == "admin_equivalent"
        assert findings[0]["severity"] == "critical"

    def test_deny_effect_not_flagged(self):
        data = {"statements": [{"Sid": "A", "Effect": "Deny", "Action": "*", "Resource": "*"}]}
        assert check_least_privilege(data) == []

    def test_scoped_policy_not_flagged(self):
        data = {
            "statements": [
                {"Sid": "A", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
            ]
        }
        assert check_least_privilege(data) == []

    def test_wildcard_service_action_detected(self):
        data = {"statements": [{"Sid": "A", "Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"}]}
        findings = check_least_privilege(data)
        assert findings[0]["violation_type"] == "wildcard_action"


class TestMapToFiscIsmapControls:
    def test_both_scope_populates_both_ids(self):
        findings = [{"violation_type": "admin_equivalent", "policy_arn": "x", "statement_id": "y", "severity": "critical"}]
        mapped = map_to_fisc_ismap_controls(findings, "both")
        assert mapped[0]["fisc_control_id"] is not None
        assert mapped[0]["ismap_control_id"] is not None

    def test_fisc_scope_omits_ismap(self):
        findings = [{"violation_type": "admin_equivalent", "policy_arn": "x", "statement_id": "y", "severity": "critical"}]
        mapped = map_to_fisc_ismap_controls(findings, "FISC")
        assert mapped[0]["fisc_control_id"] is not None
        assert mapped[0]["ismap_control_id"] is None

    def test_ismap_scope_omits_fisc(self):
        findings = [{"violation_type": "admin_equivalent", "policy_arn": "x", "statement_id": "y", "severity": "critical"}]
        mapped = map_to_fisc_ismap_controls(findings, "ISMAP")
        assert mapped[0]["fisc_control_id"] is None
        assert mapped[0]["ismap_control_id"] is not None


class TestRedactSensitiveIdentifiers:
    def test_arn_redacted(self):
        text = "policy arn:aws:iam::123456789012:policy/Foo is bad"
        redacted, changed = redact_sensitive_identifiers(text)
        assert changed
        assert "arn:aws:iam::123456789012" not in redacted

    def test_access_key_redacted(self):
        text = "key AKIAABCDEFGHIJKLMNOP leaked"
        redacted, changed = redact_sensitive_identifiers(text)
        assert changed
        assert "AKIA" not in redacted

    def test_clean_text_unchanged(self):
        text = "no sensitive identifiers here"
        redacted, changed = redact_sensitive_identifiers(text)
        assert not changed
        assert redacted == text


class TestHashAccountId:
    def test_deterministic(self):
        assert hash_account_id("123456789012") == hash_account_id("123456789012")

    def test_different_input_different_hash(self):
        assert hash_account_id("123456789012") != hash_account_id("999999999999")

    def test_never_contains_raw_id(self):
        assert "123456789012" not in hash_account_id("123456789012")
