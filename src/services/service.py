"""AgentCore Platform v1.0 — CMN-C1-653 domain service layer.

Deterministic domain logic for the AWS IAM least-privilege + FISC/ISMAP audit:
  - input credential-pattern scan (S-2 domain check helper)
  - IAM policy fetch (Tool-call, read-only — Step 2)
  - least-privilege static analysis vs CIS AWS Foundations Benchmark (Step 3)
  - FISC 11th-edition / ISMAP control mapping (Step 4)
  - output sanitisation: strip raw ARNs / account IDs, preserve findings (Step 6)

No agenticstar imports. No business logic lives in nodes — nodes call these
pure functions and own only the FunctionNode/state/security plumbing.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# ── S-2: embedded-credential detection (deterministic regex, NOT an LLM check) ──

_AWS_ACCESS_KEY_RE = re.compile(r"AKIA[A-Z0-9]{16}")
_AWS_SECRET_KEY_FIELD_RE = re.compile(r"aws_secret_access_key", re.IGNORECASE)
_BEARER_CRED_RE = re.compile(r"(Bearer\s+[A-Za-z0-9._-]{10,}|\"password\"\s*:|\"credential\"\s*:)", re.IGNORECASE)


def scan_for_embedded_credentials(payload: str) -> str | None:
    """Return a violation reason string if payload embeds AWS credentials, else None.

    Deterministic regex scan — this is a static-analysis check, not an LLM judgment.
    """
    if not payload:
        return None
    if _AWS_ACCESS_KEY_RE.search(payload):
        return "embedded AWS access key pattern (AKIA...) detected in policy export payload"
    if _AWS_SECRET_KEY_FIELD_RE.search(payload):
        return "embedded aws_secret_access_key field detected in policy export payload"
    if _BEARER_CRED_RE.search(payload):
        return "embedded bearer token / credential JSON field detected in policy export payload"
    return None


# ── Step 2: IAMPolicyFetch — read-only Tool-call over AWS IAM APIs ──────────────


class IamClientError(Exception):
    """Raised when the read-only AWS IAM API call fails."""


class AwsIamReadOnlyClient:
    """Thin read-only wrapper over AWS IAM APIs (GetPolicy / SimulatePrincipalPolicy /
    ListAttachedGroupPolicies). No write actions are exposed by this class.

    A real deployment injects a boto3-backed implementation via the graph config;
    tests inject a fake client. This class intentionally has no default boto3
    dependency so the template stays deterministic-core.
    """

    def __init__(self, boto_iam_client: Any | None = None) -> None:
        self._client = boto_iam_client

    def fetch_policy_data(self, iam_policy_json: str) -> dict[str, Any]:
        """Parse the caller-supplied IAM policy export.

        In production this Tool-call may additionally call GetPolicy /
        SimulatePrincipalPolicy / ListAttachedGroupPolicies against the live
        account via `self._client`; the caller-supplied export is the
        deterministic baseline used for static analysis either way.
        """
        import json

        try:
            data = json.loads(iam_policy_json) if iam_policy_json else {}
        except (ValueError, TypeError) as exc:
            raise IamClientError(f"invalid IAM policy export JSON: {exc}") from exc

        statements = data.get("Statement", data.get("statements", []))
        if isinstance(statements, dict):
            statements = [statements]
        return {"statements": statements, "policy_arns": data.get("policy_arns", [])}


# ── Step 3: LeastPrivilegeCheck — deterministic static analysis vs CIS ──────────

_WILDCARD_ACTION_PATTERNS = ("*", "*:*")
_ADMIN_EQUIVALENT_ACTIONS = ("iam:*", "*:*", "*")


def check_least_privilege(iam_policy_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic static analysis: detect over-permissive IAM statements.

    Flags wildcard actions/resources and admin-equivalent statements, per the
    CIS AWS Foundations Benchmark. Not an LLM check.
    """
    findings: list[dict[str, Any]] = []
    statements = iam_policy_data.get("statements", []) or []

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        actions = stmt.get("Action", stmt.get("action", []))
        actions = [actions] if isinstance(actions, str) else (actions or [])
        resources = stmt.get("Resource", stmt.get("resource", []))
        resources = [resources] if isinstance(resources, str) else (resources or [])
        effect = stmt.get("Effect", stmt.get("effect", "Allow"))
        statement_id = stmt.get("Sid", stmt.get("sid", f"stmt-{idx}"))
        policy_arn = stmt.get("PolicyArn", stmt.get("policy_arn", "unknown"))

        if effect != "Allow":
            continue

        is_admin_equivalent = any(a in _ADMIN_EQUIVALENT_ACTIONS for a in actions)
        has_wildcard_action = any(a in _WILDCARD_ACTION_PATTERNS or a.endswith(":*") for a in actions)
        has_wildcard_resource = any(r in _WILDCARD_ACTION_PATTERNS for r in resources)

        if is_admin_equivalent:
            findings.append(
                {
                    "policy_arn": policy_arn,
                    "statement_id": statement_id,
                    "violation_type": "admin_equivalent",
                    "severity": "critical",
                    "actions": actions,
                    "resources": resources,
                }
            )
        elif has_wildcard_action and has_wildcard_resource:
            findings.append(
                {
                    "policy_arn": policy_arn,
                    "statement_id": statement_id,
                    "violation_type": "wildcard_action_and_resource",
                    "severity": "high",
                    "actions": actions,
                    "resources": resources,
                }
            )
        elif has_wildcard_action:
            findings.append(
                {
                    "policy_arn": policy_arn,
                    "statement_id": statement_id,
                    "violation_type": "wildcard_action",
                    "severity": "medium",
                    "actions": actions,
                    "resources": resources,
                }
            )

    return findings


# ── Step 4: FISCCloudCheck — deterministic FISC/ISMAP control-mapping rule table ─

# Config-driven rule table (v1). Pending curation against the authoritative
# FISC 11th-edition + ISMAP control tables (deployer-owned); this
# table is the deterministic-core placeholder mapping violation_type -> control IDs.
_FISC_ISMAP_RULE_TABLE: dict[str, dict[str, str]] = {
    "admin_equivalent": {
        "fisc_control_id": "FISC-11-AC-01",
        "ismap_control_id": "ISMAP-AC-1.1",
    },
    "wildcard_action_and_resource": {
        "fisc_control_id": "FISC-11-AC-02",
        "ismap_control_id": "ISMAP-AC-1.2",
    },
    "wildcard_action": {
        "fisc_control_id": "FISC-11-AC-03",
        "ismap_control_id": "ISMAP-AC-1.3",
    },
}

_FIX_EXAMPLES: dict[str, str] = {
    "admin_equivalent": 'Replace "Action": "*" with the minimal explicit action list required by the workload.',
    "wildcard_action_and_resource": (
        'Scope "Resource" to specific ARNs and replace wildcard actions with an explicit action list.'
    ),
    "wildcard_action": 'Replace the service-wildcard action (e.g. "s3:*") with the specific actions used.',
}


def map_to_fisc_ismap_controls(findings: list[dict[str, Any]], compliance_scope: str) -> list[dict[str, Any]]:
    """Deterministic rule-table mapping: violation_type -> FISC/ISMAP control IDs.

    Config-driven, NOT an LLM call. `compliance_scope` in {"FISC", "ISMAP", "both"}
    controls which control-id field(s) are populated.
    """
    scope = (compliance_scope or "both").strip().upper()
    include_fisc = scope in ("FISC", "BOTH")
    include_ismap = scope in ("ISMAP", "BOTH")

    mapped: list[dict[str, Any]] = []
    for finding in findings:
        rule = _FISC_ISMAP_RULE_TABLE.get(finding["violation_type"], {})
        entry = dict(finding)
        entry["fisc_control_id"] = rule.get("fisc_control_id") if include_fisc else None
        entry["ismap_control_id"] = rule.get("ismap_control_id") if include_ismap else None
        entry["recommended_fix_example"] = _FIX_EXAMPLES.get(
            finding["violation_type"], "Review and scope this statement to least privilege."
        )
        mapped.append(entry)
    return mapped


# ── Step 6: OutputValidate — S-3 deterministic output gate (preservation variant) ─

_ARN_RE = re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+")
_ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
_ACCESS_KEY_ID_RE = re.compile(r"AKIA[A-Z0-9]{16}")


def hash_account_id(account_id: str) -> str:
    """Deterministic one-way hash — account_id_hash is the only form persisted."""
    return hashlib.sha256((account_id or "").encode("utf-8")).hexdigest()[:16]


def redact_sensitive_identifiers(text: str) -> tuple[str, bool]:
    """Strip raw ARNs / account IDs / access-key-ID patterns from free text.

    Preservation variant: this REMOVES identifiers while
    preserving the surrounding finding description / control IDs / fix
    guidance — it does not drop the whole field.
    Returns (redacted_text, was_redacted).
    """
    if not text:
        return text, False
    redacted = _ARN_RE.sub("[REDACTED_ARN]", text)
    redacted = _ACCESS_KEY_ID_RE.sub("[REDACTED_ACCESS_KEY]", redacted)
    redacted = _ACCOUNT_ID_RE.sub("[REDACTED_ACCOUNT_ID]", redacted)
    return redacted, redacted != text


def build_output_contract(
    mapped_findings: list[dict[str, Any]],
    remediation_report: str,
    account_id_hash: str,
    scan_ts: str,
    compliance_scope: str,
) -> dict[str, Any]:
    """Assemble + sanitise the locked output contract (docs/02_design.md).

    `violations[]` entries keep policy_arn / statement_id / control IDs / fix
    example (business identifiers, not AWS account/customer secrets); free-text
    fields go through redact_sensitive_identifiers() as a defence-in-depth pass.
    """
    violations = []
    critical_count = 0
    for f in mapped_findings:
        fix_example, _ = redact_sensitive_identifiers(f.get("recommended_fix_example", ""))
        if f.get("severity") == "critical":
            critical_count += 1
        violations.append(
            {
                "policy_arn": f.get("policy_arn", "unknown"),
                "statement_id": f.get("statement_id", "unknown"),
                "violation_type": f.get("violation_type", "unknown"),
                "fisc_control_id": f.get("fisc_control_id"),
                "ismap_control_id": f.get("ismap_control_id"),
                "severity": f.get("severity", "medium"),
                "recommended_fix_example": fix_example,
            }
        )

    scope = (compliance_scope or "both").strip().upper()
    summary = {
        "total_violations": len(violations),
        "critical_count": critical_count,
        "fisc_compliance_status": "non_compliant" if (scope in ("FISC", "BOTH") and violations) else "compliant",
        "ismap_compliance_status": "non_compliant" if (scope in ("ISMAP", "BOTH") and violations) else "compliant",
    }
    audit_metadata = {"account_id_hash": account_id_hash, "scan_ts": scan_ts}

    report_redacted, _ = redact_sensitive_identifiers(remediation_report or "")

    return {
        "violations": violations,
        "summary": summary,
        "audit_metadata": audit_metadata,
        "report": report_redacted,
    }
