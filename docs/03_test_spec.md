# Test Specification — CMN-C1-653 AWSIAMPermissionAuditAgent

## Test Strategy
- Coverage target: every node ≥1 success + ≥1 error/edge unit test; ≥1 full-graph integration test
- Test types: Unit (per node + services) / Integration (compile+invoke) / Proof-of-Boundary

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict | Type check pass, no Pydantic/dataclass | PASS |
| TC-02 | SecurityViolationError-equivalent fires on invalid input | `status=ERROR` + `error_log` on missing/invalid policy export, invalid scope, embedded credential | PASS |
| TC-03 | No JWT/Credential in State | CI `gate-credential-scan`: 0 violations | PASS |
| TC-04 | InvocationContext via configurable only | Direct access raises error; node uses `InvocationContext.from_state(state)` | PASS |
| TC-05 | S-4: no duplicate lifecycle events in `execute()` | `node_start` / `node_complete` / `node_error` absent from `execute()` body | 0 duplicates |
| TC-06 | S-2: `_security_gate_input()` not overridden (`FunctionNode` subclass) | `TypeError` raised at class definition if overridden (`@final` enforced by framework) | 0 overrides |
| TC-07 | S-3: `_security_gate_output()` not overridden (`FunctionNode` subclass) | `TypeError` raised at class definition if overridden (`@final` enforced by framework) | 0 overrides |
| TC-08 | `required_trust_level` enforced | `InputValidateNode`/`MainNode` = INTERNAL; ANONYMOUS caller refused | PASS |
| TC-09 | S-2: `_extra_security_gate_input()` non-trivial | Re-scans for embedded AWS credentials at the gate boundary | PASS |
| TC-10 | S-3: `_extra_security_gate_output()` non-trivial | Re-scans + redacts raw ARN/account-ID/access-key from report at the gate boundary | PASS |
| TC-11 | S-4: at least one domain `emit_trace_event()` inside each `execute()` | Domain event emitted on every invocation path (all 3 nodes) | ≥1 per node |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result | Result |
|-------|----------|------|----------------|--------|
| PB-1 | BaseNode → EventEmitter | `emit_trace_event()` fires on every invocation path | No silent failures | PASS |
| PB-2 | State serialization | Post-invoke State is primitives only | No Pydantic/dataclass | PASS |
| PB-3 | Level 2 → External service | Read-only IAM Tool-call (`AwsIamReadOnlyClient`) parses policy export | Data retrieved | PASS |
| PB-4 | Import isolation | No Level 0 imports | AST scan: 0 violations | PASS |
| PB-5 | Checkpoint safety | No JWT/Pydantic in checkpoint; raw `account_id` never in state | Inspection pass | PASS |
| PB-6 | Invoke execution order | `__call__()`: S-1 trust gate → S-4 `node_start` → S-2 `_security_gate_input` → `execute()` → S-3 `_security_gate_output` → S-4 `node_complete` | Order verified | PASS |

## Domain PB-Test Contract (the design review locked output schema)

| PB-ID | Boundary | Test | Expected Result | Result |
|-------|----------|------|----------------|--------|
| PB-D1 | Control-mapping completeness | Each `violations[]` entry carries a non-null `fisc_control_id` OR `ismap_control_id` per the requested `compliance_scope` | Deterministic control-mapping check, independent of LLM narrative | PASS (`test_service.py::TestMapToFiscIsmapControls`) |
| PB-D2 | Identifier-absence assertion | `account_id` never appears in output — only `account_id_hash` | No raw 12-digit AWS account id in `audit_metadata` / `violations` / `result` | PASS (`test_output_validate_node.py`, `test_service.py::TestHashAccountId`) |

## Business Logic Tests

| TC-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | Admin-equivalent IAM statement detected | `{"Action": "*", "Resource": "*", "Effect": "Allow"}` | `violation_type=admin_equivalent`, `severity=critical` | PASS |
| BL-02 | Least-privilege policy produces no findings | Scoped `s3:GetObject` on a specific ARN | `over_permissive_findings == []` | PASS |
| BL-03 | Embedded AWS access key rejected at InputValidate | Policy export containing `AKIA...` | `status=ERROR`, S-2 gate message | PASS |
| BL-04 | Raw ARN redacted from remediation report | Report text containing `arn:aws:iam::123456789012:...` | ARN replaced with `[REDACTED_ARN]`, finding description preserved | PASS |

## Test Execution Summary
- Execution date: 2026-07-03
- Total tests: see `pytest tests/ -v` output (unit: input/main/output/service nodes; integration: full graph; proof_of_boundary: import isolation, state safety, invoke order)
- Pass: all / Fail: 0 / Skip: 0
- Coverage: every node has ≥1 success + ≥1 error/edge unit test; 1 full-graph integration test

## 1. Deployment path tests

### TC-DEP-01 Marketplace entry point identity — `tests/unit/test_cli_entry_point.py`

| Case | Expected |
|---|---|
| Identity is concrete | `agent_name` / `namespace` are non-empty and not the runner default |
| Identity matches the HTTP entry point | the values equal what `src/api/server.py` passes to `secrets_factory`; where that entry point provisions no secrets, they equal the manifest `namespace` and the lower-cased template id |
| The runner call uses the constants | `run_agent_marketplace` is called with the module constants, not inline literals |

### TC-DEP-02 Standalone entry point boundary — `tests/proof_of_boundary/test_server_llm_injection.py`

| Case | Expected |
|---|---|
| Boots with no credential provisioned | the module imports and the app/agent objects are constructed |
| External bearer never reaches the internal level | resolves to the verified-external level |
| Staging runner credential reaches the internal level | resolves to the internal level |
| Wrong or missing bearer while auth is enabled | rejected with 401 |
