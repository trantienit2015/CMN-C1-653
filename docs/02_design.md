# Template Design Specification

## Position in AgentCore Architecture

- **Agent Class**: `Graph` (`src/graph/graph.py`, class `Graph(AgentBaseGraph)`)
- **L1 Base**: AgentBaseGraph
- **Three-Layer Separation**:
  - State: flat TypedDict composition (no Pydantic — msgpack incompatible)
  - Node: L1 inheritance (Template Method: `execute(self, state: dict) -> dict` override only)
  - Graph: composition (`register_nodes()` for node substitution)

## Architecture Overview

Cat 1 — single technical capability (AWS IAM least-privilege + FISC/ISMAP audit),
generic and use-case-agnostic. Flat 3-slot `AgentBaseGraph` pipeline (NOT Cat 2
GraphNode/inner-subgraph). The 6-step design workflow maps onto the fixed
3-slot pipeline as follows (the standard ">3 steps -> 3 slots + services/"
rule for Cat 1):

| Design step | AgentBaseGraph slot | Node class | Logic kind |
|---|---|---|---|
| 1. InputValidate | `pre_process` | `InputValidateNode` | S-1 INTERNAL + S-2 deterministic credential regex scan |
| 2. IAMPolicyFetch | `main` (via `src/services/service.py`) | `MainNode` calls `AwsIamReadOnlyClient.fetch_policy_data()` | Deterministic Tool-call, read-only |
| 3. LeastPrivilegeCheck | `main` (via services) | `MainNode` calls `check_least_privilege()` | Deterministic static analysis vs CIS |
| 4. FISCCloudCheck | `main` (via services) | `MainNode` calls `map_to_fisc_ismap_controls()` | Deterministic config-driven rule table |
| 5. RemediationReport | `main` | `MainNode` calls `self._llm.complete(...)` | LLM-essential (grounded synthesis) |
| 6. OutputValidate | `post_process` | `OutputValidateNode` | S-3 deterministic output gate (preservation variant) + S-4 |

### Node Configuration

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|---------------|-------------|--------------|-------------------|
| initialize | schema_version, session_id, caller_trust_level | — | — | InitializeNode (default) |
| pre_process | S-1 INTERNAL gate + S-2 credential scan on IAM policy export | `user_input`, `input_context.{iam_policy_json,compliance_scope,account_id}` | `iam_policy_json`, `compliance_scope`, `account_id_hash` | `InputValidateNode(FunctionNode)` |
| main | IAM fetch + least-privilege check + FISC/ISMAP mapping + LLM remediation | `iam_policy_json`, `compliance_scope` | `iam_policy_data`, `over_permissive_findings`, `control_mapped_findings`, `remediation_report` | `MainNode(FunctionNode)` |
| post_process | S-3 identifier redaction + output-contract assembly | `control_mapped_findings`, `remediation_report`, `account_id_hash` | `violations`, `summary`, `audit_metadata`, `result` | `OutputValidateNode(FunctionNode)` |
| finalize | response_metadata, total_time_ms | — | — | FinalizeNode (default) |

### Data Flow

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                            ↓ (retry)
                                          pre_process
```

### State Definition

| Field | Type | Purpose | Required |
|-------|------|---------|----------|
| compliance_scope | str | "FISC" \| "ISMAP" \| "BOTH" | Yes |
| iam_policy_json | str | Raw caller-supplied IAM policy export (pre-scan) | Yes |
| account_id_hash | str | S-3-safe derived identifier — never the raw account_id | Yes (may be empty) |
| iam_policy_data | dict | Parsed IAM policy statements (Step 2 output) | No |
| over_permissive_findings | list | Step 3 deterministic static-analysis output | No |
| control_mapped_findings | list | Step 4 FISC/ISMAP control-mapped findings | No |
| remediation_report | str | Step 5 LLM-synthesised report body | No |
| violations | list | Final validated `violations[]` (output contract) | No |
| summary | dict | Final validated `summary{}` (output contract) | No |
| audit_metadata | dict | Final validated `audit_metadata{}` (output contract) | No |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serializable types)
- No JWT, API keys, credentials in State (checkpoint DB leakage) — raw `account_id`
  is intentionally NOT a state field; only `account_id_hash` is persisted
- InvocationContext via `config["configurable"]` only (not in State)
- No Pydantic models, dataclass, arbitrary Python objects (msgpack incompatible)

## Framework Utilization

### Shared Components Used
- [x] InvocationContext (correlation_id, session_id, permissions, credential handle)
- [ ] ConnectionPolicy (retry/timeout strategy)
- [x] SecurityViolationError-equivalent (status=ERROR + error_log; raise-free per S-3 hook contract)
- [x] S-2: `_extra_security_gate_input()` — re-verifies no embedded AWS credential slipped through
      (`InputValidateNode`)
- [x] S-3: `_extra_security_gate_output()` — re-verifies no raw ARN/account-ID/access-key slipped
      through the report (`OutputValidateNode`, preservation variant)
- [x] S-4: `emit_trace_event()` — at least one domain-specific event inside each `execute()`

> **S-2/S-3 gate behaviour by node type (ADR-017):**
> - `FunctionNode` subclass → framework `@final` gate always runs automatically;
>   extend via `_extra_security_gate_input()` / `_extra_security_gate_output()` only
> - `GraphNode` / `RemoteAgentNode` → deliberate no-op (upstream or remote node's gate already applied)
> - Custom `BaseNode` subclass → must implement `_security_gate_input()` and
>   `_security_gate_output()` directly (`@abstractmethod` — omission raises `TypeError` at instantiation)

### Composition Pattern

- **Pattern**: Standalone (flat Cat 1 pipeline; no GraphNode/subgraph composition)
- **Composition target**: N/A
- **Error propagation strategy**: propagate (node returns `status=ERROR` + `error_log`; graph router
  sends non-SUCCESS statuses to `finalize`, no silent swallow)

## Import Isolation Confirmation
- [x] Template does not import agenticstar-platform SDK (Level 0)
- [x] Import targets: framework/ and shared/ only (no agents/base/ required)

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | **AgentBaseGraph** | Cat 1 single capability, fixed pipeline — no autonomous loop needed |
| Composition pattern | Flat 3-slot | GraphNode + inner subgraph (Cat 2) | **Flat 3-slot** | Cat 1 template; 6 workflow steps map to 3 slots + `services/` |
| Credential source | `os.environ` | `ctx.secrets.require()` | **`ctx.secrets.require()`** | S-3 — never `os.environ`; AWS credentials declared in `agent.yaml requires.secrets` |
| Account identifier in state | raw `account_id` | `account_id_hash` only | **`account_id_hash` only** | Raw account_id never persisted to state/checkpoint (S-3, PB-test contract) |

## 1. Deployment entry points

The agent is reachable through two entry points, and both resolve their runtime inputs the same way.

| Entry point | File | Used by |
|---|---|---|
| Standalone HTTP | `src/api/server.py` | staging rehearsal, direct invocation |
| Marketplace one-shot Pod | `cli.py` | the platform runner (container `CMD`) |

Both read runtime parameters from `config/config.yaml` — the manifest carries discovery metadata
only — and both scope secrets to the same location (`namespace=cmn`, `agent_name=cmn-c1-653`), so a
secret provisioned for one path resolves identically on the other.

**Deployment-provided LLM client.** The three Azure OpenAI connection values
(`AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` — the bare resource endpoint — and
`AZURE_OPENAI_DEPLOYMENT`) are resolved through the agent's own secret provider, never from the
process environment. Both entry points build the client only when all three resolve and pass it in
as `config["llm"]`; when any is absent the key stays unset and the graph keeps its deterministic
path. The manifest declares the three secrets and the provider extra.

Even when the client is configured, `MainNode._generate_remediation_report()` treats the call as
best-effort: a provider/network error, or a response that does not match the canonical
`BaseLLM.complete()` shape (`{"content": str, ...}`), degrades to the same deterministic
`_fallback_report()` used when no client is configured at all — `RemediationReport` never raises
and `status` never becomes `error` on account of the LLM alone.

**Progress events.** Each pipeline stage emits a non-terminal progress event at its start, so a
caller sees the run advancing. Outside the Marketplace runtime the emitter resolves to a no-op, so
the same code is safe on every path. Terminal events belong to the platform runner and are never
emitted by this agent.

**Caller authentication at the standalone entry point.** A caller that no upstream middleware
vouched for stays anonymous unless it presents a deployment-level credential: the external bearer
token grants the verified-external level, and a separate staging-only runner credential is the only
way to reach the internal level. Trust established upstream is never changed.

**Known constraint — Marketplace one-shot Pod entry point.** `required_trust_level: INTERNAL`
(this template's S-1 requirement — IAM policy exports and account identifiers are internal-only
data) is currently incompatible with the Marketplace one-shot Pod runtime: AgentCore 1.0.3's
`run_agent_marketplace` entry point hard-stamps every caller `VERIFIED_EXTERNAL` with no elevation
path, so the S-1 gate rejects every invocation reaching this agent through `cli.py` / the
Marketplace Pod (confirmed by verifying the built image locally before push). The
Standalone HTTP entry point (`src/api/server.py`) is unaffected — trust is established upstream
there and can reach `INTERNAL`.

This is a platform contract gap, not a template defect — the Marketplace entry point's caller-trust
handling is already a known, tracked limitation of the platform runtime, independent of this
template. Lowering this template's `required_trust_level` to force Marketplace compatibility is
rejected as a workaround — it widens a security boundary and needs a PM/architect decision, not a
code change. Until the platform resolves trust elevation, the Marketplace one-shot Pod entry point
is **out of scope for real-stg / Marketplace registration** for this template; the Standalone HTTP
entry point remains the supported deployment path. This is a present-state constraint, not a
permanent exclusion.
