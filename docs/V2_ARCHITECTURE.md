# V2 Architecture — atlasent-sdk deliverables (historical filename)

**Status**: design · **Canonical plan**:
the internal canonical `V2_ARCHITECTURE.md` (docs repo, not public)

> **Reframing normalization header (2026-05-18).** Per
> the internal `VERSIONING_DOCTRINE.md`
> the platform-generation `v2 / v3` framing has been retired. There is
> no "AtlaSent v2.0.0" platform release. The SDK work captured here
> ships **additively on the stable AtlaSent v1 contract** and is
> sequenced across **Phase 1 — Stabilization & Pilot Readiness**
> (`recordExecutionResult`, `replayDecision`, `guard` wrapper, framework
> guards), **Phase 2 — Enterprise Hardening** (compliance / evidence
> tooling, AI gate composition), and **Phase 3 — Execution Assurance**
> (deterministic-replay verifier extensions, mTLS / SPIFFE workload
> identity).
>
> **Per-package SemVer is independent of platform phases** per
> Doctrine 5. References below to "`@atlasent/sdk@2.0.0`",
> "`atlasent==2.0.0`", "v2.0.0 tag", and "Version 2.0.0 tag on both
> `@atlasent/sdk` and `atlasent` (pypi)" are **per-language SDK
> SemVer majors** — they are an SDK ergonomics/typing change, not an
> "AtlaSent v2" platform release. Contract schema directories
> (`contract/schemas/`), code-level wire-type identifiers
> (`ExecutionResultWire`, `DecisionReplayWire`, etc.), preview
> package names (`@atlasent/anthropic-middleware`,
> `@atlasent/openai-middleware`, `@atlasent/claude-code`,
> `@atlasent/cursor`, `@atlasent/langchain`, `@atlasent/llamaindex`),
> and references to `Phases 1–5` in the rollout-order section
> (which are SDK-internal phase numbers, not the platform-wide
> Phase 1 / 2 / 3) are all code-level / SDK-local identifiers
> preserved per Doctrines 3, 4, and 5.

This doc is the SDK-specific task list — TypeScript + Python parity —
for the additive SDK capabilities that ship on the `v1` contract.
Vision, phases, and cross-repo contract live in the canonical plan;
read that first.

---

## What the SDKs own in v2

- **Client methods** for the new execution-governance surface:
  `recordExecutionResult` / `record_execution_result`,
  `replayDecision` / `replay_decision`,
  `runRedteamScenario` / `run_redteam_scenario`.
- **The `guard` wrapper** — one call around a tool invocation that
  does evaluate → permit → execute → record-execution-result → done.
  This is how agent authors adopt v2 without writing any permit
  plumbing themselves.
- **Contract schemas** in `contract/schemas/` for every new endpoint
  so the existing drift detector (`contract/tools/drift.py`, already
  generalised in v1.4 to handle GET / projections / reference-only
  shapes) catches wire drift automatically.
- **Version 2.0.0 tag** on both `@atlasent/sdk` and `atlasent` (pypi),
  coordinated release.

---

## TypeScript surface

```ts
// Existing (v1):
atlasent.evaluate()
atlasent.permit()               // aka protect()
atlasent.verifyPermit()

// New in v2:
atlasent.recordExecutionResult({
  permitId: string,
  actorId: string,
  actionType: string,
  toolCalls: ToolCallTrace[],
  outputFingerprint?: string,
  succeeded: boolean,
  errorCode?: string,
  errorMessage?: string,
  startedAt: Date,
  completedAt: Date,
});

atlasent.replayDecision(evaluationId: string): Promise<DecisionReplay>;

atlasent.runRedteamScenario(scenarioId: string, opts?: {
  policyBundleId?: string,
}): Promise<RedteamResult>;

// The one that agent authors will actually call:
await atlasent.guard({
  actor,
  action,
  resource,
  payload,
  execute: async () => tool.call(args),
});
// guard() internally:
//   1. evaluate → permit
//   2. await execute()  (or throw AtlaSentDeniedError on deny)
//   3. recordExecutionResult(... with result + duration + error capture)
//   4. return the execute() return value
```

### New public types

```ts
export interface ToolCallTrace {
  tool: string;
  args: Record<string, unknown>;
  at: string;              // ISO 8601
}

export type VarianceKind =
  | 'NONE'
  | 'EXECUTION_DRIFT'
  | 'BINDING_MISMATCH'
  | 'CHAIN_ESCAPE';

export interface ExecutionResult { /* mirrors the server wire; see console doc */ }
export interface PostExecutionEvaluation { /* ditto */ }
export interface DecisionReplay {
  evaluation: EvaluateResponse;
  permit: Permit | null;
  execution: ExecutionResult | null;
  postEvaluation: PostExecutionEvaluation | null;
}
export interface RedteamResult {
  scenarioId: string;
  passed: boolean;
  expectedOutcome: 'allow' | 'deny' | 'hold' | 'escalate';
  actualOutcome: 'allow' | 'deny' | 'hold' | 'escalate';
  variance: VarianceKind;
  runAt: string;
}
```

---

## Python surface

Mirror everything above, with sync + async variants where they exist
in v1 already (evaluate, verify, gate, protect):

```python
# Existing (v1):
client.evaluate(...)
client.verify(...)
client.gate(...)
client.protect(...)

# New in v2:
client.record_execution_result(
    permit_id: str,
    actor_id: str,
    action_type: str,
    tool_calls: list[ToolCallTrace],
    output_fingerprint: str | None = None,
    succeeded: bool,
    error_code: str | None = None,
    error_message: str | None = None,
    started_at: datetime,
    completed_at: datetime,
) -> ExecutionResult
client.replay_decision(evaluation_id: str) -> DecisionReplay
client.run_redteam_scenario(
    scenario_id: str,
    *,
    policy_bundle_id: str | None = None,
) -> RedteamResult

# Decorator for agent authors:
@atlasent.guard(action="send_email", resource="customer_data")
def send_email(to: str, subject: str, body: str) -> None:
    ...
# @atlasent.guard equivalent for async:
@atlasent.guard_async(...)
async def send_email_async(...): ...
```

Pydantic models for `ExecutionResult`, `PostExecutionEvaluation`,
`ToolCallTrace`, `DecisionReplay`, `RedteamResult` in
`atlasent/models.py`; exports wired into `atlasent/__init__.py`.

The `@atlasent.guard` decorator is the adoption moat: one line per
tool function and the full loop runs.

---

## Contract schemas (new)

```
contract/schemas/
  execution-result.schema.json          ← what the client POSTs and the server returns
  post-evaluation.schema.json
  redteam-scenario.schema.json
  redteam-run.schema.json
  redteam-result.schema.json
  decision-replay.schema.json
```

Each extends the pattern already used by
`evaluate-request.schema.json` / `api-key-self.schema.json`:
`$id`, `title`, `description`, `required`, `properties`,
`additionalProperties: true` so the server can extend the envelope
without breaking older clients.

### Drift coverage

`contract/tools/drift.py` registers the new endpoints automatically
once the SDKs have the matching models (the v1.4 generalisation
supports `request_keys: None` for GET-only endpoints and a
`non_wire` allow-set for runtime-annotated fields). New entries:

| Endpoint | Python model | TS interface |
|---|---|---|
| `/v1-execution-results` POST | `ExecutionResult` | `ExecutionResultWire` |
| `/v1-post-evaluations` POST / GET | `PostExecutionEvaluation` | `PostEvaluationWire` |
| `/v1-decisions/:id/replay` GET | `DecisionReplay` | `DecisionReplayWire` |
| `/v1-redteam/runs` POST / GET | `RedteamRun` / `RedteamResult` | `RedteamRunWire` / `RedteamResultWire` |

---

## Rollout order (matches canonical Phases 1–5)

1. **`recordExecutionResult` / `record_execution_result` + schema.**
   SDKs can emit execution results. `@atlasent.guard` not yet wired.
2. **`@atlasent.guard` decorator + Node wrapper.** Single-line agent
   adoption. Internally calls 1.
3. **`replayDecision` / `replay_decision` + schema.** Read path so
   agent authors can fetch the full trace for debugging.
4. **`runRedteamScenario` + schema.** Developer-facing path for
   running the shared scenario library locally.
5. **Tag 2.0.0 on both SDKs.** Matches the coordinated release across
   `atlasent-api` + `atlasent-console`.

Each step ships as a minor on the 1.x line (1.5.0 → 1.6.0 → …). The
2.0.0 tag coincides with the coordinated cross-repo release, not a
specific SDK change.

---

## Tests

Every new method gets the same coverage pattern v1 established:

- **Python**: happy path, method-is-GET/POST pin (regression guard
  against future `_request` refactors flipping verbs), defaults for
  optional fields, `bad_response` on missing required fields, 401 →
  `AtlaSentError(invalid_api_key)`, 429 → `RateLimitError`,
  rate-limit header surfacing. Sync + async.
- **TypeScript**: snake→camel mapping, rate-limit plumbing, null
  defaulting, bad_response, 401 propagation.
- **Contract**: `python contract/tools/drift.py` must emit `No drift`
  across all 3+n endpoints × 2 SDKs before merging any v2 PR.

---

## CHANGELOG cadence

Python:

```
## 2.0.0 — <date>

### Added
- record_execution_result (sync + async)
- replay_decision (sync + async)
- run_redteam_scenario (sync + async)
- @atlasent.guard decorator (sync + async)
- ExecutionResult, PostExecutionEvaluation, DecisionReplay,
  RedteamResult, ToolCallTrace pydantic models

### Non-breaking
Purely additive. All v1 methods retained identically.
```

TypeScript CHANGELOG mirrors.

---

## Growth waves — SDK surface impact

All seven waves are **in-scope for v2.0.0**. Full spec:
the internal canonical plan, "Growth waves" section.
First-ships: Anthropic SDK middleware (Wave F), SOC2 Type II (Wave G).

This repo's slice of each wave:

| Wave | `atlasent-sdk` is... | What to add |
|---|---|---|
| F — guards | **primary** | New packages, each ~500 LOC, separate publish cadence: `@atlasent/anthropic-middleware` (reference), then `@atlasent/langchain`, `@atlasent/llamaindex`, `@atlasent/openai-middleware`, `@atlasent/claude-code` (MCP server), `@atlasent/cursor`. Python parity where the framework has a Python SDK (LangChain, LlamaIndex, Anthropic, OpenAI). |
| G — compliance | supporting | `atlasent bundles install <slug>` subcommand in the CLI; pydantic + TS types for `ComplianceRegime`, `EvidenceExportRequest`, `EvidenceExportResponse`; shared fixtures for the SOC2 reference bundle. |
| H — AI gates | supporting | Middleware chain helper: `atlasent.chain(piiRedact(), promptInjectScan(), budgetCheck(maxUsd: 5), guard({ ... }))`. Each gate a separate opt-in package; consumers compose. |
| I — crypto | **primary** (verifier) | Extends v1's `audit_bundle.py` / `auditBundle.ts`: decision-scope verifier, Merkle-inclusion proof checker, ZK disclosure helper. `atlasent verify` CLI subcommand. |
| J — DX | **primary** | `atlasent dev` + `atlasent lint` CLI subcommands; VS Code extension (separate repo, reuses `atlasent` CLI). New SDK languages land as sibling repos (atlasent-sdk-go, -rust, -java, -dotnet, -ruby) — each wires into the existing `contract/schemas/` + drift detector. |
| K — ops | supporting | `atlasent.otel.enable()` — one-call OTel instrumentation. Streaming-client helper for the SSE decision feed: `atlasent.streamDecisions({ since, onDecision })`. |
| L — identity | supporting | mTLS client opt-in: `new AtlaSentClient({ mTls: { cert, key } })`. SPIFFE workload-api consumer for per-run credentials. |

Rollout order on the SDK side: Wave F Anthropic middleware first
(reference implementation; unblocks Wave F follow-ons). Then Wave I
verifier extensions (crypto is additive to the v1 audit-bundle
verifier). Then Wave J CLI + dev kit. Then H/G/K/L as capacity
allows.

Each wave F follow-on package publishes independently; pin
`"@atlasent/sdk": "^2.0.0"` as a peer dependency in every adapter.

---

## Peer repos

- Console: the internal console-side `V2_ARCHITECTURE.md`
- API: the internal API-side `V2_ARCHITECTURE.md`
- Docs (canonical): the internal docs-repo `V2_ARCHITECTURE.md`
