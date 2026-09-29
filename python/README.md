# AtlaSent Python SDK

[![PyPI](https://img.shields.io/pypi/v/atlasent.svg)](https://pypi.org/project/atlasent/)
[![Python versions](https://img.shields.io/pypi/pyversions/atlasent.svg)](https://pypi.org/project/atlasent/)

**Execution-time authorization for AI agents.** One call before a sensitive
action runs. Fail-closed by design — no action proceeds without an explicit,
verified permit.

```bash
pip install atlasent
# offline audit-bundle verification (Ed25519):
pip install "atlasent[verify]"
```

## Quickstart

```python
from atlasent import protect

permit = protect(
    agent="deploy-bot",
    action="production.deploy",
    context={
        "commit": commit,
        "approver": approver,
        "environment": "production",
    },
    # Required — see "State snapshots" below.
    state_snapshot={"source": "github-actions", "complete": True},
)
# If we got here, the action is authorized end-to-end.
# Otherwise protect() raised and the action never ran.
```

Set `ATLASENT_API_KEY` in the environment, or call
`atlasent.configure(api_key=...)`. That's the whole setup. No key yet? See
[Get an API key](#get-an-api-key).

## State snapshots (required)

Action classes default to `requires_state_snapshot = true`, so **every**
`protect()` / `evaluate()` call must include a `state_snapshot`. Omitting it
returns a `SNAPSHOT_REQUIRED` deny — which `protect()` surfaces as
`AtlaSentDeniedError` (the action never runs):

```python
from atlasent import protect, AtlaSentDeniedError

try:
    permit = protect(
        agent="deploy-bot",
        action="production.deploy",
        context={"environment": "production"},
        state_snapshot={"source": "github-actions", "complete": True},
    )
except AtlaSentDeniedError as exc:
    # exc.reason names SNAPSHOT_REQUIRED when the snapshot was missing.
    log.warning("Denied: %s", exc.reason)
```

The minimum payload is `{"source": "<your-system>", "complete": True}`. Add
any state your policy evaluates (git SHA, approval count, environment) under
the snapshot. `state_snapshot` is a **top-level** argument — it is not part of
`context`. The hosted GitHub Action injects one automatically, so you only
need to set it on direct SDK / API calls.

## The protect() contract

`atlasent.protect()` is the category primitive. On allow, it returns a
verified `Permit`. On anything else, it **raises**:

| Outcome                                   | Raises                                       |
|-------------------------------------------|----------------------------------------------|
| Policy `DENY`                             | `AtlaSentDeniedError`                        |
| Permit failed verification                | `AtlaSentDeniedError`                        |
| HTTP 401 / 403 / 4xx / 5xx                | `AtlaSentError` (with `.code`)               |
| Timeout / network failure                 | `AtlaSentError` (`code="timeout" / "network"`) |
| Rate limit (429)                          | `RateLimitError` (subclass of `AtlaSentError`, `.retry_after`) |

There is no `permitted=False` return path to forget. The action cannot
execute unless a `Permit` is in hand.

```python
from atlasent import protect, AtlaSentDeniedError, AtlaSentError

try:
    permit = protect(agent=agent, action=action, context=context)
    # Run the action. permit.permit_id + permit.audit_hash go in your log.
except AtlaSentDeniedError as exc:
    # Policy said no. exc.decision, exc.reason, exc.evaluation_id.
    log.warning("Denied: %s (evaluation_id=%s)", exc.reason, exc.evaluation_id)
except AtlaSentError as exc:
    # Transport / auth / server failure. exc.code, exc.status_code.
    log.error("AtlaSent unavailable: %s", exc)
```

`AtlaSentDeniedError` subclasses `AtlaSentDenied`, so
`except AtlaSentDenied:` still catches `protect()` denials. Use
`except AtlaSentDeniedError:` when you need to distinguish a policy
decision from a transport error.

## Async

```python
from atlasent import AsyncAtlaSentClient

async with AsyncAtlaSentClient(api_key="ask_live_...") as client:
    permit = await client.protect(
        agent="clinical-data-agent",
        action="modify_patient_record",
        context={"user": "dr_smith", "patient_id": "PT-001"},
    )
```

Full feature parity with the sync surface — same return type, same
exceptions, same fail-closed contract.

## What a Permit gives you

```python
@dataclass(frozen=True)
class Permit:
    permit_id: str     # opaque decision id (use for audit lookup)
    permit_hash: str   # verification hash bound to the permit
    audit_hash: str    # hash-chained audit-trail entry (21 CFR Part 11)
    reason: str        # policy engine's explanation
    timestamp: str     # ISO 8601 of the verification
```

Log `permit_id` + `audit_hash` for every action your code performs —
they're the two fields a regulator or support ticket will ask for.

## Framework integration

### FastAPI

```python
from fastapi import FastAPI, HTTPException
from atlasent import AsyncAtlaSentClient, AtlaSentDeniedError, AtlaSentError

app = FastAPI()
client = AsyncAtlaSentClient(api_key="ask_live_...")

@app.post("/modify-record")
async def modify_record(patient_id: str, agent_id: str):
    try:
        permit = await client.protect(
            agent=agent_id,
            action="modify_patient_record",
            context={"patient_id": patient_id},
        )
    except AtlaSentDeniedError as exc:
        raise HTTPException(403, detail=exc.reason) from None
    except AtlaSentError as exc:
        raise HTTPException(503, detail=str(exc)) from None
    return {"permit_id": permit.permit_id, "audit_hash": permit.audit_hash}
```

### Flask

```python
from flask import Flask, jsonify, abort, request
from atlasent import AtlaSentClient, AtlaSentDeniedError, AtlaSentError

app = Flask(__name__)
client = AtlaSentClient(api_key="ask_live_...")

@app.post("/modify-record")
def modify_record():
    try:
        permit = client.protect(
            agent="flask-agent",
            action="modify_patient_record",
            context={"patient_id": request.json["patient_id"]},
        )
    except AtlaSentDeniedError as exc:
        abort(403, description=exc.reason)
    except AtlaSentError as exc:
        abort(503, description=str(exc))
    return jsonify(permit_id=permit.permit_id, audit_hash=permit.audit_hash)
```

Decorator shortcuts — `atlasent_guard` for sync views,
`async_atlasent_guard` for async ones — remain available for the
pre-`protect()` `gate()` + `GateResult` idiom. See
[`examples/fastapi_integration.py`](./examples/fastapi_integration.py)
and [`examples/flask_integration.py`](./examples/flask_integration.py).

## configure()

```python
import atlasent

atlasent.configure(
    api_key="ask_live_...",               # else reads ATLASENT_API_KEY
    base_url="https://api.atlasent.io",   # default
)
```

Or pass the same settings to `AtlaSentClient(...)` / `AsyncAtlaSentClient(...)`
directly for per-client configuration:

```python
from atlasent import AtlaSentClient

client = AtlaSentClient(
    api_key="ask_live_...",
    base_url="https://api.atlasent.io",  # default
    timeout=10,                          # seconds, default
    max_retries=2,                       # on 5xx / timeouts, default
    retry_backoff=0.5,                   # seconds, doubles each retry
)
```

## Canonical SDK surface

Three primitives, each with a distinct mental model. New code should
pick one of these:

| Primitive | Use when | Lifecycle |
|---|---|---|
| **`protect()`** | You want fail-closed execution: "no permit, no execution." | Evaluate + verify in one call. Returns a `Permit` on allow; raises on `deny` / `hold` / `escalate` / verification failure / transport error. |
| **`evaluate()`** | You need to inspect the four-value decision (`allow` / `deny` / `hold` / `escalate`). | Returns the raw decision object. Does not collapse `hold` and `escalate` into a deny; does not auto-verify. |
| **`verify()`** | You hold a permit token from a prior `evaluate()` and want to confirm it before execution. | Distinct from the other two — operates on an existing permit. |

```python
from atlasent import protect, evaluate, verify
```

### Decision replay

Re-evaluate a recorded decision against its originally-pinned policy bundle
and engine version. **Side-effect-free**: no audit row written, no permit
minted (ADR-016 `mode: "replay"` sentinel). Useful for compliance review,
regression-testing bundle changes, and post-incident investigation.

```python
from atlasent import AtlaSentClient

client = AtlaSentClient(api_key="ask_live_...")
r = client.replay(evaluation_id="dec_abc123")

match r.variance_kind:
    case "NONE":
        ...  # replay agrees with the original decision
    case "POLICY_DRIFT":
        ...  # same envelope/bundle, different decision (normalized
             # from the wire `DECISION_CHANGED` value)
    case "ENVELOPE_DRIFT":
        ...  # recorded envelope no longer hashes to the recorded value
    case "ENGINE_DRIFT":
        ...  # original engine retired beyond archival window
    case "BUNDLE_MISSING":
        ...  # original eval had no bundle pinned
    case "CHAIN_TAMPER":
        ...  # audit-chain v5 detector tripped
```

`409 replay_not_eligible` responses are surfaced as a `ReplayResponse` with
`variance_kind` of `ENGINE_DRIFT` or `BUNDLE_MISSING` rather than raising —
callers can always branch on the variance kind without try/except plumbing.

Async parity: `AsyncAtlaSentClient.replay(*, evaluation_id=...)` mirrors the
sync surface exactly.

`/v1/decisions/:id/replay` is alpha per
`atlasent-api/docs/STABLE_V2_PROMOTION.md` — wire shapes can shift without a
deprecation cycle until it graduates to stable v1.

### Deprecated convenience wrappers

These exist for backward compatibility and **will be removed in
`atlasent` v3**. They emit `DeprecationWarning` on use.

- `authorize(agent, action, context)` — data-not-exception variant
  (returns `permitted: bool`). **Migrate to `protect()`** for the
  fail-closed contract, or `evaluate()` if you specifically want to
  inspect the decision without raising.
- `gate(action, agent, context)` — evaluate + verify, returning an
  inspectable `GateResult`. **Migrate to `protect()`** if you want
  fail-closed semantics, or `evaluate()` + `verify()` if you want
  the two-step inspectable shape.

There is no `gate(...)` lifecycle that `protect()` cannot express
fail-closed, and there is no `authorize(...)` lifecycle that
`evaluate()` cannot express by inspection.

## Design choices

- **Fail-closed by construction.** `protect()` either returns a
  `Permit` or raises. No ambiguous return values, no silent permits.
- **Sync + async feature parity.** Every public method exists on
  both `AtlaSentClient` and `AsyncAtlaSentClient`.
- **Wire-compatible with the TypeScript SDK.** A permit issued by
  one SDK verifies from the other.
- **PEP 561 typed.** Ships a `py.typed` marker; every public
  function and type is annotated.

## API endpoints

The SDK calls:

- `POST https://api.atlasent.io/v1-evaluate`
- `POST https://api.atlasent.io/v1-verify-permit`
- `POST https://api.atlasent.io/v1/decisions/{id}/replay` (`.replay()` — alpha)

Override with the `base_url` argument.

## Requirements

- Python **3.10+** (for `str | None` unions and
  `datetime.UTC`).
- `httpx >= 0.24`, `pydantic >= 2.0`.

## Related

- **TypeScript SDK**: [`../typescript/`](../typescript/README.md).
  Same wire contract, same fail-closed philosophy, same
  `protect()` verb.
- **Shared contract**: [`../contract/`](../contract/) — schemas,
  vectors, and the CI drift detector that keeps both SDKs honest.

## Get an API key

1. Create an account at **[console.atlasent.io/auth/sign-up](https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=pypi-readme)**.
2. In the console, open **API keys** and create a key with the `evaluate:write`
   and `verify:execute` scopes.
3. Export it as `ATLASENT_API_KEY`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
