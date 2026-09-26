# @atlasent/sdk

[![npm](https://img.shields.io/npm/v/@atlasent/sdk.svg)](https://www.npmjs.com/package/@atlasent/sdk)

Execution-time authorization for AI agents, in TypeScript. Two methods, zero runtime dependencies, one function call per decision.

```bash
npm i @atlasent/sdk
```

## Get an API key

1. Create an account at **[console.atlasent.io/auth/sign-up](https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=npm-readme)**.
2. In the console, open **API keys** and create a key with the `evaluate:write`
   and `verify:execute` scopes.
3. Export it as `ATLASENT_API_KEY`.

## Quickstart

```ts
import { AtlaSentClient } from "@atlasent/sdk";

const client = new AtlaSentClient({ apiKey: process.env.ATLASENT_API_KEY! });

const gate = await client.deployGate({
  context: { repo: "atlasent/api", commit: process.env.GIT_SHA },
  stateSnapshot: { source: "github-actions", complete: true }, // required — see below
});

if (!gate.allowed) {
  console.error("Deploy blocked:", gate.reason);
  process.exit(1);
}

// runDeploy();
```

That's it. `deployGate()` performs the V1 Deploy Gate sequence against `production.deploy`: `evaluate()` calls `POST /v1-evaluate`, receives a permit when allowed, then `verifyPermit()` calls `POST /v1-verify-permit` before your deployment can run. A clean `deny` is returned as a block result — network / server / auth failures are thrown.

## State snapshots (required)

Action classes default to `requires_state_snapshot = true`, so **every** evaluate must carry a state snapshot. Omitting it returns a `SNAPSHOT_REQUIRED` deny (the action is blocked, never executed).

- `deployGate()` takes a camelCase `stateSnapshot`: `{ source, complete, ... }`.
- The raw `evaluate()` method takes the wire-shaped snake_case `state_snapshot` — a **top-level** field, not part of `context`:

```ts
const result = await client.evaluate({
  action_type: "production.deploy",
  actor_id: "agent:ci-bot",
  context: { environment: "production" },
  state_snapshot: { source: "github-actions", complete: true },
});
```

The minimum payload is `{ source: "<your-system>", complete: true }`. Add any state your policy evaluates (git SHA, approval count, environment) under the snapshot. The hosted GitHub Action injects one automatically, so you only set it on direct SDK / API calls.

## Why two calls? (the mental model)

AtlaSent is **authorize-before-execute**, not after-the-fact logging. The two-step pattern is intentional:

1. **`evaluate()`** asks the policy engine: "should this action run?" Returns a decision and, when allowed, a single-use **permit token** — a cryptographic proof that evaluation happened.
2. **`verifyPermit()`** consumes the permit server-side *before* the action executes. This is what makes the audit chain tamper-evident: every execution is hash-linked to the evaluation that authorized it, and no permit can be replayed.

**You rarely call them separately.** `deployGate()` wraps both steps for deploy workflows. The Python SDK's `protect()` wraps them for arbitrary actions. Use the raw two-step form only when something external — a human approval, a change-window check — needs to happen *between* evaluate and execute (evaluate → wait → verify → run).

## Simple V1 surface

```ts
client.evaluate({ actor_id, action_type, context? })
  // → { decision: "allow" | "deny" | "hold" | "escalate", permitId, reason, auditHash, timestamp }
  // Legacy { agent, action } is still accepted (deprecated alias, normalized internally).

client.verifyPermit({ permitId, agent?, action?, context? })
  // → { verified, outcome, permitHash, timestamp }

client.deployGate({ agent?, action?, context? })
  // defaults action to "production.deploy" and returns { allowed, reason, evidence }
```

`verifyPermit()` confirms a previously-issued permit server-side. Signed/offline permit artifacts never imply deployment authorization by themselves.

## Decision replay

Re-evaluate a recorded decision against its originally-pinned policy bundle and engine version. **Side-effect-free**: no audit row is written, no permit is minted (ADR-016 `mode: "replay"` sentinel). Useful for compliance review, regression-testing bundle changes, and post-incident investigation.

Two surfaces exist; pick the one that matches your call site:

```ts
// SDK-canonical (preferred for new code) — wire DECISION_CHANGED is normalized
// to POLICY_DRIFT; 409 replay_not_eligible returns ENGINE_DRIFT or BUNDLE_MISSING
// instead of throwing. You can always `switch` on the variance kind.
const r = await client.replay({ evaluationId: "dec_abc123" });
switch (r.varianceKind) {
  case "NONE":             /* replay agrees */                          break;
  case "POLICY_DRIFT":     /* same envelope/bundle, different decision */ break;
  case "ENVELOPE_DRIFT":   /* recorded envelope no longer hashes */     break;
  case "ENGINE_DRIFT":     /* original engine retired beyond archival */ break;
  case "BUNDLE_MISSING":   /* original eval had no bundle pinned */     break;
  case "CHAIN_TAMPER":     /* audit-chain v5 detector tripped */        break;
}
```

```ts
// Raw-wire surface — variance values pass through verbatim
// (NONE / DECISION_CHANGED / ENVELOPE_DRIFT); 409 throws AtlaSentError
const result = await client.replayDecision("dec_abc123");
if (result.variance === "DECISION_CHANGED") {
  console.warn(
    `Decision ${result.decision_id} drifted: ` +
    `${result.original_decision} → ${result.replay_decision}`,
  );
}
```

`/v1/decisions/:id/replay` is alpha per `atlasent-api/docs/STABLE_V2_PROMOTION.md` — wire shapes can shift without a deprecation cycle until it graduates to stable v1.

## CI deploy-gate pattern

```ts
import { AtlaSentClient } from "@atlasent/sdk";

const client = new AtlaSentClient({ apiKey: process.env.ATLASENT_API_KEY! });

const evaluation = await client.evaluate({
  actor_id: "ci-deploy-bot",
  action_type: "production.deploy",
  context: { service: "billing-api", commit: process.env.GIT_SHA },
});

if (evaluation.decision !== "allow") {
  console.error("Deploy blocked:", evaluation.reason);
  process.exit(1);
}

const verification = await client.verifyPermit({
  permitId: evaluation.permitId,
});

if (!verification.verified) {
  console.error("Permit verification failed — aborting");
  process.exit(1);
}

// runDeploy();
```

See [`examples/deploy-gate.ts`](./examples/deploy-gate.ts) for a complete CI-shaped script.

## Constructor options

```ts
new AtlaSentClient({
  apiKey: "ask_live_...", // required
  baseUrl: "https://api.atlasent.io", // default
  timeoutMs: 10_000, // default — per-request
  fetch: customFetch, // default: globalThis.fetch
});
```

## Error handling

The SDK throws exactly one error type — `AtlaSentError` — with a flat shape that mirrors Stripe / Octokit / Supabase conventions:

```ts
import { AtlaSentError } from "@atlasent/sdk";

try {
  await client.evaluate({ actor_id: "a", action_type: "b" });
} catch (err) {
  if (err instanceof AtlaSentError) {
    console.error(err.code, err.status, err.requestId, err.retryAfterMs);
  }
}
```

| `err.code`        | When it's thrown                         |
| ----------------- | ---------------------------------------- |
| `invalid_api_key` | HTTP 401                                 |
| `forbidden`       | HTTP 403                                 |
| `rate_limited`    | HTTP 429 (check `err.retryAfterMs`)      |
| `bad_request`     | HTTP 4xx (other than 401/403/429)        |
| `server_error`    | HTTP 5xx                                 |
| `timeout`         | `timeoutMs` exceeded                     |
| `network`         | DNS / connection failure, fetch threw    |
| `bad_response`    | non-JSON body or missing required fields |

Every `AtlaSentError` carries `err.requestId` — the UUID the SDK sent as `X-Request-ID`, correlatable in your server logs.

## Design choices

- **Fail-closed.** A clean `DENY` is returned so your code explicitly handles it; every other failure throws, so no action proceeds silently.
- **Native `fetch` only.** No axios, no polyfills. Node 20+ has everything we need.
- **Zero runtime dependencies.** Strongly typed via plain TS interfaces.
- **Bearer-token auth.** `Authorization: Bearer <apiKey>` so request-body logs never capture the key. (The SDK also includes `api_key` in the body for wire compat with the current policy engine; that will be removed once the server drops body-based auth.)

## Requirements

- Node.js **20** or newer (native `fetch`, `AbortSignal.timeout`, `crypto.randomUUID`).
- **Browser:** Chrome 103+, Firefox 100+, Safari 16+, Edge 103+. The SDK uses
  `AbortSignal.timeout` for per-request deadlines — the constructor throws a
  clear `AtlaSentError(code: "network")` on runtimes that lack it so the failure
  is loud rather than silent.
- TypeScript **5.0+** for best type-inference ergonomics (older is fine — types are plain interfaces).

## Hono middleware

Drop-in protection for [Hono](https://hono.dev) routes via the
`@atlasent/sdk/hono` subpath export (requires `hono` as a peer dep):

```ts
import { Hono } from "hono";
import { atlaSentGuard, atlaSentErrorHandler } from "@atlasent/sdk/hono";

const app = new Hono();
app.onError(atlaSentErrorHandler());

app.post(
  "/deploy/:service",
  atlaSentGuard({
    action: (c) => `deploy_${c.req.param("service")}`,
    agent: (c) => c.req.header("x-agent-id") ?? "anonymous",
    context: async (c) => ({ commit: (await c.req.json()).commit }),
  }),
  (c) => c.json({ ok: true, permit: c.get("atlasent") }),
);
```

`atlaSentGuard` calls `protect()` under the hood — fail-closed
semantics. On allow it stashes a `Permit` on the context (key:
`"atlasent"`, override via `options.key`). On deny or transport error
it throws; `atlaSentErrorHandler` maps those to 403 / 503 responses
so every guarded route shares one error-handling path.

> **Upcoming migration:** after `@atlasent/enforce` reaches GA the
> guard API will change to accept a pre-constructed `Enforce` instance
> instead of per-route `action/agent/context` options. The current API
> is **not deprecated** until that ships. See the
> [CHANGELOG](./CHANGELOG.md) for the full before/after and
> [`contract/ENFORCE_PACK.md`](../contract/ENFORCE_PACK.md) for
> migration details.

## Browser support

The SDK is universal and works in modern browsers with no build-time changes:

```ts
import { AtlaSentClient } from "@atlasent/sdk";

const client = new AtlaSentClient({
  apiKey: import.meta.env.VITE_ATLASENT_API_KEY,
  baseUrl: import.meta.env.VITE_ATLASENT_API_URL,
});

const result = await client.evaluate({
  actor_id: currentUser.id,
  action_type: "view_sensitive_report",
});
```

**Auth model in browser contexts.** Shipping a long-lived API key in a browser
bundle exposes it in DevTools and makes it replayable if exfiltrated. The
recommended options in increasing security order are:

- **Option B — browser-scoped keys (short term):** Create a read-only,
  scope-restricted, IP-allowlisted key class from the AtlaSent console.
  Safe for internal dashboards where you control the network. Not suitable
  for public-facing apps.
- **Option A — session-token mode (recommended for atlasent-hosted surfaces):**
  After SSO sign-in, the frontend obtains a short-lived (15-min) Bearer token
  from `GET /v1-session/token` bound to the user's scopes and tenant. The SDK
  handles token refresh transparently.

The `User-Agent` header is set to `@atlasent/sdk/<version> browser` in browser
runtimes (browsers strip this header anyway — it's harmless) and
`@atlasent/sdk/<version> node/<node-version>` in Node.

## Related

- **Python SDK:** same repo, [`../python/`](../python/README.md). Wire-compatible.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
