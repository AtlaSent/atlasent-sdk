# Atlasent SDKs

SDK layer for Atlasent — thin wrappers around atlasent-api. Python (`atlasent` on PyPI) and TypeScript (`@atlasent/sdk` on npm), plus framework guards.

[![PyPI](https://img.shields.io/pypi/v/atlasent.svg)](https://pypi.org/project/atlasent/)
[![npm](https://img.shields.io/npm/v/@atlasent/sdk.svg)](https://www.npmjs.com/package/@atlasent/sdk)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Atlasent is security and organizational authority infrastructure for consequential actions by people, software, and AI.**

These SDKs add that check to your own code in Python or TypeScript, right before a consequential action runs:

1. **Wrap the risky call** (a deploy, a migration, a payment, an agent's tool call) with `protect()`.
2. **It waits for approval** if your policy says a person must sign off. If not approved, it doesn't run.
3. **Every run gets a signed receipt** your auditor can check, without trusting us.

### For engineers

Client SDKs for **authorization of consequential computational actions**.

Atlasent performs **execution-time authorization**: before a governed side effect,
the server-authoritative runtime determines whether this exact Action is authorized
under current organizational Authority, Policy, approvals, Assertions, Target /
Resource state, environment, and Context. On `allow`, the runtime can issue a
bounded Permit that is verified at the execution boundary before the native effect.

> **A plausible request is not organizational authority.**

The SDKs are client-side integration surfaces. They do **not** derive or mint
organizational Authority locally.

```text
Action proposed
      │
      ▼
   Evaluate
      │
 Decision: allow | deny | hold | escalate
      │ allow
      ▼
 bounded Permit
      │
      ▼
 Permit Verification at the Gate
      │
      ▼
 native Execution
      │
      ▼
 Evidence / Proof
```

## Packages

| Language | Package | Install |
|---|---|---|
| Python | `atlasent` | `pip install atlasent` |
| TypeScript | `@atlasent/sdk` | `npm install @atlasent/sdk` |
| Go | [`go/`](go/) | Preview — not yet published (no Go module version has been tagged) |
| Java | [`java/`](java/) | Preview — not yet published to Maven Central |

SDK SemVer is independent of the stable Atlasent `/v1-*` platform contract. A
package major version does not create a separate Atlasent product generation.

## Get an API key

1. Create an account at **[console.atlasent.io/auth/sign-up](https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=github-readme)**.
2. In the console, open **API keys** and create a key with the `evaluate:write`
   and `verify:execute` scopes.
3. Export it as `ATLASENT_API_KEY`.

## Python quick start

```python
import os
from atlasent import AtlaSentClient

client = AtlaSentClient(api_key=os.environ["ATLASENT_API_KEY"])

# protect() performs the authorization / Permit-verification path before returning.
permit = client.protect(
    agent="ci-deploy-bot",
    action="production.deploy",
    context={
        "repo": "acme/payments-api",
        "commit": os.environ["GIT_SHA"],
        "environment": "production",
    },
    state_snapshot={
        "source": "github-actions",
        "complete": True,
    },
)

# Reached only after the selected protected path has completed its required
# authorization / verification checks.
run_deploy()
```

## TypeScript quick start

Some SDK helpers preserve historical names for compatibility. For example,
`deployGate()` is an SDK helper name; customer-facing product language uses
**Deploy Gate** and the canonical Action Type remains
`production.deploy`.

```ts
import { AtlaSentClient } from "@atlasent/sdk";

const client = new AtlaSentClient({
  apiKey: process.env.ATLASENT_API_KEY!,
});

const gate = await client.deployGate({
  context: {
    repo: "acme/payments-api",
    commit: process.env.GIT_SHA,
    environment: "production",
  },
  stateSnapshot: {
    source: "github-actions",
    complete: true,
  },
});

if (!gate.allowed) {
  throw new Error(`Production change blocked: ${gate.reason}`);
}

runDeploy();
```

Check the current helper/version contract for the SDK you install. The stable
integration invariant is more important than a convenience method name:
**the native side effect must be unreachable until the required Authorization
and Permit Verification have succeeded.**

## Canon-backed Action Types

Do not create a new `action_type` taxonomy simply because an application or agent
framework exposes arbitrary tool names.

Atlasent separates:

- **Action Type** — Canon-backed categorical identity of the Action;
- **Action Instance** — this specific occurrence;
- **Action Class** — organization-specific governance/configuration for the Action Type;
- **Target / Resource + Context** — where system-, tool-, object-, and request-specific facts belong.

Examples:

```text
production.deploy
agent.tool.invoke
```

For an AI-agent tool call, use the applicable Canon-backed Action Type (for
example `agent.tool.invoke`) and place tool-specific information such as
`database.delete`, target record, destination, arguments, environment, delegation
context, and payload facts in the supported Target / Context fields.

New Action identities should go through the Atlasent Action Canon process rather
than being invented independently in each SDK integration.

## AI agents and MCP

AI agents use the same organizational-authority model as humans, services, and
workflows. Agent identity, tool access, delegation, or a human Approval can all
be relevant facts; none of them alone establishes that the organization
currently authorizes this exact consequential Action.

For MCP-compatible hosts, use the public
[`atlasent-mcp-server`](https://github.com/Atlasent/atlasent-mcp-server).
A framework wrapper or prompt instruction is not by itself a non-bypassable Gate.
Security claims belong to the actual execution topology that controls the native
side effect.

## GitHub Actions

For CI/CD integration, use the public
[`atlasent-action`](https://github.com/Atlasent/atlasent-action).
It can derive GitHub execution facts and place the Atlasent authorization /
Permit-verification path before a governed deployment or other consequential CI
step.

The public product label for this use case is **Deploy Gate**;
historical Action/SDK/repository names may remain for compatibility.

## Wire contract

Canonical request/response schemas and compatibility fixtures live in
[`contract/`](./contract/). The Python and TypeScript clients share the same
runtime wire semantics.

Primary authorization endpoints:

```text
POST /v1-evaluate
POST /v1-verify-permit
```

Use the current server-authoritative OpenAPI and handlers for exact wire fields.
Do not copy historical nested-Permit response examples into new integrations.

## Authority, Policy, Approval, and Permit

These concepts are intentionally different:

- **Authority** — standing, scoped organizational right to cause a class of change.
- **Authorization** — per-request determination whether this exact Action may proceed now.
- **Policy** — rules defining conditions under which Authority may permit an Action.
- **Approval** — verified approver input that may satisfy a Policy condition.
- **Assertion** — verified governance fact consumed by Evaluation.
- **Decision** — runtime outcome (`allow | deny | hold | escalate`).
- **Permit** — bounded positive-Authorization artifact for the execution attempt.
- **Verification** — point-in-time check of the Permit before the governed effect.
- **Evidence / Proof** — durable record connecting the determination to execution / observed outcome.

A human Approval is **not a source of organizational Authority** merely because it
is favorable. Policy rules, risk/context signals, change tickets, test results,
and deployment gates are also not Authority. They can be conditions or evidence
used in Evaluation.

The SDK should depend on the server-authoritative Authorization / Permit path
rather than reimplementing these distinctions locally.

## Fail-closed integration

For a path that is intentionally configured and accepted as fail-closed and
permit-gated, treat these as block conditions:

- `deny`, `hold`, or `escalate` when execution requires `allow`;
- missing Permit when a Permit is required;
- failed, expired, revoked, replayed, or mismatched Permit;
- missing required execution binding;
- authentication failure;
- authorization-service failure where the integration requires live Authorization.

Shadow/advisory workflows can evaluate and record without blocking. Do not
describe those modes as enforced execution protection.

## Independent evidence verification

The public
[`atlasent-verify`](https://github.com/Atlasent/atlasent-verify)
repository contains the standalone offline evidence verifier and its public
canonical-form contract. Public verifier keys, revocations, and trust-root
material are published in
[`atlasent-keys`](https://github.com/Atlasent/atlasent-keys).

These repositories are public so a customer or reviewer can inspect applicable
verification material without private Atlasent infrastructure.

Prefer **tamper-evident** over **immutable** unless the underlying storage has a
separately verified stronger property.

## Repository layout

```text
atlasent-sdk/
├── python/         # Python SDK
├── typescript/     # TypeScript SDK
├── contract/       # shared wire schemas, vectors, and drift checks
├── docs/           # SDK-facing documentation
└── .github/        # CI and release workflows
```

## Development

Python:

```bash
cd python
python -m pytest tests/
```

TypeScript:

```bash
cd typescript
npm ci
npm run typecheck
npm test
npm run build
```

Use the repository's pinned CI and package-manager configuration as the
authoritative release check. A passing SDK CI run is not customer production
acceptance for a particular execution topology.

## Security

Do not place API keys, private signing material, customer secrets, or production
credentials in source control. Keep authorization context limited to the facts
required by the selected Policy / execution binding.

Security-sensitive integration code must keep the protected side effect **after**
the required Authorization and Permit-verification boundary in control flow—not
merely log a Decision and continue.

## Public ecosystem

- [`atlasent-action`](https://github.com/Atlasent/atlasent-action) — GitHub Actions integration for production-change authorization
- [`atlasent-mcp-server`](https://github.com/Atlasent/atlasent-mcp-server) — MCP authorize-before-execute integration
- [`atlasent-verify`](https://github.com/Atlasent/atlasent-verify) — independent offline evidence verifier
- [`atlasent-keys`](https://github.com/Atlasent/atlasent-keys) — public verification material

## License

Licensed under the [Apache License, Version 2.0](./LICENSE). See
[`NOTICE`](./NOTICE) for attribution.

Copyright (c) AtlaSent IP Holdings LLC
