# Changelog

All notable changes to `@atlasent/sdk` are documented here. The SDK
follows [semver](https://semver.org/): breaking changes bump the major
(or minor while on 0.x).

---

## Unreleased

### Added: Shopify claim-time identity and existing agent broker integration

The private Shopify guard now obtains fresh identity for the original actor
before claiming an `approved_awaiting_claim` approval. Missing/unavailable
identity stops before HTTP and leaves that pending approval resumable. The
approval client sends only the optional `actor_identity` claim field; legacy
`approved` claim requests remain empty. Separate permit verification and
consumption are still required before submission.

`createAgentActorIdentityResolver` connects trusted hosts to the existing
key-bound agent broker, with fresh requests per boundary, HTTPS/no redirects,
bounded timeout/response size and binding/currentness checks. It does not mint
human approval, grant authority, cache assertions or replace runtime signature
verification. No CLI broker configuration, credential, policy, deployment or
native merchant acceptance is added; API #4656 remains open.

### Added: trusted-host actor identity for the private Shopify refund guard

Shopify library/server hosts may resolve a fresh signed actor assertion at
both evaluate and verify through the existing SDK wire fields. Approval resume
uses the original permit actor, never the staff member who clicks Resume.
A configured identity source that fails or returns no JSON assertion blocks
execution; browser/model identity fields cannot populate it. Assertions are
not persisted in pending approvals or decision evidence. No resolver retains
the legacy wire omission. This supplies transport only: runtime identity and
authority verification, native merchant acceptance and API #4656 remain required.

### Added: explicit internal Shopify preview → Action Inbox observation

The private Shopify integration has a separate `serve:inbox` command, backed by
API #4727's Observe-only connector route. An explicit action re-reads the order,
checks the current key/tenant/shop/connector/environment and validates a matching
non-authorizing receipt. Pending submissions lock edits and preserve their original
order/amount/destination outcome even when the host changes the selected order.
The default preview remains independent of AtlaSent.
This requires a reserved server credential; no customer scope or plan is widened.
Live merchant/tenant self-service acceptance and refund execution remain open.

### Fixed: Shopify preview defaults to a read-only app and server (private demo)

`@atlasent/shopify` now runs an order-preview-only server with `npm run serve`,
without AtlaSent runtime credentials, approval clients or a permit ledger.
The default Shopify app requests `read_orders` only, subscribes to no refund
webhook, and its order action exposes no refund or approval-resume button.
The existing guarded write demo remains explicit through
`npm run serve:refund-demo` and `shopify.app.refund-demo.toml`. Existing
write-capable installs must use a separate app/consent path and verify granted
scopes; this source change does not revoke old permissions. Live development
store, merchant/tenant binding and full refund acceptance remain unverified.

### Fixed: `keySelf()` accepts a key with no stored rate limit (contract-conforming)

`GET /v1-api-key-self` is now served by the runtime (atlasent-api#4632); before
that it did not exist and `keySelf()` always failed with a 404. The runtime
reports `rate_limit_per_minute` as `null` when the key has no stored limit,
because enforced limits are per plan (read them from `rateLimit`, parsed from
`X-RateLimit-*`). `ApiKeySelfResponse.rateLimitPerMinute` is therefore
`number | null`, and a missing or non-numeric value reads as `null`. The
contract schema was widened first. Type-level change: code that treated the
field as always a number needs a null check.

### Changed: key-set verification matches atlasent-api#4640 (fail closed, unreleased surface)

The key-set path of `verifyPermitV4` (added below, not yet released) now
follows atlasent-api's `PERMIT_ED25519_PUBLIC_KEYS` rules exactly. A key set
whose revocation state cannot be read is refused as a whole, for kid-bearing
and kid-less tokens alike, with the new reason `key_set_untrustworthy`:

- a revocation whose key material cannot be resolved: a `revoked_keys` /
  `revoked_kids` kid that no entry carries with readable material, or a
  `revoked: true` entry whose own `x` is unreadable (its material could be
  any live entry's, so no key in the set is trusted);
- any entry without a boolean `revoked` (missing, `"false"`, `0`, `null`),
  or an entry that is not an object;
- a duplicate kid (on any entry, whatever its role), a `keys` that is not an
  array, and a `revoked_keys` / `revoked_kids` that is present but malformed
  (formerly ignored);
- an inline revocation with neither a kid nor readable material.

A kid-less token (the auto-selected key or `defaultKid`) is now also bounded
by the validity window of every `R2_permit` entry sharing the selected key's
material, so a retired or staged alias entry for the same key refuses it; an
unreadable bound on such an entry refuses it too. A token naming a kid is
still checked against its own entry's window only. Key material must use the
base64 / base64url alphabet strictly, and a non-string `valid_from` /
`valid_until` is invalid rather than coerced. Pinned-key verification is
unchanged. The published trust root (atlasent-keys `.well-known`) satisfies
every rule.

Only a raw 32-byte Ed25519 key counts as readable material: a revocation
whose `x` decodes to anything else (`""`, `"AA"`) is unresolved.
`bootstrapTrust()` keeps its lenient parsing, but when it drops a key entry
or meets a present-but-unreadable `revoked_keys` it now sets
`revocations_unreadable: true` on the `TrustSnapshot`, and the verifier
refuses such a snapshot. `TrustRootManager`'s refresh keeps its current
snapshot when the fetched ledger is present but unreadable.

### Added: kid-aware pt.v4 verification (reading side only, additive)

`verifyPermitV4(token, key)` now accepts a COSE protected header with or
without a `kid` (`{1:-8}` or `{1:-8, 4:bstr(kid)}`). The runtime still mints
`{1:-8}`. Accepting a kid now means the runtime can start stamping one later
without breaking SDKs already in the field. `key` may be one pinned key
(unchanged behaviour: it is used whatever the header says) or a key set: the
trust root's `atlasent-verifier-keys.json` document or any `{ keys: [...] }`.
With a key set, the header kid selects the `R2_permit` key. Revoked keys
(an entry's own `revoked`, the ledger's `revoked_keys`, or a flat
`revoked_kids`; a `null` validity bound is open-ended),
keys whose validity window excludes the permit's `iat`, and non-permit roles
are refused. A kid-less token uses the single usable key or
`opts.defaultKid`; otherwise it fails with `kid_required`. New reasons:
`unknown_kid`, `key_revoked`, `key_not_valid_for_permit`, `kid_required`,
`key_set_expired` (a set whose own `expires_at`/`valid_until` has passed).
Revocation propagates to every entry with the same key bytes. A permit key
whose bytes also appear on an entry with any role other than `R2_permit` (an
audit key, or no role) is refused with `key_role_conflict`. The kid-less
fallback counts only keys valid for the permit's `iat`.
The result adds `kid` and `verifiedWithKid`. Any other header label, a
duplicate label, a non-EdDSA alg or a text-string kid still fails with
`wrong_protected_header`.

### Added: full pt.v4 claim decode, typed verify error codes, `execution_payload_hash_accepted` (additive)

- `verifyPermitV4()` now decodes every claim key the runtime signs (4, 6, 7
  and -1 to -35): delegation lineage, execution binding, exceptional
  authority, AWS/Azure locus, operation intent, change brief, H8 identity,
  agent runtime identity and the Entra slice. Before this it decoded only -1
  to -7 and skipped the rest. `PermitClaimsV4` gains the matching optional
  fields. Absent means "not bound".
- Cross-language parity vectors (`contract/vectors/permit-v4/vectors.json`)
  are generated from atlasent-api's own `signPermitV4`. The TS and Python
  decoders must both reproduce the runtime's claim bag exactly.
- `VERIFY_ERROR_CODES`, `LEGACY_VERIFY_ERROR_CODES`,
  `TRANSIENT_VERIFY_ERROR_CODES`, `isVerifyErrorCode()` and the
  `VerifyErrorCode` type (plain `as const` arrays, side-effect free), mirroring atlasent-api's verify error-code catalog.
  `verifyPermit()` now returns `verifyErrorCode` and `verifyReason`; both are
  optional and the code is an open string.
- `evaluate()` and `evaluatePreflight()` surface
  `execution_payload_hash_accepted`. `false` means your digest was dropped and
  verify will return `PAYLOAD_MISMATCH`.

### Added: `approvalRequestId` on evaluate responses (additive, contract-conforming)

`/v1-evaluate` returns `approval_request_id` on hold and escalate decisions
whenever it creates an approval request (every escalate, and approval-gated
holds), but `evaluate()` dropped it, so a caller could not find the approval
to wait on. `EvaluateResponse.approvalRequestId` now carries it; it is absent
when the response has none. A person resolves the request in the AtlaSent
console; the caller polls `GET /v1-approvals/{id}` and claims the single
permit with `POST /v1-approvals/{id}/claim-permit` (the protocol
atlasent-action and the MCP server already use). Added to
`contract/schemas/evaluate-response.schema.json` and `contract/openapi.yaml`
first. Distinct from `escalationId`, the HITL escalation.

### Fixed: per-permit methods address the `v1-permits` function

Under the hosted functions root the first path segment is the function name,
so the slash-form paths these methods used (`/v1/permits/:id/verify` and
friends) reached no function. They now call the `v1-permits` function:

| Method | Route |
|---|---|
| `getPermit(id)` | `GET /v1-permits/{id}` |
| `checkPermitValid(id)` | `GET /v1-permits/{id}/valid` |
| `listPermits(...)` | `GET /v1-permits` |
| `verifyPermitById(id)` | `POST /v1-permits/{id}/verify` |
| `revokePermitById(id, { reason })` | `POST /v1-permits/{id}/revoke` |

The id is still `encodeURIComponent`-encoded, so `/` and `?` cannot change the
route. Request bodies and return types are unchanged. The framework guards'
`permitRevalidationIntervalMs` heartbeat uses `checkPermitValid` and so moves
with it. The runtime serves this shape from atlasent-api#4522; until that is
deployed to production these calls fail closed with an `AtlaSentError` there,
as before.

### Fixed: `verifyPermit()` is no longer deprecated

`verifyPermit()` (and its `VerifyPermitResponse`) carried `@deprecated` in
favour of `verifyPermitById()`. That pointed callers the wrong way:
`verifyPermit()` calls `/v1-verify-permit`, the execution-boundary verifier
(signature, binding and replay checks, then consume), while
`verifyPermitById()` is a permit lifecycle/status transition that performs none
of those checks. The tags are removed and the JSDoc now says which is which. No
public API is removed. `revokePermit()` keeps its existing deprecation.

### Added: human-approval binding on the wire (additive, contract-conforming)

- **`EvaluateRequest.resource_id` and `EvaluateRequest.approval`** are now
  sent at the top level of the `/v1-evaluate` body. Both were already
  declared by `contract/schemas/evaluate-request`, but `buildEvaluateBody`
  whitelisted the body and dropped them without an error, so no SDK caller
  could name the resource a human approval's `action_hash` covers, or deliver
  an `approval_artifact.v1` at all (the runtime reads it only from
  `body.approval.artifact`). The legacy `{agent, action}` normalizer, which
  `protect()` uses, carries both too.
- **`EvaluateResponse.signingHint`** surfaces the runtime's `signing_hint`
  (ADR-055): the `action_hash` an approval for this exact request must sign,
  which a caller cannot recompute because the runtime hashes its enriched
  context. Shape-checked, including the optional `required_role` /
  `required_roles`; a partial or mistyped hint is omitted rather than surfaced.
  Contract-first: `signing_hint` is added to
  `contract/schemas/evaluate-response.schema.json` and `contract/openapi.yaml`.
- **`VerifyPermitResponse.consumed`** surfaces whether verify burned the
  permit (declared by `contract/schemas/verify-permit-response`). An executor
  that must run an action once should require `consumed === true`.
- New exported types `EvaluateApproval` and `EvaluateSigningHint`.

### `@atlasent/gmail` 0.2.0 (unpublished) — breaking on 0.x

- **Fixed: no guarded send could ever succeed.** The guard presented at
  verify a bare-hex digest of `{action_type, actor_id, context}`. The runtime
  binds a permit with no caller digest to `"sha256:" +` a hash of the whole
  posted body, which includes `environment`, so every send ended in a
  deterministic `PAYLOAD_MISMATCH`. The 0.1.0 suite stubbed the client and
  could not see it; the new suite drives the real `AtlaSentClient` against a
  fake runtime that applies the binding rules.
- **Changed: the permit and any human approval are bound to the exact
  message.** The guard snapshots the `userId`, base64url `raw` RFC 2822
  message and `threadId`, hashes them (`computeGmailSendDigest`), sends the
  digest as top-level `execution_payload_hash` and `resource_id`, and
  re-presents it at verify. Gmail is called with a request built from the
  snapshot, so mutating the caller's object mid-flight changes nothing sent,
  and other `requestBody` fields are no longer forwarded. Media uploads and
  requests without `requestBody.raw` are refused (`invalid_request`).
- **Changed: `context.approvals` is no longer a caller claim.** It is 1 only
  when `options.approvalArtifact` is attached for the runtime to verify, else
  0. `GmailExternalSendFacts.approvals` is deprecated and ignored: on an
  action class that does not demand an artifact, 0.1.0 sent a typed count
  that the template accepted as the approval itself.
- **Added: the ADR-055 two-step approval.** `requestGmailSendApproval` /
  `requestGmailSendDraftApproval` return the runtime's `signingHint` for
  exactly this message; sign it, then send with `approvalArtifact`. Both
  calls compose the evaluate request in one place, so they differ only in
  the artifact.
- **Changed: a verified permit must also be consumed.** `verified: true`
  without `consumed: true` blocks the send.
- **Changed: `guardedGmailSendDraft` binds the draft's content.** It reads
  the draft (`drafts.get`, `format: "raw"`), binds those bytes, and reads it
  again just before `drafts.send`; an edit after authorization blocks the send
  (`content_changed`). `drafts.send` with replacement `message` content or a
  media upload is refused.
- `GmailSendSuccess.messageDigest` / `GmailSendDenial.messageDigest` report
  the bound digest. New decisions: `invalid_request`, `content_changed`.
- **Peer dependency raised to `@atlasent/sdk@^2.23.0`** (the release that
  carries `resource_id` / `approval` / `signingHint` / `consumed`).
- The package's tests now run in CI (`gmail-ci.yml`). They never did before,
  and the test file did not typecheck, which would have failed
  `prepublishOnly`.
- `publish-npm-gmail.yml` installs and builds the root SDK before testing and
  publishing, as the cursor/langchain/llamaindex publish workflows do; a clean
  tag checkout otherwise failed with `ERR_MODULE_NOT_FOUND`.

### Fixed: the default `baseUrl` reached no function

`new AtlaSentClient({ apiKey })` posted to `https://api.atlasent.io/v1-evaluate`.
The hosted gateway serves edge functions only under `/functions/v1` and answers
every other path with `404 {"error":"requested path is invalid"}`, so every
call from a client built with the default base URL (including the README
quickstart, `deployGate()`, `protect()` and `withPermit()` without
`ATLASENT_BASE_URL`) failed with `bad_request` before reaching the evaluator.
It failed closed: nothing ran, but nothing could be authorized either.

- The default is now `https://api.atlasent.io/functions/v1`.
- A `baseUrl` whose host is the hosted runtime (`api.atlasent.io` or the
  hosted Supabase project hosts) and whose path is empty or `/` has
  `/functions/v1` appended, so code copied from earlier READMEs keeps working.
  Any other host, and a hosted host with an explicit path, is used as given.
- New module `src/baseUrl.ts` holds the rule; tests in `test/base-url.test.ts`.

Not changed by this fix: the per-permit methods (`verifyPermitById`,
`getPermit`, `listPermits`, `revokePermitById`, `checkPermitValid`) still used
slash-form paths; see "per-permit methods address the `v1-permits` function"
above. Use `verifyPermit()` (`/v1-verify-permit`) at the execution boundary.

### Added: shared framework tool-guard core (additive)

AtlaSent/atlasent#350 (D-03). `@atlasent/cursor`, `@atlasent/langchain` and
`@atlasent/llamaindex` each carried their own copy of the evaluate →
verifyPermit → heartbeat loop. That loop now lives once, in
`src/guardCore.ts`, exported from the package entrypoint:
`runGuardedToolCall`, `resolveGuardValue`, `DEFAULT_GUARD_TOOL_ACTION`, the
stock adapters `jsonStringResultAdapter` (string-returning tools) and
`objectResultAdapter` (object-returning tools), and the types
`GuardCoreOptions`, `GuardAdapter`, `GuardDenialResult`, `GuardPermitInfo`,
`GuardResolver` and `GuardedToolCall`. No wire change: it calls the existing
`evaluate`, `verifyPermit` and `checkPermitValid`.

### Framework guards — `@atlasent/langchain`, `@atlasent/llamaindex`, `@atlasent/cursor` (unpublished 1.6.0)

- **Refactor, no runtime behaviour change:** each guard is now a thin adapter
  over `runGuardedToolCall`. Every public export, type and option is
  unchanged, and the existing guard test suites pass unmodified.
- **Peer dependency raised to `@atlasent/sdk@^2.23.0`**, the first SDK release
  that will carry the guard core. Publish `@atlasent/sdk` 2.23.0 before any of
  the three guard packages.
- Docs only: `withCursorGuard`'s comment said JSON-object string results
  were returned unchanged. They have always been annotated with
  `_atlasent_permit_id` / `_atlasent_audit_hash` (a test asserts it); the
  comment now says so.

## 2.22.0

### Changed: missing-key errors say where to get a key

The error raised when no API key is configured now ends with
`Get a free API key at https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=ts-error`.
Covers `new AtlaSentClient({ apiKey: "" })`, `protect()` with no `configure()` and no `ATLASENT_API_KEY`, the approval runtime and `BCCAEClient`. The exception types, codes and the rest of each message are
unchanged. A malformed key is not given the link: it already has one.

### Added: `actor_identity` on evaluate, verify and `protect()` (additive)

atlasent-api#3915. The runtime requires an `actor_identity.v1` at evaluate for
the mandatory change-control action types (`production.deploy`,
`infrastructure.change`, `production.rollback`,
`secret.configuration.change`; deny `ACTOR_UNVERIFIED` without one), and at
verify when the action class is classified `verified_actor`. The SDK had no
way to send one. Now `EvaluateRequest.actor_identity`,
`VerifyPermitRequest.actorIdentity` and `ProtectRequest.actorIdentity` send it
top-level as `actor_identity`; `protect()` and `protectWithEvidence()` present
it at both boundaries. The SDK forwards it unchanged and never mints or
inspects it. Omitting it sends byte-identical requests. Contract:
`evaluate-request.schema.json`, `verify-permit-request.schema.json`,
`openapi.yaml`.

### Added: `org_authority_assertion` on `approval_artifact.v1` (additive)

Mirrors atlasent-api#3798 (B2a). An approval artifact may now carry an optional
`org_authority_assertion` (`org_authority_assertion.v1`), the console-signed
evidence for the `atlasent_verified_org_authority` approver basis: an owner or
admin of the approval's org, after a server-side step-up. New `OrgAuthorityAssertionV1` (plus `OrgAuthoritySubject`, `OrgAuthorityRole`, `OrgAuthorityBinding`, `OrgAuthorityIssuer`, `OrgAuthorityAuthContext`, `OrgAuthorityStepUp`) types, exported from the package entrypoint. An artifact
carrying it alongside `identity_assertion` or `approver_grant_assertion` is
rejected, as the runtime rejects it. Artifacts without the field are unchanged.
The SDK carries the assertion; it never signs or verifies it. Contract:
`contract/schemas/org-authority-assertion.schema.json`.

### Build: TypeScript 7 (#482)

The package now typechecks and emits its declarations with TypeScript 7.0.
tsup's `dts: true` drives a copy of `rollup-plugin-dts` that tsup vendors, and
that copy calls the TypeScript compiler API, which the TypeScript 7 package no
longer ships, so the declaration build crashed. JS is still bundled by tsup;
declarations now come from TypeScript 7's `tsc` and are bundled by
`rollup-plugin-dts` 6.5 (`scripts/build-dts.mjs`), in the same file layout as
before. The `.js`/`.cjs` bundles and source maps are byte-identical to the
TypeScript 6 build. The `.d.ts`/`.d.cts` files declare the same exports and
types; they differ only in form (split `export` / `export type` statements,
the source's quote style on literal types, member order in some inferred
object types, and the shared chunk's content hash). `baseUrl` and
`ignoreDeprecations` are removed from `tsconfig.json`. No runtime or Node
support change.

### Added: `meaning`, `entra_provenance`, `approval_kind`, `subject_agent_identity_id` on `approval_artifact.v1` (additive)

The runtime (atlasent-api `_shared/approval_artifact.ts`) emits and signs these
four optional fields, but the contract schema set `additionalProperties: false`
without declaring them, so SDK validation rejected real runtime artifacts. Now
declared: `meaning` (`approved` | `reviewed` | `authored`, 21 CFR Part 11
§11.50), `entra_provenance` (new `contract/schemas/entra-provenance.schema.json`;
`relation` must be `approve` on an approval artifact), and the ADR CROSS-056 pair
`approval_kind` (`single_human_over_machine`) + `subject_agent_identity_id`
(uuid), which must appear together. New `EntraProvenanceV1`, `SignatureMeaning` and `ApprovalKind` types, exported from the package entrypoint, and four optional fields on `ApprovalArtifactV1`. Artifacts without the fields
are unchanged.

### Added: `approver_grant_assertion` on `approval_artifact.v1` (additive)

Mirrors atlasent-api#3870 (#3863, tracked in #3876). An approval artifact may
now carry an optional `approver_grant_assertion` (`approver_grant_assertion.v1`),
the console-signed alternative to `identity_assertion` for the
`atlasent_approver_grant` approver basis. New `ApproverGrantAssertionV1` (plus `ApproverGrantSubject`, `ApproverGrantBinding`, `ApproverGrantIssuer`, `ApproverGrantAuthContext`, `ApproverGrantStepUp`) types, exported from the package entrypoint. An artifact carrying
both assertions is rejected, as the runtime rejects it. Artifacts without the
field are unchanged. The SDK carries the assertion; it never signs or verifies
it. Contract: `contract/schemas/approver-grant-assertion.schema.json`.

### Added: edge-function region pinning (`functionRegion`)

Every request to the AtlaSent runtime now carries an `x-region` header. The
hosted runtime is pinned to `us-west-1`, the region of its database.
Supabase otherwise runs the function nearest the caller. Measured on
staging with the same request shape, evaluate went from a p50 of 4.70 s to
1.42 s (handler time) once pinned. The database work was unchanged: 49
round trips either way.

Configure with the `functionRegion` client option or the
`ATLASENT_FUNCTION_REGION` environment variable. `"auto"` or `null` turns
pinning off. Three cases send no header unless configured, which keeps
their requests byte-identical:

- a self-hosted `baseUrl`, which may run in another region;
- a browser, where the header would fail the runtime's CORS preflight;
- `functionRegion: "auto"` or `null`.

A malformed value throws at construction. `src/functionRegion.ts` is the
only place that writes the header, and a test fails if any other source
file does, or if a request path skips it.

### Framework guards — `@atlasent/langchain`, `@atlasent/llamaindex`, `@atlasent/cursor` 1.6.0 (unpublished)

- **Fixed: the guards evaluated the bare tool name as the action, so every
  guarded call was denied.** With no `action` option, `withLangChainGuard`,
  `withLlamaIndexGuard` and `withCursorGuard` sent the tool's name (e.g.
  `"delete_user"`) as the action type. The runtime has no action class named
  after arbitrary tools, so every call failed closed. The default is now
  **`agent.tool.invoke`** (Canon ACT-0029), exported as `DEFAULT_TOOL_ACTION`.
- **Added: `context.tool` is always the invoked tool's name.** It is written
  after `extraContext` is merged, so a caller-supplied `extraContext.tool`
  cannot relabel the call as a different tool. `context.tool_input` is
  unchanged.
- The `agent.tool.invoke` action class requires context inputs `tool` and
  `environment`. The guard supplies `tool` and does **not** invent an
  `environment`; pass it via `extraContext` (see each package README).
- An explicit `action` option (string or resolver) is used exactly as before.
- Not changed: the permit is **not** bound to the tool as a verify-time target
  (`@atlasent/sdk`'s evaluate request carries no top-level `resource_id` and
  `verifyPermit` presents no `target_id`).
- Test-only: the guard test suites' `makeClient` doubles are typed loosely so
  `npm run typecheck` (a step in each `publish-npm-*.yml`) passes; it
  previously failed with 4 `TS2322` errors per package.

### Fixed

- **The no-caller-digest path still presented an execution-payload digest the
  runtime could never match, so every `protect()` / `withPermit()` /
  `protectWithEvidence()` call that does not opt into a digest — the default —
  was a deterministic `PAYLOAD_MISMATCH` deny at the verify boundary.** The
  previous change on this line fixed the caller-digest path and explicitly
  preserved this one ("With no caller digest, behaviour is exactly as
  before"); the unchanged behaviour is the deny. The digest
  was emitted as bare hex; the value it is compared against —
  `execution_evaluations.payload_hash`, or the permit's signed
  `execution_hash_expected` — is written by the runtime's `hashPayload`, which
  prefixes `sha256:`. `/v1-verify-permit` folds case and normalizes nothing
  else, so the two could not compare equal. The canonical BYTES were always
  correct: verified byte-identical to the server's canonicalization across
  unicode, escape-sequence, `undefined`, numeric and key-ordering vectors. The
  scheme prefix alone denied the permit. Affects every caller of these three
  entry points, including `ProtectToolWrapper` and `ProtectFunctionDispatch`
  in `atlasent-llm-integrations`.

  Nothing caught it because the two implementations were only ever tested
  against themselves — the SDK suite mocks `fetch`, so the server's digest
  appeared in no assertion. Now pinned from both sides by
  `test/payload-hash-parity.test.ts` (a vendored reference copy of the server
  function AND committed golden digests generated from the real server source,
  so neither can be edited into agreement with a broken counterpart) and
  `test/protect-execution-binding.test.ts` (asserts the posted request bodies,
  not the arguments handed to a client method — an argument-level assertion
  cannot see which field a value lands in, or whether it reaches the wire).

- **`protectWithEvidence()` silently ignored `executionPayloadHash` entirely.**
  The camelCase field never matches `client.evaluate`'s snake_case allowlist, so
  the digest was dropped and the permit was never bound to it — the exact
  silent-drop defect `normalizeExecutionPayloadHash` exists to prevent, in the
  sibling of the function that received the fix. It now normalizes, sends and
  re-presents the digest on the same contract as `protect()`. Found by mutation
  testing: reverting this survived the whole suite, because nothing covered
  this entry point's digest handling.

### Added

- **`serverPayloadHash`, `canonicalizePayload`, `isBarePayloadHash`** exported
  from `@atlasent/sdk`. `serverPayloadHash` reproduces the runtime's fallback
  binding, prefix included; `canonicalizePayload` is a byte-identical port of
  the server's canonicalization, pinned by the parity suite.

- `buildEvaluateBody` exported from `client.ts` as the single evaluate-body
  construction site, so `protect()` hashes the body it actually posts instead
  of a hand-written mirror of it. There is deliberately only one
  digest normalizer (`normalizeExecutionPayloadHash`, from the previous change
  on this line) rather than a second invention.

### Changed

- **Re-vendored the embedded trust-root snapshot from `atlasent-keys` main
  (`45e8b95`; index and bundles re-signed by the governed publish in
  `01968e9`, run 34931280498, after an independent approving review on
  atlasent-keys#35).** Adds `kid: ak_2026_q3_atlasent_audit` (`R3_audit`,
  `tenant: "atlasent"`, valid 2026-09-13T21:51Z → 2027-03-31) — the outer
  Ed25519 signer of `v1-export-audit` envelopes on production runtime since
  the 2026-09-13 export-signer rotation (`key_id` = `EXPORT_KID`, SPKI
  fingerprint `1903850d6a201501`), verified against a live production
  export before publication. Until this entry an embedded-baseline
  `verifyAuditBundle()` caller could not resolve the current export
  signer's `key_id` and had to wait for `TrustRootManager`'s first
  background refresh. Nothing is revoked or replaced by this pass; `kid: v1`
  (the per-row `audit_events.signature` signer) is unchanged. Regenerated
  with `node scripts/vendor-trust-root.mjs`; the sibling
  `vendor/trust-root/*.json` reference copies were refreshed to the same
  upstream files.

- **Re-vendored the embedded trust-root snapshot from `atlasent-keys` main
  (`f357d8a`, bundles re-signed in `aebdac8`).** Adds `kid: v1` (`R3_audit`,
  valid 2026-06-07 → 2027-07-08) — the per-row `audit_events.signature`
  signer on production runtime, verified 7/7 against production rows before
  publication — and marks `v2-audit-2026` `revoked: true`, `replaced_by:
  "v1"`, with the matching `revoked_keys` ledger entry. `v2-audit-2026` was
  never the production audit signer (0/7 sampled rows verify under it). Any
  `verifyAuditBundle()` caller relying on the embedded baseline now resolves
  the real production audit key and rejects the revoked one without waiting
  for `TrustRootManager`'s first background refresh. Regenerated with
  `node scripts/vendor-trust-root.mjs` (validation script from #517); the
  sibling `vendor/trust-root/*.json` reference copies were refreshed to the
  same upstream files.

### Fixed

- **ADR-005 revocation was checked against the bundle's unsigned
  `signing_key_id` hint, not the key that verified the signature.** During a
  rotation window a verifier legitimately holds both the revoked key and its
  successor; `verifyAuditBundle()` tried every key, recorded the real
  `matchedKeyId`, and then consulted `revoked_keys` using the hint — so a
  bundle signed by revoked `v2-audit-2026` but advertising `v1` returned
  `verified: true` (Codex P1 on #519). `VerifyKey` now carries
  `publicKeyRaw` (populated for every key loaded from `publicKeysPem`; new
  `verifyKeyFromSpkiPem()` helper), and revocation and role are resolved
  against the trust-root entry whose `x` matches the verifying key's material.
  The hint is still rejected on its own when it names a revoked kid or a
  non-audit kid (fail-closed). Two follow-up bypasses from review on #519 are
  closed in the same change: (1) a `VerifyKey` supplied **without** material
  no longer falls back to the hint — the material is exported from the
  `CryptoKey`, and a non-extractable key with a trust root present fails
  closed with the new `key_material_unavailable` reason; (2) the hint no
  longer narrows the trust-root entries that share the verifying material —
  **every** entry with that material is judged (`revoked` flag or
  `revoked_keys` ledger), so a revoked key re-published under a live alias
  kid is still revoked whichever kid the bundle advertises. Negative tests
  for both in `audit-bundle-revocation-material.test.ts`; the contract-vector
  fixture, which published one material under three kids (an invalid trust
  root that hid bypass 2), now gives each kid distinct material.
  A third review round closed the last gap in the same area: a
  caller-constructed `VerifyKey` whose `publicKeyRaw` **metadata** named a
  live key while its `publicKey` was the revoked one was judged by the
  metadata. The material now always comes from the key that verified —
  exported from the `CryptoKey`, or, for a non-extractable key, the caller's
  `publicKeyRaw` only after those bytes are re-imported and shown to verify
  the same signature; metadata that disagrees with the verifying key is
  ignored and, with nothing else to anchor on, fails closed with
  `key_material_unavailable`. `verifyKeyFromSpkiPem()` (and
  `rawEd25519FromSpki()`) are now exported from the package entry point —
  the previous changelog line advertised the helper while `src/index.ts` did
  not re-export it — and the key it returns is imported extractable so the
  export path is the one exercised. A fourth round fixed the shared contract
  fixture (`contract/tests/test_trust_root_contract.py`), which still
  published the signing key's material under all three kids and so failed the
  contract suite under the corrected verifier; Contract CI had been reading
  green only because it never installed `cryptography` and silently skipped
  every behaviour vector. It now installs the `verify` extra and fails, rather
  than skips, when those vectors would not run.

- **A duplicate signing key could produce a false `key_material_unavailable`
  denial under trust-root enforcement** (review on #519, round 5, landed
  after that PR merged). `resolveKeys()` places `options.keys` ahead of
  `publicKeysPem`, so the same key can appear first as a caller-built
  non-extractable `CryptoKey` (no usable `publicKeyRaw`) and again as the
  extractable PEM-derived copy; the verify loop stopped at the first
  signature-valid candidate, so a valid bundle was refused because that
  copy's material could not be anchored. With a trust root present the loop
  now keeps scanning signature-valid candidates until one can anchor its
  material and reports that one as `matchedKeyId`; it still fails closed
  with `key_material_unavailable` when none can, and still lands
  `key_revoked` on a revoked signer found on a later copy. Without a trust
  root the first signature-valid candidate remains the match. Regressions in
  `audit-bundle-revocation-material.test.ts`, including the exact
  `verifyBundle({ keys, publicKeysPem })` shape.

- **The SDK's embedded default trust root was always empty** — `verifyBundle()`
  (and any `AtlaSentClient`/`getGlobalTrustRootManager()` caller that didn't
  pass its own `trustRoot`) silently got a snapshot with zero keys and zero
  revocations, valid until 2099, on every real install. Confirmed directly
  against the published `@atlasent/sdk@2.16.0` package. Root cause was two
  independent defects in `trustRoot.ts`'s `_loadVendorSnapshot()`: (1)
  `package.json`'s `files` field never listed `vendor/`, so the vendored
  `vendor/trust-root/*.json` files were never included in the published npm
  tarball; (2) even had they been, the path-resolution math
  (`resolve(dirname(fileURLToPath(import.meta.url)), "..", "..")`) went up
  one directory too many for tsup's single-file bundle output, so it would
  have looked in the wrong place regardless. The existing test suite didn't
  catch this because it only ever ran against the monorepo's dev checkout,
  where `vendor/` happens to sit two directories above `typescript/src/` at
  the repo root — an unrelated coincidence of this monorepo's layout, not a
  correct resolution.
  - With an empty snapshot, `verifyAuditBundle()`'s revocation check
    (`revoked_keys.some(...)`) and role-mismatch check (`keys.find(...)`)
    were permanent no-ops: a bundle signed by a revoked key, or by a key
    used outside its intended role, was never caught by the default trust
    root path — contradicting this module's own ADR-005 D3/D4 fail-closed
    design. The background refresh (`_doRefresh`) could eventually populate
    real data, but only on a `setInterval` (default 4h) with no immediate
    refresh on construction, so any short-lived process (a CLI run, a
    Lambda, a one-off verification script — exactly this feature's intended
    use case) never got real trust-root data at all.
  - Fixed by embedding the baseline snapshot as a plain TypeScript object
    literal (`src/vendoredTrustRoot.generated.ts`, generated from
    atlasent-keys' live `.well-known/*.json` files by the new
    `scripts/vendor-trust-root.mjs`) instead of reading it from disk at
    runtime. `trustRoot.ts` no longer imports `node:fs`/`node:url`/
    `node:path` at all — this also fixes the SDK's main entry failing to
    bundle for any browser consumer (confirmed via a real Vite build in a
    downstream app; the SDK's `crypto`/`fs/promises` usage elsewhere still
    blocks a full browser build, tracked separately).
  - `getGlobalTrustRootManager()`'s background refresh behavior, `_doRefresh`,
    and the public `TrustRootManager`/`getGlobalTrustRootManager` APIs are
    unchanged — only how the initial baseline snapshot is sourced changed.

### Removed

- Removed the public client, types, and evaluate request/response fields for
  the unshipped `/v1/trajectory-verify` contract. Evaluate, permit issuance,
  execution binding, completion proofs, and permit verification remain
  supported.

---

## 2.21.2

### Fixed

- `protectStream()` was POSTing a flat `{action, agent, context, api_key}`
  body to `/v1/evaluate/stream` (falling back to legacy `/v1-evaluate-stream`
  on 404/405). The real handler (`atlasent-api`
  `supabase/functions/v1-evaluate-stream/handler.ts`) is body-compatible
  with `/v1/evaluate/batch`: `{items: [{action_type, actor_id, context,
  ...}]}` — a different shape, not just different field names — and rejects
  the old body outright via its `!Array.isArray(body.items)` check. Auth
  also incorrectly rode a body `api_key` field instead of the
  `Authorization` header every other call path in this SDK already uses.
  Same class of bug as the Python `protect_stream()` fix in #499; see
  `src/v2.ts`'s `authorizeStream()` for the reference implementation this
  fix mirrors.
  - `protectStream()` now builds a single-item `items` array
    (`{action_type, actor_id, context}`); `api_key` is no longer sent in
    the body.
  - `parseSseStream()` now treats the real terminal `event: complete`
    (`{batch_id, count, partial}`) as an end-of-stream signal alongside the
    legacy/generic `event: done`.
  - `parseSseStream()`'s error-frame handling now reads the real
    `error_code` field (falling back to legacy `code`).
  - Decision-frame parsing now prefers the canonical `permit_token` field
    over the legacy `decision_id`, mirroring the pattern `evaluate()`
    already uses.

## 2.21.1

### Fixed

- `evaluate()` was silently dropping `evaluation_profile`, `override`, and
  `completion_proofs` from the request body before it ever reached the
  wire, even though `EvaluateRequest` declares all three and the runtime
  genuinely reads them (`resolveProfile(body.evaluation_profile)`, the
  emergency-override gate on `body.override`, and the quorum check on
  `body.completion_proofs`). A caller setting `override` to invoke an
  emergency override, `evaluation_profile` to request a non-default
  profile, or `completion_proofs` to satisfy multi-actor quorum had the
  field silently discarded with no error — the evaluation proceeded as if
  the field had never been set. Same fix applied to the legacy-shape
  branch of `normalizeEvaluateRequest()` (`compat.ts`), which had the
  identical omission. Purely additive/corrective: callers not using these
  three fields are unaffected.

## 2.21.0

### Added

- `CrossOrgPermissionCheckResult` (`checkCrossOrgPermission()` /
  `listCrossOrgPermissionChecks()`) gains four additive fields making the
  cross-org federation trust precheck's non-authoritative nature explicit
  on the wire (CROSS-028, atlasent-api #2251): `trust_precheck_passed`
  (canonical replacement for reading `allowed` as authoritative),
  `authorizes_execution` (always `false` — this result never authorizes
  execution of anything; route the real decision through `/v1-evaluate`),
  `requires_local_authority_evaluation` (always `true`), and
  `conditions_evaluated` (always `false` today — `conditions` is returned
  unevaluated). New `summarizeTrustPrecheck()` helper, whose return values
  (`"trust_established"` / `"trust_established_with_unevaluated_conditions"`
  / `"no_trust"`) deliberately avoid authorization-implying vocabulary.
  `allowed` and `summarizeCrossOrgPermission()` are deprecated (not
  removed) in favor of the above.
  `CrossOrgPermissionCheckRequest.identity_id` is deprecated: the server
  does not read, persist, or act on it (item 3 of the ratified ADR — no
  representation-verification mechanism exists yet to wire it into).

- `AtlaSentClient.explainAuthority({ principalId, requestedScope, resourceId? })`:
  a new read-only client method for `GET
  /v1/authority-intelligence/explain-authority` (atlasent-api #2235), which
  answers "why may principal P exercise scope/action A in organization O right
  now?". Returns `paths` (one entry per matching authority mechanism —
  `direct_grant` / `delegation` / `role_capability`) and `unresolved` (every
  excluded or ambiguous relationship as a named finding). Pure pass-through —
  no client-side interpretation of the response. New types exported from the
  package root: `ExplainAuthorityResult`, `AuthorityExplanationPath`,
  `AuthorityPathMechanism`, `AuthorityUnresolvedFinding`,
  `KnownAuthorityUnresolvedFindingType`. Requires the runtime route from
  atlasent-api #2235 (draft as of this change) to be deployed; against an
  older runtime this surfaces as a normal 404 `AtlaSentError`, not a crash.
- **First SDK exposure of the `integrity-audit` sub-route**, and the first
  `client.authorityIntelligence` namespace. New sub-client with a single
  method, `integrityAudit(query?)`, wrapping
  `GET /v1-authority-intelligence/integrity-audit`. Read-only; requires an API
  key carrying the `authority_intelligence:read` scope. The organization is
  derived server-side from the authenticated key — there is no client-supplied
  `organization_id` on this route. One optional query option,
  `decisionWindowDays` (integer, 1–3650); omit it and **no**
  `decision_window_days` parameter is sent at all, so the server applies its
  own default and echoes the window actually applied in
  `report.summary.audited_scope`. The SDK never substitutes a guessed default.
  New types `IntegrityReport`, `IntegrityFinding`, `IntegrityClassification`,
  `IntegritySeverity`, `IntegrityEvidencePosture`, `IntegrityAuditQuery`,
  `IntegrityClassificationCounts`, plus the helper
  `countFindingsByClassification()`. The three sibling sub-routes
  (`sod-eligibility`, `blast-radius`, `explain-authority`) are deliberately
  **not** wrapped in this change; the namespace is left open for them. Note
  `explainAuthority` landed concurrently (see the entry above) as a *flat*
  client method against the slash path form
  `/v1/authority-intelligence/explain-authority`; this method uses the
  hyphenated `/v1-authority-intelligence/...` form its own route was specified
  with. Reconciling the two path forms — and whether `explainAuthority` should
  move under this namespace — is deliberately left to a follow-up rather than
  silently harmonized here.

  Two semantics are load-bearing and deliberate. **The classification is
  three-way, not a pass/fail signal** — a `non_exercisable` finding is
  frequently the *correct*, healthy state, and an `unresolved` finding must
  never be silently treated as clean — so no `isHealthy` / `hasErrors`
  convenience exists and none should be added; the only summary helper
  preserves all three counts explicitly. And **the value vocabulary is open at
  runtime**: `classification` / `severity` / `evidence_posture` are typed as
  their known unions widened with the repo's `(string & Record<never, never>)`
  idiom, and nothing is validated or rejected client-side, so a future
  server-side value passes through verbatim rather than throwing. A 5xx (the
  server refusing to return a partial report) propagates as `AtlaSentError`
  through the normal transport, exactly like every other endpoint — never as
  an empty report.
- `EvaluateResponse` gains two optional fields surfacing the two-stage
  authorization lifecycle (atlasent-api #1617): `humanApprovalRequired`
  (whether this evaluation requires a verified human approval) and
  `humanApprovalStatus` (the current satisfaction state — closed set
  `not_required | pending | satisfied | rejected | expired | revoked`).
  Both are already emitted by `/v1-evaluate` on runtimes that have shipped
  the lifecycle; this change teaches the SDK response type and mapping to
  surface them. No wire request shape, decision semantics, or existing
  field changed — purely additive and optional (`undefined` on older
  runtimes that predate the fields, never a fabricated default).
- Two temporal-execution-window deny-code constants to `DENY_CODES`:
  `NO_EXECUTION_WINDOW` and `OUTSIDE_EXECUTION_WINDOW`. These are part of the
  six evaluate-path authorization deny codes frozen in the runtime catalog
  (contract freeze 63 → 69, B5 Amendment 3); the other four
  (`NO_AUTHORITY`, `NO_SNAPSHOT`, `SNAPSHOT_TAMPERED`, `BOUNDARY_VIOLATION`)
  were already present. Client-side convenience constants only — no wire
  request/response, permit, or CDO shape changed; the `deny_code` field
  remains an open string. (atlasent#348 PR 2)

### Fixed

- `checkCrossOrgPermission()` and `listCrossOrgPermissionChecks()` posted
  to `/v1/cross-org/permissions/check[s]`, a path with no matching
  server-side route anywhere (not the edge function's own router, not the
  control-plane gateway, not the public OpenAPI spec) — every call would
  404 against a real deployment. Corrected to the real route,
  `/v1/federation/permission-check[s]`. Pre-existing bug, found while
  live-verifying the CROSS-028 production deploy; unrelated to the fields
  above, no request/response shape changed.

## 2.20.0

### Changed

- **`EvaluateRequest` now uses the canonical `actor_id` / `action_type`
  field names** (matching the runtime `/v1-evaluate` wire format and the
  contract at `contract/schemas/evaluate-request.schema.json`). This resolves
  the SDK field-name divergence tracked in atlasent issue #345 (finding T-02,
  ADR CROSS-008): the type surface previously taught `agent` / `action`, which
  no consumer can send to the runtime directly.

  This is a **compatibility-preserving transition, not a breaking removal**:
  - `actor_id` / `action_type` are the documented, recommended fields.
  - `agent` / `action` remain accepted as **deprecated aliases** — they are
    normalized to `actor_id` / `action_type` internally (per-field, so a mixed
    shape like `{ actor_id, action }` resolves correctly) and emit a one-time
    `console.warn` deprecation notice. They will be removed in a future major
    release.
  - The wire body sent to `/v1-evaluate` is unchanged — it has always been
    `{ action_type, actor_id, context }`; only the SDK-facing input type and
    its documentation changed. No permit bytes, CDO shapes, or runtime
    authorization semantics are affected.
  - Existing callers using `client.evaluate({ agent, action })` continue to
    work at runtime.

### Added

- `resolveEvaluateIdentity(input)` — exported helper that resolves the
  canonical `{ action_type, actor_id }` identity from either the canonical or
  legacy input shape (per-field, with a deprecation warning when a legacy alias
  is used). Used internally by `evaluate()`, `evaluatePreflight()`, and
  `protectStream()` so all three accept both shapes.

## 2.19.0

### Added

- `client.clinicalTrials` sub-client for the clinical trial unblinding gate
  (`v1-clinical-unblind`, `/v1/clinical-unblind`): `list` / `get` / `history`
  (reads, `clinical:read`) and `blind` / `requestUnblind` / `emergencyUnblind`
  / `verifyPermit` (writes, `clinical:manage`). Plus `makeClinicalTrialsClient`
  and the `ClinicalTrialsSubClient` / `ClinicalVerifyPermitRequest` /
  `ClinicalVerifyPermitResult` / `ClinicalTrialListQuery` types. Consumes the
  existing `clinical.ts` wire shapes; no new endpoint invented.

## 2.18.0

### Added

- `AtlaSentClient.complianceControls({ framework?, from?, to? })` — read the
  compliance control catalog (`GET /v1-compliance-controls`) resolved to
  live enforcement status per regulatory clause (`enforced` / `partial` /
  `not_enforced` / `no_data` / `attested`). Optional `framework` filters to
  one regime; `from`/`to` bound the evaluation window. Read-only — requires
  the `compliance:read` scope.
- `AtlaSentClient.complianceEvidencePack({ framework, from?, to? })` — fetch
  a signed, self-contained compliance evidence pack for one framework
  (`GET /v1-compliance-evidence-pack`). `framework` is required. The returned
  `bundle` is hashable offline against `sha256`, and `signature` /
  `signingStatus` / `keyId` carry the signing state.
- New exported result/query types: `ComplianceControlsResponse`,
  `ComplianceControlsQuery`, `ComplianceEvidencePackResponse`,
  `ComplianceEvidencePackQuery`, plus `ComplianceControl`,
  `ComplianceEvidenceControl`, `ComplianceEvidenceBundle`,
  `ComplianceSummary`, `ComplianceWindow`, and `ComplianceControlStatus`.
- Contract schemas `compliance-controls.schema.json` and
  `compliance-evidence-pack.schema.json`; the drift detector now pins both
  read endpoints.

## Unreleased

### Added

- `DENY_CODES.ACTOR_UNVERIFIED` — the verified-actor gate deny code. Returned
  when an action class requires a verified actor identity
  (`requires_verified_actor`) and the request carried no valid, in-binding
  `actor_identity.v1` assertion. Distinct from `INSUFFICIENT_APPROVALS`
  (`isHumanApprovalRequired` returns `false` for it). `retry_advice` is
  `with_modified_input`: attach a signed `actor_identity` assertion.
- `taxonomy` module — the canonical authorization taxonomy:
  `ACTION_CLASS_FAMILIES` (10), `CONDITION_TYPES` (26), `REASON_CODES` (31,
  the frozen deny-code set), plus `familyForSlug()` (roll an `action_type`
  slug up to one of the 10 families), `getReasonCode()`, and
  `isActionClassFamilyId` / `isConditionTypeId` / `isReasonCode` guards.
  Generated from the canonical registry (`atlasent/contract/taxonomy/v1`).

- `EvaluateResponse.deny_code` — the stable machine code naming *why* a
  non-allow decision was reached (e.g. `"SNAPSHOT_REQUIRED"`). `null` on
  `allow`. Branch on this instead of parsing the human-readable `reason`.
- `DENY_CODES` (constant registry of documented deny codes, incl.
  `INSUFFICIENT_APPROVALS`), the `DenyCode` type, and
  `isHumanApprovalRequired(input)` — accepts a raw code, an evaluate
  response, or an `AtlaSentDeniedError`. Route a denied action into an
  approval queue instead of treating it as a hard refusal. The wire
  `deny_code` stays an open string; the registry is convenience, not a
  closed enum. Companion to the atlasent-api per-class
  `requires_human_approval` gate.

### Fixed

- Canonical denials now capture the deny metadata correctly. `handler.ts`
  emits **top-level** `deny_code` / `deny_reason`, but the client previously
  read only the nested `denial.{reason,code}` shape — so canonical denials
  surfaced with an empty `reason` and no code. The client now reads both
  shapes (`deny_code ?? denial.code`, `deny_reason ?? denial.reason ?? reason`).

### Documentation

- README: the Quickstart `deployGate()` example now passes the required
  `stateSnapshot`, and a new "State snapshots (required)" section explains
  that action classes default to `requires_state_snapshot = true` — omitting
  the snapshot returns a `SNAPSHOT_REQUIRED` deny. `deployGate()` takes
  camelCase `stateSnapshot`; the raw `evaluate()` takes top-level snake_case
  `state_snapshot` (not part of `context`).
## @atlasent/sdk 2.17.0 (2026-06-10)

### New features

#### `client.smsOtp` — SMS OTP step-up authentication

New sub-client for sending and verifying one-time passcodes for session-level
operations that require step-up authentication (`break_glass`, `api_key_create`,
`governance_hold_approve`). JWT session auth only (not API key).

```ts
const { otp_id, expires_at } = await client.smsOtp.send({
  phone_e164: "+15551234567",
  action_context: "break_glass",
});

const { valid } = await client.smsOtp.verify({ otp_id, code: "123456" });
```

New types exported: `SmsOtpActionContext`, `SmsOtpSendRequest`,
`SmsOtpSendResponse`, `SmsOtpVerifyRequest`, `SmsOtpVerifyResponse`,
`SmsOtpSubClient`.

#### `client.usageMetering` — usage metering

New sub-client for listing billable evaluation records and fetching
aggregated usage summaries by billing period. Requires scope `usage:read`.

```ts
// Paginated list of evaluation records
const { data, next_cursor } = await client.usageMetering.list({
  limit: 100,
  decision: "allow",
});

// Aggregated summary
const summary = await client.usageMetering.summary({ period: "month" });
console.log(summary.total_evaluations, summary.billable_allows);
```

New types exported: `UsageMeteringPeriod`, `UsageMeteringRecord`,
`UsageMeteringListResponse`, `UsageMeteringListParams`,
`UsageMeterySummary`, `UsageMeteringSummaryParams`,
`UsageMeteringSubClient`.

---

## @atlasent/sdk 2.16.0 (2026-06-04)

### New features

#### `evaluation_profile` and `override` on `EvaluateRequest`

Two new optional fields on `EvaluateRequest` that surface the 12-layer
authorization algorithm controls:

**`evaluation_profile`** (`EvaluationProfile`) — controls which algorithm
layers run. Pass `"basic"` for pilot integrations that call
evaluate → permit → verify without supplying a full state snapshot;
snapshot enforcement is skipped while policy evaluation, risk envelope,
and audit all still run. Unknown values fall back to `"standard"` server-side.

```ts
const result = await client.evaluate({
  action_type:        "production.deploy",
  actor_id:           "github-actions",
  environment:        "production",
  evaluation_profile: "basic",          // pilot-safe: no snapshot required
});
```

**`override`** (`EmergencyOverrideV1`) — emergency override to clear snapshot
hard blocks. Only evaluated when `evaluation_profile` is `"advanced"` or
`"enterprise"`. The `authority_actor_id` must hold `override:execute` scope
on an active API key in the org and must differ from `actor_id`.

```ts
const result = await client.evaluate({
  action_type:        "production.deploy",
  actor_id:           "deploy-bot",
  environment:        "production",
  evaluation_profile: "advanced",
  state_snapshot: { source: "ci", payload: { tests_passed: false } },
  override: {
    version:             "override.v1",
    authority_actor_id:  "ops-lead-uuid",
    reason:              "Tests failed due to flaky test infra; manually verified",
    time_bound_seconds:  900,
  },
});
```

Both fields are additive — existing callers that omit them are unaffected.

New public types: `EvaluationProfile`, `EmergencyOverrideV1`.

---

## @atlasent/sdk 2.15.0 (2026-06-04)

### New features

#### `client.submitAssertion()` — F06 External Signal Ingestion

Submit a boolean point-in-time fact from an external connector (GitHub,
Stripe, Slack, or any custom source) so that policy rules can gate on
`context.activeAssertions` during evaluate calls.

```ts
const result = await client.submitAssertion({
  assertion_type: 'github.ci_passed',
  source_system:  'github',
  subject_ref:    `${repo}@${sha}`,
  actor_id:       'github-actions',
  action_type:    'production.deploy',
  trust_level:    'attested',
  valid_until:    new Date(Date.now() + 24 * 3_600_000).toISOString(),
});
// result.assertion_id  — server-assigned UUID
// result.payload_hash  — SHA-256 deduplication key
// result.reused        — true when an identical unexpired assertion already existed
```

Calls `POST /v1/assertions`. Requires API key scope `assertions:write`.

New public types: `AssertionSubmitInput`, `AssertionSubmitResult`.

---

## @atlasent/sdk 2.14.0 (2026-06-03)

### New features

#### `state_snapshot` field on `EvaluateRequest`

AtlaSent action classes may now require a state snapshot at evaluation time
(`requires_state_snapshot = true`). When required, omitting `state_snapshot`
causes the server to return `decision: "deny"` with `deny_code: "SNAPSHOT_REQUIRED"`.

Add the field to your evaluate calls:

```ts
const result = await client.evaluate({
  action_type: "production.deploy",
  actor_id:    "github-actions",
  environment: "production",
  state_snapshot: {
    source:      "github-actions",
    source_kind: "trusted",
    complete:    true,
    payload: {
      commit_sha:   process.env.GITHUB_SHA,
      workflow_ref: process.env.GITHUB_WORKFLOW_REF,
    },
  },
});
```

**Handling `SNAPSHOT_REQUIRED`:**

```ts
if (result.decision === "deny" && result.denial?.code === "SNAPSHOT_REQUIRED") {
  // Add state_snapshot to this evaluate call.
  // See: https://docs.atlasent.io/error-codes#SNAPSHOT_REQUIRED
}
```

The `state_snapshot` payload is recorded in the audit chain alongside the
permit, giving compliance teams a tamper-evident view of system state at
authorization time.

**TypeScript types** (`src/types.ts`, `src/compat.ts`):
- `EvaluateRequest.state_snapshot` — optional; present when the action class
  enforces snapshot capture.
- `V2EvaluateRequest.state_snapshot` — same field on the wire-format type;
  forwarded through `normalizeEvaluateRequest`.

---

## @atlasent/sdk 2.13.0 (2026-06-03)

### New features

#### License verification — self-hosted / air-gapped deployments

Two new types and two new `AtlaSentClient` methods for the
`GET /v1/license` and `POST /v1/license/verify` endpoints added to
`atlasent-api` for self-hosted and air-gapped postures.

**New types** (`src/types.ts`):
- `LicenseStatus` — license validity state (`"active" | "grace" | "expired" | "revoked"`),
  `org_slug`, `posture`, `expires_at`, optional `grace_until`, `features` array,
  and optional `eval_limit` / `seat_limit` capacity limits.
- `LicenseVerifyResult` — `valid` flag plus optional `org_slug`, `expires_at`, and
  machine-readable `error` code.

**New client methods**:
- `client.getLicense()` — calls `GET /v1/license`; returns `LicenseStatus & { rateLimit }`.
- `client.verifyLicense(blob)` — calls `POST /v1/license/verify`; returns
  `LicenseVerifyResult & { rateLimit }`. A `valid: false` response is not thrown.

### Documentation

- README: added "Why two calls? (the mental model)" section explaining the evaluate → permit token → verifyPermit → execute invariant and when to use `deployGate()` / `protect()` vs the raw two-step form.

### Internal

- Coverage: added tests for the `doDelete` non-JSON error body path and `pickFetch` globalThis fallback; added `type-coverage.test.ts` to force V8 evaluation of type-only modules. Lines and functions coverage now comfortably above the 95% floor.

---

## @atlasent/sdk 2.12.0 (2026-05-28)

### New features

#### Trust-root V1 — vendor snapshot, background refresh, fail-closed expiry

`@atlasent/sdk` now ships a vendored trust-root snapshot and a background
refresh manager implementing ADR-005 D2/D3/D4.

**`TrustRootManager`** (`src/trustRoot.ts`):
- Loads `vendor/trust-root/` at startup; falls back gracefully if files
  are missing.
- Refreshes from `https://keys.atlasent.io/.well-known/` every 4 hours
  (floor: 5 min) via a non-blocking background timer.
- `getGlobalTrustRootManager()` — singleton accessor; idempotent across
  multiple imports.
- `checkExpiry()` — returns `"ok" | "half_life" | "expired"` and emits
  one-time `console.warn` at the half-life point and on expiry.

**Global auto-inject (B2.3):**
`verifyBundle()` automatically calls `getGlobalTrustRootManager().getSnapshot()`
when no explicit `trustRoot` option is passed.

**Fail-closed expiry (B2.4) — ⚠ breaking change:**
`verifyAuditBundle()` now **throws** `BundleVerificationError` when the
trust snapshot is expired instead of returning `{ verified: false }`.
Callers that branch on `result.verified === false` must migrate to:
```ts
try {
  await verifyAuditBundle(bundle, keys);
} catch (err) {
  if (err instanceof BundleVerificationError) { /* ... */ }
}
```
Pass `allowExpiredSnapshot: true` to disable fail-closed for air-gap
environments (emits one-time warning per process).

**Revocation enforcement (B2.5):**
- `BundleVerificationError(reason: "key_revoked")` — key in `revoked_keys`.
- `BundleVerificationError(reason: "key_role_mismatch")` — key role is not
  `R3_audit`.
- New `PermitOutcome` literal: `"permit_signing_key_revoked"`.
- `AtlaSentDeniedError.isSigningKeyRevoked` convenience getter.

**`BundleVerificationError`** extends `AtlaSentError` and carries:
`reason`, `snapshotValidUntil`, `snapshotFetchedAt`, `snapshotSource`, `kid`.

### Tests

- `test/trust-root-b31-smoke.test.ts` — 8 bootstrap smoke tests (vendor
  snapshot loads, dates parseable, ≥1 key, idempotent manager).
- `test/trust-root-b32-refresh.test.ts` — 6 refresh integration tests
  (mock fetch updates `valid_until`, keys, revoked_keys; silent on errors).

---

## @atlasent/sdk 2.11.0 (2026-05-27)

### New features

#### `client.auth` — multi-IdP token management sub-client

`AtlaSentClient` now exposes a `client.auth` sub-client for programmatic token
lifecycle management:

- `client.auth.refresh(refreshToken)` — refresh against the default IdP
  (`POST /v1/auth/token/refresh`). Returns `{ accessToken, refreshToken, tokenType, expiresIn }`.
- `client.auth.refreshWithIdp(idpId, refreshToken)` — refresh against a named
  SSO connection (`POST /v1/auth/idp/{idpId}/token/refresh`).
- `client.auth.listIdpConnections()` — list available IdP connections for the
  org (`GET /v1/auth/idp-connections`). Returns `{ id, name, provider, enabled, isDefault, createdAt, domains? }[]`.

#### `client.scim` — SCIM 2.0 provisioning sub-client

`AtlaSentClient` now exposes a `client.scim` sub-client for managing
SCIM-provisioned users and groups:

- `client.scim.users.list(orgId, { filter?, startIndex?, count? })`
- `client.scim.users.create(orgId, user)` — `schemas` injected automatically
- `client.scim.users.update(orgId, userId, user)` — full PUT replacement
- `client.scim.users.delete(orgId, userId)`
- `client.scim.groups.list(orgId, { filter?, startIndex?, count? })`
- `client.scim.groups.create(orgId, group)`
- `client.scim.groups.delete(orgId, groupId)`

#### `client.evidenceBundles` — compliance evidence bundle sub-client

- `client.evidenceBundles.create(orgId, { incidentId?, includedPermits?, includeOverrides? })`
- `client.evidenceBundles.get(orgId, bundleId)`
- `client.evidenceBundles.download(orgId, bundleId, { format? })` — returns `ArrayBuffer`

#### `Decision` — unified decision type alias (Phase 2)

`Decision = "allow" | "deny" | "hold" | "escalate"` is now exported from the
package root as a canonical type alias. Use it for typed `switch` statements and
function signatures that accept or return a decision value.

```typescript
import type { Decision } from "@atlasent/sdk";

function handleDecision(d: Decision) { ... }
```

#### `Permit.permitExpiresAt` — permit expiry surface (Phase 2)

`Permit` now carries an optional `permitExpiresAt: string | undefined` field
populated from the server's `expires_at` on `protect()` responses. Callers can
use this for proactive permit-refresh scheduling without polling `/v1/permits/:id`.

#### `EvaluateResult.reasons` — plural reasons array (Phase 2)

`EvaluateResult` now carries `reasons: string[]` alongside the existing singular
`reason` string. The array is populated directly from the wire `reasons` field;
when the server returns only a singular `reason` the SDK wraps it in a
one-element array for backward compatibility. New code should prefer `reasons`.

#### Retries with jitter (Phase 2)

The SDK's internal retry loop now uses **full-jitter exponential back-off** on
transient errors (5xx, network timeout, `ECONNRESET`). Previously the back-off
was a fixed delay. The jitter prevents thundering-herd retry storms in
high-concurrency deployments. Maximum retry count and base delay are unchanged;
no public API surface change.

#### Browser guard warning (Phase 2)

When the SDK detects it is running in a browser context (i.e. `window` is
defined and `process` is not), it now emits a `console.warn` advising that API
keys should not be used client-side. No error is thrown — the warning is
informational only and can be suppressed by passing `{ suppressBrowserWarning:
true }` in the client constructor options.

#### `verifyEvidenceBundle(bundle)` — offline evidence-bundle verifier (Phase 3)

A new top-level `verifyEvidenceBundle(bundle)` function verifies a compliance
evidence bundle dict offline without a backend round-trip:

```typescript
import { verifyEvidenceBundle } from "@atlasent/sdk";

const result = verifyEvidenceBundle(bundle);
if (!result.valid) {
  console.error(result.reason);
}
```

Checks:
1. Required top-level fields are present.
2. `bundle.status === "ready"`.
3. SHA-256 root hash integrity when `hash_chain` is present.

Returns `EvidenceVerificationResult: { valid: boolean; permitId?: string; bundleId?: string; reason?: string }`.

Both `verifyEvidenceBundle` and `EvidenceVerificationResult` are exported from
the package root.

## Unreleased

### Packaging

- Normalized framework package licensing artifacts before publish:
  - `@atlasent/langchain`, `@atlasent/llamaindex`, and `@atlasent/cursor`
    now declare `"license": "Apache-2.0"` in `package.json`.
  - Package `LICENSE` files were normalized to Apache-2.0 text.
  - README license sections were updated to Apache-2.0.

## @atlasent/sdk 2.9.0 (2026-05-25)

### New features

#### `AtlaSentDeniedError.outcome` — permit-side denial discriminator (D4)

`AtlaSentDeniedError` now carries an `outcome` field typed as
`PermitOutcome | undefined`. When `/v1-verify-permit` rejects a permit,
the server's `outcome` string is normalized and surfaced here. Four
predicates provide ergonomic branching:

| Predicate | `outcome` value | When |
|---|---|---|
| `isRevoked` | `"permit_revoked"` | Operator revoked the permit mid-flight |
| `isExpired` | `"permit_expired"` | Permit TTL elapsed before verify |
| `isConsumed` | `"permit_consumed"` | Single-use permit already consumed |
| `isNotFound` | `"permit_not_found"` | Permit token not in DB |

Unknown future outcome strings normalize to `undefined` (forward-compat).
See `docs/REVOCATION_RUNBOOK.md` for the operator runbook.

```ts
try {
  await atlasent.protect({ agent, action, context });
} catch (err) {
  if (err instanceof AtlaSentDeniedError) {
    if (err.isRevoked) notifySecurity("permit revoked mid-flight");
    else if (err.isExpired) scheduleReauthorization();
  }
}
```

#### `protect()` / `protectWithEvidence()` — client-side `action` format validation

Both functions now validate that `action` matches the canonical
dot-notation format (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) before
making any network call. Invalid values throw `AtlaSentError` with
`code: "bad_request"` immediately at call site, matching the 400
`invalid_action_type` the server would return. This surfaces
mis-configured callers at integration time rather than at runtime.

#### Risk envelope — Phase C

Every evaluate response from engine version `wire-v1@1.0.0+` now includes
a `riskEnvelope` field exposing the composite risk score and how the policy
engine decision interacts with the risk envelope:

```typescript
const result = await client.evaluate({ agent, action, explain: true });

if (result.riskEnvelope) {
  console.log(result.riskEnvelope.weightedScore);      // 0.723
  console.log(result.riskEnvelope.engineDecision);    // "allow"
  console.log(result.riskEnvelope.envelopeDecision);  // "hold"
  console.log(result.riskEnvelope.promoted);          // true
  console.log(result.riskEnvelope.hardBlocks);        // []
  console.log(result.riskEnvelope.factors);           // per-factor breakdown
}
```

New types: `EvaluateRiskEnvelope`, `EvaluateRiskEnvelopeFactor` (exported from the root).

`promoted: true` means the envelope raised the engine decision's severity via
most-restrictive-wins. The envelope structurally cannot soften a deny.

`factors` is only populated when `explain: true` is passed on the request (see below).

#### `explain` request flag

Pass `explain: true` on `EvaluateRequest` to receive a per-factor breakdown in
`riskEnvelope.factors`:

```typescript
const result = await client.evaluate({
  agent: "payment-agent",
  action: "approve_payment",
  explain: true,
});
// result.riskEnvelope.factors is now populated
```

Seven factors: `ACTION_SENSITIVITY`, `ACTOR_AUTHORITY`, `ORG_POLICY_STRICTNESS`,
`ENVIRONMENT`, `CONTEXT_ANOMALY`, `HISTORY`, `BEHAVIOR_BASELINE`.
Each carries `{ factor, value, weight, reason }`.

Omit `explain` (or pass `false`) to keep payloads small.

### Exports added

- `PermitOutcome` — `"permit_consumed" | "permit_expired" | "permit_revoked" | "permit_not_found"`
- `normalizePermitOutcome(raw)` — maps server strings to `PermitOutcome | undefined`

---

## @atlasent/sdk 2.8.0 (2026-05-24)

### New features

#### `client.replay()` — ADR-015 Phase C parity runtime

`replay({ evaluationId })` re-evaluates a recorded decision against its
originally-pinned policy bundle via `POST /v1/decisions/:id/replay`.
Returns SDK-canonical variance kinds — callers always `switch` on
`result.varianceKind` and never need to catch.

Key differences from `replayDecision()` (2.7.0):

| | `replayDecision()` | `replay()` |
|---|---|---|
| Path | `/v1-decisions-replay/:id/replay` | `/v1/decisions/:id/replay` |
| Variance kind | raw wire (`DECISION_CHANGED`) | SDK-canonical (`POLICY_DRIFT`) |
| 409 handling | throws `AtlaSentError` | returns `ENGINE_DRIFT` / `BUNDLE_MISSING` |
| Input shape | `decisionId: string` | `{ evaluationId: string }` |

Variance mapping: `DECISION_CHANGED` → `POLICY_DRIFT`; 409
`replay_not_eligible` → `ENGINE_DRIFT` or `BUNDLE_MISSING` (based on
message content).

New exports: `ReplayRequest`, `ReplayResponse` (from `./replay.js`).
`ReplayVarianceKind` is extended to the 7-value superset covering both
`replayDecision()` raw wire values and `replay()` canonical values.

---
## @atlasent/sdk 2.7.0 (2026-05-24)

### New features

#### Decision replay client

A new `client.replayDecision(decisionId)` method that wraps
`POST /v1-decisions-replay/:id/replay`. Re-evaluates a recorded
decision against its originally-pinned policy bundle and engine version,
and reports whether the result agrees with the recorded one. Side-effect
free — no audit chain row is written and no permit is issued (per
ADR-016). Useful for compliance review, regression testing of bundle
changes, and post-incident investigation.

Surface returns one of three `variance` outcomes:
- `NONE` — replay agrees with the original.
- `DECISION_CHANGED` — same envelope, same bundle, different decision
  (typically a rule non-determinism bug).
- `ENVELOPE_DRIFT` — recorded request envelope no longer hashes to the
  recorded value; replay short-circuits without re-evaluating.

Also exports the supporting wire types: `ReplayDecisionResponse`,
`ReplayVarianceKind`, `EngineVersionKind`, `EnvelopeDriftDetail`,
`EnvelopeVerification`, `ReplayDecisionValue`.

> Note: `/v1/decisions/:id/replay` is **alpha** per atlasent-api's
> `STABLE_V2_PROMOTION.md`. Wire shapes can shift without a deprecation
> cycle until the endpoint graduates to stable v1.

---

## @atlasent/sdk 2.6.0 (2026-05-22)

