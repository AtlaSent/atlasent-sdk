# Constraint Schema Alignment Plan — SDK ↔ Console ↔ API

Status: **proposal / for review** · Owner: TBD · Date: 2026-05-31

## V1 decision — accept multiple bounded dialects (settled 2026-05-31)

For V1 we **accept multiple runtime condition dialects** across the platform, as
long as each is **documented and bounded**. We do **not** force convergence across
all dialects during V1. Specifically:

- **Canonical vocabulary alignment is COMPLETE.** The canonical target remains
  `atlasent-api/packages/types/schemas/policy-rule.schema.json`, with the long-form
  operator set: `equals, not_equals, greater_than, greater_than_or_equal,
  less_than, less_than_or_equal, in, not_in, contains, regex, exists, prefix`. The
  console `RuleCondition` mirror (`atlasent-console/packages/types/src/policy.ts`)
  is aligned to this set (WS2).
- **Runtime / evaluator representation convergence is POST-V1.** The runtime
  dialects (below) are intentionally not unified onto the canonical vocabulary for
  V1. Convergence follows the gated ordering in §5 (post-V1).
- **No evaluator rewrites during V1 stabilization.** The console edge evaluator
  (`_shared/evaluator.ts`) and the API runtime engine (`rules.ts` /
  `_shared/rules.ts`, `rules-sync` byte-identical) are frozen for V1.
- **No public SDK contract breaking changes during V1.** The SDK policy-document
  contract (`contract/schemas/policy.schema.json`) and the SDK wire types are not
  re-pointed or broken during V1.

### Runtime dialect map (V1)

Six condition surfaces exist across the platform. They map to the three model
layers documented below; this table is the authoritative bounded inventory. Only
the canonical row is a V1 convergence target — the rest are accepted as-is for V1.

| # | Dialect / surface | Location | Shape & operator vocabulary | Role | V1 status |
|---|---|---|---|---|---|
| **A** | **API canonical policy-rule schema** | `atlasent-api/packages/types/schemas/policy-rule.schema.json` (+ `@atlasent/types`) | flat `conditions[]` of `{condition_group, field_path, operator, value_json}`; long-form ops `equals/not_equals/greater_than/greater_than_or_equal/less_than/less_than_or_equal/in/not_in/contains/regex/exists/prefix` | **Canonical** authoring/storage source of truth | ✅ canonical target (settled) |
| **B** | **Console `RuleCondition` mirror** | `atlasent-console/packages/types/src/policy.ts` | `{field_path, operator, value_json}`; same long-form set **+** back-compat `not_contains`/`not_exists` (flagged non-canonical) | Console-side mirror of A | ✅ aligned to A (WS2) |
| **C** | **API SDK runtime engine dialect** | `atlasent-api/packages/sdk/src/rules.ts` (≡ `_shared/rules.ts`, `rules-sync`) | `templates[].when{all\|any\|none\|not}` of operator-keyed objects; ops `eq/neq/gt/gte/lt/lte/in/nin/contains/startswith/endswith/regex/exists/has_any/has_all/subset_of` + logical combinators; decision `decision`+`deny_code` | Runtime evaluation language for `/v1-evaluate`; the 21 packs author here | ⚠️ frozen — **A↔C gap → atlasent-api#1042** |
| **D** | **Standalone SDK public policy document** | `atlasent-sdk/contract/schemas/policy.schema.json` | `rules[].match` nesting `agent`/`action`/`context.<key>` matchers (stringMatcher/valueMatcher); `effect: allow/deny` | Author-side example/fixture lint format (SDKs never parse policies at runtime) | ⚠️ frozen — no breaking change in V1 |
| **E** | **Console runtime evaluator shorthand** | `atlasent-console/.../_shared/evaluator.ts` (+ persisted `conditions_json`) | `{field, op, value, valueField}` in `ifAll`/`ifAny`; shorthand ops `eq/neq/gt/gte/lt/lte/in/notIn/missing/present/before/after/withinSeconds` | **Active V1 runtime contract** for console-authored policies | ⚠️ frozen — convergence post-V1 (§5) |
| **F** | **Console guard/CLI string DSL** | `atlasent-console/packages/sdk/src/policy/condition.ts` | string-expression DSL (`"content_length > 200"`, `"repo_visibility == public"`) + boolean flags (`secret_detected`, `branch_protected`, …); `PolicyRule { action_types[] }` | Local guard/CLI pre-checks (the `atlasent` package) | ⚠️ frozen — bounded local form, not a wire/storage type |

Layer mapping: **A** + **B** are the *rule-row authoring/storage model* (two
instances of the same model). **C** is the *runtime rule-engine DSL*. **D** is the
*SDK policy-document example format*. **E** is the *console's own edge runtime*
representation (the active V1 contract for console policies). **F** is a
*local-only guard/CLI* expression form. See the three-model framing in the next
section and `atlasent-api/docs/TWO_RULE_SYSTEMS.md`.

### Tracking

The **A↔C gap** — the canonical schema (A) and the API SDK runtime engine (C) use
different operator vocabularies/representations, and C carries operators
(`startswith`/`endswith`/`has_any`/`has_all`/`subset_of`) and nestable logical
combinators with no canonical (A) equivalent — is tracked in AtlaSent's
internal API issue tracker.
It is to be investigated and either documented as intentional layering or
converged **post-V1**. No V1 action.

The A↔C divergence is the **primary convergence issue to track after V1
stabilization** — it is the most important outcome of this investigation.

### Architectural objective

> The existence of multiple runtime dialects is currently accepted. The
> architectural objective is not immediate dialect elimination, but convergence
> toward a single API-owned canonical representation after V1 runtime
> stabilization.

## Architecture decision (settled)

**Policy types move under API ownership.** `atlasent-api/packages/types` becomes
the canonical home for the policy rule/condition types. Ownership flows in one
direction:

```
atlasent-api/packages/types   (canonical — runtime/API is the execution authority)
        │
        ├─► atlasent-sdk        re-exports (never redefines; honors the existing
        │                       "wire types source of truth is atlasent-api" invariant)
        │
        └─► atlasent-console    consumes (drops local ownership of these types)
```

Rationale:
- The **runtime/API is the execution authority** — it evaluates policies, so it
  owns the canonical shape.
- The **console is a consumer**, not an owner. Its
  `packages/types/src/policy.ts` becomes a thin re-export of the API types.
- **SDK re-exports** continue to honor the existing `atlasent-sdk/CLAUDE.md`
  invariant ("wire types source of truth is `atlasent-api/packages/types/`; SDK
  re-exports, never redefines independently").
- **No new shared package** (e.g. `@atlasent/policy-types`) is introduced until
  V1 runtime convergence and semantic stabilization are complete. Extracting a
  standalone package now would freeze a still-moving contract; revisit post-V1.

This resolves the former WS1 "package home" open question in favor of Option 1.

## Scope clarification: three distinct rule representations (added post-WS1)

Investigation during WS4 and WS3 surfaced a premise this plan originally got
wrong. There are **three separate rule representations** in the platform, not one:

1. **Authoring / storage rule-row model** — `policy_rules` / `rule_conditions` /
   `rule_obligations` tables, the console policy builders, and (as of WS1) the
   canonical `@atlasent/types` policy types. Operators are long-form
   (`equals`, `greater_than`), conditions are a flat `conditions[]` with
   `condition_group` AND/OR grouping. **This is what the plan unifies.**

2. **Runtime rule-engine DSL** — `packages/sdk/src/rules.ts` (kept byte-identical
   to `supabase/functions/_shared/rules.ts` via `rules-sync` CI). This is the
   zero-dependency evaluator that every `/v1-evaluate` call runs. Its language is
   `{templates:[{decision, deny_code, when:{all|any:[{field, eq|gt|gte|lt|…}]}}]}`
   with nestable `all`/`any` combinators. The **21 policy packs author their
   `templates[].rule` in this DSL**, and the seed path stores it verbatim into
   `constraint_bundles.rules`.

3. **SDK policy document** — `atlasent-sdk/contract/schemas/policy.schema.json`, a
   `match`-DSL *document* format (`rules[].match` nesting `agent`/`action`/
   `context.<key>` matchers) used **only** to lint SDK-shipped example
   policies/fixtures via `policy_lint.py`. Per SDK doctrine the SDKs never parse
   policies at runtime; this is an author-side example format, not a wire type
   (so `drift.py` does not govern it).

These are intentionally different layers: the rule-row model is for *authoring and
storage*; the engine DSL is the *runtime evaluation language*; the SDK document is
an *author-side example/fixture* format. Packs belong to system (2); the SDK
schema is system (3). Neither can be converted to the rule-row vocabulary without
rewriting the production engine (2) or violating SDK doctrine (3).

**Decision (settled):** keep systems (2) and (3) separate. The plan unifies only
the rule-row model (WS1–WS2) and documents the relationship among all three in
`atlasent-api/docs/TWO_RULE_SYSTEMS.md`. WS3 and WS4 are re-scoped to
documentation accordingly (see below).

## Goal

Today the same "constraint" concept is expressed in several incompatible shapes
across the SDK, the console, and the API. This plan unifies the **authoring /
storage rule-row model** on a **single source of truth: the console/API rule-row
format** (the shape stored in `policy_rules` / `rule_conditions`), and brings the
SDK contract schema into conformance with it.

Note: the **API policy packs** are a *different* system — they author in the
runtime rule-engine DSL (`rules.ts`), not the rule-row model — and are explicitly
**out of scope** for conversion. See "two distinct rule systems" above. The packs
column in the table below is retained only to show where the engine DSL sits
relative to the rule-row model; it is **not** a conversion target.

## Why the rule-row format is the canonical *target*

It is the richest representation and the intended convergence target:

- 5-value `effect` (`allow | deny | hold | escalate | require_approval`)
- `deny_code` + `deny_reason` for explainability
- `require_approvals` / obligations
- layered-policy columns (`policy_layer`, `tags`, `overrides_policy_id`, …)

**Important correction (post-WS2):** the rule-row model is the canonical *target*,
**not** the currently-active runtime representation everywhere. In particular the
console persists and evaluates **shorthand `conditions_json`** (`{field, op,
value}`) via its own edge evaluator — that shorthand is the current V1 runtime
contract. The canonical `RuleCondition` (`field_path`/`operator`/`value_json`)
becomes the active representation only after the post-V1 convergence (§5) proves
runtime parity. Until then, do not assume rule-row == what's stored/evaluated.
- mirrors the DB tables `policy_rules`, `rule_conditions`, `rule_obligations`

The SDK contract schema (`contract/schemas/policy.schema.json`) is strictly
weaker (only `allow`/`deny`, no deny codes, no approvals, nested
`agent`/`action`/`context` matchers), so collapsing *toward* it would lose
information. We align everything *to* the rule-row format instead.

## Current state (the shapes)

Three of the columns below are the rule-row model in different states of
divergence (the unification targets). The **packs** column is the separate runtime
engine DSL, shown for contrast only — *not* a conversion target.

| Aspect | SDK contract (`atlasent-sdk/contract/schemas/policy.schema.json`) | API packs — engine DSL *(separate system, not converted)* | Console UI (`conditions_json`) | Console types (`atlasent-console/packages/types/src/policy.ts`) |
|---|---|---|---|---|
| Rule container | `rules[].match` | `rules.templates[].when` | `conditions_json[]` | `conditions[]` (`RuleCondition`) |
| Field key | nested `agent`/`action`/`context.<f>` | `field` | `field` | `field_path` |
| Equality | `equals` | `eq` | `eq` | `equals` |
| Compare | `gt/gte/lt/lte` | `gt`… inline | `gt/gte/lt/lte` | `greater_than/less_than` |
| Set | `in` | `in` | `in/notIn` | `in/not_in` |
| String | `prefix`, `regex` | — | — | `contains`, `regex` |
| Presence | `exists` | — | `present/missing` | `exists/not_exists` |
| Decision | `effect` (allow/deny) | `decision` + `deny_code` | `effect` (5) | `effect` (5, `RuleEffect`) |
| Approvals | — | `require_approvals` | obligations | obligations |
| Value | inline | inline | `value` | `value_json` |

A constraint authored in any one of these cannot be validated/consumed by the
others.

## Target canonical schema (v1)

A single normalized rule shape, **owned by `atlasent-api/packages/types`**,
hardened into a formal JSON Schema that the SDK re-exports and the console
consumes.

```jsonc
{
  "id": "string",
  "name": "string",
  "description": "string|null",
  "priority": 100,
  "enabled": true,
  "effect": "allow|deny|hold|escalate|require_approval",
  "stop_on_match": true,
  "rationale_template": "string|null",
  "deny_code": "string?",            // promoted to first-class (from packs)
  "require_approvals": 0,            // promoted to first-class (from packs)
  // layered policy
  "policy_layer": "global|domain|environment|action_type|resource|exception",
  "tags": ["string"],
  "overrides_policy_id": "string?",
  "override_reason": "string?",
  "override_scope": "string?",
  "override_expires_at": "iso8601?",
  "resource_type": "string?",
  "resource_id": "string?",
  // conditions (AND within a group; groups OR'd by condition_group)
  "conditions": [
    {
      "condition_group": 0,
      "field_path": "context.environment",   // dotted path; replaces nested match
      "operator": "equals",                  // canonical operator vocabulary
      "value_json": "production"
    }
  ],
  "obligations": [
    { "obligation_type": "string", "config_json": {} }
  ]
}
```

### Canonical operator vocabulary (the one true list)

The canonical, long-form operator set (used for **all storage and wire
formats**):

`equals, not_equals, greater_than, greater_than_or_equal, less_than,
less_than_or_equal, in, not_in, contains, regex, exists, prefix`

Notes:
- adds `greater_than_or_equal` / `less_than_or_equal` (today only `gt/lt` exist
  in console types — gap to close)
- adds `prefix` (only the SDK has it today)
- `exists` replaces the SDK `exists:bool` and console `present/missing`
- **Dropped from the canonical set:** `not_contains` and `not_exists` (present in
  today's console `ConditionOperator`). These are **not** canonical. Any stored
  rule using them must be migrated — `not_exists` → `exists` with negated intent
  handled at the rule level (or a `not_equals`-style rewrite), `not_contains` →
  re-expressed via the negation path. The migration codemod must flag any rule it
  cannot mechanically convert for manual review.

**Shorthand (UI only).** The UI may expose `eq / gt / gte / lt / lte` as
author-friendly shorthand, but these are presentation aliases only. They MUST be
expanded to the canonical long-form names before persistence or transmission —
canonical storage and wire formats never contain shorthand. A single bidirectional
mapping table (shorthand ⇄ canonical) lives with the canonical types in
`atlasent-api/packages/types` and is the only place the aliasing is defined.

| Shorthand (UI) | Canonical (storage/wire) |
|---|---|
| `eq` | `equals` |
| `gt` | `greater_than` |
| `gte` | `greater_than_or_equal` |
| `lt` | `less_than` |
| `lte` | `less_than_or_equal` |

### Decision/effect

Canonical `effect` is the 5-value set. The SDK schema's 2-value `effect` is a
strict subset, so existing SDK policies remain valid after migration.

### Match → conditions mapping

The SDK's nested `match.agent/action/context` collapses to flat
`field_path` conditions:

| SDK match | Canonical condition |
|---|---|
| `agent: {prefix: "clinical-"}` | `{field_path:"agent", operator:"prefix", value_json:"clinical-"}` |
| `action: {in:[...]}` | `{field_path:"action", operator:"in", value_json:[...]}` |
| `context.amount:{lte:10000}` | `{field_path:"context.amount", operator:"less_than_or_equal", value_json:10000}` |
| `require:["x"]` | `{field_path:"context.x", operator:"exists", value_json:true}` |

## Workstreams

### 1. Canonical types in the API (foundation)
- **Move the rule-row types into `atlasent-api/packages/types`.** Today
  `ConditionOperator`/`RuleEffect`/`RuleCondition`/`PolicyRule` are defined only in
  `atlasent-console/packages/types/src/policy.ts`; the API types package exists but
  holds only governance/context types. Add a `policy.ts` (rule-row types +
  canonical operator vocabulary + shorthand mapping table) and export it from the
  package `index.ts`. This makes the API the canonical owner per the architecture
  decision above.
- Author a canonical JSON Schema `policy-rule.schema.json` alongside the TS types
  (single generator so the schema and TS never drift). The API also drops its
  duplicate copy in `_shared/layered-evaluator.ts`, importing from the package
  instead.
- Add JSON Schema validation fixtures (port from `atlasent-sdk/contract/vectors`).
- **Do not** create a new standalone shared package yet — defer until post-V1
  runtime convergence per the architecture decision.

### 2. Console (consumer) — **DONE, scoped to types + bridge**
Investigation (WS2) corrected the premise here. The console does **not** store the
rule-row model: both `PolicyBuilderPage` and `ConstraintBuilder` persist
**shorthand** `conditions_json` (`{ field, op, value }`, ops `eq`/`gt`/`notIn`/…),
and the console's own edge evaluator (`supabase/functions/_shared/evaluator.ts`)
reads that shorthand at runtime. **Shorthand `conditions_json` is the current V1
runtime contract.** The rule-row `RuleCondition` (`field_path`/`operator`/
`value_json`) is **not** the active runtime representation — it is the target
post-V1 representation.

What WS2 actually did (no runtime behavior change):
- Aligned the console's own `ConditionOperator` to the canonical long-form set
  (`packages/types/src/policy.ts`): added `greater_than_or_equal`,
  `less_than_or_equal`, `prefix`; exported `CANONICAL_CONDITION_OPERATORS`. Kept
  `not_contains`/`not_exists` (still referenced by a live pack template), marked
  explicitly non-canonical.
- Added `src/lib/policy/conditionOperators.ts` — `toCanonicalOperator` /
  `toShorthandOperator` / `toCanonicalConditionView`, **tested bridges only**.
  These translate between shorthand and canonical for diff/lint/round-trip
  tooling. They are **not** wired into persistence — builders still write
  shorthand `conditions_json`, unchanged.
- Console keeps its own `@atlasent/types` package for now (drift-watched); the
  re-export consolidation with API-owned types is deferred to post-V1.

Both builders stay active. `ConstraintBuilder` is **not** legacy-format — it is a
separate UX over the same V1 wire format as `PolicyBuilder`. There is no
deprecation in this pass (a banner asserting otherwise was added and then
reverted once the code proved both builders emit the same format).

### 5. Post-V1 convergence (replaces the former WS5 "deprecation")
Migrating the console onto the canonical rule-row representation is a **post-V1**
effort gated on proven runtime parity — not an in-product deprecation. Strict
ordering, each step landing before the next:

1. **Lock the contract.** Treat shorthand `conditions_json` as the current V1
   runtime contract and document it as such. The canonical `RuleCondition` is the
   *target* representation, explicitly not yet active at runtime.
2. **Evaluator dual-accept.** Teach the console edge evaluator
   (`_shared/evaluator.ts`) to accept **both** shorthand and canonical conditions,
   normalizing internally. No builder changes yet.
3. **Prove semantic parity.** Add tests that run the same rule in both shapes
   through the evaluator and assert identical decisions across the operator
   matrix (including edge cases: presence ops, numeric coercion, set ops). The
   `toCanonicalRule()`/`fromCanonicalRule()` bridges are validated here.
4. **Migrate builders one at a time.** Only after parity is green, switch a single
   builder to persist canonical, soak it, then the next. Both builders remain
   functional throughout.
5. **Deprecate shorthand last.** Shorthand `conditions_json` is deprecated only
   after every writer emits canonical and runtime parity has held in production.
   Removal of the shorthand path is the final step, not the first.

Do **not** change production evaluator behavior or what the builders persist
ahead of step 2's parity proof. The risk being avoided: writing a canonical shape
the live evaluator cannot read, which would silently break evaluation.

### 3. SDK — **RE-SCOPED** (documentation only; no SDK code change)
Original premise (SDK re-exports the rule-row types, re-points
`policy.schema.json` at the canonical shape, adds a builder/validator + V0→V1
codemod, repairs malformed JSON) was **wrong on every count** — investigation
during WS3 found:
- **No malformed JSON.** `contract/schemas/policy.schema.json` parses cleanly; the
  lines flagged earlier were valid `oneOf` matcher structures. Nothing to repair.
- **The SDK has no rule-row surface.** It does not depend on `@atlasent/types` and
  defines none of `field_path` / `condition_group` / `RuleEffect` /
  `RuleCondition`. Its only `Constraint*` types are `ConstraintTrace*`, which are
  *decision-trace output*, not authoring inputs. There is nothing to "re-export".
- **`policy.schema.json` is a third representation**, not the rule-row model and
  not the engine DSL: a `match`-DSL policy *document* (`rules[].match` nesting
  `agent`/`action`/`context.<key>` matchers) used **only** to lint SDK-shipped
  example policies/fixtures via `contract/tools/policy_lint.py`. It is **not** a
  wire type, so `drift.py` does not govern it; re-pointing it would silently
  change every shipped fixture.
- **SDK doctrine forbids the rest.** "SDKs never parse policies directly" and "do
  not invent new bundle formats in the SDK without a `contract/` proposal first."
  A builder/validator/codemod would invert both.

Re-scoped deliverable: document the SDK policy-document model as the **third**
representation alongside the engine DSL and the rule-row model (folded into the
same `atlasent-api/docs/TWO_RULE_SYSTEMS.md` doc, now a three-model reference).
**No SDK code, schema, or type change.** The `rules.ts` byte-identical and
contract-first invariants are therefore untouched. If a first-class SDK
policy-authoring API is ever wanted, it begins as a `contract/` proposal — not as
a re-point of the example-lint schema.

### 4. API / policy packs — **RE-SCOPED** (do NOT convert packs)
Original premise (convert packs from inline `eq` to canonical `conditions[]`) was
**wrong** — see "two distinct rule systems" above. The packs author in the runtime
rule-engine DSL (`rules.ts`), not the rule-row model. Converting them would mean
rewriting the production evaluate path. Re-scoped to documentation + guard rails:
- **Do not** change pack `templates[].rule` shapes or the `rules.ts` DSL.
- Author a **mapping document** describing how the two systems relate: the engine
  DSL operators (`eq/gt/gte/lt/in/…`, `when.all`/`when.any`) vs. the canonical
  rule-row operators (`equals/greater_than/…`, `conditions[]` + `condition_group`),
  and which surfaces use which. Cross-link the canonical shorthand table (the
  engine DSL's `eq/gt` are *coincidentally* the same tokens as the UI shorthand,
  but they live in a different system — call this out to prevent confusion).
- Note the boundary in `packages/packs` and near `rules.ts` so future work does
  not try to "align" the engine DSL onto the rule-row vocabulary without an
  explicit engine-rewrite decision.
- The `policy-rule.schema.json` from WS1 validates the **rule-row** model only; it
  is explicitly **not** applied to pack files.

### 5. Compatibility & rollout
- Ship `migratePolicyV0toV1()` in the SDK; run it over `contract/vectors`.
- Dual-accept window: API validators accept both shapes for one minor version,
  emit a deprecation warning on legacy.
- Version the schema (`schema_version: "1"`) in stored rules and pack files.

## Sequencing

1. WS1 canonical types in `atlasent-api/packages/types` + JSON Schema + fixtures. **(done — PR atlasent-api#1036)**
2. WS4 **re-scoped** to the three-model mapping doc, no pack conversion. **(done — PR atlasent-api#1036, sdk#337)**
3. WS3 **re-scoped** to documenting the SDK policy document as the third model; no SDK code change. **(done — same doc)**
4. WS2 console aligns its `ConditionOperator` + adds tested shorthand⇄canonical bridges; no behavior change. **(done — PR console#594)**
5. WS5 **replaced** by the post-V1 convergence plan (evaluator dual-accept → parity tests → builders migrate one at a time → shorthand deprecated last). **(plan only; no V1 code)**

## Resolved decisions

- **Package home** — *Resolved:* canonical home is `atlasent-api/packages/types`
  (API ownership). No new shared package until post-V1 runtime convergence.
  SDK re-exports; console consumes.
- **Operator labels** — *Resolved:* canonical storage/wire uses long-form names;
  UI may show `eq/gt/gte/lt/lte` shorthand, expanded via the shared mapping table
  before persistence.
- **Legacy ConstraintBuilder** — *Resolved:* three-phase deprecation
  (V1 dual-accept → V2 read-only → V3 removal).

## Open questions (remaining)

- **`not_contains` / `not_exists` migration** — confirm the rewrite strategy for
  stored rules using these dropped operators (mechanical vs. manual-review
  fallback).
- **Backfill** — rewrite already-stored rule rows to the versioned canonical
  shape, or tag-and-translate on read until V3?
- **Operator labels**: keep shorthand `eq/gt` as console UI sugar, or surface the
  wordy ops directly to users?
- **Legacy ConstraintBuilder page**: refactor onto canonical, or deprecate/remove?
- **Backfill**: rewrite already-stored rule rows to the versioned shape, or only
  tag-and-translate on read?

## Affected files (index)

- `atlasent-api/packages/types/src/policy.ts` (**new** — canonical rule-row types + operator vocabulary + shorthand map)
- `atlasent-api/packages/types/src/index.ts` (export policy types)
- `atlasent-api/packages/types/.../policy-rule.schema.json` (**new** — canonical JSON Schema)
- `atlasent-api/supabase/functions/_shared/layered-evaluator.ts` (drop duplicate types; import from package)
- `atlasent-api/packages/packs/src/packs/*` (21 packs convert)
- `atlasent-api/packages/packs/src/index.ts` (+ build-time validator)
- `atlasent-sdk/contract/schemas/policy.schema.json` (re-point at canonical + repair malformed JSON)
- `atlasent-sdk/contract/vectors/policies/*.json` (migrate)
- `atlasent-sdk/typescript/src/{types.ts,evidenceEngine.ts,protect.ts}` (re-export API types; + new builder/validator)
- `atlasent-sdk/python/atlasent/models.py` (+ new builder/validator)
- `atlasent-console/packages/types/src/policy.ts` (replace definitions with re-exports of API types)
- `atlasent-console/src/pages/PolicyBuilderPage.tsx` (shorthand→canonical on serialize)
- `atlasent-console/src/pages/ConstraintBuilder.tsx` (deprecation path V1→V3)
- `atlasent-console/src/components/policy/TemplateEditorModal.tsx`
- `atlasent-console/src/hooks/usePolicyBundles.ts`
- `atlasent-console/src/lib/api/rpc-client.ts`
</content>
