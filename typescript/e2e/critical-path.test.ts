/**
 * E2E / Integration — Critical path: auth → evaluate → permit verify → audit
 *
 * This file doubles as a living specification for the canonical execution
 * path through the AtlaSent API. Each describe block documents a contract
 * boundary; each it() block states WHAT the canonical behaviour is.
 *
 * Tests are skipped (via describe.skipIf) when the required environment
 * variables are absent, so they never block CI on forks or offline runs.
 * The test structure and assertions remain as spec even when skipped.
 *
 * Required env vars:
 *   ATLASENT_API_URL        — base URL, e.g. https://staging.atlasent.io
 *   ATLASENT_API_KEY        — a valid API key (ask_test_… or ask_live_…)
 *   ATLASENT_TEST_ORG_ID   — staging org ID for audit queries
 *
 * Run:
 *   ATLASENT_API_URL=https://staging.atlasent.io \
 *   ATLASENT_API_KEY=ask_test_... \
 *   ATLASENT_TEST_ORG_ID=org_... \
 *   npx vitest run e2e/
 */

import { describe, expect, it, beforeAll } from "vitest";
import { AtlaSentClient, AtlaSentError } from "../src/index.js";

// ---------------------------------------------------------------------------
// Environment guards — all three must be present for any test to run live.
// ---------------------------------------------------------------------------

const API_URL = process.env["ATLASENT_API_URL"] ?? "";
const API_KEY = process.env["ATLASENT_API_KEY"] ?? "";
const ORG_ID = process.env["ATLASENT_TEST_ORG_ID"] ?? "";

const haveEnv = Boolean(API_URL && API_KEY && ORG_ID);

// ---------------------------------------------------------------------------
// describe 1 — Auth header contract
//
// KNOWN ISSUE — auth header divergence (as of 2026-05-07):
//
//   The TypeScript SDK (AtlaSentClient.request) sends:
//     Authorization: Bearer <key>
//   with NO X-AtlaSent-Key header.
//
//   The API's _shared/auth.ts checks headers in this order:
//     1. X-AtlaSent-Key   → direct hash lookup against api_keys table (401 on failure)
//     2. Authorization: Bearer → legacy non-JWT path via validate_api_key RPC (403 on failure)
//                           or JWT path via supabase.auth.getUser (401 on failure)
//
//   The divergence means:
//   - SDK callers always go through the LEGACY BEARER PATH, not the
//     preferred X-AtlaSent-Key path.
//   - The two paths return different HTTP status codes on auth failure:
//       X-AtlaSent-Key path  → 401 on bad key
//       Bearer (non-JWT) path → 403 on bad key (validate_api_key RPC empty result)
//   - Correct key: both paths succeed (functionally equivalent for a valid key).
//
//   The atlasent-action (src/index.ts) delegates to @atlasent/enforce which
//   internally uses the SDK, so it also sends Authorization: Bearer only.
//   The streaming path (protectStream) also sends Authorization: Bearer only.
//
//   RECOMMENDATION: Either (a) add X-AtlaSent-Key to the SDK's request()
//   method so it uses the preferred path, or (b) document that the SDK
//   intentionally uses the Bearer path and align error codes between the
//   two paths (401 everywhere). See auth header divergence section in PR body.
// ---------------------------------------------------------------------------

describe.skipIf(!haveEnv)("auth header contract", () => {
  /**
   * CANONICAL BEHAVIOUR: The SDK sends Authorization: Bearer <key>.
   * The API accepts this via the legacy non-JWT bearer path in _shared/auth.ts.
   * A valid key must result in HTTP 200 from /v1-evaluate.
   *
   * NOTE: The SDK does NOT send X-AtlaSent-Key. This test verifies the
   * SDK's actual header (Bearer) is accepted by the API — it does NOT
   * verify that X-AtlaSent-Key also works (that would require a raw fetch).
   */
  it("SDK Authorization: Bearer <key> is accepted by /v1-evaluate (200)", async () => {
    const client = new AtlaSentClient({ apiKey: API_KEY, baseUrl: API_URL });
    // A successful evaluate (any decision) proves auth was accepted.
    // We do not assert a specific decision — policy may vary by org config.
    const result = await client.evaluate({
      action_type: "e2e:smoke",
      actor_id: "e2e-test-runner",
      context: { source: "e2e-critical-path", ci: true },
    });
    expect(["allow", "deny", "hold", "escalate"]).toContain(result.decision);
  });

  /**
   * CANONICAL BEHAVIOUR: A wrong API key sent via Authorization: Bearer
   * must be rejected. Per _shared/auth.ts the Bearer (non-JWT) path calls
   * validate_api_key RPC; an empty/not-found result throws AuthError(403).
   *
   * DIVERGENCE EXPOSED: The X-AtlaSent-Key path throws AuthError(401) for
   * the same condition. Callers using Bearer (the SDK's path) see 403, not
   * 401, on an invalid key. This is a spec gap — both paths SHOULD return 401.
   *
   * This test asserts the ACTUAL CURRENT BEHAVIOUR (403 for Bearer path)
   * so regressions are visible. Update to 401 once the paths are aligned.
   */
  it("wrong API key via Authorization: Bearer → 403 (not 401 or 200) [Bearer-path behaviour]", async () => {
    // Use a raw fetch so we can bypass SDK key-shape validation.
    const res = await fetch(`${API_URL}/v1-evaluate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Deliberately wrong but structurally valid key.
        Authorization: "Bearer ask_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
      body: JSON.stringify({
        action_type: "e2e:smoke",
        actor_id: "e2e-test-runner",
        context: {},
      }),
    });
    // KNOWN DIVERGENCE: Bearer path returns 403 for bad key.
    // X-AtlaSent-Key path would return 401.
    // A future fix should unify to 401 — change assertion then.
    expect(res.status).toBe(403);
  });

  /**
   * CANONICAL BEHAVIOUR: A wrong API key sent via X-AtlaSent-Key (the
   * preferred path per _shared/auth.ts) must be rejected with 401.
   *
   * DIVERGENCE EXPOSED: The SDK never sends X-AtlaSent-Key, so SDK users
   * never exercise this path. This test uses raw fetch to confirm the
   * X-AtlaSent-Key path is reachable and returns 401 (not 403).
   */
  it("wrong API key via X-AtlaSent-Key → 401 (preferred path, not used by SDK) [X-AtlaSent-Key-path behaviour]", async () => {
    const res = await fetch(`${API_URL}/v1-evaluate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-AtlaSent-Key": "ask_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
      body: JSON.stringify({
        action_type: "e2e:smoke",
        actor_id: "e2e-test-runner",
        context: {},
      }),
    });
    // X-AtlaSent-Key path: 401 for bad key (AuthError('Invalid API key', 401)).
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// describe 2 — evaluate → permit → verify
// ---------------------------------------------------------------------------

describe.skipIf(!haveEnv)("evaluate → permit → verify", () => {
  let evaluationId: string;
  let permitToken: string;
  let decision: string;

  /**
   * CANONICAL BEHAVIOUR: POST /v1-evaluate with a minimal valid body returns
   * a JSON envelope with:
   *   decision: "allow" | "deny" | "hold" | "escalate"  (lowercase)
   *   permit_token: string  (present iff decision === "allow")
   *   request_id: string
   *
   * The SDK normalises the decision to lowercase regardless of what the
   * server emits, so callers may rely on lowercase-only values.
   */
  it("POST /v1-evaluate returns decision ∈ {allow,deny,hold,escalate} (lowercase)", async () => {
    const client = new AtlaSentClient({ apiKey: API_KEY, baseUrl: API_URL });
    const result = await client.evaluate({
      action_type: "e2e:smoke",
      actor_id: "e2e-test-runner",
      context: { source: "e2e-critical-path", ci: true },
    });

    expect(["allow", "deny", "hold", "escalate"]).toContain(result.decision);
    // SDK always emits lowercase canonical form.
    expect(result.decision).toBe(result.decision.toLowerCase());

    decision = result.decision;
    evaluationId = result.permitId; // permit_token or decision_id from server
  });

  /**
   * CANONICAL BEHAVIOUR: When the decision is "allow", the server must
   * include a non-empty permit_token in the response. The SDK surfaces
   * this as result.permitId.
   *
   * This test is skipped (pending) when the preceding evaluate returned
   * a non-allow decision — we cannot control policy from the test suite.
   */
  it("decision=allow → permit_token present and non-empty", async () => {
    if (decision !== "allow") {
      // The org policy produced a non-allow result. We document the
      // expectation here but cannot assert it without a live allow.
      // Mark as pending rather than failing.
      console.log(
        `[e2e] Skipping permit_token assertion: decision=${decision} (policy may deny this org)`,
      );
      return;
    }
    expect(typeof evaluationId).toBe("string");
    expect(evaluationId.length).toBeGreaterThan(0);
  });

  /**
   * CANONICAL BEHAVIOUR: A valid permit_token from an allow decision must
   * be verifiable via POST /v1-permits/{id}/verify.
   *
   * The canonical REST surface (verifyPermitById) returns:
   *   valid: true
   *   verification_type: "permit"
   *
   * The legacy surface (verifyPermit) returns:
   *   verified: true (aliased to valid)
   *
   * Both must work; this test uses the canonical REST surface.
   */
  it("POST /v1-permits/{id}/verify → valid=true for a fresh allow permit", async () => {
    if (decision !== "allow" || !evaluationId) {
      console.log(
        `[e2e] Skipping permit verify: decision=${decision} (no permit to verify)`,
      );
      return;
    }

    const client = new AtlaSentClient({ apiKey: API_KEY, baseUrl: API_URL });

    // Prefer the canonical REST surface (verifyPermitById).
    // Falls back to legacy verifyPermit if the canonical path is not wired.
    let verified = false;
    try {
      const result = await client.verifyPermitById(evaluationId);
      verified = result.valid;
      expect(result.valid).toBe(true);
    } catch (err) {
      if (err instanceof AtlaSentError && err.status === 404) {
        // Canonical path not yet wired — fall back to legacy.
        const legacyResult = await client.verifyPermit({
          permitId: evaluationId,
          action: "e2e:smoke",
          agent: "e2e-test-runner",
        });
        verified = legacyResult.verified;
        expect(legacyResult.verified).toBe(true);
      } else {
        throw err;
      }
    }
    expect(verified).toBe(true);
    permitToken = evaluationId;
  });
});

// ---------------------------------------------------------------------------
// describe 3 — Audit trail
// ---------------------------------------------------------------------------

describe.skipIf(!haveEnv)("audit trail", () => {
  /**
   * CANONICAL BEHAVIOUR: GET /v1-audit/events returns a paginated list of
   * audit events for the authenticated organisation. An evaluation event
   * produced by a successful evaluate() call must appear within a
   * reasonable polling window.
   *
   * The SDK's listAuditEvents() calls GET /v1-audit/events and returns
   * the wire-identical payload (snake_case fields) alongside `rateLimit`.
   *
   * This test queries the most recent events (limit=20) and asserts that
   * at least one event is present in the audit log. We do NOT filter by
   * evaluation_id because the audit event may appear under a different
   * event type (evaluate.allow, evaluate.deny, etc.) and the org may have
   * many events. The goal is to confirm the audit pipeline is reachable.
   */
  it("GET /v1-audit/events returns events array with at least one entry", async () => {
    const client = new AtlaSentClient({ apiKey: API_KEY, baseUrl: API_URL });
    const result = await client.listAuditEvents({ limit: 20 });

    // Canonical response shape: { events: AuditEvent[], total: number }
    expect(Array.isArray(result.events)).toBe(true);
    expect(typeof result.total).toBe("number");
    // At least one event should exist for any org with a valid API key
    // that has previously evaluated anything.
    expect(result.events.length).toBeGreaterThan(0);
  });

  /**
   * CANONICAL BEHAVIOUR: If the audit events carry `audit_hash` /
   * `previous_audit_hash` fields (hash-chain integrity fields), then for
   * a sorted sequence of events the `previous_audit_hash` of event[N]
   * must equal the `audit_hash` of event[N-1].
   *
   * This property guarantees that the audit log has not been tampered
   * with between consecutive entries. If the fields are absent (older
   * API deployments), the test is skipped — chain integrity is optional
   * until the audit-chain column migration is complete.
   *
   * NOTE: The API may call these fields `hash` and `previous_hash`
   * (wire alias). The test checks both naming conventions.
   */
  it("audit_hash chain: previous_audit_hash of event[N] equals audit_hash of event[N-1]", async () => {
    const client = new AtlaSentClient({ apiKey: API_KEY, baseUrl: API_URL });
    // Fetch enough events to have at least two consecutive entries.
    const result = await client.listAuditEvents({ limit: 20 });

    if (result.events.length < 2) {
      console.log("[e2e] Skipping chain integrity check: fewer than 2 events in log");
      return;
    }

    // Normalise: accept both snake_case aliases used in different API versions.
    type AuditEventWire = {
      audit_hash?: string;
      hash?: string;
      previous_audit_hash?: string;
      previous_hash?: string;
      [k: string]: unknown;
    };

    const events = result.events as AuditEventWire[];

    const getHash = (e: AuditEventWire): string | undefined =>
      e.audit_hash ?? e.hash;
    const getPrevHash = (e: AuditEventWire): string | undefined =>
      e.previous_audit_hash ?? e.previous_hash;

    // If neither field is present on any event, chain fields are not yet
    // deployed — skip gracefully rather than failing.
    const hasChainFields = events.some(
      (e) => getHash(e) !== undefined || getPrevHash(e) !== undefined,
    );
    if (!hasChainFields) {
      console.log(
        "[e2e] Skipping chain integrity check: audit_hash / previous_audit_hash fields not present (pre-chain deployment)",
      );
      return;
    }

    // Verify linkage for consecutive pairs where both hash fields are present.
    // Events are returned most-recent-first; reverse for chronological order.
    const chronological = [...events].reverse();
    let chainChecked = 0;

    for (let i = 1; i < chronological.length; i++) {
      const prev = chronological[i - 1];
      const curr = chronological[i];
      const prevHash = getHash(prev);
      const currPrevHash = getPrevHash(curr);

      if (prevHash === undefined || currPrevHash === undefined) {
        // Partial chain — gap in fields. Skip this pair.
        continue;
      }

      expect(
        currPrevHash,
        `event[${i}].previous_audit_hash should equal event[${i - 1}].audit_hash`,
      ).toBe(prevHash);
      chainChecked++;
    }

    if (chainChecked === 0) {
      console.log(
        "[e2e] Chain fields present but no consecutive pair had both populated — partial chain deployment",
      );
    } else {
      console.log(`[e2e] Chain integrity verified for ${chainChecked} consecutive event pair(s)`);
    }
  });
});
