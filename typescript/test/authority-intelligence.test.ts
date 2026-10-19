import { describe, expect, it, vi, type MockedFunction } from "vitest";

import { AtlaSentClient, AtlaSentError } from "../src/index.js";
import {
  countFindingsByClassification,
  makeAuthorityIntelligenceClient,
  type IntegrityAuditQuery,
  type IntegrityFinding,
  type IntegrityReport,
} from "../src/authorityIntelligence.js";

const PATH = "/v1-authority-intelligence/integrity-audit";

function makeMocks() {
  const getFn = vi.fn();
  const client = makeAuthorityIntelligenceClient(getFn as never);
  return { client, getFn };
}

const WIRE_FINDING: IntegrityFinding = {
  finding_type: "authority_without_action_class",
  classification: "defect",
  severity: "high",
  subject_id: "did:key:z6Mk",
  source_table: "authorities",
  source_id: "auth-1",
  related_source_ids: ["ac-1", "ac-2"],
  effective_at: "2026-08-01T00:00:00Z",
  evidence_posture: "observed",
  reason: "Authority declares no action classes and cannot be exercised.",
};

const WIRE_REPORT: IntegrityReport = {
  schema_version: "authority_intelligence.integrity_report.v1",
  query: "integrity-audit",
  organization_id: "org-1",
  evaluated_at: "2026-08-22T12:00:00Z",
  produced_by: ["authority_integrity_auditor@1.0.0"],
  summary: {
    audited_scope: { decision_window_days: 90 },
    counts_by_classification: { defect: 1 },
  },
  findings: [WIRE_FINDING],
  nodes: [{ id: "auth-1", kind: "authority" }],
  edges: [{ from: "auth-1", to: "ac-1", kind: "grants" }],
};

// ── request shape ─────────────────────────────────────────────────────────────

describe("authorityIntelligence.integrityAudit — request", () => {
  it("GETs the integrity-audit sub-route of v1-authority-intelligence", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await client.integrityAudit();
    expect(getFn.mock.calls[0]![0]).toBe(PATH);
  });

  it("sends NO query params when no options are given", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await client.integrityAudit();
    expect(getFn.mock.calls[0]![1]).toBeUndefined();
  });

  it("sends NO query params for an empty options object", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await client.integrityAudit({});
    expect(getFn.mock.calls[0]![1]).toBeUndefined();
  });

  it("never client-side defaults decision_window_days when omitted", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    // Cast: `exactOptionalPropertyTypes` forbids an explicit `undefined` at
    // the type level, but a JS caller spreading a partial config can still
    // produce one at runtime — it must not become a guessed default.
    await client.integrityAudit({
      decisionWindowDays: undefined,
    } as unknown as IntegrityAuditQuery);
    // A guessed default here would silently misreport the audited scope.
    expect(getFn.mock.calls[0]![1]).toBeUndefined();
  });

  it("passes decision_window_days as a snake_case query param", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await client.integrityAudit({ decisionWindowDays: 90 });
    const qs = getFn.mock.calls[0]![1] as URLSearchParams;
    expect(qs.get("decision_window_days")).toBe("90");
  });

  it("passes the boundary values 1 and 3650 through unchanged", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await client.integrityAudit({ decisionWindowDays: 1 });
    expect(
      (getFn.mock.calls[0]![1] as URLSearchParams).get("decision_window_days"),
    ).toBe("1");
    await client.integrityAudit({ decisionWindowDays: 3650 });
    expect(
      (getFn.mock.calls[1]![1] as URLSearchParams).get("decision_window_days"),
    ).toBe("3650");
  });

  it("does not validate the range client-side — the server owns it", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await expect(
      client.integrityAudit({ decisionWindowDays: 99999 }),
    ).resolves.toBeDefined();
    expect(
      (getFn.mock.calls[0]![1] as URLSearchParams).get("decision_window_days"),
    ).toBe("99999");
  });
});

// ── response shape ────────────────────────────────────────────────────────────

describe("authorityIntelligence.integrityAudit — response", () => {
  it("returns the wire report field-for-field", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    const report = await client.integrityAudit();
    expect(report).toEqual(WIRE_REPORT);
  });

  it("preserves every finding field verbatim", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    const report = await client.integrityAudit();
    expect(report.findings[0]).toEqual(WIRE_FINDING);
  });

  it("keeps summary an open-ended bag, untouched", async () => {
    const { client, getFn } = makeMocks();
    const summary = {
      audited_scope: { decision_window_days: 30, from: "2026-07-23" },
      a_key_this_sdk_has_never_heard_of: [1, 2, 3],
    };
    getFn.mockResolvedValue({ body: { ...WIRE_REPORT, summary } });
    const report = await client.integrityAudit();
    expect(report.summary).toEqual(summary);
  });

  it("echoes back the server's audited_scope rather than the requested window", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        ...WIRE_REPORT,
        summary: { audited_scope: { decision_window_days: 365 } },
      },
    });
    const report = await client.integrityAudit({ decisionWindowDays: 90 });
    expect(report.summary["audited_scope"]).toEqual({
      decision_window_days: 365,
    });
  });

  it("passes nodes and edges through as opaque records", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    const report = await client.integrityAudit();
    expect(report.nodes).toEqual([{ id: "auth-1", kind: "authority" }]);
    expect(report.edges).toEqual([
      { from: "auth-1", to: "ac-1", kind: "grants" },
    ]);
  });

  it("null-able finding fields stay null, never coerced to a string", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        ...WIRE_REPORT,
        findings: [
          {
            ...WIRE_FINDING,
            subject_id: null,
            source_table: null,
            source_id: null,
            effective_at: null,
          },
        ],
      },
    });
    const report = await client.integrityAudit();
    expect(report.findings[0]!.subject_id).toBeNull();
    expect(report.findings[0]!.source_table).toBeNull();
    expect(report.findings[0]!.source_id).toBeNull();
    expect(report.findings[0]!.effective_at).toBeNull();
  });

  it("defaults absent produced_by/nodes/edges/summary to empty rather than undefined", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        schema_version: "v1",
        query: "integrity-audit",
        organization_id: "org-1",
        evaluated_at: "2026-08-22T12:00:00Z",
        findings: [],
      },
    });
    const report = await client.integrityAudit();
    expect(report.produced_by).toEqual([]);
    expect(report.nodes).toEqual([]);
    expect(report.edges).toEqual([]);
    expect(report.summary).toEqual({});
  });

  // `findings` is required by the committed wire schema and is NOT defaulted
  // like the other arrays above: a response missing it is malformed, not "an
  // audit that found nothing". This was the actual bug (caught in review) —
  // an earlier version of this method silently defaulted a missing/malformed
  // `findings` to `[]`, which would have manufactured a clean audit out of a
  // truncated or misconfigured-proxy 200 response.
  it("throws rather than manufacturing an empty report when findings is missing", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        schema_version: "v1",
        query: "integrity-audit",
        organization_id: "org-1",
        evaluated_at: "2026-08-22T12:00:00Z",
        // findings omitted entirely
      },
    });
    await expect(client.integrityAudit()).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("throws when findings is present but not an array", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: { ...WIRE_REPORT, findings: null },
    });
    await expect(client.integrityAudit()).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("returns an empty findings list as data, not as an error", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: { ...WIRE_REPORT, findings: [] } });
    const report = await client.integrityAudit();
    expect(report.findings).toEqual([]);
    expect(report.organization_id).toBe("org-1");
  });

  it("does not send organization_id — the org is derived server-side", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    await client.integrityAudit({ decisionWindowDays: 90 });
    const qs = getFn.mock.calls[0]![1] as URLSearchParams;
    expect(qs.get("organization_id")).toBeNull();
    expect([...qs.keys()]).toEqual(["decision_window_days"]);
  });
});

// ── open vocabulary ───────────────────────────────────────────────────────────

describe("integrity vocabulary is open at runtime", () => {
  it("passes an unrecognized classification through as a string", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        ...WIRE_REPORT,
        findings: [{ ...WIRE_FINDING, classification: "future_fourth_value" }],
      },
    });
    const report = await client.integrityAudit();
    expect(report.findings[0]!.classification).toBe("future_fourth_value");
  });

  it("passes an unrecognized severity through as a string", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        ...WIRE_REPORT,
        findings: [{ ...WIRE_FINDING, severity: "catastrophic" }],
      },
    });
    const report = await client.integrityAudit();
    expect(report.findings[0]!.severity).toBe("catastrophic");
  });

  it("passes an unrecognized evidence_posture through as a string", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({
      body: {
        ...WIRE_REPORT,
        findings: [{ ...WIRE_FINDING, evidence_posture: "attested" }],
      },
    });
    const report = await client.integrityAudit();
    expect(report.findings[0]!.evidence_posture).toBe("attested");
  });
});

// ── error propagation (fail closed) ───────────────────────────────────────────

describe("integrityAudit propagates transport errors", () => {
  it("rethrows a 5xx instead of returning a partial report", async () => {
    const { client, getFn } = makeMocks();
    const boom = Object.assign(new Error("API error 500"), {
      status: 500,
      code: "server_error",
    });
    getFn.mockRejectedValue(boom);
    await expect(client.integrityAudit()).rejects.toBe(boom);
  });

  it("rethrows a 403 (missing authority_intelligence:read scope)", async () => {
    const { client, getFn } = makeMocks();
    const forbidden = Object.assign(new Error("forbidden"), { status: 403 });
    getFn.mockRejectedValue(forbidden);
    await expect(client.integrityAudit()).rejects.toBe(forbidden);
  });

  it("does not swallow an error into an empty report", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockRejectedValue(new Error("network"));
    const result = await client.integrityAudit().catch((e: unknown) => e);
    expect(result).toBeInstanceOf(Error);
  });
});

// ── countFindingsByClassification ─────────────────────────────────────────────

describe("countFindingsByClassification", () => {
  const f = (classification: string): IntegrityFinding => ({
    ...WIRE_FINDING,
    classification,
  });

  it("always reports all three known classifications, zero-filled", () => {
    const counts = countFindingsByClassification({ findings: [] });
    expect(counts).toEqual({ defect: 0, non_exercisable: 0, unresolved: 0 });
  });

  it("counts each classification separately, never collapsing them", () => {
    const counts = countFindingsByClassification({
      findings: [
        f("defect"),
        f("defect"),
        f("non_exercisable"),
        f("unresolved"),
      ],
    });
    expect(counts.defect).toBe(2);
    expect(counts.non_exercisable).toBe(1);
    expect(counts.unresolved).toBe(1);
  });

  it("keeps non_exercisable distinct from defect (it is often the healthy state)", () => {
    const counts = countFindingsByClassification({
      findings: [f("non_exercisable"), f("non_exercisable")],
    });
    expect(counts.non_exercisable).toBe(2);
    expect(counts.defect).toBe(0);
  });

  it("keeps unresolved distinct — it must never read as clean", () => {
    const counts = countFindingsByClassification({
      findings: [f("unresolved")],
    });
    expect(counts.unresolved).toBe(1);
    expect(counts.defect).toBe(0);
    expect(counts.non_exercisable).toBe(0);
  });

  it("surfaces an unknown classification as its own key, not folded in", () => {
    const counts = countFindingsByClassification({
      findings: [f("future_fourth_value"), f("future_fourth_value"), f("defect")],
    });
    expect(counts["future_fourth_value"]).toBe(2);
    expect(counts.defect).toBe(1);
    expect(counts.non_exercisable).toBe(0);
  });

  it("tolerates an absent findings array", () => {
    const counts = countFindingsByClassification({
      findings: undefined as unknown as IntegrityFinding[],
    });
    expect(counts).toEqual({ defect: 0, non_exercisable: 0, unresolved: 0 });
  });

  it("works on a full report object", async () => {
    const { client, getFn } = makeMocks();
    getFn.mockResolvedValue({ body: WIRE_REPORT });
    const report = await client.integrityAudit();
    expect(countFindingsByClassification(report).defect).toBe(1);
  });

  it("exposes no boolean pass/fail convenience", () => {
    const counts = countFindingsByClassification({ findings: [f("defect")] });
    expect("isHealthy" in counts).toBe(false);
    expect("hasErrors" in counts).toBe(false);
  });
});

// ── wiring through AtlaSentClient ─────────────────────────────────────────────

type FetchMock = MockedFunction<typeof fetch>;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": "req_test" },
  });
}

function mockFetch(
  impl: (url: string, init: RequestInit) => Response | Promise<Response>,
): FetchMock {
  return vi.fn(
    async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as Request).url;
      return impl(url, init ?? {});
    },
  ) as unknown as FetchMock;
}

function makeHostClient(fetchImpl: FetchMock) {
  return new AtlaSentClient({
    apiKey: "ask_live_test",
    fetch: fetchImpl,
    timeoutMs: 5_000,
    retryPolicy: { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0 },
  });
}

describe("client.authorityIntelligence", () => {
  it("is exposed on AtlaSentClient", () => {
    const client = makeHostClient(mockFetch(() => jsonResponse({})));
    expect(typeof client.authorityIntelligence.integrityAudit).toBe("function");
  });

  it("issues a real GET to the integrity-audit path with the bearer key", async () => {
    let seenUrl = "";
    let seenInit: RequestInit = {};
    const client = makeHostClient(
      mockFetch((url, init) => {
        seenUrl = url;
        seenInit = init;
        return jsonResponse(WIRE_REPORT);
      }),
    );
    const report = await client.authorityIntelligence.integrityAudit();
    expect(seenUrl).toBe(
      "https://api.atlasent.io/functions/v1/v1-authority-intelligence/integrity-audit",
    );
    expect(seenInit.method).toBe("GET");
    expect(
      (seenInit.headers as Record<string, string>)["Authorization"],
    ).toBe("Bearer ask_live_test");
    expect(report.organization_id).toBe("org-1");
  });

  it("appends decision_window_days to the query string", async () => {
    let seenUrl = "";
    const client = makeHostClient(
      mockFetch((url) => {
        seenUrl = url;
        return jsonResponse(WIRE_REPORT);
      }),
    );
    await client.authorityIntelligence.integrityAudit({
      decisionWindowDays: 30,
    });
    expect(seenUrl).toBe(
      "https://api.atlasent.io/functions/v1/v1-authority-intelligence/integrity-audit?decision_window_days=30",
    );
  });

  it("throws AtlaSentError on a 500 rather than yielding a degraded report", async () => {
    const client = makeHostClient(
      mockFetch(() => jsonResponse({ error: "audit failed" }, 500)),
    );
    await expect(
      client.authorityIntelligence.integrityAudit(),
    ).rejects.toBeInstanceOf(AtlaSentError);
  });
});
