import { describe, expect, it, vi, type MockedFunction } from "vitest";

import { AtlaSentClient, AtlaSentError } from "../src/index.js";

type FetchMock = MockedFunction<typeof fetch>;

const EVALUATE_PERMIT_WIRE = {
  permitted: true,
  decision_id: "dec_alpha",
  reason: "Operator authorized under GxP policy",
  audit_hash: "hash_alpha",
  timestamp: "2026-04-17T10:00:00Z",
};

const EVALUATE_DENY_WIRE = {
  permitted: false,
  decision_id: "dec_beta",
  reason: "Missing change_reason for critical field",
  audit_hash: "hash_beta",
  timestamp: "2026-04-17T10:01:00Z",
};

const VERIFY_OK_WIRE = {
  verified: true,
  outcome: "verified",
  permit_hash: "permit_alpha",
  timestamp: "2026-04-17T10:00:01Z",
};

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
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
            : input.url;
      return impl(url, init ?? {});
    },
  ) as unknown as FetchMock;
}

function makeClient(
  fetchImpl: FetchMock,
  overrides: Partial<ConstructorParameters<typeof AtlaSentClient>[0]> = {},
) {
  return new AtlaSentClient({
    apiKey: "ask_live_test",
    fetch: fetchImpl,
    timeoutMs: 5_000,
    retryPolicy: { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0 },
    ...overrides,
  });
}

describe("AtlaSentClient constructor", () => {
  it("throws if apiKey is missing", () => {
    expect(() => new AtlaSentClient({ apiKey: "" })).toThrow(AtlaSentError);
    // @ts-expect-error — intentionally invalid for the runtime check
    expect(() => new AtlaSentClient({})).toThrow(AtlaSentError);
  });

  it("rejects malformed apiKey", () => {
    expect(() => new AtlaSentClient({ apiKey: "not_a_real_key" })).toThrow(
      /ask_/,
    );
  });

  it("rejects whitespace-padded apiKey", () => {
    expect(() => new AtlaSentClient({ apiKey: " ask_test_xxxxxxxx " })).toThrow(
      /ask_/,
    );
  });

  it("accepts ask_live_ and ask_test_ prefixes", () => {
    expect(
      () => new AtlaSentClient({ apiKey: "ask_live_abc123" }),
    ).not.toThrow();
    expect(
      () => new AtlaSentClient({ apiKey: "ask_test_abc123" }),
    ).not.toThrow();
  });

  it("strips trailing slashes from baseUrl", () => {
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl, {
      baseUrl: "https://staging.atlasent.io///",
    });
    return client.evaluate({ agent: "a", action: "b" }).then(() => {
      const [url] = fetchImpl.mock.calls[0]!;
      expect(url).toBe("https://staging.atlasent.io/v1-evaluate");
    });
  });

  it("rejects http:// baseUrl", () => {
    expect(
      () =>
        new AtlaSentClient({
          apiKey: "ask_test_xxxxxxxx",
          baseUrl: "http://api.atlasent.io",
        }),
    ).toThrow(/https/);
  });

  it("allows http:// when ATLASENT_ALLOW_INSECURE_HTTP=1", () => {
    const prev = process.env.ATLASENT_ALLOW_INSECURE_HTTP;
    process.env.ATLASENT_ALLOW_INSECURE_HTTP = "1";
    try {
      const c = new AtlaSentClient({
        apiKey: "ask_test_xxxxxxxx",
        baseUrl: "http://localhost:8000",
      });
      expect(c).toBeDefined();
    } finally {
      if (prev === undefined) delete process.env.ATLASENT_ALLOW_INSECURE_HTTP;
      else process.env.ATLASENT_ALLOW_INSECURE_HTTP = prev;
    }
  });
});

describe("evaluate()", () => {
  it("returns decision: ALLOW on permitted response", async () => {
    const client = makeClient(
      mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE)),
    );
    const result = await client.evaluate({
      agent: "clinical-data-agent",
      action: "modify_patient_record",
      context: { user: "dr_smith", environment: "production" },
    });
    expect(result).toEqual({
      decision: "allow",
      decision_canonical: "allow",
      evaluationId: "dec_alpha",
      permitId: "dec_alpha",
      permit: null,
      permitToken: "dec_alpha",
      reasons: ["Operator authorized under GxP policy"],
      reason: "Operator authorized under GxP policy",
      deny_code: null,
      auditHash: "hash_alpha",
      timestamp: "2026-04-17T10:00:00Z",
      // Headerless response → no rate-limit state surfaced.
      rateLimit: null,
    });
  });

  it("returns decision: DENY on non-permitted response (does not throw)", async () => {
    const client = makeClient(
      mockFetch(() => jsonResponse(EVALUATE_DENY_WIRE)),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.decision).toBe("deny");
    expect(result.permitId).toBe("dec_beta");
    expect(result.reason).toBe("Missing change_reason for critical field");
  });

  it("sends the wire-format body (snake_case)", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({
      agent: "agent-X",
      action: "act",
      context: { u: "v" },
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-evaluate");
    expect(init!.method).toBe("POST");
    const body = JSON.parse(init!.body as string);
    expect(body).toEqual({
      action_type: "act",
      actor_id: "agent-X",
      context: { u: "v" },
    });
  });

  // ── issue #345 / ADR CROSS-008: canonical actor_id/action_type ──────────
  it("accepts the canonical actor_id/action_type shape and sends it verbatim", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({
      actor_id: "clinical-data-agent",
      action_type: "modify_patient_record",
      context: { env: "prod" },
    });
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    expect(body).toEqual({
      action_type: "modify_patient_record",
      actor_id: "clinical-data-agent",
      context: { env: "prod" },
    });
    // Canonical input must NOT emit a deprecation warning.
    const depWarn = warnSpy.mock.calls.find((args) =>
      String(args[0]).includes("Deprecation"),
    );
    expect(depWarn).toBeUndefined();
    warnSpy.mockRestore();
  });

  it("accepts the legacy agent/action shape, warns, and still sends canonical wire", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({
      agent: "clinical-data-agent",
      action: "modify_patient_record",
      context: { env: "prod" },
    });
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    // Wire is always canonical regardless of the input field names.
    expect(body).toEqual({
      action_type: "modify_patient_record",
      actor_id: "clinical-data-agent",
      context: { env: "prod" },
    });
    const depWarn = warnSpy.mock.calls.find((args) =>
      String(args[0]).includes("Deprecation"),
    );
    expect(depWarn).toBeDefined();
    warnSpy.mockRestore();
  });

  it("sets Authorization, User-Agent, and X-Request-ID headers", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({ agent: "a", action: "b" });
    const [, init] = fetchImpl.mock.calls[0]!;
    const headers = init!.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer ask_live_test");
    expect(headers["User-Agent"]).toMatch(
      /^@atlasent\/sdk\/\d+\.\d+\.\d+ node\//,
    );
    expect(headers["X-Request-ID"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers.Accept).toBe("application/json");
  });

  it("defaults missing context to an empty object", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({ agent: "a", action: "b" });
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    expect(body.context).toEqual({});
  });

  it("populates decision_canonical='allow' when wire decision is 'allow'", async () => {
    const wire = {
      decision: "allow",
      permit_token: "pt_canonical_allow",
      request_id: "req_a",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.decision).toBe("allow");
    expect(result.decision_canonical).toBe("allow");
  });

  it("populates decision_canonical='deny' when wire decision is 'deny'", async () => {
    const wire = {
      decision: "deny",
      denial: { reason: "policy denied", code: "POLICY_DENY" },
      request_id: "req_d",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.decision).toBe("deny");
    expect(result.decision_canonical).toBe("deny");
    expect(result.reason).toBe("policy denied");
    // Legacy nested `denial.code` shape surfaces as `deny_code`.
    expect(result.deny_code).toBe("POLICY_DENY");
  });

  it("surfaces top-level deny_code / deny_reason (canonical handler.ts shape)", async () => {
    // handler.ts emits deny metadata at the TOP LEVEL, not nested under `denial`.
    const wire = {
      decision: "deny",
      deny_code: "SNAPSHOT_REQUIRED",
      deny_reason: "action class requires a state_snapshot in the request body",
      request_id: "req_snap",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.decision).toBe("deny");
    expect(result.deny_code).toBe("SNAPSHOT_REQUIRED");
    expect(result.reason).toBe(
      "action class requires a state_snapshot in the request body",
    );
    expect(result.reasons).toEqual([
      "action class requires a state_snapshot in the request body",
    ]);
  });

  it("sets deny_code to null on an allow decision", async () => {
    const wire = { decision: "allow", permit_token: "pt_x", request_id: "req_a" };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.deny_code).toBeNull();
  });

  it("populates decision_canonical='hold' (legacy decision collapses to DENY)", async () => {
    const wire = {
      decision: "hold",
      denial: { reason: "awaiting reviewer", code: "ACTOR_HELD" },
      request_id: "req_h",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    // Canonical 4-value preserves the distinct hold state on both fields.
    expect(result.decision).toBe("hold");
    expect(result.decision_canonical).toBe("hold");
    expect(result.reason).toBe("awaiting reviewer");
  });

  it("populates decision_canonical='escalate' (legacy decision collapses to DENY)", async () => {
    const wire = {
      decision: "escalate",
      denial: { reason: "queued for human review", code: "ACTOR_ESCALATED" },
      request_id: "req_e",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    // Canonical 4-value preserves the distinct escalate state on both fields.
    expect(result.decision).toBe("escalate");
    expect(result.decision_canonical).toBe("escalate");
    expect(result.reason).toBe("queued for human review");
  });

  it("passes explain:true in the request body when specified", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({ agent: "a", action: "b", explain: true });
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    expect(body.explain).toBe(true);
  });

  it("omits explain from the request body when not specified", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.evaluate({ agent: "a", action: "b" });
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    expect(body).not.toHaveProperty("explain");
  });

  it("maps risk_envelope to riskEnvelope when present (no factors)", async () => {
    const wire = {
      decision: "allow",
      permit_token: "pt_envelope",
      risk_envelope: {
        weighted_score: 0.42,
        engine_decision: "allow",
        envelope_decision: "allow",
        promoted: false,
        hard_blocks: [],
      },
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.riskEnvelope).toEqual({
      weightedScore: 0.42,
      engineDecision: "allow",
      envelopeDecision: "allow",
      promoted: false,
      hardBlocks: [],
    });
  });

  it("maps risk_envelope.factors when explain:true causes server to populate them", async () => {
    const wire = {
      decision: "hold",
      permit_token: "",
      denial: { reason: "high risk score", code: "RISK_HOLD" },
      risk_envelope: {
        weighted_score: 0.85,
        engine_decision: "allow",
        envelope_decision: "hold",
        promoted: true,
        hard_blocks: ["SANCTION_LIST"],
        factors: [
          {
            factor: "ACTION_SENSITIVITY",
            value: 0.9,
            weight: 0.5,
            reason: "action touches PII",
          },
          {
            factor: "ACTOR_TRUST",
            value: 0.7,
            weight: 0.5,
            reason: "actor has recent anomalies",
          },
        ],
      },
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({
      agent: "a",
      action: "b",
      explain: true,
    });
    expect(result.riskEnvelope).toEqual({
      weightedScore: 0.85,
      engineDecision: "allow",
      envelopeDecision: "hold",
      promoted: true,
      hardBlocks: ["SANCTION_LIST"],
      factors: [
        { factor: "ACTION_SENSITIVITY", value: 0.9, weight: 0.5, reason: "action touches PII" },
        { factor: "ACTOR_TRUST", value: 0.7, weight: 0.5, reason: "actor has recent anomalies" },
      ],
    });
  });

  it("leaves riskEnvelope undefined when risk_envelope absent from server response", async () => {
    const wire = {
      decision: "allow",
      permit_token: "pt_no_envelope",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.riskEnvelope).toBeUndefined();
  });
});

const CONSTRAINT_TRACE_WIRE = {
  rules_evaluated: [
    {
      policy_id: "pol_close_window_v3",
      decision: "deny",
      fingerprint: "fp_abc123",
      stages: [
        {
          stage: "role_check",
          rule: "preparer_required",
          matched: true,
          order: 0,
        },
        {
          stage: "context",
          rule: "change_reason_required",
          matched: false,
          detail: "context.change_reason missing",
          order: 1,
        },
      ],
    },
  ],
  matching_policy_id: "pol_close_window_v3",
};

const EVALUATE_PREFLIGHT_DENY_WITH_TRACE = {
  decision: "deny",
  permit_token: "",
  denial: { reason: "preflight: change_reason missing", code: "MISSING_FIELD" },
  constraint_trace: CONSTRAINT_TRACE_WIRE,
};

const EVALUATE_PREFLIGHT_ALLOW_NO_TRACE = {
  // Older atlasent-api version that does not echo `constraint_trace`
  // — the helper must degrade gracefully (constraintTrace=null).
  decision: "allow" as const,
  permit_token: "dec_pf_42",
  request_id: "req_pf",
};

describe("evaluatePreflight()", () => {
  it("appends ?include=constraint_trace to the URL", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse(EVALUATE_PREFLIGHT_DENY_WITH_TRACE),
    );
    const client = makeClient(fetchImpl);
    await client.evaluatePreflight({
      agent: "agent-1",
      action: "close_period",
      context: { period: "2025-12" },
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    // Whole point of the helper: always set the include query param.
    expect(url).toBe(
      "https://api.atlasent.io/functions/v1/v1-evaluate?include=constraint_trace",
    );
    expect(init!.method).toBe("POST");
    // Body shape is identical to evaluate() — trace is requested via
    // the URL, not the body.
    const body = JSON.parse(init!.body as string);
    expect(body).toEqual({
      action_type: "close_period",
      actor_id: "agent-1",
      context: { period: "2025-12" },
    });
  });

  it("parses the typed preflight response with constraint_trace populated", async () => {
    const client = makeClient(
      mockFetch(() => jsonResponse(EVALUATE_PREFLIGHT_DENY_WITH_TRACE)),
    );
    const result = await client.evaluatePreflight({
      agent: "agent-1",
      action: "close_period",
    });
    // Does NOT throw on a deny — preflight returns the outcome so the
    // caller can branch on it and render the trace.
    expect(result.evaluation.decision).toBe("deny");
    expect(result.evaluation.reason).toBe("preflight: change_reason missing");
    expect(result.constraintTrace).not.toBeNull();
    expect(result.constraintTrace!.matching_policy_id).toBe(
      "pol_close_window_v3",
    );
    expect(result.constraintTrace!.rules_evaluated).toHaveLength(1);
    const policy = result.constraintTrace!.rules_evaluated[0]!;
    expect(policy.policy_id).toBe("pol_close_window_v3");
    expect(policy.decision).toBe("deny");
    expect(policy.stages).toHaveLength(2);
    expect(policy.stages[0]!.matched).toBe(true);
    expect(policy.stages[1]!.matched).toBe(false);
    expect(policy.stages[1]!.detail).toBe("context.change_reason missing");
    expect(policy.stages[1]!.order).toBe(1);
  });

  it("returns constraintTrace=null when the server omits the trace", async () => {
    // Forward-compat: an older atlasent-api version that does not
    // populate `constraint_trace` in the response must not break
    // the helper. The method returns the response with trace=null.
    const client = makeClient(
      mockFetch(() => jsonResponse(EVALUATE_PREFLIGHT_ALLOW_NO_TRACE)),
    );
    const result = await client.evaluatePreflight({
      agent: "agent-1",
      action: "close_period",
    });
    expect(result.evaluation.decision).toBe("allow");
    expect(result.evaluation.permitId).toBe("dec_pf_42");
    expect(result.constraintTrace).toBeNull();
  });

  it("tolerates unknown engine-side keys inside the trace", async () => {
    const wire = {
      decision: "allow",
      permit_token: "dec_x",
      constraint_trace: {
        rules_evaluated: [
          {
            policy_id: "p1",
            decision: "allow",
            fingerprint: "fp_1",
            stages: [
              {
                stage: "s1",
                matched: true,
                order: 0,
                future_field: "yo",
              },
            ],
            next_field_we_haven_t_seen: 42,
          },
        ],
        future_top_level_field: true,
      },
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluatePreflight({
      agent: "actor",
      action: "act",
    });
    expect(result.constraintTrace).not.toBeNull();
    expect(result.constraintTrace!.rules_evaluated[0]!.stages[0]!.matched).toBe(
      true,
    );
  });
});

describe("verifyPermit()", () => {
  it("returns the verified payload, no throw when verified: false", async () => {
    const client = makeClient(
      mockFetch(() => jsonResponse({ ...VERIFY_OK_WIRE, verified: false })),
    );
    const result = await client.verifyPermit({ permitId: "dec_alpha" });
    expect(result.verified).toBe(false);
    expect(result.outcome).toBe("verified");
  });

  it("maps permit_hash → permitHash", async () => {
    const client = makeClient(mockFetch(() => jsonResponse(VERIFY_OK_WIRE)));
    const result = await client.verifyPermit({ permitId: "dec_alpha" });
    expect(result.permitHash).toBe("permit_alpha");
    expect(result.verified).toBe(true);
  });

  it("sends the wire-format body with permit_id → permit_token (canonical)", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_OK_WIRE));
    const client = makeClient(fetchImpl);
    await client.verifyPermit({
      permitId: "dec_alpha",
      action: "read_phi",
      agent: "agent-1",
      context: { patientId: "PT-001" },
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-verify-permit");
    const body = JSON.parse(init!.body as string);
    // Canonical wire — no `context`, no `api_key`. Verify handler reads
    // only permit_token / action_type / actor_id.
    expect(body).toEqual({
      permit_token: "dec_alpha",
      action_type: "read_phi",
      actor_id: "agent-1",
    });
  });
});

describe("deployGate()", () => {
  it("defaults action to production.deploy and uses /v1-evaluate then /v1-verify-permit", async () => {
    const fetchImpl = mockFetch((url) =>
      url.endsWith("/v1-evaluate")
        ? jsonResponse({
            decision: "allow",
            permit_token: "pt_deploy_1",
            request_id: "req_deploy_1",
            reason: "approved",
            audit_hash: "audit_deploy_1",
          })
        : jsonResponse({
            valid: true,
            verified: true,
            outcome: "allow",
            permit_hash: "hash_deploy_1",
            timestamp: "2026-05-13T00:00:00Z",
          }),
    );
    const client = makeClient(fetchImpl);

    const result = await client.deployGate({
      context: { repo: "atlasent/api", commit: "abc123" },
    });

    expect(result.allowed).toBe(true);
    expect(result.evidence).toEqual({
      permitId: "pt_deploy_1",
      permitHash: "hash_deploy_1",
      auditHash: "audit_deploy_1",
      verifiedAt: "2026-05-13T00:00:00Z",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    const [evaluateUrl, evaluateInit] = fetchImpl.mock.calls[0]!;
    expect(evaluateUrl).toBe("https://api.atlasent.io/functions/v1/v1-evaluate");
    expect(JSON.parse(evaluateInit!.body as string)).toEqual({
      action_type: "production.deploy",
      actor_id: "ci-deploy-bot",
      context: { repo: "atlasent/api", commit: "abc123" },
    });

    const [verifyUrl, verifyInit] = fetchImpl.mock.calls[1]!;
    expect(verifyUrl).toBe("https://api.atlasent.io/functions/v1/v1-verify-permit");
    expect(JSON.parse(verifyInit!.body as string)).toEqual({
      permit_token: "pt_deploy_1",
      action_type: "production.deploy",
      actor_id: "ci-deploy-bot",
    });
  });

  it("blocks if server-side verifyPermit fails", async () => {
    const fetchImpl = mockFetch((url) =>
      url.endsWith("/v1-evaluate")
        ? jsonResponse({
            decision: "allow",
            permit_token: "pt_deploy_2",
            request_id: "req_deploy_2",
            audit_hash: "audit_deploy_2",
          })
        : jsonResponse({
            valid: false,
            verified: false,
            outcome: "deny",
            reason: "permit revoked",
          }),
    );
    const client = makeClient(fetchImpl);

    const result = await client.deployGate();

    expect(result.allowed).toBe(false);
    expect(result.verification?.verified).toBe(false);
    expect(result.reason).toContain("permit verification");
  });

  it("blocks without calling verifyPermit when evaluate denies", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({
        decision: "deny",
        request_id: "req_deploy_3",
        denial: { reason: "change window closed" },
      }),
    );
    const client = makeClient(fetchImpl);

    const result = await client.deployGate();

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("change window closed");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("HTTP error mapping", () => {
  it("401 → AtlaSentError(code: invalid_api_key)", async () => {
    const client = makeClient(
      mockFetch(() => new Response("unauthorized", { status: 401 })),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      name: "AtlaSentError",
      status: 401,
      code: "invalid_api_key",
    });
  });

  it("403 → AtlaSentError(code: forbidden)", async () => {
    const client = makeClient(
      mockFetch(() => new Response("nope", { status: 403 })),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      status: 403,
      code: "forbidden",
    });
  });

  it("429 → AtlaSentError(code: rate_limited) with retryAfterMs from Retry-After header", async () => {
    const client = makeClient(
      mockFetch(
        () =>
          new Response("too many", {
            status: 429,
            headers: { "Retry-After": "30" },
          }),
      ),
      { retryPolicy: { maxAttempts: 1 } },
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      status: 429,
      code: "rate_limited",
      retryAfterMs: 30_000,
    });
  });

  it("429 → retryAfterMs parsed from HTTP-date Retry-After header", async () => {
    const future = new Date(Date.now() + 45_000).toUTCString();
    const client = makeClient(
      mockFetch(
        () =>
          new Response("too many", {
            status: 429,
            headers: { "Retry-After": future },
          }),
      ),
      { retryPolicy: { maxAttempts: 1 } },
    );
    let thrown: AtlaSentError | undefined;
    try {
      await client.evaluate({ agent: "a", action: "b" });
    } catch (err) {
      thrown = err as AtlaSentError;
    }
    expect(thrown).toBeDefined();
    expect(thrown!.code).toBe("rate_limited");
    // Allow some slack for scheduling; the header encodes ~45s out.
    expect(thrown!.retryAfterMs).toBeGreaterThan(30_000);
    expect(thrown!.retryAfterMs).toBeLessThanOrEqual(45_000);
  });

  it("429 → Retry-After HTTP-date in the past clamps to 0", async () => {
    const past = new Date(Date.now() - 10_000).toUTCString();
    const client = makeClient(
      mockFetch(
        () =>
          new Response("too many", {
            status: 429,
            headers: { "Retry-After": past },
          }),
      ),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      code: "rate_limited",
      retryAfterMs: 0,
    });
  });

  it("500 with a body whose .text() throws still yields code: server_error", async () => {
    // Simulate a Response whose body stream errors on consumption — the
    // SDK should swallow the read failure and fall back to a default
    // server_error message rather than crash.
    const client = makeClient(
      mockFetch(() => {
        const response = new Response(null, { status: 500 });
        Object.defineProperty(response, "text", {
          value: () => Promise.reject(new Error("stream broken")),
        });
        return response;
      }),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      status: 500,
      code: "server_error",
    });
  });

  it("500 → AtlaSentError(code: server_error)", async () => {
    const client = makeClient(
      mockFetch(() => new Response("oops", { status: 500 })),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      status: 500,
      code: "server_error",
    });
  });

  it("422 (other 4xx) → AtlaSentError(code: bad_request) surfaces server message", async () => {
    const client = makeClient(
      mockFetch(
        () =>
          new Response(JSON.stringify({ message: "bad field: agent" }), {
            status: 422,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      status: 422,
      code: "bad_request",
      message: "bad field: agent",
    });
  });
});

describe("Network / transport errors", () => {
  it("fetch rejecting maps to code: network", async () => {
    const client = makeClient(
      mockFetch(() => {
        throw new TypeError("fetch failed: ECONNREFUSED");
      }),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      code: "network",
    });
  });

  it("AbortController timeout maps to code: timeout", async () => {
    const client = makeClient(
      mockFetch(() => {
        const err = new DOMException("timed out", "TimeoutError");
        throw err;
      }),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      code: "timeout",
    });
  });

  it("generic AbortError (non-DOMException) also maps to code: timeout", async () => {
    // Some runtimes surface an Error whose name is "AbortError" rather
    // than a DOMException("TimeoutError"). Both should map to timeout.
    const client = makeClient(
      mockFetch(() => {
        const err = new Error("aborted");
        err.name = "AbortError";
        throw err;
      }),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      code: "timeout",
    });
  });

  it("invalid JSON body → code: bad_response", async () => {
    const client = makeClient(
      mockFetch(
        () =>
          new Response("not-json", {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("JSON object missing required evaluate fields → code: bad_response", async () => {
    const client = makeClient(mockFetch(() => jsonResponse({ foo: "bar" })));
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("JSON object missing required verifyPermit fields → code: bad_response", async () => {
    const client = makeClient(mockFetch(() => jsonResponse({ outcome: "ok" })));
    await expect(client.verifyPermit({ permitId: "x" })).rejects.toMatchObject({
      code: "bad_response",
    });
  });
});

describe("X-RateLimit-* header parsing", () => {
  const RESET_SECONDS = 1_714_068_060; // 2026-05-12 arbitrary instant
  const RESET_DATE_MS = RESET_SECONDS * 1000;

  function rateLimitResponse(
    body: unknown,
    headers: Record<string, string>,
  ): Response {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json", ...headers },
    });
  }

  it("exposes rateLimit on evaluate when all three headers are present", async () => {
    const client = makeClient(
      mockFetch(() =>
        rateLimitResponse(EVALUATE_PERMIT_WIRE, {
          "X-RateLimit-Limit": "1000",
          "X-RateLimit-Remaining": "762",
          "X-RateLimit-Reset": String(RESET_SECONDS),
        }),
      ),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.rateLimit).toEqual({
      limit: 1000,
      remaining: 762,
      resetAt: new Date(RESET_DATE_MS),
    });
  });

  it("exposes rateLimit on verifyPermit when all three headers are present", async () => {
    const client = makeClient(
      mockFetch(() =>
        rateLimitResponse(VERIFY_OK_WIRE, {
          "X-RateLimit-Limit": "600",
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(RESET_SECONDS),
        }),
      ),
    );
    const result = await client.verifyPermit({ permitId: "dec_alpha" });
    expect(result.rateLimit).toEqual({
      limit: 600,
      remaining: 0,
      resetAt: new Date(RESET_DATE_MS),
    });
  });

  it("accepts ISO 8601 string for X-RateLimit-Reset", async () => {
    const iso = new Date(RESET_DATE_MS).toISOString();
    const client = makeClient(
      mockFetch(() =>
        rateLimitResponse(EVALUATE_PERMIT_WIRE, {
          "X-RateLimit-Limit": "100",
          "X-RateLimit-Remaining": "50",
          "X-RateLimit-Reset": iso,
        }),
      ),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.rateLimit?.resetAt.getTime()).toBe(RESET_DATE_MS);
  });

  it("rateLimit === null when headers absent (older deployments)", async () => {
    const client = makeClient(
      mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE)),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.rateLimit).toBeNull();
  });

  it("rateLimit === null when one header is missing", async () => {
    const client = makeClient(
      mockFetch(() =>
        rateLimitResponse(EVALUATE_PERMIT_WIRE, {
          "X-RateLimit-Limit": "100",
          "X-RateLimit-Remaining": "50",
          // Reset intentionally missing
        }),
      ),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.rateLimit).toBeNull();
  });

  it("rateLimit === null when numeric header is NaN", async () => {
    const client = makeClient(
      mockFetch(() =>
        rateLimitResponse(EVALUATE_PERMIT_WIRE, {
          "X-RateLimit-Limit": "not-a-number",
          "X-RateLimit-Remaining": "50",
          "X-RateLimit-Reset": String(RESET_SECONDS),
        }),
      ),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.rateLimit).toBeNull();
  });

  it("rateLimit === null when reset header is unparseable", async () => {
    const client = makeClient(
      mockFetch(() =>
        rateLimitResponse(EVALUATE_PERMIT_WIRE, {
          "X-RateLimit-Limit": "100",
          "X-RateLimit-Remaining": "50",
          "X-RateLimit-Reset": "whenever",
        }),
      ),
    );
    const result = await client.evaluate({ agent: "a", action: "b" });
    expect(result.rateLimit).toBeNull();
  });

  it("forwards state-context fields in request body", async () => {
    let capturedBody: Record<string, unknown> = {};
    const client = makeClient(
      mockFetch((url, init) => {
        capturedBody = JSON.parse((init?.body as string) ?? "{}");
        return Promise.resolve(
          new Response(JSON.stringify(EVALUATE_PERMIT_WIRE), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
    await client.evaluate({
      agent: "bot",
      action: "database.schema.drop",
      environment: "production",
      resource: { type: "database", id: "db-123" },
      current_state: { description: "table exists" },
      proposed_state: { description: "table dropped" },
      execution_binding: { kind: "supabase_migration", adapter_version: "1.0" },
    });
    expect(capturedBody.environment).toBe("production");
    expect(capturedBody.resource).toEqual({ type: "database", id: "db-123" });
    expect(capturedBody.current_state).toEqual({ description: "table exists" });
    expect(capturedBody.proposed_state).toEqual({ description: "table dropped" });
    expect(capturedBody.execution_binding).toEqual({ kind: "supabase_migration", adapter_version: "1.0" });
  });

  it("forwards evaluation_profile, override, and completion_proofs in request body (previously silently dropped)", async () => {
    // Regression test: EvaluateRequest declares these three fields, and the
    // runtime genuinely reads all of them (resolveProfile(body.evaluation_profile),
    // the emergency-override gate on body.override, and the quorum check on
    // body.completion_proofs) — but evaluate()'s body construction never
    // forwarded them, so a caller setting any of these had it silently
    // dropped before the request ever reached the server.
    let capturedBody: Record<string, unknown> = {};
    const client = makeClient(
      mockFetch((url, init) => {
        capturedBody = JSON.parse((init?.body as string) ?? "{}");
        return Promise.resolve(
          new Response(JSON.stringify(EVALUATE_PERMIT_WIRE), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
    await client.evaluate({
      actor_id: "bot",
      action_type: "production.deploy",
      evaluation_profile: "advanced",
      override: {
        version: "override.v1",
        authority_actor_id: "ops-lead-1",
        reason: "P0 hotfix, snapshot hard block accepted",
      },
      completion_proofs: [
        { actor_id: "reviewer-1", action_type: "code_review.approve", permit_id: "pt.v2.tok" },
      ],
    });
    expect(capturedBody.evaluation_profile).toBe("advanced");
    expect(capturedBody.override).toEqual({
      version: "override.v1",
      authority_actor_id: "ops-lead-1",
      reason: "P0 hotfix, snapshot hard block accepted",
    });
    expect(capturedBody.completion_proofs).toEqual([
      { actor_id: "reviewer-1", action_type: "code_review.approve", permit_id: "pt.v2.tok" },
    ]);
  });

  it("omits evaluation_profile, override, and completion_proofs from request body when not supplied", async () => {
    let capturedBody: Record<string, unknown> = {};
    const client = makeClient(
      mockFetch((url, init) => {
        capturedBody = JSON.parse((init?.body as string) ?? "{}");
        return Promise.resolve(
          new Response(JSON.stringify(EVALUATE_PERMIT_WIRE), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
    await client.evaluate({ agent: "bot", action: "act" });
    expect(capturedBody.evaluation_profile).toBeUndefined();
    expect(capturedBody.override).toBeUndefined();
    expect(capturedBody.completion_proofs).toBeUndefined();
  });

  it("maps risk_class, authority_basis, escalation_id from response", async () => {
    const wire = {
      ...EVALUATE_PERMIT_WIRE,
      risk_class: "high",
      authority_basis: {
        kind: "approval",
        reference: "esc_abc123",
        rationale: "HITL fallback",
      },
      escalation_id: "esc_abc123",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "bot", action: "act" });
    expect(result.riskClass).toBe("high");
    expect(result.authorityBasis).toEqual({
      kind: "approval",
      reference: "esc_abc123",
      rationale: "HITL fallback",
    });
    expect(result.escalationId).toBe("esc_abc123");
  });

  it("omits riskClass, authorityBasis, escalationId when absent from response", async () => {
    const client = makeClient(mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE)));
    const result = await client.evaluate({ agent: "bot", action: "act" });
    expect(result.riskClass).toBeUndefined();
    expect(result.authorityBasis).toBeUndefined();
    expect(result.escalationId).toBeUndefined();
  });

  it("maps human_approval_required and human_approval_status from response (two-stage lifecycle, #1617)", async () => {
    const wire = {
      ...EVALUATE_PERMIT_WIRE,
      human_approval_required: true,
      human_approval_status: "pending",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "bot", action: "act" });
    expect(result.humanApprovalRequired).toBe(true);
    expect(result.humanApprovalStatus).toBe("pending");
  });

  it("maps approval_request_id from a hold/escalate response", async () => {
    const wire = { decision: "escalate", deny_code: "MANAGER_APPROVAL_REQUIRED", approval_request_id: "apr_123" };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.evaluate({ agent: "bot", action: "act" });
    expect(result.approvalRequestId).toBe("apr_123");
  });

  it("omits approvalRequestId when absent or empty", async () => {
    const client = makeClient(mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE)));
    expect((await client.evaluate({ agent: "bot", action: "act" })).approvalRequestId).toBeUndefined();
    const empty = makeClient(mockFetch(() => jsonResponse({ decision: "escalate", approval_request_id: "" })));
    expect((await empty.evaluate({ agent: "bot", action: "act" })).approvalRequestId).toBeUndefined();
  });

  it("omits humanApprovalRequired and humanApprovalStatus when absent from response (backward compat with older runtimes)", async () => {
    const client = makeClient(mockFetch(() => jsonResponse(EVALUATE_PERMIT_WIRE)));
    const result = await client.evaluate({ agent: "bot", action: "act" });
    expect(result.humanApprovalRequired).toBeUndefined();
    expect(result.humanApprovalStatus).toBeUndefined();
  });
});

describe("keySelf()", () => {
  const KEY_SELF_WIRE = {
    key_id: "550e8400-e29b-41d4-a716-446655440000",
    org_id: "123e4567-e89b-12d3-a456-426614174000",
    environment: "live",
    scopes: ["evaluate", "audit.read"],
    allowed_cidrs: ["10.0.0.0/8"],
    rate_limit_per_minute: 1000,
    client_ip: "10.2.3.4",
    expires_at: "2026-12-31T23:59:59Z",
  };

  it("issues a GET to /v1-api-key-self and maps snake_case → camelCase", async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toMatch(/\/v1-api-key-self$/);
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
      expect((init.headers as Record<string, string>).Authorization).toBe(
        "Bearer ask_live_test",
      );
      return jsonResponse(KEY_SELF_WIRE);
    });
    const client = makeClient(fetchImpl);
    const result = await client.keySelf();

    expect(result).toEqual({
      keyId: "550e8400-e29b-41d4-a716-446655440000",
      orgId: "123e4567-e89b-12d3-a456-426614174000",
      environment: "live",
      scopes: ["evaluate", "audit.read"],
      allowedCidrs: ["10.0.0.0/8"],
      rateLimitPerMinute: 1000,
      clientIp: "10.2.3.4",
      expiresAt: "2026-12-31T23:59:59Z",
      // Headerless response → no rate-limit state surfaced.
      rateLimit: null,
    });
  });

  it("surfaces rateLimit when X-RateLimit-* headers are present", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response(JSON.stringify(KEY_SELF_WIRE), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": "1000",
            "X-RateLimit-Remaining": "987",
            "X-RateLimit-Reset": "1714068060",
          },
        }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.keySelf();
    expect(result.rateLimit).toEqual({
      limit: 1000,
      remaining: 987,
      resetAt: new Date(1_714_068_060 * 1000),
    });
  });

  it("defaults allowed_cidrs to null and expires_at to null when absent", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({
        key_id: "k",
        org_id: "o",
        environment: "test",
        rate_limit_per_minute: 60,
        // allowed_cidrs, client_ip, expires_at, scopes all omitted
      }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.keySelf();
    expect(result.allowedCidrs).toBeNull();
    expect(result.clientIp).toBeNull();
    expect(result.expiresAt).toBeNull();
    expect(result.scopes).toEqual([]);
  });

  it("throws bad_response when required fields are missing", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ environment: "live", rate_limit_per_minute: 60 }),
    );
    const client = makeClient(fetchImpl);
    await expect(client.keySelf()).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("propagates 401 as a typed AtlaSentError", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response(JSON.stringify({ error: "invalid_api_key" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const client = makeClient(fetchImpl);
    await expect(client.keySelf()).rejects.toBeInstanceOf(AtlaSentError);
  });
});

describe("complianceControls()", () => {
  const CONTROLS_WIRE = {
    framework: "cfr_part_11",
    window: { from: "2026-05-01T00:00:00Z", to: "2026-06-01T00:00:00Z" },
    generated_at: "2026-06-19T00:00:00Z",
    summary: {
      enforced: 8,
      partial: 2,
      not_enforced: 1,
      no_data: 1,
      attested: 0,
      total: 12,
    },
    controls: [
      {
        clause_id: "11.10(a)",
        framework_code: "cfr_part_11",
        section: "11.10",
        title: "Validation of systems",
        requirement: "Validation of systems to ensure accuracy.",
        atlasent_primitive: "execution_evaluations",
        status_query: "evaluations_present_30d",
        evidence_source: "execution_evaluations",
        doc_ref: "https://docs/cfr-11-10a",
        display_order: 1,
        status: "enforced",
        metric: { count: 42 },
      },
    ],
    truncated: false,
  };

  it("issues a GET to /v1-compliance-controls with query params", async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toMatch(/\/v1-compliance-controls\?/);
      expect(url).toContain("framework=cfr_part_11");
      expect(url).toContain("from=2026-05-01");
      expect(url).toContain("to=2026-06-01");
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
      return jsonResponse(CONTROLS_WIRE);
    });
    const client = makeClient(fetchImpl);
    const result = await client.complianceControls({
      framework: "cfr_part_11",
      from: "2026-05-01",
      to: "2026-06-01",
    });

    expect(result.framework).toBe("cfr_part_11");
    expect(result.window).toEqual({
      from: "2026-05-01T00:00:00Z",
      to: "2026-06-01T00:00:00Z",
    });
    expect(result.generatedAt).toBe("2026-06-19T00:00:00Z");
    expect(result.summary.total).toBe(12);
    expect(result.controls).toHaveLength(1);
    expect(result.controls[0]?.status).toBe("enforced");
    expect(result.truncated).toBe(false);
    expect(result.rateLimit).toBeNull();
  });

  it("omits query params when called with no args and defaults framework to null", async () => {
    const fetchImpl = mockFetch((url) => {
      expect(url).toMatch(/\/v1-compliance-controls$/);
      return jsonResponse({
        framework: null,
        window: { from: null, to: null },
        generated_at: "2026-06-19T00:00:00Z",
        summary: {
          enforced: 0,
          partial: 0,
          not_enforced: 0,
          no_data: 0,
          attested: 0,
          total: 0,
        },
        controls: [],
        // truncated omitted → defaults to false
      });
    });
    const client = makeClient(fetchImpl);
    const result = await client.complianceControls();
    expect(result.framework).toBeNull();
    expect(result.window).toEqual({ from: null, to: null });
    expect(result.truncated).toBe(false);
  });

  it("throws bad_response when `controls` is missing", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ generated_at: "2026-06-19T00:00:00Z" }),
    );
    const client = makeClient(fetchImpl);
    await expect(client.complianceControls()).rejects.toMatchObject({
      code: "bad_response",
    });
  });
});

describe("complianceEvidencePack()", () => {
  const PACK_WIRE = {
    framework: "cfr_part_11",
    window: { from: "2026-05-01T00:00:00Z", to: "2026-06-01T00:00:00Z" },
    generated_at: "2026-06-19T00:00:00Z",
    summary: {
      enforced: 8,
      partial: 2,
      not_enforced: 1,
      no_data: 1,
      attested: 0,
      total: 12,
    },
    sha256: "a".repeat(64),
    signature: "ed25519:abc",
    signing_status: "signed",
    key_id: "v1",
    bundle: {
      schema: "atlasent.compliance.evidence_pack.v1",
      framework: "cfr_part_11",
      window: { from: "2026-05-01T00:00:00Z", to: "2026-06-01T00:00:00Z" },
      org_id: "123e4567-e89b-12d3-a456-426614174000",
      summary: {
        enforced: 8,
        partial: 2,
        not_enforced: 1,
        no_data: 1,
        attested: 0,
        total: 12,
      },
      controls: [],
    },
  };

  it("issues a GET to /v1-compliance-evidence-pack and maps the signed bundle", async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toMatch(/\/v1-compliance-evidence-pack\?/);
      expect(url).toContain("framework=cfr_part_11");
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
      return jsonResponse(PACK_WIRE);
    });
    const client = makeClient(fetchImpl);
    const result = await client.complianceEvidencePack({
      framework: "cfr_part_11",
      from: "2026-05-01",
      to: "2026-06-01",
    });

    expect(result.framework).toBe("cfr_part_11");
    expect(result.generatedAt).toBe("2026-06-19T00:00:00Z");
    expect(result.sha256).toBe("a".repeat(64));
    expect(result.signature).toBe("ed25519:abc");
    expect(result.signingStatus).toBe("signed");
    expect(result.keyId).toBe("v1");
    expect(result.bundle.schema).toBe("atlasent.compliance.evidence_pack.v1");
    expect(result.bundle.org_id).toBe("123e4567-e89b-12d3-a456-426614174000");
    expect(result.rateLimit).toBeNull();
  });

  it("throws bad_request when framework is missing", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(PACK_WIRE));
    const client = makeClient(fetchImpl);
    await expect(
      // @ts-expect-error — deliberately omit required framework
      client.complianceEvidencePack({}),
    ).rejects.toMatchObject({ code: "bad_request" });
  });

  it("defaults key_id to null when absent", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ ...PACK_WIRE, key_id: undefined, signing_status: "unsigned" }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.complianceEvidencePack({ framework: "cfr_part_11" });
    expect(result.keyId).toBeNull();
    expect(result.signingStatus).toBe("unsigned");
  });

  it("throws bad_response when `bundle` is missing", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ framework: "cfr_part_11", sha256: "a".repeat(64) }),
    );
    const client = makeClient(fetchImpl);
    await expect(
      client.complianceEvidencePack({ framework: "cfr_part_11" }),
    ).rejects.toMatchObject({ code: "bad_response" });
  });
});

describe("listAuditEvents()", () => {
  const EVENT_ALPHA = {
    id: "evt_a",
    org_id: "org-1",
    sequence: 1,
    type: "evaluate.allow",
    decision: "allow" as const,
    actor_id: "agent-1",
    resource_type: null,
    resource_id: null,
    payload: { action: "read_data" },
    hash: "a".repeat(64),
    previous_hash: "0".repeat(64),
    occurred_at: "2026-04-21T00:00:00Z",
    created_at: "2026-04-21T00:00:01Z",
  };

  const EVENTS_PAGE_WIRE = {
    events: [EVENT_ALPHA],
    total: 1,
    next_cursor: "cursor_beta",
  };

  it("issues a GET to /v1-audit/events and preserves snake_case wire fields", async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toMatch(/\/v1-audit\/events$/);
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
      expect((init.headers as Record<string, string>).Authorization).toBe(
        "Bearer ask_live_test",
      );
      return jsonResponse(EVENTS_PAGE_WIRE);
    });
    const client = makeClient(fetchImpl);
    const result = await client.listAuditEvents();

    expect(result.total).toBe(1);
    expect(result.next_cursor).toBe("cursor_beta");
    expect(result.events[0]).toMatchObject({
      id: "evt_a",
      previous_hash: "0".repeat(64),
      hash: "a".repeat(64),
      decision: "allow",
    });
    expect(result.rateLimit).toBeNull();
  });

  it("serializes all query fields as snake_case URL params", async () => {
    const fetchImpl = mockFetch((url) => {
      expect(url).toContain("/v1-audit/events?");
      const parsed = new URL(url);
      expect(parsed.searchParams.get("types")).toBe(
        "evaluate.allow,policy.updated",
      );
      expect(parsed.searchParams.get("actor_id")).toBe("agent-1");
      expect(parsed.searchParams.get("from")).toBe("2026-04-20T00:00:00Z");
      expect(parsed.searchParams.get("to")).toBe("2026-04-22T00:00:00Z");
      expect(parsed.searchParams.get("limit")).toBe("25");
      expect(parsed.searchParams.get("cursor")).toBe("abc");
      return jsonResponse({ events: [], total: 0 });
    });
    const client = makeClient(fetchImpl);
    await client.listAuditEvents({
      types: "evaluate.allow,policy.updated",
      actor_id: "agent-1",
      from: "2026-04-20T00:00:00Z",
      to: "2026-04-22T00:00:00Z",
      limit: 25,
      cursor: "abc",
    });
  });

  it("sends no query string when the filter is empty", async () => {
    const fetchImpl = mockFetch((url) => {
      expect(url).toMatch(/\/v1-audit\/events$/);
      expect(url).not.toContain("?");
      return jsonResponse({ events: [], total: 0 });
    });
    const client = makeClient(fetchImpl);
    await client.listAuditEvents({});
  });

  it("surfaces rateLimit when X-RateLimit-* headers are present", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response(JSON.stringify(EVENTS_PAGE_WIRE), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": "500",
            "X-RateLimit-Remaining": "499",
            "X-RateLimit-Reset": "1714070000",
          },
        }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.listAuditEvents();
    expect(result.rateLimit).toEqual({
      limit: 500,
      remaining: 499,
      resetAt: new Date(1_714_070_000 * 1000),
    });
  });

  it("throws bad_response when events is not an array", async () => {
    const fetchImpl = mockFetch(() => jsonResponse({ total: 0 }));
    const client = makeClient(fetchImpl);
    await expect(client.listAuditEvents()).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("throws bad_response when total is missing", async () => {
    const fetchImpl = mockFetch(() => jsonResponse({ events: [] }));
    const client = makeClient(fetchImpl);
    await expect(client.listAuditEvents()).rejects.toMatchObject({
      code: "bad_response",
    });
  });
});

describe("createAuditExport()", () => {
  const BUNDLE_WIRE = {
    export_id: "export-1",
    org_id: "org-1",
    events: [
      {
        id: "evt-1",
        org_id: "org-1",
        sequence: 1,
        type: "policy.event",
        decision: null,
        actor_id: "actor-1",
        resource_type: "policy",
        resource_id: "policy-1",
        payload: { action: "create" },
        hash: "a".repeat(64),
        previous_hash: "0".repeat(64),
        occurred_at: "2026-04-21T00:00:00Z",
        created_at: "2026-04-21T00:00:00Z",
      },
    ],
    chain_head_hash: "a".repeat(64),
    chain_integrity_ok: true,
    tampered_event_ids: [],
    signature: "sig_bytes_base64url",
    signature_status: "signed" as const,
    signing_key_id: "test-key",
    signed_at: "2026-04-21T00:00:00Z",
    event_count: 1,
  };

  it("POSTs to /v1-audit/exports with an empty body by default and returns the bundle verbatim", async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toMatch(/\/v1-audit\/exports$/);
      expect(init.method).toBe("POST");
      expect(init.body).toBe("{}");
      expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
        "application/json",
      );
      return jsonResponse(BUNDLE_WIRE);
    });
    const client = makeClient(fetchImpl);
    const result = await client.createAuditExport();

    expect(result.export_id).toBe("export-1");
    expect(result.chain_head_hash).toBe("a".repeat(64));
    expect(result.signature).toBe("sig_bytes_base64url");
    expect(result.signature_status).toBe("signed");
    expect(result.signing_key_id).toBe("test-key");
    expect(result.events).toHaveLength(1);
    expect(result.rateLimit).toBeNull();
  });

  it("forwards the filter fields as JSON body", async () => {
    const fetchImpl = mockFetch((url, init) => {
      const body = JSON.parse(init.body as string);
      expect(body).toEqual({
        types: "evaluate.allow",
        actor_id: "agent-1",
        from: "2026-04-20T00:00:00Z",
        to: "2026-04-22T00:00:00Z",
      });
      return jsonResponse(BUNDLE_WIRE);
    });
    const client = makeClient(fetchImpl);
    await client.createAuditExport({
      types: "evaluate.allow",
      actor_id: "agent-1",
      from: "2026-04-20T00:00:00Z",
      to: "2026-04-22T00:00:00Z",
    });
  });

  it("surfaces rateLimit when X-RateLimit-* headers are present", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response(JSON.stringify(BUNDLE_WIRE), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "9",
            "X-RateLimit-Reset": "1714070000",
          },
        }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.createAuditExport();
    expect(result.rateLimit).toEqual({
      limit: 10,
      remaining: 9,
      resetAt: new Date(1_714_070_000 * 1000),
    });
  });

  it("throws bad_response when export_id is missing", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ chain_head_hash: "x", events: [] }),
    );
    const client = makeClient(fetchImpl);
    await expect(client.createAuditExport()).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("throws bad_response when events is not an array", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ export_id: "e", chain_head_hash: "x" }),
    );
    const client = makeClient(fetchImpl);
    await expect(client.createAuditExport()).rejects.toMatchObject({
      code: "bad_response",
    });
  });
});

describe("response-shape error paths", () => {
  // These guard against stream-or-non-stream JSON malformation that
  // sneaks past the HTTP layer (200 OK, but the body isn't a JSON
  // object). All three paths flow through `post()` so any endpoint
  // call exercises them; we use evaluate() because it's the simplest.

  it("throws bad_response when the body is not parseable JSON", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response("<!doctype html>oops", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const client = makeClient(fetchImpl);
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({ code: "bad_response" });
  });

  it("throws bad_response when the body parses to a non-object (null)", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(null));
    const client = makeClient(fetchImpl);
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({ code: "bad_response" });
  });

  it("throws bad_response when the body parses to a primitive", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(42));
    const client = makeClient(fetchImpl);
    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toMatchObject({ code: "bad_response" });
  });
});

describe("revokePermit()", () => {
  // Wire shape mirrors the server response: snake_case, decision_id is the
  // permit identifier the SDK exposes as permitId.
  const REVOKE_OK_WIRE = {
    revoked: true,
    decision_id: "dec_to_revoke",
    revoked_at: "2026-04-30T01:00:00Z",
    audit_hash: "hash_revoked",
  };

  it("POSTs to /v1-revoke-permit with decision_id + reason and returns the SDK shape", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(REVOKE_OK_WIRE));
    const client = makeClient(fetchImpl);

    const result = await client.revokePermit({
      permitId: "dec_to_revoke",
      reason: "policy violation",
    });

    expect(fetchImpl.mock.calls).toHaveLength(1);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toContain("/v1-revoke-permit");
    expect(init!.method).toBe("POST");
    const body = JSON.parse(init!.body as string);
    expect(body).toMatchObject({
      decision_id: "dec_to_revoke",
      reason: "policy violation",
      api_key: "ask_live_test",
    });

    expect(result).toMatchObject({
      revoked: true,
      permitId: "dec_to_revoke",
      revokedAt: "2026-04-30T01:00:00Z",
      auditHash: "hash_revoked",
    });
  });

  it("defaults reason to empty string when omitted", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(REVOKE_OK_WIRE));
    const client = makeClient(fetchImpl);
    await client.revokePermit({ permitId: "dec_to_revoke" });
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    expect(body.reason).toBe("");
  });

  it("surfaces revoked=false from the server without throwing", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ ...REVOKE_OK_WIRE, revoked: false }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.revokePermit({ permitId: "dec_to_revoke" });
    expect(result.revoked).toBe(false);
  });

  it("throws bad_response when revoked is not a boolean", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ ...REVOKE_OK_WIRE, revoked: "yes" }),
    );
    const client = makeClient(fetchImpl);
    await expect(
      client.revokePermit({ permitId: "dec_to_revoke" }),
    ).rejects.toMatchObject({ code: "bad_response" });
  });

  it("throws bad_response when decision_id is missing", async () => {
    const fetchImpl = mockFetch(() => jsonResponse({ revoked: true }));
    const client = makeClient(fetchImpl);
    await expect(
      client.revokePermit({ permitId: "dec_to_revoke" }),
    ).rejects.toMatchObject({ code: "bad_response" });
  });
});

describe("getPermit()", () => {
  const PERMIT_WIRE = {
    id: "pt_alpha",
    org_id: "org_x",
    actor_id: "agent-1",
    action_id: "ehr.write",
    status: "verified" as const,
    issued_at: "2026-05-07T01:00:00Z",
    expires_at: "2026-05-07T01:15:00Z",
    consumed_at: null,
    revoked_at: null,
    revoked_by: null,
    revoke_reason: null,
    payload_hash: "sha256:deadbeef",
    decision_id: "eval_a",
  };

  it("hits GET /v1-permits/:id and returns the permit row", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.getPermit("pt_alpha");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-permits/pt_alpha");
    expect(init!.method).toBe("GET");
    expect(result.permit.id).toBe("pt_alpha");
    expect(result.permit.status).toBe("verified");
  });

  it("URL-encodes the permitId", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(PERMIT_WIRE));
    const client = makeClient(fetchImpl);
    await client.getPermit("pt with spaces");
    const [url] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-permits/pt%20with%20spaces");
  });

  it("throws when permitId is empty", async () => {
    const client = makeClient(mockFetch(() => jsonResponse({})));
    await expect(client.getPermit("")).rejects.toMatchObject({
      code: "bad_request",
    });
  });

  it("surfaces revocation fields when status is revoked", async () => {
    const revoked = {
      ...PERMIT_WIRE,
      status: "revoked" as const,
      revoked_at: "2026-05-07T01:10:00Z",
      revoked_by: "user_admin",
      revoke_reason: "approval rescinded",
    };
    const client = makeClient(mockFetch(() => jsonResponse(revoked)));
    const result = await client.getPermit("pt_alpha");
    expect(result.permit.status).toBe("revoked");
    expect(result.permit.revoked_at).toBe("2026-05-07T01:10:00Z");
    expect(result.permit.revoked_by).toBe("user_admin");
    expect(result.permit.revoke_reason).toBe("approval rescinded");
  });
});

describe("listPermits()", () => {
  const LIST_WIRE = {
    permits: [
      {
        id: "pt_a",
        org_id: "org_x",
        actor_id: "a",
        action_id: "x",
        status: "issued" as const,
        issued_at: "2026-05-07T01:00:00Z",
        expires_at: "2026-05-07T01:15:00Z",
      },
      {
        id: "pt_b",
        org_id: "org_x",
        actor_id: "a",
        action_id: "x",
        status: "consumed" as const,
        issued_at: "2026-05-07T00:00:00Z",
        expires_at: "2026-05-07T00:15:00Z",
        consumed_at: "2026-05-07T00:10:00Z",
      },
    ],
    total: 2,
  };

  it("hits GET /v1-permits with no query params when no filters", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(LIST_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.listPermits();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-permits");
    expect(init!.method).toBe("GET");
    expect(result.permits).toHaveLength(2);
    expect(result.total).toBe(2);
  });

  it("translates camelCase filters to snake_case query params", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(LIST_WIRE));
    const client = makeClient(fetchImpl);
    await client.listPermits({
      status: "revoked",
      actorId: "user_42",
      actionType: "ehr.write",
      from: "2026-05-01T00:00:00Z",
      to: "2026-05-07T00:00:00Z",
      limit: 100,
      cursor: "2026-05-06T00:00:00Z",
    });
    const [url] = fetchImpl.mock.calls[0]!;
    const u = new URL(url as string);
    expect(u.pathname).toBe("/functions/v1/v1-permits");
    expect(u.searchParams.get("status")).toBe("revoked");
    expect(u.searchParams.get("actor_id")).toBe("user_42");
    expect(u.searchParams.get("action_type")).toBe("ehr.write");
    expect(u.searchParams.get("from")).toBe("2026-05-01T00:00:00Z");
    expect(u.searchParams.get("to")).toBe("2026-05-07T00:00:00Z");
    expect(u.searchParams.get("limit")).toBe("100");
    expect(u.searchParams.get("cursor")).toBe("2026-05-06T00:00:00Z");
  });

  it("surfaces nextCursor when present", async () => {
    const client = makeClient(
      mockFetch(() =>
        jsonResponse({
          ...LIST_WIRE,
          next_cursor: "2026-05-06T23:00:00Z",
        }),
      ),
    );
    const result = await client.listPermits({ limit: 2 });
    expect(result.nextCursor).toBe("2026-05-06T23:00:00Z");
  });

  it("throws bad_response when permits array is missing", async () => {
    const client = makeClient(mockFetch(() => jsonResponse({ total: 0 })));
    await expect(client.listPermits()).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("falls back to permits.length when total is missing", async () => {
    const { total: _t, ...withoutTotal } = LIST_WIRE;
    const client = makeClient(mockFetch(() => jsonResponse(withoutTotal)));
    const result = await client.listPermits();
    expect(result.total).toBe(2);
  });
});

describe("revokePermitById()", () => {
  const REVOKED_WIRE = {
    id: "pt_alpha",
    org_id: "org_x",
    actor_id: "agent-1",
    action_id: "ehr.write",
    status: "revoked" as const,
    issued_at: "2026-05-07T01:00:00Z",
    expires_at: "2026-05-07T01:15:00Z",
    consumed_at: null,
    revoked_at: "2026-05-07T01:10:00Z",
    revoked_by: "user_admin",
    revoke_reason: "approval rescinded",
  };

  it("hits POST /v1-permits/:id/revoke and returns updated permit", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(REVOKED_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.revokePermitById("pt_alpha", {
      reason: "approval rescinded",
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-permits/pt_alpha/revoke");
    expect(init!.method).toBe("POST");
    expect(JSON.parse(init!.body as string)).toEqual({
      reason: "approval rescinded",
    });
    expect(result.permit.status).toBe("revoked");
    expect(result.permit.revoked_at).toBe("2026-05-07T01:10:00Z");
    expect(result.permit.revoked_by).toBe("user_admin");
    expect(result.permit.revoke_reason).toBe("approval rescinded");
  });

  it("omits reason from body when not supplied", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(REVOKED_WIRE));
    const client = makeClient(fetchImpl);
    await client.revokePermitById("pt_alpha");
    const body = JSON.parse(fetchImpl.mock.calls[0]![1]!.body as string);
    expect(body).toEqual({});
  });

  it("URL-encodes the permitId", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(REVOKED_WIRE));
    const client = makeClient(fetchImpl);
    await client.revokePermitById("pt with spaces");
    const [url] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(
      "https://api.atlasent.io/functions/v1/v1-permits/pt%20with%20spaces/revoke",
    );
  });

  it("throws bad_request when permitId is empty", async () => {
    const client = makeClient(mockFetch(() => jsonResponse({})));
    await expect(client.revokePermitById("")).rejects.toMatchObject({
      code: "bad_request",
    });
  });
});

describe("verifyPermitById()", () => {
  const VERIFY_OK_WIRE = {
    valid: true,
    verification_type: "permit" as const,
    reason: null,
    verified_at: "2026-05-07T01:00:00.214Z",
    evidence: {
      permit_id: "pt_alpha",
      status: "verified" as const,
      actor_id: "agent-1",
      action_id: "ehr.write",
      expires_at: "2026-05-07T01:15:00Z",
      payload_hash: "sha256:deadbeef",
      decision_id: "eval_a",
    },
    // Legacy fields preserved at top level (allOf in openapi):
    id: "pt_alpha",
    org_id: "org_x",
    actor_id: "agent-1",
    action_id: "ehr.write",
    status: "verified" as const,
    issued_at: "2026-05-07T01:00:00Z",
    expires_at: "2026-05-07T01:15:00Z",
    payload_hash: "sha256:deadbeef",
    decision_id: "eval_a",
  };

  it("hits POST /v1-permits/:id/verify and returns the canonical envelope", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_OK_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.verifyPermitById("pt_alpha");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.atlasent.io/functions/v1/v1-permits/pt_alpha/verify");
    expect(init!.method).toBe("POST");
    expect(result.valid).toBe(true);
    expect(result.verification_type).toBe("permit");
    expect(result.reason).toBeNull();
    expect(result.verified_at).toBe("2026-05-07T01:00:00.214Z");
    expect(result.evidence.permit_id).toBe("pt_alpha");
    expect(result.evidence.status).toBe("verified");
    expect(result.permit.id).toBe("pt_alpha");
    expect(result.permit.status).toBe("verified");
  });

  it("URL-encodes the permitId", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_OK_WIRE));
    const client = makeClient(fetchImpl);
    await client.verifyPermitById("pt with spaces");
    const [url] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(
      "https://api.atlasent.io/functions/v1/v1-permits/pt%20with%20spaces/verify",
    );
  });

  it("throws bad_request when permitId is empty", async () => {
    const client = makeClient(mockFetch(() => jsonResponse({})));
    await expect(client.verifyPermitById("")).rejects.toMatchObject({
      code: "bad_request",
    });
  });
});

// ── Retry behaviour ────────────────────────────────────────────────────────────

describe("AtlaSentClient retry", () => {
  it("retries on 500 and succeeds on the second attempt", async () => {
    let calls = 0;
    const fetchImpl = mockFetch(() => {
      calls++;
      if (calls === 1) return new Response("boom", { status: 500 });
      return jsonResponse({
        decision: "allow",
        permit_token: "pt_retry",
        request_id: "r1",
      });
    });
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 2, baseDelayMs: 0, maxDelayMs: 0 },
    });
    const result = await client.evaluate({ agent: "agent_1", action: "write" });
    expect(calls).toBe(2);
    expect(result.decision).toBe("allow");
    expect(result.permitId).toBe("pt_retry");
  });

  it("retries on 429 and respects Retry-After", async () => {
    let calls = 0;
    const fetchImpl = mockFetch(() => {
      calls++;
      if (calls === 1) {
        return new Response("rate limited", {
          status: 429,
          headers: { "Retry-After": "0" },
        });
      }
      return jsonResponse({
        decision: "allow",
        permit_token: "pt_429",
        request_id: "r2",
      });
    });
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 2, baseDelayMs: 0, maxDelayMs: 0 },
    });
    const result = await client.evaluate({ agent: "agent_1", action: "write" });
    expect(calls).toBe(2);
    expect(result.decision).toBe("allow");
  });

  it("retries on network error and succeeds", async () => {
    let calls = 0;
    const fetchImpl = mockFetch(() => {
      calls++;
      if (calls === 1) throw new TypeError("fetch failed");
      return jsonResponse({
        decision: "deny",
        permit_token: "",
        request_id: "r3",
      });
    });
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 2, baseDelayMs: 0, maxDelayMs: 0 },
    });
    const result = await client.evaluate({ agent: "agent_2", action: "read" });
    expect(calls).toBe(2);
    expect(result.decision).toBe("deny");
  });

  it("exhausts attempts and throws on persistent 500", async () => {
    const fetchImpl = mockFetch(() => new Response("err", { status: 500 }));
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0 },
    });
    await expect(
      client.evaluate({ agent: "agent_3", action: "write" }),
    ).rejects.toMatchObject({ code: "server_error" });
    expect(fetchImpl.mock.calls).toHaveLength(3);
  });

  it("does not retry 401", async () => {
    const fetchImpl = mockFetch(() => new Response("unauth", { status: 401 }));
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0 },
    });
    await expect(
      client.evaluate({ agent: "agent_4", action: "write" }),
    ).rejects.toMatchObject({ code: "invalid_api_key" });
    expect(fetchImpl.mock.calls).toHaveLength(1);
  });

  it("does not retry 400 bad_request", async () => {
    const fetchImpl = mockFetch(() => new Response("bad", { status: 400 }));
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0 },
    });
    await expect(
      client.evaluate({ agent: "agent_5", action: "write" }),
    ).rejects.toMatchObject({ code: "bad_request" });
    expect(fetchImpl.mock.calls).toHaveLength(1);
  });

  it("maxAttempts: 1 disables retries", async () => {
    const fetchImpl = mockFetch(() => new Response("err", { status: 503 }));
    const client = makeClient(fetchImpl, {
      retryPolicy: { maxAttempts: 1 },
    });
    await expect(
      client.evaluate({ agent: "agent_6", action: "write" }),
    ).rejects.toMatchObject({ code: "server_error" });
    expect(fetchImpl.mock.calls).toHaveLength(1);
  });
});

// ── evaluateBatch ──────────────────────────────────────────────────────────

const BATCH_WIRE = {
  batch_id: "batch-uuid-1",
  items: [
    {
      index: 0,
      decision: "allow",
      decision_id: "dec_a",
      permit_token: "ptk_a",
      reason: "",
      audit_entry_hash: "h_a",
      timestamp: "2026-05-23T08:00:00Z",
    },
    {
      index: 1,
      decision: "deny",
      decision_id: "dec_b",
      permit_token: null,
      reason: "policy blocked",
      audit_entry_hash: "h_b",
      timestamp: "2026-05-23T08:00:01Z",
    },
  ],
  partial: false,
};

describe("evaluateBatch()", () => {
  it("maps wire response to EvaluateBatchResponse", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(BATCH_WIRE));
    const client = makeClient(fetchImpl);

    const result = await client.evaluateBatch([
      { agent: "bot", action: "production.deploy" },
      { agent: "bot", action: "rollback" },
    ]);

    expect(result.batchId).toBe("batch-uuid-1");
    expect(result.partial).toBe(false);
    expect(result.items).toHaveLength(2);
    expect(result.items[0]).toMatchObject({
      index: 0,
      decision: "allow",
      decisionId: "dec_a",
      permitToken: "ptk_a",
      auditHash: "h_a",
    });
    expect(result.items[1]).toMatchObject({
      index: 1,
      decision: "deny",
      decisionId: "dec_b",
      reason: "policy blocked",
    });
  });

  it("posts to /v1/evaluate/batch with snake_case body", async () => {
    let captured: { url: string; body: unknown } = { url: "", body: null };
    const fetchImpl = mockFetch((url, init) => {
      captured = { url, body: JSON.parse(init.body as string) };
      return jsonResponse(BATCH_WIRE);
    });
    const client = makeClient(fetchImpl);

    await client.evaluateBatch([
      { agent: "bot", action: "production.deploy", context: { env: "prod" } },
    ]);

    expect(captured.url).toContain("/v1/evaluate/batch");
    expect(captured.body).toMatchObject({
      items: [{ action_type: "production.deploy", actor_id: "bot", context: { env: "prod" } }],
    });
  });

  it("falls back to /v1-evaluate-batch when canonical batch route is unavailable", async () => {
    const fetchImpl = mockFetch((url) => {
      if (url.includes("/v1/evaluate/batch")) {
        return new Response("{}", {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.includes("/v1-evaluate-batch")) {
        return jsonResponse(BATCH_WIRE);
      }
      return new Response("unexpected", { status: 500 });
    });
    const client = makeClient(fetchImpl);

    const result = await client.evaluateBatch([
      { agent: "bot", action: "production.deploy" },
    ]);

    expect(result.batchId).toBe("batch-uuid-1");
    expect(fetchImpl.mock.calls[0]?.[0]).toContain("/v1/evaluate/batch");
    expect(fetchImpl.mock.calls[1]?.[0]).toContain("/v1-evaluate-batch");
  });

  it("includes caller-supplied batchId in the request body", async () => {
    let body: unknown;
    const fetchImpl = mockFetch((_url, init) => {
      body = JSON.parse(init.body as string);
      return jsonResponse({ ...BATCH_WIRE, batch_id: "my-batch" });
    });
    const client = makeClient(fetchImpl);

    await client.evaluateBatch([{ agent: "bot", action: "action" }], "my-batch");

    expect((body as Record<string, unknown>).batch_id).toBe("my-batch");
  });

  it("throws AtlaSentError on empty requests array (does not call fetch)", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(BATCH_WIRE));
    const client = makeClient(fetchImpl);

    await expect(client.evaluateBatch([])).rejects.toMatchObject({
      code: "bad_request",
    });
    expect(fetchImpl.mock.calls).toHaveLength(0);
  });

  it("throws AtlaSentError when requests.length > 100", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(BATCH_WIRE));
    const client = makeClient(fetchImpl);
    const tooMany = Array.from({ length: 101 }, () => ({
      agent: "bot",
      action: "act",
    }));

    await expect(client.evaluateBatch(tooMany)).rejects.toMatchObject({
      code: "bad_request",
    });
    expect(fetchImpl.mock.calls).toHaveLength(0);
  });

  it("throws AtlaSentError on 401", async () => {
    const fetchImpl = mockFetch(() =>
      new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } }),
    );
    const client = makeClient(fetchImpl);

    await expect(
      client.evaluateBatch([{ agent: "bot", action: "act" }]),
    ).rejects.toBeInstanceOf(AtlaSentError);
  });

  it("surfaces partial=true from the wire response", async () => {
    const partialWire = {
      ...BATCH_WIRE,
      partial: true,
      items: [
        { index: 0, error: "item_failed", message: "rpc timeout" },
      ],
    };
    const fetchImpl = mockFetch(() => jsonResponse(partialWire));
    const client = makeClient(fetchImpl);

    const result = await client.evaluateBatch([{ agent: "bot", action: "act" }]);

    expect(result.partial).toBe(true);
    expect(result.items[0]).toMatchObject({ index: 0, error: "item_failed" });
  });

  it("propagates replayed=true from the wire response", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ ...BATCH_WIRE, replayed: true }),
    );
    const client = makeClient(fetchImpl);

    const result = await client.evaluateBatch([{ agent: "bot", action: "act" }]);

    expect(result.replayed).toBe(true);
  });
});

// ── subscribeDecisions ─────────────────────────────────────────────────────

function sseResponse(frames: string[]): Response {
  const body = frames.join("");
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

describe("subscribeDecisions()", () => {
  it("yields typed events from SSE frames", async () => {
    const sse = [
      "id: evt_1\nevent: evaluate.allow\ndata: {\"decision\":\"allow\",\"actor_id\":\"bot\",\"resource_type\":\"deploy\",\"occurred_at\":\"2026-05-23T08:00:00Z\"}\n\n",
      "id: evt_2\nevent: evaluate.deny\ndata: {\"decision\":\"deny\",\"actor_id\":\"bot2\"}\n\n",
      "event: session_end\ndata: {\"reason\":\"max_seconds_reached\"}\n\n",
    ];
    const fetchImpl = mockFetch(() => sseResponse(sse));
    const client = makeClient(fetchImpl);

    const events = [];
    for await (const ev of client.subscribeDecisions()) {
      events.push(ev);
    }

    expect(events).toHaveLength(3);
    expect(events[0]).toMatchObject({ id: "evt_1", type: "evaluate.allow", decision: "allow", actorId: "bot" });
    expect(events[1]).toMatchObject({ id: "evt_2", type: "evaluate.deny", decision: "deny" });
    expect(events[2]).toMatchObject({ type: "session_end" });
  });

  it("yields heartbeat for SSE comment lines", async () => {
    const sse = [
      ": keep-alive\n\n",
      "event: session_end\ndata: {}\n\n",
    ];
    const fetchImpl = mockFetch(() => sseResponse(sse));
    const client = makeClient(fetchImpl);

    const events = [];
    for await (const ev of client.subscribeDecisions()) {
      events.push(ev);
    }

    expect(events[0]).toMatchObject({ type: "heartbeat" });
    expect(events[1]).toMatchObject({ type: "session_end" });
  });

  it("passes types and actor_id as query params", async () => {
    let capturedUrl = "";
    const fetchImpl = mockFetch((url) => {
      capturedUrl = url;
      return sseResponse(["event: session_end\ndata: {}\n\n"]);
    });
    const client = makeClient(fetchImpl);

    for await (const _ of client.subscribeDecisions({
      types: ["evaluate.allow", "evaluate.deny"],
      actorId: "deploy-bot",
    })) { break; }

    expect(capturedUrl).toContain("types=evaluate.allow%2Cevaluate.deny");
    expect(capturedUrl).toContain("actor_id=deploy-bot");
  });

  it("sends Last-Event-ID header when lastEventId is supplied", async () => {
    let capturedHeaders: Record<string, string> = {};
    const fetchImpl: FetchMock = vi.fn(async (_input, init) => {
      for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
        capturedHeaders[k.toLowerCase()] = v;
      }
      return sseResponse(["event: session_end\ndata: {}\n\n"]);
    }) as unknown as FetchMock;
    const client = makeClient(fetchImpl);

    for await (const _ of client.subscribeDecisions({ lastEventId: "evt_42" })) { break; }

    expect(capturedHeaders["last-event-id"]).toBe("evt_42");
  });

  it("throws AtlaSentError on 401", async () => {
    const fetchImpl = mockFetch(() =>
      new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } }),
    );
    const client = makeClient(fetchImpl);

    await expect(async () => {
      for await (const _ of client.subscribeDecisions()) { /* empty */ }
    }).rejects.toBeInstanceOf(AtlaSentError);
  });

  it("throws AtlaSentError on network error during connect", async () => {
    const fetchImpl: FetchMock = vi.fn(async () => {
      throw new TypeError("network failure");
    }) as unknown as FetchMock;
    const client = makeClient(fetchImpl);

    await expect(async () => {
      for await (const _ of client.subscribeDecisions()) { /* empty */ }
    }).rejects.toBeInstanceOf(AtlaSentError);
  });

  it("throws AtlaSentError when response body is null", async () => {
    const fetchImpl: FetchMock = vi.fn(async () =>
      ({ ok: true, status: 200, body: null }) as unknown as Response,
    ) as unknown as FetchMock;
    const client = makeClient(fetchImpl);

    await expect(async () => {
      for await (const _ of client.subscribeDecisions()) { /* empty */ }
    }).rejects.toBeInstanceOf(AtlaSentError);
  });

  it("throws AtlaSentError on read error mid-stream", async () => {
    const reader = {
      read: vi.fn().mockRejectedValue(new TypeError("connection reset")),
      releaseLock: vi.fn(),
    };
    const fetchImpl: FetchMock = vi.fn(async () =>
      ({ ok: true, status: 200, body: { getReader: () => reader } }) as unknown as Response,
    ) as unknown as FetchMock;
    const client = makeClient(fetchImpl);

    await expect(async () => {
      for await (const _ of client.subscribeDecisions()) { /* empty */ }
    }).rejects.toBeInstanceOf(AtlaSentError);
  });

  it("skips malformed JSON data lines", async () => {
    const sse = [
      "event: evaluate.allow\ndata: {not-json}\n\n",
      "event: session_end\ndata: {}\n\n",
    ];
    const fetchImpl = mockFetch(() => sseResponse(sse));
    const client = makeClient(fetchImpl);

    const events = [];
    for await (const ev of client.subscribeDecisions()) {
      events.push(ev);
    }
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ type: "session_end" });
  });
});

describe("replayDecision()", () => {
  const REPLAY_NONE_WIRE = {
    decision_id: "dec_abc123",
    original_decision: "allow" as const,
    replay_decision: "allow" as const,
    engine_version: "wire-v1@1.0.0",
    engine_version_kind: "active" as const,
    accepts_replay: true,
    variance: "NONE" as const,
    envelope_verification: "verified" as const,
    replayed_at: "2026-05-24T00:00:00Z",
  };

  it("POSTs to /v1-decisions-replay/:id/replay with an empty body and surfaces NONE variance", async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toMatch(/\/v1-decisions-replay\/dec_abc123\/replay$/);
      expect(init.method).toBe("POST");
      expect(init.body).toBe("{}");
      expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
        "application/json",
      );
      return jsonResponse(REPLAY_NONE_WIRE);
    });
    const client = makeClient(fetchImpl);
    const result = await client.replayDecision("dec_abc123");

    expect(result.decision_id).toBe("dec_abc123");
    expect(result.variance).toBe("NONE");
    expect(result.original_decision).toBe("allow");
    expect(result.replay_decision).toBe("allow");
    expect(result.engine_version_kind).toBe("active");
    expect(result.envelope_verification).toBe("verified");
    expect(result.rateLimit).toBeNull();
  });

  it("surfaces DECISION_CHANGED variance with both decisions for diagnosis", async () => {
    const wire = {
      ...REPLAY_NONE_WIRE,
      original_decision: "allow" as const,
      replay_decision: "deny" as const,
      replay_deny_code: "policy.expired_consent",
      variance: "DECISION_CHANGED" as const,
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.replayDecision("dec_abc123");

    expect(result.variance).toBe("DECISION_CHANGED");
    expect(result.original_decision).toBe("allow");
    expect(result.replay_decision).toBe("deny");
    expect(result.replay_deny_code).toBe("policy.expired_consent");
  });

  it("surfaces ENVELOPE_DRIFT with hashes and no replay_decision", async () => {
    const wire = {
      decision_id: "dec_abc123",
      original_decision: "allow" as const,
      engine_version: "wire-v1@1.0.0",
      engine_version_kind: "active" as const,
      accepts_replay: true,
      variance: "ENVELOPE_DRIFT" as const,
      envelope_verification: "drift" as const,
      envelope_drift_detail: {
        recorded_hash: "sha256:aaaa",
        recomputed_hash: "sha256:bbbb",
      },
      replayed_at: "2026-05-24T00:00:00Z",
    };
    const client = makeClient(mockFetch(() => jsonResponse(wire)));
    const result = await client.replayDecision("dec_abc123");

    expect(result.variance).toBe("ENVELOPE_DRIFT");
    expect(result.envelope_verification).toBe("drift");
    expect(result.envelope_drift_detail).toEqual({
      recorded_hash: "sha256:aaaa",
      recomputed_hash: "sha256:bbbb",
    });
    expect(result.replay_decision).toBeUndefined();
  });

  it("url-encodes the decision id", async () => {
    const fetchImpl = mockFetch((url) => {
      // ':' must be %3A in the path component.
      expect(url).toMatch(/\/v1-decisions-replay\/odd%3Aid\/replay$/);
      return jsonResponse({ ...REPLAY_NONE_WIRE, decision_id: "odd:id" });
    });
    const client = makeClient(fetchImpl);
    await client.replayDecision("odd:id");
  });

  it("rejects empty / non-string decisionId without issuing a request", async () => {
    const fetchImpl = mockFetch(() => {
      throw new Error("fetch should not be called");
    });
    const client = makeClient(fetchImpl);
    await expect(client.replayDecision("")).rejects.toMatchObject({
      code: "bad_request",
    });
    // @ts-expect-error — runtime guard for non-string input
    await expect(client.replayDecision(undefined)).rejects.toMatchObject({
      code: "bad_request",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("surfaces rateLimit when X-RateLimit-* headers are present", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response(JSON.stringify(REPLAY_NONE_WIRE), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "99",
            "X-RateLimit-Reset": "1714070000",
          },
        }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.replayDecision("dec_abc123");
    expect(result.rateLimit).toEqual({
      limit: 100,
      remaining: 99,
      resetAt: new Date(1_714_070_000 * 1000),
    });
  });

  it("throws bad_response when required fields are missing", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse({ decision_id: "dec_abc123" }),
    );
    const client = makeClient(fetchImpl);
    await expect(client.replayDecision("dec_abc123")).rejects.toMatchObject({
      code: "bad_response",
    });
  });

  it("surfaces 409 replay_not_eligible as an AtlaSentError", async () => {
    const fetchImpl = mockFetch(
      () =>
        new Response(
          JSON.stringify({
            error: "replay_not_eligible",
            message: "Engine version wire-v0@0.9.0 does not accept replay (kind: archival)",
          }),
          {
            status: 409,
            headers: { "Content-Type": "application/json" },
          },
        ),
    );
    const client = makeClient(fetchImpl);
    await expect(client.replayDecision("dec_abc123")).rejects.toBeInstanceOf(
      AtlaSentError,
    );
  });
});

describe("getLicense", () => {
  const LICENSE_WIRE = {
    status: "active",
    org_slug: "acme",
    posture: "self_hosted",
    expires_at: "2027-01-01T00:00:00Z",
    features: ["gxp", "sso"],
    eval_limit: 10_000,
    seat_limit: 50,
  };

  it("returns license status on success", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(LICENSE_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.getLicense();
    expect(result.status).toBe("active");
    expect(result.org_slug).toBe("acme");
    expect(result.features).toEqual(["gxp", "sso"]);
    expect(result.rateLimit).toBeNull();
  });

  it("hits GET /v1/license", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(LICENSE_WIRE));
    const client = makeClient(fetchImpl);
    await client.getLicense();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toContain("/v1/license");
    const method = (init as RequestInit).method;
    expect(method === undefined || method === "GET").toBe(true);
  });

  it("surfaces rate limit headers", async () => {
    const fetchImpl = mockFetch(() =>
      jsonResponse(LICENSE_WIRE, {
        headers: {
          "Content-Type": "application/json",
          "X-RateLimit-Limit": "100",
          "X-RateLimit-Remaining": "99",
          "X-RateLimit-Reset": "1714070000",
        },
      }),
    );
    const client = makeClient(fetchImpl);
    const result = await client.getLicense();
    expect(result.rateLimit).toEqual({
      limit: 100,
      remaining: 99,
      resetAt: new Date(1_714_070_000 * 1000),
    });
  });
});

describe("verifyLicense", () => {
  const VERIFY_VALID_WIRE = {
    valid: true,
    org_slug: "acme",
    expires_at: "2027-01-01T00:00:00Z",
  };

  const VERIFY_INVALID_WIRE = {
    valid: false,
    error: "SIGNATURE_INVALID",
  };

  it("returns valid:true on a good blob", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_VALID_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.verifyLicense("signed-blob-abc");
    expect(result.valid).toBe(true);
    expect(result.org_slug).toBe("acme");
    expect(result.rateLimit).toBeNull();
  });

  it("returns valid:false without throwing", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_INVALID_WIRE));
    const client = makeClient(fetchImpl);
    const result = await client.verifyLicense("bad-blob");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("SIGNATURE_INVALID");
  });

  it("throws bad_request when blob is empty", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_VALID_WIRE));
    const client = makeClient(fetchImpl);
    await expect(client.verifyLicense("")).rejects.toMatchObject({
      code: "bad_request",
    });
  });

  it("posts blob to /v1/license/verify", async () => {
    const fetchImpl = mockFetch(() => jsonResponse(VERIFY_VALID_WIRE));
    const client = makeClient(fetchImpl);
    await client.verifyLicense("my-signed-blob");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toContain("/v1/license/verify");
    expect((init as RequestInit).method).toBe("POST");
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.blob).toBe("my-signed-blob");
  });
});
