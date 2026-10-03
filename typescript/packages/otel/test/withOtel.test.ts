/**
 * Tests for the OpenTelemetry adapter.
 *
 * Strategy: a real OTel `BasicTracerProvider` with an in-memory
 * exporter. Lets us assert span name, attributes, status, recorded
 * exceptions — the same way customer apps will inspect spans in
 * production exporters.
 *
 * `AtlaSentClient` is stubbed via a hand-rolled fake (no `vi.mock`
 * needed) so the tests focus on the wrapper's instrumentation
 * behavior, not v1's internals.
 */

import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-base";
import { SpanStatusCode } from "@opentelemetry/api";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { withOtel, wrapProtect } from "../src/withOtel.js";
import type { AtlaSentClient } from "@atlasent/sdk";

// ── Fake AtlaSentClient ─────────────────────────────────────────────


function fakeClient(impl: Partial<AtlaSentClient>): AtlaSentClient {
  return impl as AtlaSentClient;
}

// ── Tracer fixture ───────────────────────────────────────────────────


let exporter: InMemorySpanExporter;
let provider: BasicTracerProvider;

beforeEach(() => {
  exporter = new InMemorySpanExporter();
  // sdk-trace-base 2.x removed `addSpanProcessor`; processors are
  // passed to the constructor instead.
  provider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
});

afterEach(async () => {
  await provider.shutdown();
});

function tracer() {
  return provider.getTracer("test");
}

function spans(): ReadableSpan[] {
  return exporter.getFinishedSpans();
}

// ── evaluate ─────────────────────────────────────────────────────────


describe("withOtel — evaluate", () => {
  it("creates a span with agent + action attributes pre-call", async () => {
    const client = withOtel(
      fakeClient({
        evaluate: async () => ({
          decision: "ALLOW",
          permitId: "dec_abc",
          reason: "ok",
          auditHash: "h".repeat(64),
          timestamp: "t",
          rateLimit: null,
        }),
      }),
      { tracer: tracer() },
    );

    await client.evaluate({ agent: "deploy-bot", action: "deploy" });

    const [span] = spans();
    expect(span?.name).toBe("atlasent.evaluate");
    expect(span?.attributes["atlasent.agent"]).toBe("deploy-bot");
    expect(span?.attributes["atlasent.action"]).toBe("deploy");
    expect(span?.attributes["atlasent.decision"]).toBe("ALLOW");
    expect(span?.attributes["atlasent.permit_id"]).toBe("dec_abc");
    expect(span?.attributes["atlasent.audit_hash"]).toBe("h".repeat(64));
    expect(span?.status.code).toBe(SpanStatusCode.OK);
  });

  it("records error + exception on throw", async () => {
    class MockError extends Error {
      code = "rate_limited";
      requestId = "req_1";
    }
    const client = withOtel(
      fakeClient({
        evaluate: async () => {
          throw new MockError("rate limited");
        },
      }),
      { tracer: tracer() },
    );

    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toThrow("rate limited");

    const [span] = spans();
    expect(span?.status.code).toBe(SpanStatusCode.ERROR);
    expect(span?.status.message).toBe("rate limited");
    expect(span?.attributes["atlasent.error_code"]).toBe("rate_limited");
    expect(span?.attributes["atlasent.request_id"]).toBe("req_1");
    expect(span?.events.some((e) => e.name === "exception")).toBe(true);
  });
});

// ── verifyPermit ─────────────────────────────────────────────────────


describe("withOtel — verifyPermit", () => {
  it("creates a span with permit_id attribute", async () => {
    const client = withOtel(
      fakeClient({
        verifyPermit: async () => ({
          verified: true,
          outcome: "ok",
          permitHash: "ph",
          timestamp: "t",
          rateLimit: null,
        }),
      }),
      { tracer: tracer() },
    );

    await client.verifyPermit({ permitId: "dec_abc" });

    const [span] = spans();
    expect(span?.name).toBe("atlasent.verify_permit");
    expect(span?.attributes["atlasent.permit_id"]).toBe("dec_abc");
    expect(span?.attributes["atlasent.verified"]).toBe(true);
  });

  it("records false verification (still status OK)", async () => {
    const client = withOtel(
      fakeClient({
        verifyPermit: async () => ({
          verified: false,
          outcome: "expired",
          permitHash: "",
          timestamp: "t",
          rateLimit: null,
        }),
      }),
      { tracer: tracer() },
    );

    await client.verifyPermit({ permitId: "dec_abc" });

    const [span] = spans();
    expect(span?.attributes["atlasent.verified"]).toBe(false);
    expect(span?.status.code).toBe(SpanStatusCode.OK);
  });
});

// ── keySelf ──────────────────────────────────────────────────────────


describe("withOtel — keySelf", () => {
  it("creates a span with key_id + environment attributes", async () => {
    const client = withOtel(
      fakeClient({
        keySelf: async () => ({
          keyId: "k1",
          orgId: "org-1",
          environment: "live",
          scopes: ["evaluate"],
          allowedCidrs: null,
          rateLimitPerMinute: 1000,
          clientIp: null,
          expiresAt: null,
          rateLimit: null,
        }),
      }),
      { tracer: tracer() },
    );

    await client.keySelf();

    const [span] = spans();
    expect(span?.name).toBe("atlasent.key_self");
    expect(span?.attributes["atlasent.key_id"]).toBe("k1");
    expect(span?.attributes["atlasent.environment"]).toBe("live");
  });
});

// ── audit listing + export ──────────────────────────────────────────


describe("withOtel — listAuditEvents + createAuditExport", () => {
  it("listAuditEvents records event count", async () => {
    const client = withOtel(
      fakeClient({
        listAuditEvents: async () => ({
          events: [{ id: "e1" }, { id: "e2" }, { id: "e3" }] as never[],
          total: 3,
          rateLimit: null,
        }),
      }),
      { tracer: tracer() },
    );

    await client.listAuditEvents();

    const [span] = spans();
    expect(span?.name).toBe("atlasent.list_audit_events");
    expect(span?.attributes["atlasent.event_count"]).toBe(3);
  });

  it("createAuditExport records export_id + event count", async () => {
    const client = withOtel(
      fakeClient({
        createAuditExport: async () => ({
          export_id: "ex1",
          events: [{ id: "e1" }] as never[],
          rateLimit: null,
        } as never),
      }),
      { tracer: tracer() },
    );

    await client.createAuditExport();

    const [span] = spans();
    expect(span?.name).toBe("atlasent.create_audit_export");
    expect(span?.attributes["atlasent.export_id"]).toBe("ex1");
    expect(span?.attributes["atlasent.event_count"]).toBe(1);
  });
});

// ── Base attributes + prefix ─────────────────────────────────────────


describe("withOtel — options", () => {
  it("merges base attributes onto every span", async () => {
    const client = withOtel(
      fakeClient({
        evaluate: async () => ({
          decision: "ALLOW",
          permitId: "p",
          reason: "",
          auditHash: "",
          timestamp: "",
          rateLimit: null,
        }),
      }),
      {
        tracer: tracer(),
        attributes: {
          "service.name": "deploy-bot",
          "deployment.environment": "prod",
        },
      },
    );

    await client.evaluate({ agent: "a", action: "b" });

    const [span] = spans();
    expect(span?.attributes["service.name"]).toBe("deploy-bot");
    expect(span?.attributes["deployment.environment"]).toBe("prod");
    expect(span?.attributes["atlasent.agent"]).toBe("a");
  });

  it("respects a custom span-name prefix", async () => {
    const client = withOtel(
      fakeClient({
        keySelf: async () => ({
          keyId: "k",
          orgId: "o",
          environment: "test",
          scopes: [],
          allowedCidrs: null,
          rateLimitPerMinute: 60,
          clientIp: null,
          expiresAt: null,
          rateLimit: null,
        }),
      }),
      { tracer: tracer(), spanNamePrefix: "my-svc.atlasent." },
    );

    await client.keySelf();
    const [span] = spans();
    expect(span?.name).toBe("my-svc.atlasent.key_self");
  });
});

// ── wrapProtect (top-level fn) ──────────────────────────────────────


describe("wrapProtect", () => {
  it("creates a span with agent + action and records permit_id", async () => {
    const protect = async (input: { agent: string; action: string }) => ({
      permit_id: "permit-1",
      audit_hash: "h",
      ignored: input,
    });

    const wrapped = wrapProtect({ tracer: tracer(), protect });
    const result = await wrapped({ agent: "deploy-bot", action: "deploy" });

    expect(result.permit_id).toBe("permit-1");

    const [span] = spans();
    expect(span?.name).toBe("atlasent.protect");
    expect(span?.attributes["atlasent.agent"]).toBe("deploy-bot");
    expect(span?.attributes["atlasent.action"]).toBe("deploy");
    expect(span?.attributes["atlasent.permit_id"]).toBe("permit-1");
    expect(span?.attributes["atlasent.audit_hash"]).toBe("h");
  });

  it("records ERROR status when protect() throws", async () => {
    const protect = async () => {
      throw new Error("denied");
    };

    const wrapped = wrapProtect({ tracer: tracer(), protect });
    await expect(
      wrapped({ agent: "a", action: "b" }),
    ).rejects.toThrow("denied");

    const [span] = spans();
    expect(span?.status.code).toBe(SpanStatusCode.ERROR);
    expect(span?.status.message).toBe("denied");
  });

  it("handles non-object protect() return values without crashing", async () => {
    const protect = async () => null;
    const wrapped = wrapProtect({
      tracer: tracer(),
      protect: protect as never,
    });
    await wrapped({ agent: "a", action: "b" });
    // No assertions on permit_id since the return shape doesn't have one;
    // just confirm we didn't throw setting attributes.
    const [span] = spans();
    expect(span?.attributes["atlasent.permit_id"]).toBeUndefined();
  });
});

// ── Non-Error throw values ──────────────────────────────────────────


describe("withOtel — non-Error throws", () => {
  it("records a string throw without exploding", async () => {
    const client = withOtel(
      fakeClient({
        evaluate: async () => {
          throw "string error"; // eslint-disable-line @typescript-eslint/no-throw-literal
        },
      }),
      { tracer: tracer() },
    );

    await expect(
      client.evaluate({ agent: "a", action: "b" }),
    ).rejects.toBe("string error");

    const [span] = spans();
    expect(span?.status.code).toBe(SpanStatusCode.ERROR);
    expect(span?.status.message).toBe("string error");
    // No exception event recorded for non-Error throws.
    expect(span?.events.some((e) => e.name === "exception")).toBe(false);
  });
});
