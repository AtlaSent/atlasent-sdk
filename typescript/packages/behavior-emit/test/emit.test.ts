import { createHmac } from "node:crypto";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  createBehaviorEmitter,
  BvsEmitError,
  assertNoRawText,
  RawTextLeakError,
} from "../src/index.js";
import type { BvsEpisodeEvent, BvsPracticeEvent } from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEpisodeEvent(overrides: Partial<BvsEpisodeEvent> = {}): BvsEpisodeEvent {
  return {
    kind: "episode",
    subject_id: "sub_abc",
    episode_id: "ep_123",
    captured_at: "2026-06-07T00:00:00Z",
    context_factors: [{ factor: "pressure", intensity: "medium" }],
    energy_level: "moderate",
    emotional_tone: "calm",
    ...overrides,
  };
}

function makePracticeEvent(overrides: Partial<BvsPracticeEvent> = {}): BvsPracticeEvent {
  return {
    kind: "practice",
    subject_id: "sub_abc",
    episode_id: "ep_123",
    captured_at: "2026-06-07T00:00:00Z",
    practice_id: "pr_1",
    status_from: null,
    status_to: "complete",
    duration_setting: "10m",
    ...overrides,
  };
}

function verifySignature(
  secret: string,
  timestamp: string,
  nonce: string,
  body: string,
  signature: string,
): boolean {
  const expected =
    "sha256=" +
    createHmac("sha256", secret)
      .update(`${timestamp}.${nonce}.${body}`)
      .digest("hex");
  return signature === expected;
}

// ---------------------------------------------------------------------------
// assertNoRawText — privacy guard
// ---------------------------------------------------------------------------

describe("assertNoRawText", () => {
  it("passes for an object with no raw-text fields", () => {
    expect(() => assertNoRawText({ kind: "episode", subject_id: "x" })).not.toThrow();
  });

  it("passes when raw-text field is empty string", () => {
    expect(() => assertNoRawText({ note: "" })).not.toThrow();
  });

  it("passes when raw-text field is null", () => {
    expect(() => assertNoRawText({ note: null })).not.toThrow();
  });

  it("passes when raw-text field is a number", () => {
    expect(() => assertNoRawText({ note: 42 })).not.toThrow();
  });

  it("passes for primitives and arrays at top level", () => {
    expect(() => assertNoRawText("hello")).not.toThrow();
    expect(() => assertNoRawText(123)).not.toThrow();
    expect(() => assertNoRawText(null)).not.toThrow();
    expect(() => assertNoRawText([{ note: "bad" }])).not.toThrow(); // arrays skipped at top
  });

  const rawTextFields = [
    "text",
    "note",
    "cue",
    "interpretation",
    "body",
    "content",
    "transcript",
    "message",
    "description",
    "comment",
    "narrative",
    "label",
    "reasoning",
    "rationale",
  ] as const;

  for (const field of rawTextFields) {
    it(`throws RawTextLeakError for field "${field}"`, () => {
      expect(() => assertNoRawText({ [field]: "some text" })).toThrow(RawTextLeakError);
    });

    it(`includes field name in error message for "${field}"`, () => {
      let err: RawTextLeakError | undefined;
      try {
        assertNoRawText({ [field]: "some text" });
      } catch (e) {
        err = e as RawTextLeakError;
      }
      expect(err).toBeInstanceOf(RawTextLeakError);
      expect(err!.field).toBe(field);
      expect(err!.message).toContain(`"${field}"`);
    });
  }

  it("throws for nested raw-text fields and includes dotted path", () => {
    let err: RawTextLeakError | undefined;
    try {
      assertNoRawText({ metadata: { note: "private" } });
    } catch (e) {
      err = e as RawTextLeakError;
    }
    expect(err).toBeInstanceOf(RawTextLeakError);
    expect(err!.field).toBe("metadata.note");
  });

  it("throws for deeply nested raw-text field", () => {
    expect(() =>
      assertNoRawText({ a: { b: { c: { text: "leak" } } } }),
    ).toThrow(RawTextLeakError);
  });
});

// ---------------------------------------------------------------------------
// BvsEmitError
// ---------------------------------------------------------------------------

describe("BvsEmitError", () => {
  it("exposes status and responseBody", () => {
    const err = new BvsEmitError(422, "unprocessable entity");
    expect(err.status).toBe(422);
    expect(err.responseBody).toBe("unprocessable entity");
    expect(err.name).toBe("BvsEmitError");
    expect(err.message).toContain("422");
  });

  it("truncates long responseBody in message but preserves full in property", () => {
    const longBody = "x".repeat(500);
    const err = new BvsEmitError(500, longBody);
    expect(err.responseBody).toHaveLength(500);
    expect(err.message.length).toBeLessThan(300);
  });
});

// ---------------------------------------------------------------------------
// createBehaviorEmitter
// ---------------------------------------------------------------------------

describe("createBehaviorEmitter", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.clearAllMocks();
  });

  function makeOkResponse(status = 200) {
    return {
      ok: true,
      status,
      text: () => Promise.resolve(""),
    } as unknown as Response;
  }

  function makeErrorResponse(status: number, body = "error") {
    return {
      ok: false,
      status,
      text: () => Promise.resolve(body),
    } as unknown as Response;
  }

  it("emits a valid episode event and returns ok result", async () => {
    fetchMock.mockResolvedValue(makeOkResponse(200));

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "test-secret",
    });

    const result = await emitter.emit("hiCoach", makeEpisodeEvent());
    expect(result).toEqual({ ok: true, status: 200 });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("emits a practice event successfully", async () => {
    fetchMock.mockResolvedValue(makeOkResponse(201));

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    const result = await emitter.emit("Echobloom", makePracticeEvent());
    expect(result).toEqual({ ok: true, status: 201 });
  });

  it("strips trailing slash from endpoint", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com/",
      hmacSecret: "secret",
    });

    await emitter.emit("CalmState", makeEpisodeEvent());

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://bvs.example.com/api/internal/CalmState/events");
    expect(url).not.toContain("//api");
  });

  it("builds correct URL using source as path segment", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("LedgersMe", makeEpisodeEvent());

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://bvs.example.com/api/internal/LedgersMe/events");
  });

  it("sets Content-Type application/json", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("includes X-Signature, X-Timestamp, X-Nonce headers", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;

    expect(headers["X-Signature"]).toBeDefined();
    expect(headers["X-Timestamp"]).toBeDefined();
    expect(headers["X-Nonce"]).toBeDefined();
  });

  it("signature has sha256= prefix", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  it("signature is a valid HMAC-SHA256 of timestamp.nonce.body", async () => {
    const secret = "my-hmac-secret";
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: secret,
    });

    await emitter.emit("FutureBloomPlanner", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    const sig = headers["X-Signature"]!;
    const ts = headers["X-Timestamp"]!;
    const nonce = headers["X-Nonce"]!;
    const body = init.body as string;

    expect(verifySignature(secret, ts, nonce, body, sig)).toBe(true);
  });

  it("timestamp is a unix second-level integer string", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    const before = Math.floor(Date.now() / 1000);
    await emitter.emit("hiCoach", makeEpisodeEvent());
    const after = Math.floor(Date.now() / 1000);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    const ts = Number(headers["X-Timestamp"]);
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(after);
  });

  it("nonce is a 32-character hex string", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Nonce"]).toMatch(/^[0-9a-f]{32}$/);
  });

  it("body includes source field merged with event", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = JSON.parse(init.body as string);
    expect(parsed.source).toBe("hiCoach");
    expect(parsed.kind).toBe("episode");
    expect(parsed.subject_id).toBe("sub_abc");
  });

  it("includes Authorization header when serviceToken is provided", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
      serviceToken: "tok_abc123",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer tok_abc123");
  });

  it("omits Authorization header when serviceToken is not provided", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("throws BvsEmitError on 4xx response", async () => {
    fetchMock.mockResolvedValue(makeErrorResponse(400, "bad request body"));

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await expect(emitter.emit("hiCoach", makeEpisodeEvent())).rejects.toThrow(BvsEmitError);
  });

  it("throws BvsEmitError on 5xx response with correct status", async () => {
    fetchMock.mockResolvedValue(makeErrorResponse(503, "unavailable"));

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    let err: BvsEmitError | undefined;
    try {
      await emitter.emit("hiCoach", makeEpisodeEvent());
    } catch (e) {
      err = e as BvsEmitError;
    }

    expect(err).toBeInstanceOf(BvsEmitError);
    expect(err!.status).toBe(503);
    expect(err!.responseBody).toBe("unavailable");
  });

  it("throws BvsEmitError with an empty body when reading the error body fails", async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 502,
      text: () => Promise.reject(new Error("body stream already read")),
    } as unknown as Response);

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    const err = await emitter.emit("hiCoach", makeEpisodeEvent()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BvsEmitError);
    expect((err as BvsEmitError).status).toBe(502);
    expect((err as BvsEmitError).responseBody).toBe("");
  });

  it("rejects before fetching when event contains raw text", async () => {
    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    const badEvent = makeEpisodeEvent();
    (badEvent as unknown as Record<string, unknown>)["note"] = "private journal entry";

    await expect(emitter.emit("hiCoach", badEvent)).rejects.toThrow(RawTextLeakError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses POST method", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("POST");
  });

  it("passes an AbortSignal to fetch", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
      timeoutMs: 5000,
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("aborts if fetch takes longer than timeoutMs", async () => {
    fetchMock.mockImplementation(
      (_url: string, opts: RequestInit) =>
        new Promise((_resolve, reject) => {
          opts.signal?.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          );
        }),
    );

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
      timeoutMs: 50,
    });

    await expect(emitter.emit("hiCoach", makeEpisodeEvent())).rejects.toThrow();
  });

  it("each emit produces a unique nonce", async () => {
    fetchMock.mockResolvedValue(makeOkResponse());

    const emitter = createBehaviorEmitter({
      endpoint: "https://bvs.example.com",
      hmacSecret: "secret",
    });

    await emitter.emit("hiCoach", makeEpisodeEvent());
    await emitter.emit("hiCoach", makeEpisodeEvent());

    const nonce1 = (fetchMock.mock.calls[0] as [string, RequestInit])[1].headers as Record<string, string>;
    const nonce2 = (fetchMock.mock.calls[1] as [string, RequestInit])[1].headers as Record<string, string>;
    expect(nonce1["X-Nonce"]!).not.toBe(nonce2["X-Nonce"]!);
  });
});
