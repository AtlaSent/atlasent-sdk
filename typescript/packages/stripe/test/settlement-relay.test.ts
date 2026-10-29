import { createHmac } from "node:crypto";
import { createServer, type IncomingMessage, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  createSettlementRelayHandler,
  relayStripeEvent,
  settlementIngestUrl,
  SETTLEMENT_RELAY_PATH,
  SettlementRelayConfigError,
  type SettlementRelayConfig,
} from "../src/settlement-relay.js";

const SECRET = "whsec_settlement_test";
const KEY = "ask_test_relay_key_do_not_log";
const CONNECTOR = "3f2b8c1e-5a6d-4e7f-9a0b-1c2d3e4f5a6b";
const NOW = new Date("2026-10-29T12:00:00Z");
const T = Math.floor(NOW.getTime() / 1000);
const sign = (body: string | Buffer, t = T, secret = SECRET) =>
  `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${typeof body === "string" ? body : body.toString("utf8")}`).digest("hex")}`;

// Whitespace and a multi-byte character: Stripe signs these exact bytes, so
// a relay that re-serializes or re-encodes the body breaks the signature.
const refundEvent = (type = "refund.updated", id = "evt_1Rel4y") =>
  `{\n  "id": "${id}",\n  "type": "${type}",\n  "livemode": false,\n  "data": {"object": {"object": "refund", "id": "re_1", "status": "succeeded", "amount": 1899, "currency": "usd", "metadata": {"atlasent_business_request": "RMA-7 café"}}}\n}`;

interface Captured {
  url: string;
  init: RequestInit;
}

function stubFetch(respond: (c: Captured) => Response | Promise<Response>): { fetch: typeof fetch; calls: Captured[] } {
  const calls: Captured[] = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    const c = { url: String(url), init: init ?? {} };
    calls.push(c);
    return respond(c);
  }) as typeof fetch;
  return { fetch: f, calls };
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function config(over: Partial<SettlementRelayConfig> = {}, lines: Record<string, unknown>[] = []): SettlementRelayConfig {
  return { webhookSecret: SECRET, apiKey: KEY, connectorId: CONNECTOR, now: () => NOW, log: (l) => lines.push(l), ...over };
}

async function relay(body: string, sig: string | undefined, respond: (c: Captured) => Response | Promise<Response>, over: Partial<SettlementRelayConfig> = {}) {
  const lines: Record<string, unknown>[] = [];
  const s = stubFetch(respond);
  const out = await relayStripeEvent(Buffer.from(body, "utf8"), sig, config({ fetch: s.fetch, ...over }, lines));
  return { out, calls: s.calls, lines };
}

describe("settlementIngestUrl", () => {
  it("builds the ingest URL on the hosted functions root", () => {
    expect(settlementIngestUrl(config())).toBe(`https://api.atlasent.io/functions/v1/v1-assertion-ingest/stripe?connector_id=${CONNECTOR}`);
    expect(settlementIngestUrl(config({ baseUrl: "https://api.atlasent.io/" }))).toBe(
      `https://api.atlasent.io/functions/v1/v1-assertion-ingest/stripe?connector_id=${CONNECTOR}`,
    );
    expect(settlementIngestUrl(config({ baseUrl: "https://atlasent.example.com/fn" }))).toBe(
      `https://atlasent.example.com/fn/v1-assertion-ingest/stripe?connector_id=${CONNECTOR}`,
    );
  });
  it("allows plain http only on loopback", () => {
    expect(settlementIngestUrl(config({ baseUrl: "http://localhost:54321/functions/v1" }))).toContain("http://localhost:54321/");
    expect(settlementIngestUrl(config({ baseUrl: "http://127.0.0.1:54321/functions/v1" }))).toContain("http://127.0.0.1:54321/");
    for (const baseUrl of ["http://api.atlasent.io/functions/v1", "http://10.0.0.5/functions/v1", "ftp://x/y", "not a url"]) {
      expect(() => settlementIngestUrl(config({ baseUrl }))).toThrow(SettlementRelayConfigError);
    }
  });
  it("refuses a base URL carrying a query, fragment or credentials", () => {
    for (const baseUrl of ["https://a.example/fn?x=1", "https://a.example/fn#f", "https://u:p@a.example/fn"]) {
      expect(() => settlementIngestUrl(config({ baseUrl }))).toThrow(SettlementRelayConfigError);
    }
  });
  it("refuses a missing secret, key or a connector id that is not a UUID", () => {
    expect(() => settlementIngestUrl(config({ webhookSecret: "" }))).toThrow(/signing secret/);
    expect(() => settlementIngestUrl(config({ apiKey: " " }))).toThrow(/assertions:write/);
    for (const connectorId of ["", "conn_1", `${CONNECTOR}&connector_id=other`, "../x"]) {
      expect(() => settlementIngestUrl(config({ connectorId }))).toThrow(/UUID/);
    }
  });
});

describe("relayStripeEvent: what reaches AtlaSent", () => {
  it("cancels an oversized streaming response before draining it and asks Stripe to retry", async () => {
    let pulls = 0;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++;
        controller.enqueue(new Uint8Array(10 * 1024));
        if (pulls === 20) controller.close();
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    const body = refundEvent();
    const { out } = await relay(body, sign(body), () => new Response(stream));
    expect(out.status).toBe(502);
    expect(out.body.retry).toBe(true);
    expect(cancelled).toBe(true);
    expect(pulls).toBe(7);
  });

  it("forwards the exact bytes and Stripe-Signature with the key, refusing redirects", async () => {
    const body = refundEvent();
    const sig = sign(body);
    const { out, calls } = await relay(body, sig, () => json(200, { refund_settlement: { disposition: "consumed", reservation_id: "r-1", settlement_id: "s-1" } }));
    expect(out).toEqual({ status: 200, body: { disposition: "consumed", reservation_id: "r-1" } });
    expect(calls).toHaveLength(1);
    const c = calls[0]!;
    expect(c.url).toBe(`https://api.atlasent.io/functions/v1/v1-assertion-ingest/stripe?connector_id=${CONNECTOR}`);
    expect(c.init.method).toBe("POST");
    expect(c.init.redirect).toBe("error");
    const h = c.init.headers as Record<string, string>;
    expect(h.authorization).toBe(`Bearer ${KEY}`);
    expect(h["stripe-signature"]).toBe(sig);
    expect(h["content-type"]).toBe("application/json");
    expect(Buffer.from(c.init.body as Uint8Array).equals(Buffer.from(body, "utf8"))).toBe(true);
    expect(c.init.signal).toBeInstanceOf(AbortSignal);
  });

  it("forwards every refund event type Stripe can settle from", async () => {
    for (const type of ["refund.created", "refund.updated", "refund.failed", "charge.refund.updated"]) {
      const body = refundEvent(type);
      const { out, calls } = await relay(body, sign(body), () => json(200, { refund_settlement: { disposition: "not_terminal", provider_status: "pending" } }));
      expect(calls, type).toHaveLength(1);
      expect(out.status, type).toBe(200);
    }
  });

  it("refuses a delivery whose signature does not verify here, without calling AtlaSent", async () => {
    const body = refundEvent();
    for (const sig of [undefined, "", sign(body, T, "whsec_other"), sign(body, T - 301), sign(`${body} `)]) {
      const { out, calls } = await relay(body, sig, () => json(200, { refund_settlement: { disposition: "consumed" } }));
      expect(out.status).toBe(400);
      expect(calls).toHaveLength(0);
    }
  });

  it("acknowledges an event that is not a refund without forwarding it", async () => {
    const body = JSON.stringify({ id: "evt_2", type: "customer.subscription.updated", data: { object: {} } });
    const { out, calls } = await relay(body, sign(body), () => json(200, {}));
    expect(out).toEqual({ status: 200, body: { ignored: true, reason: "not a refund event" } });
    expect(calls).toHaveLength(0);
  });

  it("refuses a signed body that is not an event", async () => {
    for (const body of ["not json", "[]", "null", JSON.stringify({ id: "evt_3" })]) {
      const { out, calls } = await relay(body, sign(body), () => json(200, {}));
      expect(out.status, body).toBe(400);
      expect(calls).toHaveLength(0);
    }
  });

  it("refuses everything when misconfigured", async () => {
    const body = refundEvent();
    const { out, calls } = await relay(body, sign(body), () => json(200, {}), { baseUrl: "http://evil.example/fn" });
    expect(out.status).toBe(500);
    expect(calls).toHaveLength(0);
  });
});

describe("relayStripeEvent: what Stripe is told", () => {
  const body = refundEvent();

  it("answers 200 for every outcome AtlaSent recorded", async () => {
    for (const disposition of ["consumed", "released", "not_terminal", "duplicate_event", "already_settled"]) {
      const { out } = await relay(body, sign(body), () => json(200, { refund_settlement: { disposition } }));
      expect(out.status, disposition).toBe(200);
      expect(out.body.disposition).toBe(disposition);
    }
  });

  it("answers 200 for a refusal, with the reason, since a redelivery would be refused again", async () => {
    const { out, lines } = await relay(body, sign(body), () => json(200, { refund_settlement: { disposition: "refused", reason: "source_not_bound" } }));
    expect(out).toEqual({ status: 200, body: { disposition: "refused", reason: "source_not_bound" } });
    expect(lines.at(-1)).toMatchObject({ outcome: "refused", reason: "source_not_bound", stripe_event_id: "evt_1Rel4y" });
  });

  it("answers non-2xx when AtlaSent accepted the bytes but did not verify them under the connector", async () => {
    // e.g. a wrong connector id, or this endpoint's secret differs from the one enrolled.
    for (const reply of [{ ok: true }, { refund_settlement: null }, { refund_settlement: {} }, { refund_settlement: { disposition: 7 } }]) {
      const { out } = await relay(body, sign(body), () => json(200, reply));
      expect(out.status).toBe(502);
      expect(out.body.error).toBe("not_verified_by_connector");
    }
  });

  it("answers non-2xx for a disposition that recorded nothing", async () => {
    for (const disposition of ["unavailable", "settled_maybe", ""]) {
      const { out } = await relay(body, sign(body), () => json(200, { refund_settlement: { disposition } }));
      expect(out.status, disposition).toBe(502);
    }
  });

  it("answers non-2xx for every non-2xx from AtlaSent, passing 503 through", async () => {
    const { out: unavailable } = await relay(body, sign(body), () => json(503, { error: "refund_settlement_unavailable" }));
    expect(unavailable.status).toBe(503);
    for (const status of [301, 400, 401, 403, 404, 429, 500, 502]) {
      const { out } = await relay(body, sign(body), () => json(status, { error: "x" }));
      expect(out.status, String(status)).toBe(502);
      expect(out.body.upstream_status).toBe(status);
    }
  });

  it("answers 503 when AtlaSent is unreachable or slow", async () => {
    const { out: down } = await relay(body, sign(body), () => {
      throw new TypeError("fetch failed");
    });
    expect(down.status).toBe(503);
    const { out: slow } = await relay(
      body,
      sign(body),
      (c) =>
        new Promise<Response>((_, reject) => {
          c.init.signal!.addEventListener("abort", () => reject(c.init.signal!.reason));
        }),
      { timeoutMs: 20 },
    );
    expect(slow.status).toBe(503);
  });

  it("answers non-2xx for an unreadable or oversized 2xx response", async () => {
    // The oversized one carries a valid outcome: only the size limit refuses it.
    const padded = JSON.stringify({ refund_settlement: { disposition: "consumed" }, pad: "x".repeat(70_000) });
    for (const make of [() => new Response("<html>", { status: 200 }), () => new Response(padded, { status: 200 })]) {
      const { out } = await relay(body, sign(body), make);
      expect(out.status).toBe(502);
    }
  });

  it("never logs the key, the signature or the body", async () => {
    const sig = sign(body);
    const all: Record<string, unknown>[] = [];
    for (const respond of [
      () => json(200, { refund_settlement: { disposition: "consumed" } }),
      () => json(401, { error: "unauthorized" }),
      () => {
        throw new Error(`boom ${KEY}`);
      },
    ]) {
      const { lines } = await relay(body, sig, respond);
      all.push(...lines);
    }
    await relay(body, undefined, () => json(200, {})).then((r) => all.push(...r.lines));
    const text = JSON.stringify(all);
    expect(all.length).toBeGreaterThanOrEqual(4);
    expect(text).not.toContain(KEY);
    expect(text).not.toContain(sig.split("v1=")[1]!);
    expect(text).not.toContain("RMA-7");
  });
});

describe("createSettlementRelayHandler over real sockets", () => {
  const servers: Server[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
  });
  const listen = async (handler: RequestListener): Promise<string> => {
    const s = createServer(handler);
    servers.push(s);
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
    return `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
  };
  const readAll = async (req: IncomingMessage) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    return Buffer.concat(chunks);
  };

  it("carries Stripe's bytes to ingest unchanged and answers Stripe with the outcome", async () => {
    const seen: { path: string; headers: IncomingMessage["headers"]; body: Buffer }[] = [];
    const ingest = await listen(async (req, res) => {
      seen.push({ path: req.url ?? "", headers: req.headers, body: await readAll(req) });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, refund_settlement: { disposition: "released", reservation_id: "r-9" } }));
    });
    const relayUrl = await listen(createSettlementRelayHandler(config({ baseUrl: `${ingest}/functions/v1`, log: () => {} })));
    const body = refundEvent("refund.failed");
    const sig = sign(body);
    const r = await fetch(`${relayUrl}${SETTLEMENT_RELAY_PATH}`, { method: "POST", headers: { "stripe-signature": sig, "content-type": "application/json" }, body });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ disposition: "released", reservation_id: "r-9" });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.path).toBe(`/functions/v1/v1-assertion-ingest/stripe?connector_id=${CONNECTOR}`);
    expect(seen[0]!.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(seen[0]!.headers["stripe-signature"]).toBe(sig);
    expect(seen[0]!.body.equals(Buffer.from(body, "utf8"))).toBe(true);
  });

  it("answers 413, 404 and /healthz without calling AtlaSent", async () => {
    let called = 0;
    const ingest = await listen((_req, res) => {
      called++;
      res.end("{}");
    });
    const relayUrl = await listen(createSettlementRelayHandler(config({ baseUrl: `${ingest}/functions/v1`, log: () => {} })));
    const big = await fetch(`${relayUrl}${SETTLEMENT_RELAY_PATH}`, { method: "POST", body: "x".repeat(256 * 1024 + 1) });
    expect(big.status).toBe(413);
    expect((await fetch(`${relayUrl}/webhooks/stripe`, { method: "POST", body: "{}" })).status).toBe(404);
    expect((await fetch(`${relayUrl}${SETTLEMENT_RELAY_PATH}`)).status).toBe(404);
    expect((await fetch(`${relayUrl}/healthz`)).status).toBe(200);
    expect(called).toBe(0);
  });

  it("refuses to start with a plaintext non-loopback base URL", () => {
    expect(() => createSettlementRelayHandler(config({ baseUrl: "http://api.atlasent.io" }))).toThrow(SettlementRelayConfigError);
  });
});

