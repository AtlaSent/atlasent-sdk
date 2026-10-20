import { describe, expect, it } from "vitest";
import { parseLog, REFUND_ALARM_SCHEMA, REFUND_DECISION_SCHEMA, type RefundAlarmRecord, type RefundDecisionRecord } from "../src/records.js";
import { buildEvidenceReport, csvCell, escapeHtml, formatMoney } from "../src/report.js";

const decision = (over: Partial<RefundDecisionRecord> = {}): RefundDecisionRecord => ({
  schema: REFUND_DECISION_SCHEMA,
  at: "2026-10-15T10:00:00.000Z",
  system: "shopify",
  gate_ref: "g-1",
  actor: "shopify-staff:s/1",
  environment: "test",
  target: "gid://shopify/Order/1001",
  order_ref: "#PPS-1001",
  amount_cents: 1899,
  currency: "USD",
  outcome: "refunded",
  decision: "allow",
  deny_code: null,
  reason: "within policy",
  audit_hash: "audit-1",
  refund_id: "gid://shopify/Refund/1",
  order_status: "delivered",
  days_since_delivery: 5,
  ...over,
});

const alarm = (over: Partial<RefundAlarmRecord> = {}): RefundAlarmRecord => ({
  schema: REFUND_ALARM_SCHEMA,
  at: "2026-10-15T11:00:00.000Z",
  system: "stripe",
  refund_id: "re_1",
  target: "pi_1",
  amount_cents: 8500,
  currency: "USD",
  verdict: "unauthorized",
  reason: "the refund carries no AtlaSent gate reference",
  gate_ref: null,
  ...over,
});

const build = (decisions: RefundDecisionRecord[], alarms: RefundAlarmRecord[] = [], extra = {}) =>
  buildEvidenceReport({ decisions, alarms, storeName: "Pinecone", generatedAt: new Date("2026-10-20T12:00:00Z"), ...extra });

describe("summary", () => {
  it("totals by outcome and counts refunds made outside the gate", () => {
    const r = build(
      [
        decision(),
        decision({ gate_ref: "g-2", outcome: "escalated", decision: "escalate", deny_code: "MANAGER_APPROVAL_REQUIRED", amount_cents: 7200, refund_id: null }),
        decision({ gate_ref: "g-3", outcome: "denied", decision: "deny", deny_code: "ORDER_NOT_DELIVERED", amount_cents: 1200, refund_id: null }),
        decision({ gate_ref: "g-4", outcome: "refused", decision: "invalid_request", amount_cents: null, audit_hash: null, refund_id: null }),
        decision({ gate_ref: "g-5", outcome: "stopped", decision: "verify_failed", amount_cents: 500, refund_id: null }),
      ],
      [alarm(), alarm({ refund_id: "re_2", verdict: "authorized", reason: null }), alarm({ refund_id: "re_3", verdict: "ignored" })],
    );
    expect(r.summary).toMatchObject({
      decisions: 5,
      refunded: { count: 1, cents: { USD: 1899 } },
      escalated: { count: 1, cents: { USD: 7200 } },
      declined: { count: 2, cents: { USD: 1200 } },
      stopped: { count: 1, cents: { USD: 500 } },
      outsideGate: { count: 1, cents: { USD: 8500 } },
      alarmAccountedFor: 1,
    });
  });

  it("never adds different currencies together", () => {
    const r = build([decision(), decision({ gate_ref: "g-2", currency: "EUR", amount_cents: 1000 })]);
    expect(r.summary.refunded.cents).toEqual({ USD: 1899, EUR: 1000 });
    expect(r.html).toContain("$18.99 + EUR 10.00");
  });

  it("filters to the period, start inclusive, end exclusive", () => {
    const r = build(
      [decision({ at: "2026-09-30T23:59:59Z" }), decision({ gate_ref: "a", at: "2026-10-01T00:00:00Z" }), decision({ gate_ref: "b", at: "2026-11-01T00:00:00Z" })],
      [],
      { period: { from: new Date("2026-10-01T00:00:00Z"), to: new Date("2026-11-01T00:00:00Z") } },
    );
    expect(r.summary.decisions).toBe(1);
    expect(r.html).toContain("Period: 2026-10-01 to 2026-10-31");
  });
});

describe("what the page says on its face", () => {
  it("marks simulated data, and says nothing about simulation when it is not", () => {
    expect(build([decision()], [], { simulated: { stores: true, decisions: true } }).html).toMatch(/SIMULATED DATA.*audit references are placeholders/s);
    expect(build([decision()], [], { simulated: { stores: true, decisions: false } }).html).toMatch(/Decisions came from the AtlaSent runtime/);
    expect(build([decision()]).html).not.toContain("SIMULATED");
  });

  it("says the report is not itself signed and points to the signed export", () => {
    const html = build([decision()]).html;
    expect(html).toContain("It is not itself a signed record.");
    expect(html).toContain("signed audit export");
  });

  it("highlights refunds made outside the gate, or says there were none", () => {
    expect(build([decision()], [alarm()]).html).toContain('class="tile alert"');
    const quiet = build([decision()], [alarm({ verdict: "authorized", reason: null })]).html;
    expect(quiet).not.toContain('class="tile alert"');
    expect(quiet).toContain("None. 1 refund(s) reported by the platforms were all matched to a permit.");
  });

  it("lists rejected log lines instead of dropping them", () => {
    expect(build([decision()], [], { rejectedLines: [3, 7] }).html).toContain("2 log line(s) were not a recognised record");
  });

  it("shows policy codes in plain words, keeping the code", () => {
    const html = build([decision({ outcome: "escalated", decision: "escalate", deny_code: "MANAGER_APPROVAL_REQUIRED", refund_id: null })]).html;
    expect(html).toContain("$50 or more needs a manager (MANAGER_APPROVAL_REQUIRED)");
  });
});

describe("hostile values", () => {
  const evil = '<img src=x onerror="alert(1)">';
  it("escapes every value in the HTML", () => {
    const r = build([decision({ reason: evil, actor: evil, order_ref: evil, deny_code: evil, outcome: "denied", decision: "deny" })], [alarm({ reason: evil, refund_id: evil })], { storeName: evil });
    expect(r.html).not.toContain("<img");
    expect(r.html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(r.html).not.toMatch(/<script/i);
  });

  it("neutralises spreadsheet formulas in the CSV", () => {
    for (const v of ["=HYPERLINK(\"x\")", "+1", "-1+2", "@SUM(A1)", "\tx"]) expect(csvCell(v).replace(/^"/, "").startsWith("'")).toBe(true);
    const csv = build([decision({ reason: "=cmd|'/c calc'!A1", outcome: "denied", decision: "deny" })]).csv;
    expect(csv).toContain("'=cmd|'/c calc'!A1");
  });

  it("quotes commas, quotes and newlines in the CSV", () => {
    expect(csvCell('a,b "c"\nd')).toBe('"a,b ""c""\nd"');
    expect(csvCell(null)).toBe("");
    expect(escapeHtml(`'"&<>`)).toBe("&#39;&quot;&amp;&lt;&gt;");
  });
});

describe("CSV", () => {
  it("one header, one row per decision and per refund outside the gate", () => {
    const lines = build([decision(), decision({ gate_ref: "g-2" })], [alarm(), alarm({ verdict: "authorized", refund_id: "re_2" })]).csv.trim().split("\n");
    expect(lines[0]).toBe("type,at,system,order_or_payment,order_ref,amount,currency,outcome,rule,reason,requested_by,audit_reference,gate_reference,refund_id");
    expect(lines).toHaveLength(4);
    expect(lines[1]).toContain("decision,2026-10-15T10:00:00.000Z,shopify,gid://shopify/Order/1001,#PPS-1001,18.99,USD,Refunded,Within policy");
    expect(lines[3]).toMatch(/^refund_outside_gate,/);
  });
});

describe("parseLog", () => {
  it("keeps known records and reports every other line by number", () => {
    const text = [JSON.stringify(decision()), "not json", JSON.stringify({ schema: "something.else" }), "", JSON.stringify(alarm()), JSON.stringify({ ...decision(), outcome: "maybe" }), JSON.stringify({ ...alarm(), amount_cents: "85" })].join("\n");
    const p = parseLog(text);
    expect(p.decisions).toHaveLength(1);
    expect(p.alarms).toHaveLength(1);
    expect(p.rejectedLines).toEqual([2, 3, 6, 7]);
  });
});

describe("formatMoney", () => {
  it("formats cents without floating point", () => {
    expect(formatMoney(123456, "USD")).toBe("$1,234.56");
    expect(formatMoney(5, "USD")).toBe("$0.05");
    expect(formatMoney(null, "USD")).toBe("unknown");
    expect(formatMoney(1000, "EUR")).toBe("EUR 10.00");
  });
});
