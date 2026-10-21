/**
 * The Stripe and Shopify packages write the evidence log themselves
 * (EVIDENCE_LOG; see each package's src/evidence-log.ts) so they install
 * without this package. These tests keep their record definitions and this
 * package's parser from drifting apart.
 */

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { alarmRecord, appendEvidence } from "../../stripe/src/evidence-log.js";
import { alarmRecord as shopifyAlarmRecord } from "../../shopify/src/evidence-log.js";
import { asRecord, parseLog } from "../src/records.js";
import { buildEvidenceReport } from "../src/report.js";

const NOW = new Date("2026-10-21T12:00:00Z");
const refund = { id: "re_1", status: "succeeded", amount: 8500, currency: "usd", charge: "ch_1", payment_intent: "pi_2002", metadata: {} };

describe("the Stripe and Shopify packages' evidence logs", () => {
  it("every alarm verdict it writes is a record the report accepts", () => {
    const records = [
      alarmRecord({ verdict: "authorized", refundId: "re_1", paymentIntent: "pi_1", amountCents: 1899, gateRef: "g" }, refund, NOW),
      alarmRecord({ verdict: "unauthorized", refundId: "re_2", paymentIntent: "pi_2002", amountCents: 8500, reason: "no gate reference" }, refund, NOW),
      alarmRecord({ verdict: "ignored", refundId: "re_3", reason: "refund status failed" }, refund, NOW),
    ];
    for (const r of records) expect(asRecord(JSON.parse(JSON.stringify(r)))).not.toBeNull();
  });

  it("every Shopify alarm verdict is a record the report accepts", () => {
    const p = { id: 1, order_id: 2, transactions: [{ kind: "refund", amount: "18.99", currency: "USD" }] };
    for (const r of [
      shopifyAlarmRecord({ verdict: "authorized", refundId: "1", orderId: "2", amountCents: 1899, gateRef: "g" }, p, NOW),
      shopifyAlarmRecord({ verdict: "unauthorized", refundId: "1", orderId: "2", amountCents: null, reason: "no gate reference" }, p, NOW),
    ]) {
      expect(asRecord(JSON.parse(JSON.stringify(r)))).not.toBeNull();
    }
  });

  it("a log written by the CLI and the alarm builds the report", () => {
    const path = join(mkdtempSync(join(tmpdir(), "log-")), "evidence.jsonl");
    appendEvidence(path, {
      schema: "atlasent.refund_decision.v1",
      at: NOW.toISOString(),
      system: "stripe",
      gate_ref: "g",
      actor: "stripe-cli:t",
      environment: "test",
      target: "pi_1",
      order_ref: "PPS-S101",
      amount_cents: 1899,
      currency: "USD",
      outcome: "refunded",
      decision: "allow",
      deny_code: null,
      reason: "within policy",
      audit_hash: "audit-1",
      refund_id: "re_1",
      order_status: "delivered",
      days_since_delivery: 5,
      approval_request_id: null,
    });
    appendEvidence(path, alarmRecord({ verdict: "unauthorized", refundId: "re_2", paymentIntent: "pi_2002", amountCents: 8500, reason: "no gate reference" }, refund, NOW));
    const log = parseLog(readFileSync(path, "utf8"));
    expect(log.rejectedLines).toEqual([]);
    const report = buildEvidenceReport({ decisions: log.decisions, alarms: log.alarms, storeName: "Pinecone Pet Supply (fictional)", generatedAt: NOW });
    expect(report.summary).toMatchObject({ refunded: { count: 1 }, outsideGate: { count: 1, cents: { USD: 8500 } } });
  });
});
