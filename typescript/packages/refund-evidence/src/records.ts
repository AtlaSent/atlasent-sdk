/**
 * The two record formats the evidence report reads, and a JSONL log for them.
 *
 * `atlasent.refund_decision.v1` is written by the Shopify and Stripe gates
 * through their `onDecision` hook (each package carries the same
 * definition; see its `decision-record.ts`). `atlasent.refund_alarm.v1` is
 * one verdict of a refund webhook alarm. The report depends on these
 * formats, not on the gate packages.
 */

import { appendFileSync, existsSync, readFileSync } from "node:fs";

export const REFUND_DECISION_SCHEMA = "atlasent.refund_decision.v1" as const;
export const REFUND_ALARM_SCHEMA = "atlasent.refund_alarm.v1" as const;

/** `unconfirmed`: submitted, processor outcome not yet confirmed. Never counted as refunded or as nothing refunded. */
export type RefundOutcome = "refunded" | "escalated" | "held" | "denied" | "stopped" | "refused" | "unconfirmed";

export interface RefundDecisionRecord {
  schema: typeof REFUND_DECISION_SCHEMA;
  at: string;
  system: "shopify" | "stripe";
  gate_ref: string;
  actor: string;
  environment: string;
  target: string;
  order_ref: string | null;
  amount_cents: number | null;
  currency: string | null;
  outcome: RefundOutcome;
  decision: string;
  deny_code: string | null;
  reason: string;
  audit_hash: string | null;
  refund_id: string | null;
  order_status: string | null;
  days_since_delivery: number | null;
  /** The approval request behind an escalation, or behind a refund a manager approved. Absent in older records. */
  approval_request_id?: string | null;
}

export interface RefundAlarmRecord {
  schema: typeof REFUND_ALARM_SCHEMA;
  at: string;
  system: "shopify" | "stripe";
  refund_id: string;
  /** Order id (Shopify) or PaymentIntent id (Stripe), as the webhook reported it. */
  target: string | null;
  amount_cents: number | null;
  currency: string | null;
  verdict: "authorized" | "unauthorized" | "ignored";
  reason: string | null;
  gate_ref: string | null;
}

export type EvidenceRecord = RefundDecisionRecord | RefundAlarmRecord;

const OUTCOMES = new Set(["refunded", "escalated", "held", "denied", "stopped", "refused", "unconfirmed"]);
const VERDICTS = new Set(["authorized", "unauthorized", "ignored"]);
const isStr = (v: unknown): v is string => typeof v === "string";
const strOrNull = (v: unknown) => v === null || typeof v === "string";
const numOrNull = (v: unknown) => v === null || (typeof v === "number" && Number.isFinite(v));

/** Shape check for one parsed line. Returns null for anything that is not a known, well-formed record. */
export function asRecord(v: unknown): EvidenceRecord | null {
  if (v === null || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  const system = r.system === "shopify" || r.system === "stripe";
  if (r.schema === REFUND_DECISION_SCHEMA) {
    const ok =
      system && isStr(r.at) && isStr(r.gate_ref) && isStr(r.actor) && isStr(r.environment) && isStr(r.target) &&
      strOrNull(r.order_ref) && numOrNull(r.amount_cents) && strOrNull(r.currency) && OUTCOMES.has(r.outcome as string) &&
      isStr(r.decision) && strOrNull(r.deny_code) && isStr(r.reason) && strOrNull(r.audit_hash) && strOrNull(r.refund_id) &&
      strOrNull(r.order_status) && numOrNull(r.days_since_delivery) &&
      (r.approval_request_id === undefined || strOrNull(r.approval_request_id));
    return ok ? (r as unknown as RefundDecisionRecord) : null;
  }
  if (r.schema === REFUND_ALARM_SCHEMA) {
    const ok =
      system && isStr(r.at) && isStr(r.refund_id) && strOrNull(r.target) && numOrNull(r.amount_cents) && strOrNull(r.currency) &&
      VERDICTS.has(r.verdict as string) && strOrNull(r.reason) && strOrNull(r.gate_ref);
    return ok ? (r as unknown as RefundAlarmRecord) : null;
  }
  return null;
}

export interface ParsedLog {
  decisions: RefundDecisionRecord[];
  alarms: RefundAlarmRecord[];
  /** Line numbers (1-based) that were not a known record. Reported, never silently dropped. */
  rejectedLines: number[];
}

export function parseLog(text: string): ParsedLog {
  const out: ParsedLog = { decisions: [], alarms: [], rejectedLines: [] };
  text.split("\n").forEach((line, i) => {
    if (line.trim() === "") return;
    let rec: EvidenceRecord | null = null;
    try {
      rec = asRecord(JSON.parse(line));
    } catch {
      rec = null;
    }
    if (rec === null) out.rejectedLines.push(i + 1);
    else if (rec.schema === REFUND_DECISION_SCHEMA) out.decisions.push(rec);
    else out.alarms.push(rec);
  });
  return out;
}

/** Append-only JSONL file. Single-process demo storage. */
export class JsonlEvidenceLog {
  constructor(readonly path: string) {}
  append(record: EvidenceRecord): void {
    appendFileSync(this.path, JSON.stringify(record) + "\n");
  }
  read(): ParsedLog {
    return existsSync(this.path) ? parseLog(readFileSync(this.path, "utf8")) : { decisions: [], alarms: [], rejectedLines: [] };
  }
}
