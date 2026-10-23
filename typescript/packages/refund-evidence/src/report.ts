/**
 * The evidence report a finance reader opens: every refund decision in a
 * period, the rule that decided it, and every refund made around the gate.
 *
 * Output is a self-contained HTML page (no scripts, no external assets, every
 * value escaped) and a CSV for spreadsheets (formula-injection safe).
 *
 * WHAT THIS IS NOT. The report is built from the gates' decision log; it is
 * not itself signed. The proof is AtlaSent's signed audit export for the same
 * period, checked with the offline verifier. The report says so on its face.
 */

import type { RefundAlarmRecord, RefundDecisionRecord, RefundOutcome } from "./records.js";

export interface EvidenceReportInput {
  decisions: RefundDecisionRecord[];
  alarms: RefundAlarmRecord[];
  /** Shown in the heading, e.g. "Pinecone Pet Supply". */
  storeName: string;
  /** Inclusive start, exclusive end. Records outside it are left out. */
  period?: { from: Date; to: Date };
  generatedAt: Date;
  /** Marks the report as built from simulated data, on its face. */
  simulated?: { stores: boolean; decisions: boolean };
  /** Log lines that were not a known record; listed so nothing is silently dropped. */
  rejectedLines?: number[];
}

export interface MoneyTotal {
  count: number;
  /** Sum per currency, in cents; amounts with no recorded currency sum under "unknown", never under USD. Rows with an unknown amount are counted but not summed. */
  cents: Record<string, number>;
}

export interface EvidenceSummary {
  refunded: MoneyTotal;
  escalated: MoneyTotal;
  declined: MoneyTotal;
  stopped: MoneyTotal;
  /** The processor accepted these refunds but reported them pending or requiring action: not yet completed. */
  acceptedNotCompleted: MoneyTotal;
  /** Submitted, outcome not confirmed by the processor: neither refunded nor nothing refunded. */
  unconfirmed: MoneyTotal;
  outsideGate: MoneyTotal;
  alarmAccountedFor: number;
  /** Refunds issued after a manager approved them (also counted in `refunded`). */
  approvedByManager: number;
  decisions: number;
}

export interface EvidenceReport {
  summary: EvidenceSummary;
  html: string;
  csv: string;
}

export const OUTCOME_LABEL: Record<RefundOutcome, string> = {
  refunded: "Refunded",
  escalated: "Sent to a manager",
  held: "On hold",
  denied: "Declined by policy",
  refused: "Refused: invalid request",
  stopped: "Stopped: could not complete safely",
  unconfirmed: "Submitted: outcome not yet confirmed",
};

const SYSTEM_LABEL = { shopify: "Shopify", stripe: "Stripe" } as const;

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** One CSV cell: quoted when needed, and a leading = + - @ tab or CR neutralised so a spreadsheet never runs it as a formula. */
export function csvCell(v: string | number | null): string {
  if (v === null) return "";
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function formatMoney(cents: number | null, currency: string | null): string {
  if (cents === null) return "unknown";
  const sign = cents < 0 ? "-" : "";
  const abs = Math.abs(cents);
  const digits = `${Math.floor(abs / 100).toLocaleString("en-US")}.${String(abs % 100).padStart(2, "0")}`;
  // A missing currency stays unknown: it is never shown or totalled as dollars.
  if (currency === null || currency === UNKNOWN_CURRENCY) return `${sign}${digits} (currency unknown)`;
  return `${sign}${currency === "USD" ? "$" : `${currency} `}${digits}`;
}

/** The totals key for amounts whose currency was not recorded. */
export const UNKNOWN_CURRENCY = "unknown";

function total(rows: { amount_cents: number | null; currency: string | null }[]): MoneyTotal {
  const cents: Record<string, number> = {};
  for (const r of rows) {
    if (r.amount_cents === null) continue;
    const c = r.currency ?? UNKNOWN_CURRENCY;
    cents[c] = (cents[c] ?? 0) + r.amount_cents;
  }
  return { count: rows.length, cents };
}

const totalText = (t: MoneyTotal) => {
  const parts = Object.entries(t.cents).map(([c, v]) => formatMoney(v, c));
  return parts.length === 0 ? "—" : parts.join(" + ");
};

function inPeriod(at: string, period?: { from: Date; to: Date }): boolean {
  if (!period) return true;
  const t = Date.parse(at);
  return Number.isFinite(t) && t >= period.from.getTime() && t < period.to.getTime();
}

/** Plain words for the demo policy's codes; any other code is shown as is. */
export const RULE_LABEL: Record<string, string> = {
  MANAGER_APPROVAL_REQUIRED: "$50 or more needs a manager",
  ORDER_NOT_DELIVERED: "Order not delivered",
  RETURN_WINDOW_EXPIRED: "More than 30 days after delivery",
  RETURN_WINDOW_UNKNOWN: "Delivery date unknown",
  INVALID_REFUND_AMOUNT: "Invalid amount",
  allow_after_approval: "Approved by a manager",
  approval_stopped: "Approved, but could not complete safely",
  approval_not_found: "Approval request not found",
  approval_unconfirmed: "Approved; refund outcome not yet confirmed",
};

/** Statuses in which the processor accepted a refund that has not completed. */
const NOT_COMPLETED = new Set(["pending", "requires_action"]);

/** A refunded outcome the processor accepted but had not completed when it was recorded. */
export const acceptedNotCompleted = (d: Pick<RefundDecisionRecord, "outcome" | "processor_status">) =>
  d.outcome === "refunded" && typeof d.processor_status === "string" && NOT_COMPLETED.has(d.processor_status);

/** The outcome as a reader says it: a manager's "no" is not the policy's, and accepted is not completed. */
export function outcomeText(d: Pick<RefundDecisionRecord, "outcome" | "deny_code" | "processor_status">): string {
  if (d.outcome === "denied" && d.deny_code?.startsWith("APPROVAL_")) return "Declined by a manager";
  if (acceptedNotCompleted(d)) {
    return d.processor_status === "pending" ? "Accepted by the processor, pending" : "Accepted by the processor, needs action";
  }
  return OUTCOME_LABEL[d.outcome];
}

/** A refund issued after a manager approved its escalation. */
export const approvedByManager = (d: RefundDecisionRecord) => d.outcome === "refunded" && d.decision === "allow_after_approval";

const ruleOf = (d: RefundDecisionRecord) =>
  approvedByManager(d) ? "allow_after_approval" : d.outcome === "refunded" ? "Within policy" : (d.deny_code ?? d.decision);
const ruleText = (d: RefundDecisionRecord) => {
  const code = ruleOf(d);
  if (code.startsWith("APPROVAL_")) return `Manager did not approve (${code})`;
  const label = RULE_LABEL[code];
  if (code === "allow_after_approval") return label as string;
  return label ? `${label} (${code})` : code;
};
/** Resumed decisions are checked against the approval request, not a fresh evaluation. */
const auditRef = (d: RefundDecisionRecord) => {
  if (d.audit_hash) return d.audit_hash;
  const resumed = approvedByManager(d) || d.decision.startsWith("approval_");
  return resumed && d.approval_request_id ? `approval ${d.approval_request_id}` : "not evaluated";
};

export function buildEvidenceReport(input: EvidenceReportInput): EvidenceReport {
  const decisions = input.decisions.filter((d) => inPeriod(d.at, input.period)).sort((a, b) => a.at.localeCompare(b.at));
  const alarms = input.alarms.filter((a) => inPeriod(a.at, input.period)).sort((a, b) => a.at.localeCompare(b.at));
  const outside = alarms.filter((a) => a.verdict === "unauthorized");
  const outsideRows = outside.map((a) => ({ amount_cents: a.amount_cents, currency: a.currency }));
  const by = (o: RefundOutcome[]) => decisions.filter((d) => o.includes(d.outcome));

  const summary: EvidenceSummary = {
    refunded: total(by(["refunded"]).filter((d) => !acceptedNotCompleted(d))),
    acceptedNotCompleted: total(decisions.filter(acceptedNotCompleted)),
    escalated: total(by(["escalated", "held"])),
    declined: total(by(["denied", "refused"])),
    stopped: total(by(["stopped"])),
    unconfirmed: total(by(["unconfirmed"])),
    outsideGate: total(outsideRows),
    alarmAccountedFor: alarms.filter((a) => a.verdict === "authorized").length,
    approvedByManager: decisions.filter(approvedByManager).length,
    decisions: decisions.length,
  };

  const e = escapeHtml;
  const periodText = input.period
    ? `${input.period.from.toISOString().slice(0, 10)} to ${new Date(input.period.to.getTime() - 1).toISOString().slice(0, 10)}`
    : "all records in the log";
  const banner = input.simulated && (input.simulated.stores || input.simulated.decisions)
    ? `<p class="banner">SIMULATED DATA. ${input.simulated.stores ? "The stores, orders and refunds in this report are simulated; no money moved." : ""} ${input.simulated.decisions ? "Decisions came from a local stand-in for the AtlaSent runtime, not from AtlaSent, so the audit references are placeholders." : "Decisions came from the AtlaSent runtime."}</p>`
    : "";

  const tile = (label: string, t: MoneyTotal, note: string, cls = "", requested = false) =>
    `<div class="tile ${cls}"><div class="n">${t.count}</div><div class="l">${e(label)}</div><div class="m">${e(totalText(t))}${requested && Object.keys(t.cents).length > 0 ? " requested" : ""}</div><div class="note">${e(note)}</div></div>`;

  const decisionRows = decisions
    .map(
      (d) => `<tr class="o-${e(d.outcome)}"><td>${e(d.at.replace("T", " ").slice(0, 16))}</td><td>${e(SYSTEM_LABEL[d.system])}</td><td>${e(d.order_ref ?? d.target)}</td><td class="num">${e(formatMoney(d.amount_cents, d.currency))}</td><td>${e(outcomeText(d))}</td><td>${e(ruleText(d))}</td><td>${e(d.actor)}</td><td class="mono">${e(auditRef(d))}</td><td class="mono">${e(d.gate_ref)}</td></tr>`,
    )
    .join("\n");

  const alarmRows = outside
    .map(
      (a) => `<tr><td>${e(a.at.replace("T", " ").slice(0, 16))}</td><td>${e(SYSTEM_LABEL[a.system])}</td><td class="mono">${e(a.refund_id)}</td><td>${e(a.target ?? "unknown")}</td><td class="num">${e(formatMoney(a.amount_cents, a.currency))}</td><td>${e(a.reason ?? "")}</td></tr>`,
    )
    .join("\n");

  const rejected = input.rejectedLines && input.rejectedLines.length > 0
    ? `<p class="warn">${input.rejectedLines.length} log line(s) were not a recognised record and are not in this report: line ${e(input.rejectedLines.join(", "))}.</p>`
    : "";

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Refund evidence report</title>
<style>
body{font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;color:#1d1d1f;background:#fff;margin:0;padding:32px;max-width:1180px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 8px}.sub{color:#555;margin:0 0 20px}
.banner{background:#fff4d6;border:1px solid #e0b100;padding:10px 14px;border-radius:6px;font-weight:600}
.warn{background:#fdecec;border:1px solid #c62828;padding:10px 14px;border-radius:6px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.tile{border:1px solid #ddd;border-radius:8px;padding:12px 14px}.tile .n{font-size:26px;font-weight:700}.tile .l{font-weight:600}
.tile .m{color:#333}.tile .note{color:#666;font-size:12px;margin-top:4px}.tile.alert{border-color:#c62828;background:#fdecec}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}
th{background:#f6f6f7;font-weight:600}.num{text-align:right;white-space:nowrap}td:first-child{white-space:nowrap}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
tr.o-refunded td:nth-child(5){color:#1b5e20;font-weight:600}tr.o-escalated td:nth-child(5){color:#8a5a00;font-weight:600}
tr.o-denied td:nth-child(5),tr.o-refused td:nth-child(5),tr.o-stopped td:nth-child(5){color:#b71c1c}
.how{background:#f6f6f7;border-radius:8px;padding:12px 16px}
@media print{body{padding:0}.tile{break-inside:avoid}}
</style></head><body>
<h1>Refund evidence report: ${e(input.storeName)}</h1>
<p class="sub">Period: ${e(periodText)} · Generated ${e(input.generatedAt.toISOString().replace("T", " ").slice(0, 16))} UTC · ${summary.decisions} refund decision(s)</p>
${banner}
${rejected}
<div class="tiles">
${tile("Refunded", summary.refunded, `Within policy${summary.approvedByManager > 0 ? `, ${summary.approvedByManager} of them approved by a manager` : ""}; permit verified before the money moved`)}
${tile("Sent to a manager", summary.escalated, "Over the automatic limit; the manager's decision, once made, is its own row below", "", true)}
${tile("Declined", summary.declined, "Outside policy, declined by a manager, or invalid; nothing refunded", "", true)}
${tile("Stopped", summary.stopped, "Could not complete safely; nothing refunded", "", true)}
${summary.acceptedNotCompleted.count > 0 ? tile("Accepted, not yet completed", summary.acceptedNotCompleted, "The processor accepted these refunds but reported them pending or needing action. Check the processor before treating them as refunded", "alert") : ""}
${summary.unconfirmed.count > 0 ? tile("Outcome unconfirmed", summary.unconfirmed, "Submitted to the processor; whether the refund was created is not yet confirmed. Reconcile each one", "alert") : ""}
${tile("Refunds made outside the gate", summary.outsideGate, "Made in an admin or dashboard, or with another key", summary.outsideGate.count > 0 ? "alert" : "")}
</div>
<h2>Refunds made outside the gate</h2>
${outside.length === 0 ? `<p>None. ${summary.alarmAccountedFor} refund(s) reported by the platforms were all matched to a permit.</p>` : `<p>These refunds were reported by the platform with no matching AtlaSent permit. Review each one.</p><table><thead><tr><th>When (UTC)</th><th>System</th><th>Refund</th><th>Order / payment</th><th class="num">Amount</th><th>Why it was flagged</th></tr></thead><tbody>
${alarmRows}
</tbody></table>`}
<h2>Every refund decision</h2>
<table><thead><tr><th>When (UTC)</th><th>System</th><th>Order</th><th class="num">Amount</th><th>Outcome</th><th>Rule</th><th>Requested by</th><th>AtlaSent audit reference</th><th>Gate reference</th></tr></thead><tbody>
${decisionRows || '<tr><td colspan="9">No decisions in this period.</td></tr>'}
</tbody></table>
<h2>How to check this report</h2>
<div class="how">
<p>This report is built from the refund gates' decision log. It is not itself a signed record.</p>
<p>AtlaSent records every evaluation in its tamper-evident, signed audit chain. The audit reference column is the reference AtlaSent returned for each decision. To check the report, request AtlaSent's signed audit export for the same period, verify it with the offline verifier, and cross-check the decisions here against it. A row marked "not evaluated" was refused before it reached AtlaSent, for example an amount larger than the order allows.</p>
<p>A row marked "approval &lt;id&gt;" is a manager's decision on an earlier escalation. Its permit was minted by AtlaSent when the manager approved, bound to the exact refund that was escalated, and verified before the money moved; check it against the approval request with that id.</p>
<p>The gate reference is written on each refund in Shopify (the refund note) or Stripe (the refund metadata), so any refund can be traced back to its decision.</p>
</div>
</body></html>
`;

  const header = ["type", "at", "system", "order_or_payment", "order_ref", "amount", "currency", "outcome", "rule", "reason", "requested_by", "audit_reference", "gate_reference", "refund_id", "approval_request_id", "processor_status"];
  const lines = [header.join(",")];
  for (const d of decisions) {
    lines.push(
      [
        "decision", d.at, d.system, d.target, d.order_ref, d.amount_cents === null ? null : (d.amount_cents / 100).toFixed(2), d.currency,
        outcomeText(d), ruleOf(d), d.reason, d.actor, d.audit_hash, d.gate_ref, d.refund_id, d.approval_request_id ?? null,
        d.processor_status ?? null,
      ].map(csvCell).join(","),
    );
  }
  for (const a of outside) {
    lines.push(
      [
        "refund_outside_gate", a.at, a.system, a.target, null, a.amount_cents === null ? null : (a.amount_cents / 100).toFixed(2), a.currency,
        "Made outside the gate", null, a.reason, null, null, a.gate_ref, a.refund_id, null, null,
      ].map(csvCell).join(","),
    );
  }

  return { summary, html, csv: lines.join("\n") + "\n" };
}
