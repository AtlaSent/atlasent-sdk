/**
 * Record of refunds the gate authorized, so the refund.created webhook can
 * tell a gated refund from one made around the gate (for example in the
 * Stripe Dashboard).
 *
 * Same contract as @atlasent/shopify's ledger; kept separate so the two demo
 * packages install independently.
 *
 * The guard writes an entry BEFORE calling POST /v1/refunds (`authorized`),
 * and completes it with the Stripe refund id afterwards (`executed`). The
 * webhook can arrive before the second write, so it matches on the gate
 * reference carried in the refund's metadata, then checks the PaymentIntent
 * and amount. Each entry can account for exactly one Stripe refund.
 *
 * The ledger never holds the permit token itself (the SDK's `permitId` is the
 * bearer token): only its SHA-256, and the reference is a random UUID.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

export interface LedgerEntry {
  /** Random per-refund reference, written into the Stripe refund's metadata and used as its idempotency key. */
  gate_ref: string;
  /** SHA-256 of the (already consumed) permit token. */
  permit_sha256: string;
  audit_hash: string;
  payment_intent: string;
  amount_cents: number;
  actor_id: string;
  authorized_at: string;
  /** Set once POST /v1/refunds returns. */
  refund_id?: string;
  /** Set when a webhook delivery has been matched to this entry. */
  matched_refund_id?: string;
  /** Set when the gate stopped after recording, so the entry can never vouch for a refund. */
  aborted_reason?: string;
}

/**
 * An escalated refund waiting for a person's decision, frozen exactly as it
 * was evaluated, so resuming it can only ever issue that refund.
 */
export interface PendingApproval {
  approval_request_id: string;
  /** The escalated attempt's gate reference; the resumed refund carries it too (metadata and Idempotency-Key). */
  gate_ref: string;
  actor_id: string;
  environment: string;
  payment_intent: string;
  amount_cents: number;
  /** The refund snapshot the permit will be bound to. */
  snapshot: Record<string, unknown>;
  digest: string;
  reason?: string;
  created_at: string;
  /** Set once the approval is final (refunded, not approved, or stopped). */
  resolved?: { outcome: "refunded" | "not_approved" | "stopped"; at: string; detail: string };
}

export interface PermitLedger {
  recordAuthorized(entry: LedgerEntry): Promise<void>;
  recordExecuted(gateRef: string, refundId: string): Promise<void>;
  /** The refund was recorded but not issued by the gate. */
  recordAborted(gateRef: string, reason: string): Promise<void>;
  get(gateRef: string): Promise<LedgerEntry | undefined>;
  /** Marks the entry as accounting for `refundId`. False if already used by another refund. */
  claim(gateRef: string, refundId: string): Promise<boolean>;
  recordPendingApproval(pending: PendingApproval): Promise<void>;
  getPendingApproval(approvalRequestId: string): Promise<PendingApproval | undefined>;
  resolvePendingApproval(approvalRequestId: string, resolved: NonNullable<PendingApproval["resolved"]>): Promise<void>;
}

export class InMemoryLedger implements PermitLedger {
  protected entries = new Map<string, LedgerEntry>();
  protected pending = new Map<string, PendingApproval>();

  async recordAuthorized(entry: LedgerEntry): Promise<void> {
    if (this.entries.has(entry.gate_ref)) throw new Error(`duplicate ledger entry ${entry.gate_ref}`);
    this.entries.set(entry.gate_ref, { ...entry });
    this.persist();
  }

  async recordExecuted(gateRef: string, refundId: string): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e) throw new Error(`no ledger entry ${gateRef}`);
    e.refund_id = refundId;
    this.persist();
  }

  async recordAborted(gateRef: string, reason: string): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e) throw new Error(`no ledger entry ${gateRef}`);
    e.aborted_reason = reason;
    this.persist();
  }

  async get(gateRef: string): Promise<LedgerEntry | undefined> {
    const e = this.entries.get(gateRef);
    return e ? { ...e } : undefined;
  }

  async claim(gateRef: string, refundId: string): Promise<boolean> {
    const e = this.entries.get(gateRef);
    if (!e) return false;
    if (e.matched_refund_id !== undefined) return e.matched_refund_id === refundId;
    e.matched_refund_id = refundId;
    this.persist();
    return true;
  }

  async recordPendingApproval(p: PendingApproval): Promise<void> {
    if (this.pending.has(p.approval_request_id)) throw new Error(`duplicate pending approval ${p.approval_request_id}`);
    this.pending.set(p.approval_request_id, JSON.parse(JSON.stringify(p)) as PendingApproval);
    this.persist();
  }

  async getPendingApproval(id: string): Promise<PendingApproval | undefined> {
    const p = this.pending.get(id);
    return p ? (JSON.parse(JSON.stringify(p)) as PendingApproval) : undefined;
  }

  async resolvePendingApproval(id: string, resolved: NonNullable<PendingApproval["resolved"]>): Promise<void> {
    const p = this.pending.get(id);
    if (!p) throw new Error(`no pending approval ${id}`);
    p.resolved = { ...resolved };
    this.persist();
  }

  protected persist(): void {}
}

/** Same semantics, kept in a JSON file. Single-process demo storage, not a database. */
export class JsonFileLedger extends InMemoryLedger {
  constructor(private readonly path: string) {
    super();
    if (existsSync(path)) {
      const data = JSON.parse(readFileSync(path, "utf8")) as LedgerEntry[] | { entries: LedgerEntry[]; pending?: PendingApproval[] };
      // An array is the file format before pending approvals existed.
      const rows = Array.isArray(data) ? data : data.entries;
      for (const r of rows) this.entries.set(r.gate_ref, r);
      if (!Array.isArray(data)) for (const p of data.pending ?? []) this.pending.set(p.approval_request_id, p);
    }
  }

  protected override persist(): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ entries: [...this.entries.values()], pending: [...this.pending.values()] }, null, 2));
    renameSync(tmp, this.path);
  }
}
