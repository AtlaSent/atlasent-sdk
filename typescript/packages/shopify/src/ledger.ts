/**
 * Record of refunds the gate authorized, so the refunds/create webhook can
 * tell a gated refund from one made around the gate.
 *
 * The guard writes an entry BEFORE calling refundCreate (`authorized`), and
 * completes it with the Shopify refund id afterwards (`executed`). The
 * webhook can arrive before the second write, so it matches on the gate
 * reference carried in the refund note, then checks order and amount. Each
 * entry can account for exactly one Shopify refund.
 *
 * The ledger never holds the permit token itself (the SDK's `permitId` is the
 * bearer token): only its SHA-256, and the reference is a random UUID.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

export interface LedgerEntry {
  /** Random per-refund reference, written into the Shopify refund note. */
  gate_ref: string;
  /** SHA-256 of the (already consumed) permit token. */
  permit_sha256: string;
  audit_hash: string;
  order_id: string;
  amount_cents: number;
  actor_id: string;
  authorized_at: string;
  /** Set once refundCreate returns. */
  refund_id?: string;
  /** Set when a webhook delivery has been matched to this entry. */
  matched_refund_id?: string;
  /** Set when the gate stopped after recording, so the entry can never vouch for a refund. */
  aborted_reason?: string;
}

export interface PermitLedger {
  recordAuthorized(entry: LedgerEntry): Promise<void>;
  recordExecuted(gateRef: string, refundId: string): Promise<void>;
  /** The refund was recorded but not issued by the gate. */
  recordAborted(gateRef: string, reason: string): Promise<void>;
  get(gateRef: string): Promise<LedgerEntry | undefined>;
  /** Marks the entry as accounting for `refundId`. False if already used by another refund. */
  claim(gateRef: string, refundId: string): Promise<boolean>;
}

export class InMemoryLedger implements PermitLedger {
  protected entries = new Map<string, LedgerEntry>();

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

  protected persist(): void {}
}

/** Same semantics, kept in a JSON file. Single-process demo storage, not a database. */
export class JsonFileLedger extends InMemoryLedger {
  constructor(private readonly path: string) {
    super();
    if (existsSync(path)) {
      const rows = JSON.parse(readFileSync(path, "utf8")) as LedgerEntry[];
      for (const r of rows) this.entries.set(r.gate_ref, r);
    }
  }

  protected override persist(): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify([...this.entries.values()], null, 2));
    renameSync(tmp, this.path);
  }
}

const NOTE_PREFIX = "AtlaSent gate ref ";

/** The refund note the guard writes; the webhook reads the id back out of it. */
export function refundNote(gateRef: string, reason?: string): string {
  return `${NOTE_PREFIX}${gateRef}${reason ? ` — ${reason}` : ""}`;
}

export function gateRefFromNote(note: string | null | undefined): string | undefined {
  if (typeof note !== "string" || !note.startsWith(NOTE_PREFIX)) return undefined;
  const id = note.slice(NOTE_PREFIX.length).split(" ")[0];
  return id && id.length > 0 ? id : undefined;
}
