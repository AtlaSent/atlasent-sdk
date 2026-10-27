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

import { randomUUID } from "node:crypto";
import { closeSync, linkSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";

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
  /** Additive execution scope; older demo records may lack these fields. */
  shop?: string;
  environment?: string;
  parent_transaction_id?: string;
  currency?: string;
  gateway?: string;
  business_request_id?: string;
  execution_digest?: string;
  refund_note?: string;
  approval_request_id?: string;
  /** A send was attempted; its financial outcome has not been confirmed. */
  unconfirmed_reason?: string;
  observed_refund_id?: string;
}

/**
 * An escalated refund waiting for a person's decision, frozen exactly as it
 * was evaluated, so resuming it can only ever issue that refund.
 */
export interface PendingApproval {
  approval_request_id: string;
  /** The escalated attempt's gate reference; the resumed refund carries it too. */
  gate_ref: string;
  actor_id: string;
  environment: string;
  order_id: string;
  /** The order's name (e.g. #1002), for records. */
  order_ref?: string;
  amount_cents: number;
  /** The refund snapshot the permit will be bound to. */
  snapshot: Record<string, unknown>;
  digest: string;
  /** Bind approval resume to the facts actually evaluated, not just the amount. */
  source_facts_hash?: string;
  business_request_id?: string;
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
  recordUnconfirmed(gateRef: string, reason: string, refundId?: string): Promise<void>;
  get(gateRef: string): Promise<LedgerEntry | undefined>;
  /** Marks the entry as accounting for `refundId`. False if already used by another refund. */
  claim(gateRef: string, refundId: string): Promise<boolean>;
  recordPendingApproval(pending: PendingApproval): Promise<void>;
  getPendingApproval(approvalRequestId: string): Promise<PendingApproval | undefined>;
  resolvePendingApproval(approvalRequestId: string, resolved: NonNullable<PendingApproval["resolved"]>): Promise<void>;
}

export class RefundReservationError extends Error {
  constructor(public readonly code: "duplicate_request" | "request_conflict" | "reconciliation_required", message: string, public readonly gateRef: string) {
    super(message);
    this.name = "RefundReservationError";
  }
}

/** Shopify ids arrive as gids (gid://shopify/Refund/1) or bare numbers; compare their numeric part. */
function sameRefundId(a: string, b: string): boolean {
  const tail = (id: string) => String(id).split("/").pop();
  return tail(a) === tail(b);
}

export class InMemoryLedger implements PermitLedger {
  protected entries = new Map<string, LedgerEntry>();
  protected pending = new Map<string, PendingApproval>();

  async recordAuthorized(entry: LedgerEntry): Promise<void> {
    if (this.entries.has(entry.gate_ref)) throw new Error(`duplicate ledger entry ${entry.gate_ref}`);
    // Runs under JsonFileLedger's existing read-modify-write lock. This is a
    // single-machine demo interlock, not the runtime's transactional budget.
    if (entry.shop !== undefined && entry.environment !== undefined && entry.parent_transaction_id !== undefined) {
      for (const previous of this.entries.values()) {
        const sameScope = previous.shop === entry.shop && previous.environment === entry.environment;
        if (sameScope && entry.business_request_id !== undefined && previous.business_request_id === entry.business_request_id) {
          const sameRequest = previous.execution_digest === entry.execution_digest;
          // Only a definitively pre-send abort can retry the same immutable
          // operation, after a fresh evaluation and consumed permit.
          if (sameRequest && previous.aborted_reason !== undefined) continue;
          throw new RefundReservationError(
            sameRequest ? "duplicate_request" : "request_conflict",
            "this business request was already recorded; inspect its original outcome instead of issuing another refund",
            previous.gate_ref,
          );
        }
        const unresolved = previous.refund_id === undefined && previous.aborted_reason === undefined;
        const samePayment = sameScope && previous.parent_transaction_id === entry.parent_transaction_id;
        const legacyOrder = previous.shop === undefined && previous.order_id === entry.order_id;
        if (unresolved && (samePayment || legacyOrder)) {
          throw new RefundReservationError("reconciliation_required", "an earlier refund on this payment is in flight or unconfirmed; reconcile it before another request", previous.gate_ref);
        }
      }
    }
    this.entries.set(entry.gate_ref, { ...entry });
    this.persist();
  }

  async recordExecuted(gateRef: string, refundId: string): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e) throw new Error(`no ledger entry ${gateRef}`);
    if (e.aborted_reason !== undefined || (e.refund_id !== undefined && !sameRefundId(e.refund_id, refundId)) ||
        (e.observed_refund_id !== undefined && !sameRefundId(e.observed_refund_id, refundId))) throw new Error("conflicting refund outcome");
    e.refund_id = refundId;
    delete e.unconfirmed_reason;
    const pending = e.approval_request_id ? this.pending.get(e.approval_request_id) : undefined;
    if (pending) pending.resolved = { outcome: "refunded", at: new Date().toISOString(), detail: refundId };
    this.persist();
  }

  async recordAborted(gateRef: string, reason: string): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e) throw new Error(`no ledger entry ${gateRef}`);
    if (e.unconfirmed_reason !== undefined || e.refund_id !== undefined || e.observed_refund_id !== undefined) throw new Error("an attempted refund must be reconciled, not canceled");
    e.aborted_reason = reason;
    this.persist();
  }

  async recordUnconfirmed(gateRef: string, reason: string, refundId?: string): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e || e.aborted_reason !== undefined || e.refund_id !== undefined) throw new Error("no unresolved refund execution");
    e.unconfirmed_reason = reason;
    if (refundId !== undefined) e.observed_refund_id = refundId;
    this.persist();
  }

  async get(gateRef: string): Promise<LedgerEntry | undefined> {
    const e = this.entries.get(gateRef);
    return e ? { ...e } : undefined;
  }

  async claim(gateRef: string, refundId: string): Promise<boolean> {
    const e = this.entries.get(gateRef);
    if (!e) return false;
    // Re-checked here, not only by the caller: with a shared file ledger the
    // gate can cancel the entry, or record its own refund, between the
    // webhook's read and this claim (which runs under the lock).
    if (e.aborted_reason !== undefined) return false;
    if (e.refund_id !== undefined && sameRefundId(e.refund_id, refundId) === false) return false;
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

/** The ledger file's lock could not be taken; the operation did not happen. */
export class LedgerLockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LedgerLockError";
  }
}

export interface JsonFileLedgerOptions {
  /** How long to wait for another process's lock before failing. Default 5000 ms. */
  lockTimeoutMs?: number;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** The lock's token, read through one descriptor. */
function readLock(lockPath: string): { token: string } | null {
  let fd: number;
  try {
    fd = openSync(lockPath, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  try {
    return { token: readFileSync(fd, "utf8") };
  } finally {
    closeSync(fd);
  }
}

/** Locks this process holds, so an exit in the middle of an operation (process.exit) releases them. */
const heldLocks = new Map<string, string>();
let exitHookInstalled = false;
function releaseOnExit(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  const releaseAll = () => {
    for (const [path, token] of heldLocks) {
      try {
        removeLockIfHeldBy(path, token);
      } catch {
        // best effort at exit
      }
    }
  };
  process.once("exit", releaseAll);
}

/**
 * Releases the lock at `lockPath` only if it holds `token`, so a holder never
 * deletes a lock it does not own (for example one an operator replaced). It
 * renames the lock aside, reads what it moved, deletes it if it is this
 * holder's, and otherwise links it straight back. Exported for tests.
 */
export function removeLockIfHeldBy(lockPath: string, token: string): boolean {
  // Stop tracking the lock only once it is gone or known not to be ours: if
  // removing it fails, the exit hook must still be able to retry.
  const untrack = () => {
    if (heldLocks.get(lockPath) === token) heldLocks.delete(lockPath);
  };
  const aside = `${lockPath}.${process.pid}.${randomUUID()}.aside`;
  try {
    renameSync(lockPath, aside);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      untrack();
      return false;
    }
    throw err;
  }
  let moved: string | undefined;
  try {
    moved = readFileSync(aside, "utf8");
  } catch {
    moved = undefined;
  }
  let restored = false;
  if (moved !== token) {
    try {
      linkSync(aside, lockPath);
      restored = true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Another process took the path meanwhile; what we moved is discarded.
    }
  }
  // Stay tracked only when ownership is unknown (token unreadable) AND the
  // lock went back in place. If a new holder took the path instead, tracking
  // the old token would let the exit hook move that holder's lock aside.
  if (!(moved === undefined && restored)) untrack();
  unlinkSync(aside);
  return moved === token;
}

/** Whether this process is still tracking a lock at `lockPath` for release on exit. Exported for tests. */
export function isLockTracked(lockPath: string): boolean {
  return heldLocks.has(lockPath);
}

/** Throws unless the lock at `lockPath` still holds `token`. Exported for tests. */
export function assertLockHeld(lockPath: string, token: string, ledgerPath: string): void {
  if (readLock(lockPath)?.token !== token) {
    throw new LedgerLockError(`lost the lock on the permit ledger ${ledgerPath} before writing; nothing was written`);
  }
}

/**
 * Takes the exclusive lock at `lockPath` and returns this holder's token.
 * Throws LedgerLockError after `timeoutMs`. Exported for tests.
 *
 * A lock is never taken over, however old. Plain files offer no conditional
 * delete, so every takeover scheme can, in some interleaving, remove a live
 * holder's lock and let two writers overwrite each other. Instead a lock
 * left by a process that crashed inside the (milliseconds-long) critical
 * section makes every write fail closed until an operator deletes it; the
 * error says so. process.exit() mid-operation releases it; a kill does not.
 */
export async function acquireFileLock(
  lockPath: string,
  ledgerPath: string,
  opts: { timeoutMs: number },
): Promise<string> {
  const token = `${process.pid} ${randomUUID()}`;
  const started = Date.now();
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx");
      // This attempt created the file and nothing else can own it yet. If
      // writing the token or closing the file fails, remove it: a lock left
      // here untracked would block every writer until deleted by hand.
      let closed = false;
      try {
        writeFileSync(fd, token);
        closed = true; // a failed close still releases the descriptor
        closeSync(fd);
      } catch (err) {
        if (!closed) {
          try {
            closeSync(fd);
          } catch {
            // already reported by the original error
          }
        }
        unlinkSync(lockPath);
        throw err;
      }
      heldLocks.set(lockPath, token);
      releaseOnExit();
      return token;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
    if (Date.now() - started >= opts.timeoutMs) {
      throw new LedgerLockError(
        `could not lock the permit ledger ${ledgerPath} within ${Date.now() - started} ms; nothing was written. ` +
          `If no refund process is running, ${lockPath} was left by one that crashed: delete it to restore writes.`,
      );
    }
    await sleep(10 + Math.floor(Math.random() * 15));
  }
}

/**
 * Same semantics, kept in a JSON file that several processes share: the CLI
 * records refunds while the webhook server (another process) audits them.
 *
 * - Every operation re-reads the file, so nothing relies on a snapshot taken
 *   at startup.
 * - Every write holds an exclusive lock file (`<path>.lock`, created with
 *   O_EXCL, holding a random token) across read-modify-write, checks it still
 *   holds that lock just before writing, and replaces the ledger with a
 *   unique temp file plus rename, so a reader never sees a partial file and
 *   two writers never lose each other's entries.
 * - Only the holder ever removes its lock, and only by token
 *   (removeLockIfHeldBy). No other process takes a lock over, however old:
 *   see acquireFileLock for why, and for recovering from a crash.
 * - If the lock cannot be taken, the operation throws LedgerLockError and
 *   changes nothing. The gate then stops before refunding, and the webhook
 *   reports the refund as unauthorized: a lock failure never authorizes.
 *
 * Demo storage on one machine, not a database.
 */
export class JsonFileLedger extends InMemoryLedger {
  private readonly lockTimeoutMs: number;
  private heldLock: { path: string; token: string } | undefined;

  constructor(
    private readonly path: string,
    options: JsonFileLedgerOptions = {},
  ) {
    super();
    this.lockTimeoutMs = options.lockTimeoutMs ?? 5000;
    this.load();
  }

  /** Replaces the in-memory state with the file's current contents. */
  private load(): void {
    this.entries.clear();
    this.pending.clear();
    let text: string;
    try {
      text = readFileSync(this.path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    const data = JSON.parse(text) as LedgerEntry[] | { entries: LedgerEntry[]; pending?: PendingApproval[] };
    // An array is the file format before pending approvals existed.
    const rows = Array.isArray(data) ? data : data.entries;
    for (const r of rows) this.entries.set(r.gate_ref, r);
    if (!Array.isArray(data)) for (const p of data.pending ?? []) this.pending.set(p.approval_request_id, p);
  }

  /** Lock, reload, run one operation (which persists), unlock. */
  private async locked<T>(op: () => Promise<T>): Promise<T> {
    const lockPath = `${this.path}.lock`;
    const token = await acquireFileLock(lockPath, this.path, { timeoutMs: this.lockTimeoutMs });
    this.heldLock = { path: lockPath, token };
    try {
      this.load();
      return await op();
    } finally {
      this.heldLock = undefined;
      removeLockIfHeldBy(lockPath, token);
    }
  }

  override recordAuthorized(entry: LedgerEntry): Promise<void> {
    return this.locked(() => super.recordAuthorized(entry));
  }
  override recordExecuted(gateRef: string, refundId: string): Promise<void> {
    return this.locked(() => super.recordExecuted(gateRef, refundId));
  }
  override recordAborted(gateRef: string, reason: string): Promise<void> {
    return this.locked(() => super.recordAborted(gateRef, reason));
  }
  override recordUnconfirmed(gateRef: string, reason: string, refundId?: string): Promise<void> {
    return this.locked(() => super.recordUnconfirmed(gateRef, reason, refundId));
  }
  override claim(gateRef: string, refundId: string): Promise<boolean> {
    return this.locked(() => super.claim(gateRef, refundId));
  }
  override recordPendingApproval(p: PendingApproval): Promise<void> {
    return this.locked(() => super.recordPendingApproval(p));
  }
  override resolvePendingApproval(id: string, resolved: NonNullable<PendingApproval["resolved"]>): Promise<void> {
    return this.locked(() => super.resolvePendingApproval(id, resolved));
  }

  // Reads take no lock: writes replace the file by rename, so a read sees a
  // whole old or whole new ledger, never a partial one.
  override async get(gateRef: string): Promise<LedgerEntry | undefined> {
    this.load();
    return super.get(gateRef);
  }
  override async getPendingApproval(id: string): Promise<PendingApproval | undefined> {
    this.load();
    return super.getPendingApproval(id);
  }

  protected override persist(): void {
    // Every write runs inside locked(); refuse one that does not, or whose
    // lock was taken over while it worked.
    if (!this.heldLock) throw new LedgerLockError(`write to the permit ledger ${this.path} without its lock; nothing was written`);
    assertLockHeld(this.heldLock.path, this.heldLock.token, this.path);
    const tmp = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(tmp, JSON.stringify({ entries: [...this.entries.values()], pending: [...this.pending.values()] }, null, 2));
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

