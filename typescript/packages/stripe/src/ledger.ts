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

import { randomUUID } from "node:crypto";
import { closeSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";

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

/** The ledger file's lock could not be taken; the operation did not happen. */
export class LedgerLockError extends Error {
  constructor(path: string, waitedMs: number) {
    super(`could not lock the permit ledger ${path} within ${waitedMs} ms`);
    this.name = "LedgerLockError";
  }
}

export interface JsonFileLedgerOptions {
  /** How long to wait for another process's lock before failing. Default 5000 ms. */
  lockTimeoutMs?: number;
  /**
   * A lock whose owner pid cannot be read (the owner died between creating
   * and writing it) is reclaimed once older than this. A lock whose owner pid
   * is readable is reclaimed only when that process no longer exists, however
   * old it is. Default 30000 ms.
   */
  staleLockMs?: number;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function readLock(lockPath: string): { token: string; ino: number; dev: number; mtimeMs: number } | null {
  try {
    const st = statSync(lockPath);
    return { token: readFileSync(lockPath, "utf8"), ino: st.ino, dev: st.dev, mtimeMs: st.mtimeMs };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: it exists, it just belongs to someone else.
    return (err as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

/** Left by a process that died while holding it, so nobody will ever release it. */
function isAbandoned(lock: { token: string; mtimeMs: number }, staleMs: number): boolean {
  const pid = Number(lock.token.split(" ")[0]);
  if (Number.isInteger(pid) && pid > 0) return !processExists(pid);
  return Date.now() - lock.mtimeMs > staleMs;
}

/**
 * Removes an abandoned lock. Only one process may do this at a time: it must
 * first create `<lock>.break` with O_EXCL, and then re-check, under that
 * breaker, that the lock path still holds the same abandoned file. Without
 * the breaker two recovering processes could both judge the old lock
 * abandoned, and the slower one would unlink the lock the faster one had just
 * created. A live owner's lock is never removed. Returns false if another
 * process is breaking the lock right now.
 */
export function breakAbandonedLock(lockPath: string, seen: { ino: number; dev: number }, staleMs: number): boolean {
  const breaker = `${lockPath}.break`;
  let fd: number;
  try {
    fd = openSync(breaker, "wx");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw err;
  }
  try {
    closeSync(fd);
    const now = readLock(lockPath);
    if (now && now.ino === seen.ino && now.dev === seen.dev && isAbandoned(now, staleMs)) unlinkSync(lockPath);
    return true;
  } finally {
    unlinkSync(breaker);
  }
}

/**
 * Takes the exclusive lock at `lockPath` and returns this holder's token.
 * Throws LedgerLockError after `timeoutMs`. Exported for tests.
 */
export async function acquireFileLock(
  lockPath: string,
  ledgerPath: string,
  opts: { timeoutMs: number; staleMs: number },
): Promise<string> {
  const token = `${process.pid} ${randomUUID()}`;
  const started = Date.now();
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx");
      try {
        writeFileSync(fd, token);
      } finally {
        closeSync(fd);
      }
      return token;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
    const held = readLock(lockPath);
    if (held === null) continue; // released between the open and the read
    if (isAbandoned(held, opts.staleMs) && breakAbandonedLock(lockPath, held, opts.staleMs)) continue;
    if (Date.now() - started >= opts.timeoutMs) throw new LedgerLockError(ledgerPath, Date.now() - started);
    await sleep(10 + Math.floor(Math.random() * 15));
  }
}

/** Releases the lock only if this holder still owns it. Exported for tests. */
export function releaseFileLock(lockPath: string, token: string): void {
  const held = readLock(lockPath);
  // Not ours (or gone): leave it. Only an abandoned lock is ever removed by
  // anyone but its owner, and this holder is alive, so ours cannot have been.
  if (held === null || held.token !== token) return;
  unlinkSync(lockPath);
}

/**
 * Same semantics, kept in a JSON file that several processes share: the CLI
 * records refunds while the webhook server (another process) audits them.
 *
 * - Every operation re-reads the file, so nothing relies on a snapshot taken
 *   at startup.
 * - Every write holds an exclusive lock file (`<path>.lock`, created with
 *   O_EXCL, holding the owner's pid and a random token) across
 *   read-modify-write. Only the owner releases it; a lock is reclaimed only
 *   when its owner process is gone (acquireFileLock), and replaces the ledger with a unique
 *   temp file plus rename, so a reader never sees a partial file and two
 *   writers never lose each other's entries.
 * - If the lock cannot be taken, the operation throws LedgerLockError and
 *   changes nothing. The gate then stops before refunding, and the webhook
 *   reports the refund as unauthorized: a lock failure never authorizes.
 *
 * Demo storage on one machine, not a database.
 */
export class JsonFileLedger extends InMemoryLedger {
  private readonly lockTimeoutMs: number;
  private readonly staleLockMs: number;

  constructor(
    private readonly path: string,
    options: JsonFileLedgerOptions = {},
  ) {
    super();
    this.lockTimeoutMs = options.lockTimeoutMs ?? 5000;
    this.staleLockMs = options.staleLockMs ?? 30_000;
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
    const token = await acquireFileLock(lockPath, this.path, { timeoutMs: this.lockTimeoutMs, staleMs: this.staleLockMs });
    try {
      this.load();
      return await op();
    } finally {
      releaseFileLock(lockPath, token);
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
    const tmp = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(tmp, JSON.stringify({ entries: [...this.entries.values()], pending: [...this.pending.values()] }, null, 2));
    renameSync(tmp, this.path);
  }
}
