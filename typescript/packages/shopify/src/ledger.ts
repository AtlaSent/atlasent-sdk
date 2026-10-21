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
import { closeSync, fstatSync, linkSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";

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
  /**
   * A lock not released within this long is treated as left by a crashed
   * process and taken over. A holder that is still working when that happens
   * finds out before it writes, and fails closed. Default 30000 ms; every
   * ledger operation takes milliseconds.
   */
  staleLockMs?: number;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** The lock's token and age, read through one descriptor (no check-then-read gap). */
function readLock(lockPath: string): { token: string; mtimeMs: number } | null {
  let fd: number;
  try {
    fd = openSync(lockPath, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  try {
    return { mtimeMs: fstatSync(fd).mtimeMs, token: readFileSync(fd, "utf8") };
  } finally {
    closeSync(fd);
  }
}

/**
 * Removes the lock at `lockPath` only if it is the one holding `token`.
 *
 * It never deletes whatever happens to be at the path. It first renames the
 * lock aside (atomic: exactly one process gets a given lock file), then reads
 * what it moved. If that is the expected lock, it is deleted. If it is a newer
 * lock someone else now holds, it is linked straight back (link fails rather
 * than overwrite if the path was taken again meanwhile; that holder then
 * fails its pre-write ownership check). Used both to release one's own lock
 * and to take over an expired one. Exported for tests.
 */
export function removeLockIfHeldBy(lockPath: string, token: string): boolean {
  const aside = `${lockPath}.${process.pid}.${randomUUID()}.aside`;
  try {
    renameSync(lockPath, aside);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw err;
  }
  let moved: string | undefined;
  try {
    moved = readFileSync(aside, "utf8");
  } catch {
    moved = undefined;
  }
  if (moved !== token) {
    try {
      linkSync(aside, lockPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
  }
  unlinkSync(aside);
  return moved === token;
}

/** Throws unless the lock at `lockPath` still holds `token`. Exported for tests. */
export function assertLockHeld(lockPath: string, token: string, ledgerPath: string): void {
  if (readLock(lockPath)?.token !== token) {
    throw new LedgerLockError(`lost the lock on the permit ledger ${ledgerPath} before writing; nothing was written`);
  }
}

/**
 * Takes the exclusive lock at `lockPath` and returns this holder's token.
 * A lock older than `staleMs` is taken over through removeLockIfHeldBy, so
 * two processes recovering the same expired lock cannot delete each other's
 * new one. Throws LedgerLockError after `timeoutMs`. Exported for tests.
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
    if (Date.now() - held.mtimeMs > opts.staleMs) {
      removeLockIfHeldBy(lockPath, held.token);
      continue;
    }
    if (Date.now() - started >= opts.timeoutMs) {
      throw new LedgerLockError(`could not lock the permit ledger ${ledgerPath} within ${Date.now() - started} ms`);
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
 * - A lock is only ever removed by token (removeLockIfHeldBy): its owner
 *   releases it, or, once it is older than staleLockMs, another process takes
 *   it over. No pid is trusted, so a reused pid cannot keep a dead lock alive.
 * - Residual: a holder still working after staleLockMs whose lock is taken
 *   over fails its pre-write check, except in the instant between that check
 *   and its rename. Ledger operations take milliseconds; the limit is 30 s.
 * - If the lock cannot be taken, the operation throws LedgerLockError and
 *   changes nothing. The gate then stops before refunding, and the webhook
 *   reports the refund as unauthorized: a lock failure never authorizes.
 *
 * Demo storage on one machine, not a database.
 */
export class JsonFileLedger extends InMemoryLedger {
  private readonly lockTimeoutMs: number;
  private readonly staleLockMs: number;
  private heldLock: { path: string; token: string } | undefined;

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
