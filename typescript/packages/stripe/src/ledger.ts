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
import { closeSync, linkSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";

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
  /** The caller's durable business request id, when one was given. Absent on entries written before it existed. */
  business_request_id?: string;
  /** The AtlaSent action the permit was issued for. Absent means finance.payment.authorize (entries written before this field). */
  action_type?: string;
  /** The authorized refund, frozen. Needed to resubmit an unconfirmed refund; absent on older entries. */
  snapshot?: Record<string, unknown>;
  digest?: string;
  /** The order status the authorization was decided on; a resubmission requires it unchanged. */
  order_status?: string;
  /** What happened to POST /v1/refunds. Absent on entries written before this field. */
  submission?: RefundSubmission;
  /** Every provider status seen for this refund, oldest first (submission response, readback, authenticated events). */
  observations?: ProviderObservation[];
}

/**
 * The state of the one POST /v1/refunds an entry may make.
 *
 * - `submitting`: written immediately before the request. Still set after a
 *   crash, so it means the same as `unconfirmed`.
 * - `accepted`: Stripe answered with a refund that matches the authorization.
 *   Accepted is not completed: read the observations.
 * - `rejected`: Stripe definitively did not create it (a 4xx it does not
 *   process, or a returned refund in a failed state).
 * - `unconfirmed`: the request may have created a refund (timeout, connection
 *   lost, 5xx, 409, 429, an unreadable 2xx). Never treated as failed: reconcile
 *   by reading Stripe back, and retry only with the same Idempotency-Key.
 */
export type RefundSubmissionState = "submitting" | "accepted" | "rejected" | "unconfirmed";

export interface RefundSubmission {
  state: RefundSubmissionState;
  at: string;
  detail?: string;
  /** How many times POST /v1/refunds was sent with this entry's Idempotency-Key. */
  attempts?: number;
  /** The exact metadata sent. A resubmission must send identical parameters, or Stripe refuses the key. */
  metadata?: Record<string, string>;
}

export interface ProviderObservation {
  /** submission: the POST response; readback: GET /v1/refunds; event: a signature-verified webhook. */
  source: "submission" | "readback" | "event";
  refund_id: string;
  status: string;
  at: string;
  event_id?: string;
}

/**
 * One in-flight refund on a payment. `reserve` takes it atomically before
 * anything is evaluated, so two calls for the same business request, or two
 * refunds on the same payment, cannot both proceed.
 */
export interface RefundReservation {
  gate_ref: string;
  payment_intent: string;
  amount_cents: number;
  business_request_id?: string;
  created_at: string;
  /** active until released; an unconfirmed submission keeps it active. */
  state: "active" | "released";
  released_reason?: string;
  released_at?: string;
}

export type ReserveResult =
  | { reserved: true }
  /** This gate reference (the same business request) already has a reservation or an entry. */
  | { reserved: false; conflict: "same_request"; reservation?: RefundReservation; entry?: LedgerEntry }
  /** Another refund on this payment is reserved, or its submission is not yet confirmed. */
  | { reserved: false; conflict: "payment_in_flight"; gateRef: string };

/** An entry whose submission may have created a refund that nothing has confirmed yet. */
export function isUnresolvedSubmission(e: LedgerEntry): boolean {
  return e.aborted_reason === undefined && (e.submission?.state === "submitting" || e.submission?.state === "unconfirmed");
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
  resolved?: { outcome: "refunded" | "not_approved" | "stopped" | "unconfirmed"; at: string; detail: string };
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
  /** Atomically reserves one refund; see {@link ReserveResult}. A released reservation for the same reference with no entry is re-activated. */
  reserve(reservation: Omit<RefundReservation, "state">): Promise<ReserveResult>;
  releaseReservation(gateRef: string, reason: string): Promise<void>;
  getReservation(gateRef: string): Promise<RefundReservation | undefined>;
  /** Pending approvals by the escalated attempt's gate reference. */
  findPendingApprovalByGateRef(gateRef: string): Promise<PendingApproval | undefined>;
  recordSubmission(gateRef: string, submission: RefundSubmission): Promise<void>;
  /** Appends one provider observation (duplicates by source+event id are ignored). */
  recordObservation(gateRef: string, observation: ProviderObservation): Promise<void>;
}

export class InMemoryLedger implements PermitLedger {
  protected entries = new Map<string, LedgerEntry>();
  protected pending = new Map<string, PendingApproval>();
  protected reservations = new Map<string, RefundReservation>();

  async recordAuthorized(entry: LedgerEntry): Promise<void> {
    if (this.entries.has(entry.gate_ref)) throw new Error(`duplicate ledger entry ${entry.gate_ref}`);
    this.entries.set(entry.gate_ref, JSON.parse(JSON.stringify(entry)) as LedgerEntry);
    this.persist();
  }

  async reserve(r: Omit<RefundReservation, "state">): Promise<ReserveResult> {
    const existing = this.reservations.get(r.gate_ref);
    const entry = this.entries.get(r.gate_ref);
    if (entry !== undefined || existing?.state === "active") {
      return {
        reserved: false,
        conflict: "same_request",
        ...(existing ? { reservation: { ...existing } } : {}),
        ...(entry ? { entry: JSON.parse(JSON.stringify(entry)) as LedgerEntry } : {}),
      };
    }
    for (const other of this.reservations.values()) {
      if (other.state === "active" && other.payment_intent === r.payment_intent) {
        return { reserved: false, conflict: "payment_in_flight", gateRef: other.gate_ref };
      }
    }
    for (const e of this.entries.values()) {
      if (e.payment_intent === r.payment_intent && isUnresolvedSubmission(e)) {
        return { reserved: false, conflict: "payment_in_flight", gateRef: e.gate_ref };
      }
    }
    this.reservations.set(r.gate_ref, { ...r, state: "active" });
    this.persist();
    return { reserved: true };
  }

  async releaseReservation(gateRef: string, reason: string): Promise<void> {
    const r = this.reservations.get(gateRef);
    if (!r || r.state === "released") return;
    r.state = "released";
    r.released_reason = reason;
    r.released_at = new Date().toISOString();
    this.persist();
  }

  async getReservation(gateRef: string): Promise<RefundReservation | undefined> {
    const r = this.reservations.get(gateRef);
    return r ? { ...r } : undefined;
  }

  async findPendingApprovalByGateRef(gateRef: string): Promise<PendingApproval | undefined> {
    for (const p of this.pending.values()) {
      if (p.gate_ref === gateRef) return JSON.parse(JSON.stringify(p)) as PendingApproval;
    }
    return undefined;
  }

  async recordSubmission(gateRef: string, submission: RefundSubmission): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e) throw new Error(`no ledger entry ${gateRef}`);
    // Confirmed is final: a late local error (a lost response) must not regress
    // what a readback or verified event already established.
    if (e.submission?.state === "accepted" && submission.state !== "accepted") return;
    const attempts = (e.submission?.attempts ?? 0) + (submission.state === "submitting" ? 1 : 0);
    const metadata = submission.metadata ?? e.submission?.metadata;
    e.submission = { ...submission, attempts, ...(metadata ? { metadata: { ...metadata } } : {}) };
    this.persist();
  }

  async recordObservation(gateRef: string, o: ProviderObservation): Promise<void> {
    const e = this.entries.get(gateRef);
    if (!e) throw new Error(`no ledger entry ${gateRef}`);
    const list = (e.observations ??= []);
    if (o.event_id !== undefined && list.some((x) => x.source === o.source && x.event_id === o.event_id)) return;
    list.push({ ...o });
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
    if (e.refund_id !== undefined && e.refund_id !== refundId) return false;
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
    this.reservations.clear();
    let text: string;
    try {
      text = readFileSync(this.path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    const data = JSON.parse(text) as
      | LedgerEntry[]
      | { entries: LedgerEntry[]; pending?: PendingApproval[]; reservations?: RefundReservation[] };
    // An array is the file format before pending approvals existed.
    const rows = Array.isArray(data) ? data : data.entries;
    for (const r of rows) this.entries.set(r.gate_ref, r);
    if (!Array.isArray(data)) {
      for (const p of data.pending ?? []) this.pending.set(p.approval_request_id, p);
      for (const r of data.reservations ?? []) this.reservations.set(r.gate_ref, r);
    }
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
  override claim(gateRef: string, refundId: string): Promise<boolean> {
    return this.locked(() => super.claim(gateRef, refundId));
  }
  override recordPendingApproval(p: PendingApproval): Promise<void> {
    return this.locked(() => super.recordPendingApproval(p));
  }
  override resolvePendingApproval(id: string, resolved: NonNullable<PendingApproval["resolved"]>): Promise<void> {
    return this.locked(() => super.resolvePendingApproval(id, resolved));
  }
  // reserve is the check-and-set that serializes refunds across processes, so it runs under the lock.
  override reserve(r: Omit<RefundReservation, "state">): Promise<ReserveResult> {
    return this.locked(() => super.reserve(r));
  }
  override releaseReservation(gateRef: string, reason: string): Promise<void> {
    return this.locked(() => super.releaseReservation(gateRef, reason));
  }
  override recordSubmission(gateRef: string, submission: RefundSubmission): Promise<void> {
    return this.locked(() => super.recordSubmission(gateRef, submission));
  }
  override recordObservation(gateRef: string, o: ProviderObservation): Promise<void> {
    return this.locked(() => super.recordObservation(gateRef, o));
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
  override async getReservation(gateRef: string): Promise<RefundReservation | undefined> {
    this.load();
    return super.getReservation(gateRef);
  }
  override async findPendingApprovalByGateRef(gateRef: string): Promise<PendingApproval | undefined> {
    this.load();
    return super.findPendingApprovalByGateRef(gateRef);
  }

  protected override persist(): void {
    // Every write runs inside locked(); refuse one that does not, or whose
    // lock was taken over while it worked.
    if (!this.heldLock) throw new LedgerLockError(`write to the permit ledger ${this.path} without its lock; nothing was written`);
    assertLockHeld(this.heldLock.path, this.heldLock.token, this.path);
    const tmp = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(
      tmp,
      JSON.stringify(
        { entries: [...this.entries.values()], pending: [...this.pending.values()], reservations: [...this.reservations.values()] },
        null,
        2,
      ),
    );
    renameSync(tmp, this.path);
  }
}
