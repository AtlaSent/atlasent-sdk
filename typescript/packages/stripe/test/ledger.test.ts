import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { PermitLedger } from "../src/ledger.js";
import { acquireFileLock, assertLockHeld, InMemoryLedger, JsonFileLedger, LedgerLockError, removeLockIfHeldBy, type LedgerEntry } from "../src/ledger.js";
import type { StripeRefund } from "../src/stripe.js";
import { auditStripeRefund } from "../src/webhook.js";

const run = promisify(execFile);
const WRITER = fileURLToPath(new URL("./fixtures/ledger-writer.ts", import.meta.url));

/** Records refunds from a separate Node process, as the CLI does. */
const writeFromAnotherProcess = (path: string, prefix: string, count: number) =>
  run(process.execPath, ["--import", "tsx", WRITER, path, prefix, String(count)], { timeout: 60_000 });

const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry => ({
  gate_ref: "ref-1",
  permit_sha256: "x",
  audit_hash: "a",
  payment_intent: "pi_1001",
  amount_cents: 1899,
  actor_id: "support-tool:dana",
  authorized_at: new Date(0).toISOString(),
  ...over,
});

const refund = (over: Partial<StripeRefund> = {}): StripeRefund => ({
  id: "re_1",
  status: "succeeded",
  amount: 1899,
  currency: "usd",
  charge: "ch_1001",
  payment_intent: "pi_1001",
  metadata: { atlasent_gate_ref: "ref-1" },
  ...over,
});

let dir = "";
const ledgerPath = () => {
  dir = mkdtempSync(join(tmpdir(), "stripe-ledger-"));
  return join(dir, "refund-ledger.json");
};
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = "";
});

describe("JsonFileLedger shared between processes", () => {
  it("the webhook server sees a refund another process recorded after the server started", async () => {
    const path = ledgerPath();
    const server = new JsonFileLedger(path); // started first, file does not exist yet
    await writeFromAnotherProcess(path, "cli", 1);
    const seen = await server.get("cli-0");
    expect(seen?.payment_intent).toBe("pi_cli_0");
    const verdict = await auditStripeRefund(
      refund({ amount: 1000, payment_intent: "pi_cli_0", metadata: { atlasent_gate_ref: "cli-0" } }),
      server,
    );
    expect(verdict.verdict).toBe("authorized");
  }, 60_000);

  it("a claim by the server and a write by another process do not erase each other", async () => {
    const path = ledgerPath();
    const server = new JsonFileLedger(path);
    await writeFromAnotherProcess(path, "a", 1);
    expect(await server.claim("a-0", "re_a")).toBe(true);
    await writeFromAnotherProcess(path, "b", 1);
    const after = new JsonFileLedger(path);
    expect((await after.get("a-0"))?.matched_refund_id).toBe("re_a");
    expect(await after.get("b-0")).toBeDefined();
  }, 60_000);

  it("processes writing at once keep every entry", async () => {
    const path = ledgerPath();
    const writers = ["p1", "p2", "p3", "p4"];
    const each = 100;
    await Promise.all(writers.map((w) => writeFromAnotherProcess(path, w, each)));
    const data = JSON.parse(readFileSync(path, "utf8")) as { entries: LedgerEntry[] };
    const refs = new Set(data.entries.map((e) => e.gate_ref));
    expect(refs.size).toBe(writers.length * each);
    for (const w of writers) for (let i = 0; i < each; i++) expect(refs.has(`${w}-${i}`)).toBe(true);
  }, 120_000);
});

describe("JsonFileLedger lock failure fails closed", () => {
  const holdLock = (path: string) => writeFileSync(`${path}.lock`, "held by another process\n");

  it("a write that cannot take the lock throws LedgerLockError and changes nothing", async () => {
    const path = ledgerPath();
    holdLock(path);
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 50 });
    await expect(ledger.recordAuthorized(entry())).rejects.toBeInstanceOf(LedgerLockError);
    expect(await ledger.get("ref-1")).toBeUndefined();
  });

  it("the webhook reports a gated refund as unauthorized when the ledger cannot be locked", async () => {
    const path = ledgerPath();
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 50 });
    await ledger.recordAuthorized(entry());
    holdLock(path);
    const verdict = await auditStripeRefund(refund(), ledger);
    expect(verdict.verdict).toBe("unauthorized");
    expect(verdict.verdict === "unauthorized" && verdict.reason).toMatch(/permit ledger is unavailable/);
    // Nothing was claimed, so once the lock is free the refund is still accounted for exactly once.
    rmSync(`${path}.lock`);
    expect((await auditStripeRefund(refund(), ledger)).verdict).toBe("authorized");
  });

  it("an unreadable ledger file is unauthorized, not authorized", async () => {
    const path = ledgerPath();
    const ledger = new JsonFileLedger(path);
    await ledger.recordAuthorized(entry());
    writeFileSync(path, "{ not json"); // corrupted after the server started
    expect((await auditStripeRefund(refund(), ledger)).verdict).toBe("unauthorized");
  });

  it("a lock left by a crashed process is removed once stale", async () => {
    const path = ledgerPath();
    holdLock(path);
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 2000, staleLockMs: 0 });
    await ledger.recordAuthorized(entry());
    expect(await ledger.get("ref-1")).toBeDefined();
  });
});

/** Writes a lock file as another holder would, `ageMs` old. */
function foreignLock(path: string, token: string, ageMs = 0): void {
  writeFileSync(`${path}.lock`, token);
  const t = (Date.now() - ageMs) / 1000;
  utimesSync(`${path}.lock`, t, t);
}

describe("JsonFileLedger lock ownership", () => {
  it("a lock younger than staleLockMs is never taken over: the write fails closed", async () => {
    const path = ledgerPath();
    foreignLock(path, "999 someone-else");
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 100, staleLockMs: 30_000 });
    await expect(ledger.recordAuthorized(entry())).rejects.toBeInstanceOf(LedgerLockError);
    expect(readFileSync(`${path}.lock`, "utf8")).toBe("999 someone-else");
  });

  it("an expired lock is taken over even if its pid now belongs to a live process (pid reuse)", async () => {
    const path = ledgerPath();
    foreignLock(path, `${process.pid} from-a-previous-container`, 60_000);
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 2000, staleLockMs: 30_000 });
    await ledger.recordAuthorized(entry());
    expect(await ledger.get("ref-1")).toBeDefined();
    expect(existsSync(`${path}.lock`)).toBe(false);
  });

  it("taking over an expired lock never removes the newer lock now in its place", async () => {
    const path = ledgerPath();
    const lockPath = `${path}.lock`;
    // This process saw an expired lock holding "old"; another recoverer removed it and a live writer took the lock.
    const live = await acquireFileLock(lockPath, path, { timeoutMs: 1000, staleMs: 30_000 });
    expect(removeLockIfHeldBy(lockPath, "123 old")).toBe(false);
    expect(readFileSync(lockPath, "utf8")).toBe(live);
    expect(removeLockIfHeldBy(lockPath, live)).toBe(true);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("a holder whose lock was taken over writes nothing and fails closed", async () => {
    const path = ledgerPath();
    const ledger = new JsonFileLedger(path);
    await ledger.recordAuthorized(entry({ gate_ref: "before" }));
    const before = readFileSync(path, "utf8");
    const locked = (ledger as unknown as { locked: (op: () => Promise<void>) => Promise<void> }).locked.bind(ledger);
    await expect(
      locked(async () => {
        writeFileSync(`${path}.lock`, "456 took-it-over"); // another process took the lock while this one worked
        await InMemoryLedger.prototype.recordAuthorized.call(ledger, entry({ gate_ref: "after" })); // the unlocked inner write
      }),
    ).rejects.toBeInstanceOf(LedgerLockError);
    expect(readFileSync(path, "utf8")).toBe(before);
    expect(readFileSync(`${path}.lock`, "utf8")).toBe("456 took-it-over"); // and its lock is left alone
    expect(() => assertLockHeld(`${path}.lock`, "mine", path)).toThrow(LedgerLockError);
  });

  it("releasing never removes a lock this holder does not own", () => {
    const path = ledgerPath();
    foreignLock(path, "123 another-holder");
    expect(removeLockIfHeldBy(`${path}.lock`, `${process.pid} mine`)).toBe(false);
    expect(readFileSync(`${path}.lock`, "utf8")).toBe("123 another-holder");
  });

  it("processes recovering the same expired lock at once keep every entry", async () => {
    const path = ledgerPath();
    foreignLock(path, "1 crashed", 60_000);
    const writers = ["r1", "r2", "r3", "r4"];
    await Promise.all(writers.map((w) => writeFromAnotherProcess(path, w, 50)));
    const data = JSON.parse(readFileSync(path, "utf8")) as { entries: LedgerEntry[] };
    expect(new Set(data.entries.map((e) => e.gate_ref)).size).toBe(200);
  }, 120_000);
});

describe("claim re-checks the entry under the lock", () => {
  it("a refund the gate cancelled between the webhook's read and its claim is not authorized", async () => {
    const path = ledgerPath();
    const server = new JsonFileLedger(path);
    const cli = new JsonFileLedger(path); // the gate, in another process
    await cli.recordAuthorized(entry());
    // The webhook reads the entry, then the gate cancels it before the claim takes the lock.
    const racing: PermitLedger = {
      get: async (ref) => {
        const e = await server.get(ref);
        await cli.recordAborted(ref, "request error after Stripe created the refund");
        return e;
      },
      claim: (ref, id) => server.claim(ref, id),
      recordAuthorized: (e) => server.recordAuthorized(e),
      recordExecuted: (r, id) => server.recordExecuted(r, id),
      recordAborted: (r, why) => server.recordAborted(r, why),
      recordPendingApproval: (p) => server.recordPendingApproval(p),
      getPendingApproval: (id) => server.getPendingApproval(id),
      resolvePendingApproval: (id, r) => server.resolvePendingApproval(id, r),
    };
    const verdict = await auditStripeRefund(refund(), racing);
    expect(verdict.verdict).toBe("unauthorized");
    expect(verdict.verdict === "unauthorized" && verdict.reason).toMatch(/gate stopped this refund/);
    expect((await server.get("ref-1"))?.matched_refund_id).toBeUndefined();
  });

  it("an entry already completed with a different refund id cannot be claimed by another refund", async () => {
    const path = ledgerPath();
    const ledger = new JsonFileLedger(path);
    await ledger.recordAuthorized(entry());
    await ledger.recordExecuted("ref-1", "re_gated");
    expect(await ledger.claim("ref-1", "re_other")).toBe(false);
    expect(await ledger.claim("ref-1", "re_gated")).toBe(true);
  });
});
