import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { JsonFileLedger, LedgerLockError, refundNote, type LedgerEntry } from "../src/ledger.js";
import { auditRefundWebhook } from "../src/webhook.js";

const run = promisify(execFile);
const WRITER = fileURLToPath(new URL("./fixtures/ledger-writer.ts", import.meta.url));

/** Records refunds from a separate Node process, as the CLI and agent do. */
const writeFromAnotherProcess = (path: string, prefix: string, count: number) =>
  run(process.execPath, ["--import", "tsx", WRITER, path, prefix, String(count)], { timeout: 60_000 });

const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry => ({
  gate_ref: "ref-1",
  permit_sha256: "x",
  audit_hash: "a",
  order_id: "gid://shopify/Order/1001",
  amount_cents: 1899,
  actor_id: "shopify-staff:s/1",
  authorized_at: new Date(0).toISOString(),
  ...over,
});

const payload = (over: Record<string, unknown> = {}) => ({
  id: 555,
  order_id: 1001,
  note: refundNote("ref-1", "arrived torn"),
  transactions: [{ kind: "refund", status: "success", amount: "18.99" }],
  ...over,
});

let dir = "";
const ledgerPath = () => {
  dir = mkdtempSync(join(tmpdir(), "shopify-ledger-"));
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
    expect((await server.get("cli-0"))?.order_id).toBe("gid://shopify/Order/1");
    const verdict = await auditRefundWebhook(
      payload({ order_id: 1, note: refundNote("cli-0"), transactions: [{ kind: "refund", status: "success", amount: "10.00" }] }),
      server,
    );
    expect(verdict.verdict).toBe("authorized");
  }, 60_000);

  it("a claim by the server and a write by another process do not erase each other", async () => {
    const path = ledgerPath();
    const server = new JsonFileLedger(path);
    await writeFromAnotherProcess(path, "a", 1);
    expect(await server.claim("a-0", "555")).toBe(true);
    await writeFromAnotherProcess(path, "b", 1);
    const after = new JsonFileLedger(path);
    expect((await after.get("a-0"))?.matched_refund_id).toBe("555");
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
    const verdict = await auditRefundWebhook(payload(), ledger);
    expect(verdict.verdict).toBe("unauthorized");
    expect(verdict.verdict === "unauthorized" && verdict.reason).toMatch(/permit ledger is unavailable/);
    // Nothing was claimed, so once the lock is free the refund is still accounted for exactly once.
    rmSync(`${path}.lock`);
    expect((await auditRefundWebhook(payload(), ledger)).verdict).toBe("authorized");
  });

  it("an unreadable ledger file is unauthorized, not authorized", async () => {
    const path = ledgerPath();
    const ledger = new JsonFileLedger(path);
    await ledger.recordAuthorized(entry());
    writeFileSync(path, "{ not json"); // corrupted after the server started
    expect((await auditRefundWebhook(payload(), ledger)).verdict).toBe("unauthorized");
  });

  it("a lock left by a crashed process is removed once stale", async () => {
    const path = ledgerPath();
    holdLock(path);
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 2000, staleLockMs: 0 });
    await ledger.recordAuthorized(entry());
    expect(await ledger.get("ref-1")).toBeDefined();
  });
});
