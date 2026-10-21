import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Makes writing the lock token fail, as a full disk would, while the lock
// file itself is created.
const failTokenWrite = vi.hoisted(() => ({ on: false }));
vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  return {
    ...fs,
    writeFileSync: (...args: Parameters<typeof fs.writeFileSync>) => {
      if (failTokenWrite.on && typeof args[0] === "number") {
        throw Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });
      }
      return fs.writeFileSync(...args);
    },
  };
});

const { acquireFileLock, JsonFileLedger } = await import("../src/ledger.js");

let dir = "";
afterEach(() => {
  failTokenWrite.on = false;
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = "";
});

describe("a lock whose token cannot be written", () => {
  it("is removed again, so it cannot block later writers", async () => {
    dir = mkdtempSync(join(tmpdir(), "ledger-lock-init-"));
    const path = join(dir, "refund-ledger.json");
    failTokenWrite.on = true;
    await expect(acquireFileLock(`${path}.lock`, path, { timeoutMs: 100 })).rejects.toThrow(/ENOSPC/);
    expect(existsSync(`${path}.lock`)).toBe(false);
    failTokenWrite.on = false;
    const ledger = new JsonFileLedger(path, { lockTimeoutMs: 100 });
    await ledger.recordAuthorized({
      gate_ref: "ref-1",
      permit_sha256: "x",
      audit_hash: "a",
      amount_cents: 1,
      actor_id: "t",
      authorized_at: new Date(0).toISOString(),
      ...({ payment_intent: "pi_1" }),
    });
    expect(await ledger.get("ref-1")).toBeDefined();
  });
});
