import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Makes writing the lock token fail, as a full disk would, while the lock
// file itself is created.
const failTokenWrite = vi.hoisted(() => ({
  on: false,
  close: false,
  renameLock: false,
  readAside: false,
  /** After the lock is renamed aside, another process creates a new lock with this token. */
  takeOverWith: undefined as string | undefined,
}));
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
    closeSync: (fd: number) => {
      fs.closeSync(fd);
      if (failTokenWrite.close) {
        failTokenWrite.close = false;
        throw Object.assign(new Error("EIO: i/o error, close"), { code: "EIO" });
      }
    },
    readFileSync: (...args: Parameters<typeof fs.readFileSync>) => {
      if (failTokenWrite.readAside && String(args[0]).endsWith(".aside")) {
        failTokenWrite.readAside = false;
        throw Object.assign(new Error("EIO: i/o error, read"), { code: "EIO" });
      }
      return fs.readFileSync(...args);
    },
    renameSync: (from: import("node:fs").PathLike, to: import("node:fs").PathLike) => {
      if (failTokenWrite.renameLock && String(from).endsWith(".lock")) {
        failTokenWrite.renameLock = false;
        throw Object.assign(new Error("EIO: i/o error, rename"), { code: "EIO" });
      }
      fs.renameSync(from, to);
      if (failTokenWrite.takeOverWith !== undefined && String(from).endsWith(".lock")) {
        fs.writeFileSync(String(from), failTokenWrite.takeOverWith, { flag: "wx" });
        failTokenWrite.takeOverWith = undefined;
      }
    },
  };
});

const { acquireFileLock, isLockTracked, JsonFileLedger, removeLockIfHeldBy } = await import("../src/ledger.js");
const { readFileSync } = await import("node:fs");

let dir = "";
afterEach(() => {
  failTokenWrite.on = false;
  failTokenWrite.close = false;
  failTokenWrite.renameLock = false;
  failTokenWrite.readAside = false;
  failTokenWrite.takeOverWith = undefined;
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

  it("is removed if closing it fails after the token was written", async () => {
    dir = mkdtempSync(join(tmpdir(), "ledger-lock-init-"));
    const path = join(dir, "refund-ledger.json");
    failTokenWrite.close = true;
    await expect(acquireFileLock(`${path}.lock`, path, { timeoutMs: 100 })).rejects.toThrow(/EIO/);
    expect(existsSync(`${path}.lock`)).toBe(false);
    expect(isLockTracked(`${path}.lock`)).toBe(false);
  });
});

describe("a release that fails", () => {
  it("keeps the lock tracked so the exit hook can still remove it", async () => {
    dir = mkdtempSync(join(tmpdir(), "ledger-lock-init-"));
    const lockPath = join(dir, "refund-ledger.json.lock");
    const token = await acquireFileLock(lockPath, join(dir, "refund-ledger.json"), { timeoutMs: 100 });
    failTokenWrite.renameLock = true;
    expect(() => removeLockIfHeldBy(lockPath, token)).toThrow(/EIO/);
    expect(readFileSync(lockPath, "utf8")).toBe(token);
    expect(isLockTracked(lockPath)).toBe(true);
    expect(removeLockIfHeldBy(lockPath, token)).toBe(true);
    expect(isLockTracked(lockPath)).toBe(false);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("keeps the lock tracked, and in place, when its token cannot be read back", async () => {
    dir = mkdtempSync(join(tmpdir(), "ledger-lock-init-"));
    const lockPath = join(dir, "refund-ledger.json.lock");
    const token = await acquireFileLock(lockPath, join(dir, "refund-ledger.json"), { timeoutMs: 100 });
    failTokenWrite.readAside = true;
    expect(removeLockIfHeldBy(lockPath, token)).toBe(false);
    expect(readFileSync(lockPath, "utf8")).toBe(token);
    expect(isLockTracked(lockPath)).toBe(true);
    expect(removeLockIfHeldBy(lockPath, token)).toBe(true);
    expect(isLockTracked(lockPath)).toBe(false);
  });

  it("stops tracking when the token is unreadable and a new holder took the path meanwhile", async () => {
    dir = mkdtempSync(join(tmpdir(), "ledger-lock-init-"));
    const lockPath = join(dir, "refund-ledger.json.lock");
    const token = await acquireFileLock(lockPath, join(dir, "refund-ledger.json"), { timeoutMs: 100 });
    failTokenWrite.readAside = true;
    failTokenWrite.takeOverWith = "999 new-holder";
    expect(removeLockIfHeldBy(lockPath, token)).toBe(false);
    expect(readFileSync(lockPath, "utf8")).toBe("999 new-holder");
    expect(isLockTracked(lockPath)).toBe(false); // the exit hook must not touch the new holder's lock
  });
});
