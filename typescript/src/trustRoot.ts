/**
 * Hybrid trust-root bootstrap and snapshot management.
 *
 * Seeds synchronously from an embedded baseline snapshot (see
 * vendoredTrustRoot.generated.ts) — a plain object literal compiled
 * directly into this module, not read from disk at runtime. Optionally
 * refreshes from https://keys.atlasent.io/.well-known/ on a configurable
 * interval (default 4h, floor 5 min per ADR-005 D2). Refresh failure is
 * silent — falls back to the in-memory snapshot.
 *
 * Snapshot expiry (valid_until) is fail-closed per ADR-005 D3:
 * checkExpiry() emits a one-time console.warn at half-life, and again
 * on expiry. verifyAuditBundle throws BundleVerificationError when
 * expired (unless allowExpiredSnapshot=true is passed).
 *
 * CORRECTED: this module previously read vendor/trust-root/*.json via
 * fs.readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "..",
 * "..", ...)) at first use. Two independent defects made that path
 * unreachable in every real install: (1) package.json's `files` field
 * never listed `vendor`, so those JSON files were never included in the
 * published npm tarball; (2) even had they been included, tsup bundles
 * every entry into one flat file per format (dist/index.js), and going
 * up two directories from dist/ overshoots the package root by one level
 * — the math only ever "worked" by coincidence in this monorepo's dev
 * checkout, where vendor/ happens to sit two levels above typescript/src/
 * at the monorepo root. Confirmed by instantiating the real published
 * package (2.16.0) and reading its trust root: zero keys, zero
 * revocations, valid_until 2099 — the hardcoded empty fallback, always.
 * Every verifyBundle() call that didn't pass its own trustRoot explicitly
 * silently got a snapshot that can never detect a revoked key or a
 * role-mismatched key, contradicting this file's own ADR-005 D3/D4
 * fail-closed design. It was also a static node:fs/node:url/node:path
 * import, which broke bundling for any browser consumer regardless of
 * whether the file read itself would have succeeded. Embedding the
 * snapshot as a plain object literal (this module has zero imports of
 * its own) fixes both: no file I/O, no path guessing, nothing
 * Node-specific to bundle, and the data is present the instant the
 * module loads, in any environment.
 */

import { VENDORED_TRUST_ROOT_SNAPSHOT } from "./vendoredTrustRoot.generated.js";

// Types for the trust-root document shapes
export interface TrustRootKey {
  kid: string;
  role: "R1_release" | "R2_permit" | "R3_audit" | "R4_pack";
  kty: string;
  crv?: string;
  alg: string;
  x?: string;
  valid_from?: string | null;
  valid_until?: string | null;
  replaced_by?: string | null;
  revoked?: boolean;
  tenant?: string | null;
}

export interface TrustRootRevocationEntry {
  kid: string;
  role?: string;
  revoked_at: string;
  reason?: string;
}

export interface TrustRootSnapshot {
  /** ISO-8601 expiry of this snapshot; fail-closed when exceeded */
  valid_until: string;
  issued_at: string;
  keys: TrustRootKey[];
  revoked_keys: TrustRootRevocationEntry[];
  revoked_identities: Array<{ identity: string; revoked_at: string; reason?: string }>;
}

export interface TrustRootManagerOptions {
  /** Override the refresh URL (default: https://keys.atlasent.io/.well-known/) */
  refreshBaseUrl?: string;
  /** Refresh interval in ms. Default: 4h. Floor: 5 min. */
  refreshIntervalMs?: number;
  /** Disable automatic background refresh. */
  disableRefresh?: boolean;
  /** Custom fetch implementation (for tests). */
  fetch?: typeof fetch;
}

const REFRESH_INTERVAL_MS_DEFAULT = 4 * 60 * 60 * 1000; // 4 hours
const REFRESH_INTERVAL_MS_FLOOR = 5 * 60 * 1000; // 5 minutes
const KEYS_BASE_URL = "https://keys.atlasent.io/.well-known";

// Half-life and expiry warnings: emitted once per process (ADR-005 D3).
let _halfLifeWarningEmitted = false;
let _expiredWarningEmitted = false;

function _resetWarningFlags(): void {
  _halfLifeWarningEmitted = false;
  _expiredWarningEmitted = false;
}

export class TrustRootManager {
  private _snapshot: TrustRootSnapshot;
  private _refreshTimer: ReturnType<typeof setInterval> | null = null;
  private readonly _opts: Required<TrustRootManagerOptions>;

  constructor(
    initialSnapshot: TrustRootSnapshot,
    opts: TrustRootManagerOptions = {},
  ) {
    this._snapshot = initialSnapshot;
    const intervalMs = Math.max(
      opts.refreshIntervalMs ?? REFRESH_INTERVAL_MS_DEFAULT,
      REFRESH_INTERVAL_MS_FLOOR,
    );
    this._opts = {
      refreshBaseUrl: opts.refreshBaseUrl ?? KEYS_BASE_URL,
      refreshIntervalMs: intervalMs,
      disableRefresh: opts.disableRefresh ?? false,
      fetch:
        opts.fetch ??
        (typeof globalThis !== "undefined" && globalThis.fetch
          ? globalThis.fetch.bind(globalThis)
          : ((_url: string) =>
              Promise.reject(new Error("fetch not available"))) as typeof fetch),
    };
    if (!this._opts.disableRefresh) {
      this._scheduleRefresh();
    }
  }

  getSnapshot(): TrustRootSnapshot {
    return this._snapshot;
  }

  /**
   * Check whether the snapshot is expired, emit one-time warnings at
   * half-life and expiry.  Returns "ok" | "half_life" | "expired".
   *
   * Emits console.warn once per process at half-life (ADR-005 D3).
   * Emits console.warn once per process on expiry.
   */
  checkExpiry(): "ok" | "half_life" | "expired" {
    const snap = this._snapshot;
    const now = Date.now();
    const issuedAt = new Date(snap.issued_at).getTime();
    const validUntil = new Date(snap.valid_until).getTime();

    if (now > validUntil) {
      if (!_expiredWarningEmitted) {
        _expiredWarningEmitted = true;
        const daysAgo = Math.floor((now - validUntil) / (24 * 60 * 60 * 1000));
        // eslint-disable-next-line no-console
        console.warn(
          `[atlasent] Trust snapshot expired ${daysAgo} day(s) ago (valid_until: ${snap.valid_until}). ` +
            "Update to a newer SDK build or enable allowExpiredSnapshot.",
        );
      }
      return "expired";
    }
    const window = validUntil - issuedAt;
    const halfLife = issuedAt + window / 2;
    if (now > halfLife) {
      if (!_halfLifeWarningEmitted) {
        _halfLifeWarningEmitted = true;
        const daysLeft = Math.floor((validUntil - now) / (24 * 60 * 60 * 1000));
        // eslint-disable-next-line no-console
        console.warn(
          `[atlasent] Trust snapshot at half-life: expires in ${daysLeft} day(s) (valid_until: ${snap.valid_until}). ` +
            "Plan an SDK update.",
        );
      }
      return "half_life";
    }
    return "ok";
  }

  /** Look up a key entry by kid. Returns undefined if not found. */
  lookupKey(kid: string): TrustRootKey | undefined {
    return this._snapshot.keys.find((k) => k.kid === kid);
  }

  /** Returns true if the kid appears in revoked_keys. */
  isRevoked(kid: string): boolean {
    return this._snapshot.revoked_keys.some((r) => r.kid === kid);
  }

  /** Replace the snapshot (e.g. after a successful refresh). */
  replaceSnapshot(next: TrustRootSnapshot): void {
    this._snapshot = next;
  }

  stopRefresh(): void {
    if (this._refreshTimer !== null) {
      clearInterval(this._refreshTimer);
      this._refreshTimer = null;
    }
  }

  private _scheduleRefresh(): void {
    this._refreshTimer = setInterval(() => {
      void this._doRefresh();
    }, this._opts.refreshIntervalMs);
    // Don't hold the process open.
    if (
      this._refreshTimer &&
      typeof this._refreshTimer === "object" &&
      "unref" in this._refreshTimer
    ) {
      (this._refreshTimer as { unref(): void }).unref();
    }
  }

  private async _doRefresh(): Promise<void> {
    try {
      const base = this._opts.refreshBaseUrl.replace(/\/$/, "");
      const [keysRes, revocRes] = await Promise.all([
        this._opts.fetch(`${base}/atlasent-verifier-keys.json`),
        this._opts.fetch(`${base}/atlasent-revocations.json`),
      ]);
      const indexRes = await this._opts.fetch(`${base}/atlasent-trust-root.json`);

      if (!keysRes.ok || !revocRes.ok || !indexRes.ok) return;

      const [keys, revoc, index] = await Promise.all([
        keysRes.json() as Promise<{ keys: TrustRootKey[] }>,
        revocRes.json() as Promise<{
          revoked_keys: TrustRootRevocationEntry[];
          revoked_identities: unknown[];
        }>,
        indexRes.json() as Promise<{ valid_until: string; issued_at: string }>,
      ]);

      if (!index.valid_until || !Array.isArray(keys.keys)) return;
      // A revocation ledger that is present but unreadable keeps the current
      // snapshot rather than installing "nothing revoked" (atlasent-api#4640).
      const ledger: unknown = revoc?.revoked_keys;
      if (
        ledger !== undefined &&
        (!Array.isArray(ledger) ||
          !ledger.every(
            (r) =>
              r !== null &&
              typeof r === "object" &&
              typeof (r as Record<string, unknown>).kid === "string" &&
              ((r as Record<string, unknown>).kid as string).length > 0,
          ))
      ) {
        return;
      }

      this._snapshot = {
        valid_until: index.valid_until,
        issued_at: index.issued_at ?? this._snapshot.issued_at,
        keys: keys.keys,
        revoked_keys: revoc.revoked_keys ?? [],
        revoked_identities:
          (revoc.revoked_identities as Array<{
            identity: string;
            revoked_at: string;
          }>) ?? [],
      };
    } catch {
      // Refresh failure is silent — keep using the current snapshot.
    }
  }
}

// ─── Load the embedded (vendored) snapshot ───────────────────────────────────

function _loadVendorSnapshot(): TrustRootSnapshot {
  // The embedded constant is committed source (see vendoredTrustRoot.generated.ts),
  // always present at build time — there is no I/O and nothing to fall back from.
  return VENDORED_TRUST_ROOT_SNAPSHOT;
}

// Process-global manager — created lazily.
let _globalManager: TrustRootManager | null = null;

export function getGlobalTrustRootManager(
  opts?: TrustRootManagerOptions,
): TrustRootManager {
  if (!_globalManager) {
    _globalManager = new TrustRootManager(
      _loadVendorSnapshot(),
      opts ?? { disableRefresh: false },
    );
  }
  return _globalManager;
}

/** Replace the global manager (primarily for tests). */
export function __setGlobalTrustRootManagerForTests(
  mgr: TrustRootManager | null,
): void {
  _globalManager = mgr;
  _resetWarningFlags();
}

export { _resetWarningFlags as __resetWarningFlagsForTests };
