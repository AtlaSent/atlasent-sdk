/**
 * Trust-root Phase 2 — hybrid snapshot bootstrap + revocation enforcement.
 *
 * Provides a lightweight TrustSnapshot type (numeric epoch timestamps,
 * JWK-array keys, flat revoked_kids list) alongside three helpers that
 * the verify() path and application code can call directly.
 *
 * Design decisions (ADR-005):
 *
 * - D3 (fail-closed expiry): isTrustSnapshotExpired() defaults to a 24-hour
 *   TTL and returns true when the snapshot is older than that or when
 *   expires_at has already passed. Callers in verify() must treat an expired
 *   snapshot as a denial.
 *
 * - D4 (R2/R3 split): revoked_kids is a flat allowlist consulted for ANY
 *   KID regardless of role. Role enforcement belongs in auditBundle.ts;
 *   this module only answers "is this KID revoked?"
 *
 * - Bootstrap: bootstrapTrust() fetches the .well-known endpoint and merges
 *   the response with an optional pinned snapshot.  The pinned snapshot is
 *   returned as-is if the fetch fails (silent fallback).
 *
 * - Refresh: background scheduling is handled by TrustRootManager in
 *   trustRoot.ts.  bootstrapTrust() is intentionally a one-shot function
 *   for callers that need an explicit initial snapshot without wiring up
 *   the full manager.
 */

/**
 * Minimal JWK key entry as returned by the .well-known endpoint.
 *
 * Deliberately loose — additional vendor-defined fields (kid, use,
 * alg, crv, x, …) are preserved but not enumerated here so the type
 * survives forward additions to the key document.
 */
export interface JWK {
  /** Key identifier — used for revocation checks. */
  kid: string;
  /** Key type, e.g. "OKP", "EC", "RSA". */
  kty: string;
  [key: string]: unknown;
}

/**
 * Trust snapshot in the Phase 2 wire format.
 *
 * Uses numeric epoch-millisecond timestamps so callers can compare
 * directly with Date.now() without parsing ISO-8601 strings.
 */
export interface TrustSnapshot {
  /** Active verification keys from the trust root. */
  keys: JWK[];
  /** KIDs that have been revoked; any permit signed by these must be rejected. */
  revoked_kids: string[];
  /**
   * Unix epoch (ms) when this snapshot was fetched from the server.
   * Used as the reference point for TTL expiry checks.
   */
  fetched_at: number;
  /**
   * Unix epoch (ms) at which this snapshot expires regardless of TTL.
   * bootstrapTrust() derives this from the `valid_until` field in the
   * server response when available, otherwise from fetched_at + TTL.
   */
  expires_at: number;
  /**
   * Set when the fetched documents could not be read in full: a key entry
   * without a string kid/kty was dropped, or `revoked_keys` was present but
   * not a list of rows each naming a kid. Either could have hidden a
   * revocation, so `verifyPermitV4` refuses a snapshot carrying it
   * (`key_set_untrustworthy`, atlasent-api#4640). Absent on a sound fetch.
   */
  revocations_unreadable?: true;
}

/** Default snapshot TTL: 24 hours in milliseconds. */
export const DEFAULT_TRUST_TTL_MS = 24 * 60 * 60 * 1000;

/** Wire shape of GET /.well-known/atlasent-verifier-keys.json */
interface VerifierKeysWire {
  keys?: unknown[];
}

/** Wire shape of GET /.well-known/atlasent-revocations.json */
interface RevocationsWire {
  revoked_keys?: Array<{ kid: string; [k: string]: unknown }>;
}

/** Wire shape of GET /.well-known/atlasent-trust-root.json */
interface TrustRootWire {
  valid_until?: string;
  issued_at?: string;
}

/**
 * Fetch a fresh TrustSnapshot from the AtlaSent trust-root documents.
 *
 * Fetches three documents from `${baseUrl}/.well-known/` in parallel:
 *   - `atlasent-verifier-keys.json`  — active verification keys
 *   - `atlasent-revocations.json`    — revoked KIDs
 *   - `atlasent-trust-root.json`     — validity window (valid_until, issued_at)
 *
 * Uses a 10-second timeout across all three fetches.  On any failure
 * (network error, non-2xx, malformed response) the function returns the
 * `pinnedSnapshot` if provided, or re-throws the underlying error when no
 * fallback is available.
 *
 * The `expires_at` field is derived from the trust-root document's
 * `valid_until` field when present; otherwise it is set to
 * `fetched_at + ttlMs`.
 *
 * @param baseUrl        Root URL of the AtlaSent keys host (no trailing slash).
 * @param pinnedSnapshot Optional pre-loaded snapshot to use as fallback.
 * @param ttlMs          TTL for the snapshot in ms (default: 24 hours).
 * @param fetchImpl      Custom fetch implementation (for tests/environments
 *                       without a global fetch).
 */
export async function bootstrapTrust(
  baseUrl: string,
  pinnedSnapshot?: TrustSnapshot,
  ttlMs: number = DEFAULT_TRUST_TTL_MS,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<TrustSnapshot> {
  let base = baseUrl;
  while (base.endsWith("/")) base = base.slice(0, -1);
  const wk = `${base}/.well-known`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);

    let keysRes: Response, revocRes: Response, indexRes: Response;
    try {
      [keysRes, revocRes] = await Promise.all([
        fetchImpl(`${wk}/atlasent-verifier-keys.json`, { signal: controller.signal }),
        fetchImpl(`${wk}/atlasent-revocations.json`, { signal: controller.signal }),
      ]);
      indexRes = await fetchImpl(`${wk}/atlasent-trust-root.json`, { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }

    if (!keysRes.ok || !revocRes.ok || !indexRes.ok) {
      if (pinnedSnapshot !== undefined) return pinnedSnapshot;
      const failedStatus = !keysRes.ok
        ? keysRes.status
        : !revocRes.ok
          ? revocRes.status
          : indexRes.status;
      throw new Error(
        `bootstrapTrust: server returned HTTP ${failedStatus} from ${wk}`,
      );
    }

    const [keysWire, revocWire, indexWire] = await Promise.all([
      keysRes.json() as Promise<VerifierKeysWire>,
      revocRes.json() as Promise<RevocationsWire>,
      indexRes.json() as Promise<TrustRootWire>,
    ]);

    // Coerce keys to JWK[]: accept any array entry that has a `kid` string.
    const rawKeys: unknown[] = Array.isArray(keysWire.keys) ? keysWire.keys : [];
    const keys: JWK[] = rawKeys.filter(
      (k): k is JWK =>
        k !== null &&
        typeof k === "object" &&
        typeof (k as Record<string, unknown>).kid === "string" &&
        typeof (k as Record<string, unknown>).kty === "string",
    ) as JWK[];

    // A dropped key entry, or a revocations ledger that is present but not a
    // list of rows each naming a kid, may have hidden a revocation: the
    // snapshot is marked so the permit verifier refuses it (fail closed).
    const ledgerWire: unknown = revocWire.revoked_keys;
    const revocationsUnreadable =
      keys.length !== rawKeys.length ||
      !Array.isArray(keysWire.keys) ||
      (ledgerWire !== undefined &&
        (!Array.isArray(ledgerWire) ||
          !ledgerWire.every(
            (r) =>
              r !== null &&
              typeof r === "object" &&
              typeof (r as Record<string, unknown>).kid === "string" &&
              ((r as Record<string, unknown>).kid as string).length > 0,
          )));

    // Revoked KIDs from the dedicated revocations document.
    const revokedKids: string[] = Array.isArray(revocWire.revoked_keys)
      ? revocWire.revoked_keys
          .filter(
            (r): r is { kid: string } =>
              r !== null &&
              typeof r === "object" &&
              typeof (r as Record<string, unknown>).kid === "string",
          )
          .map((r) => r.kid)
      : [];

    const fetchedAt = Date.now();
    const expiresAt =
      typeof indexWire.valid_until === "string" && indexWire.valid_until.length > 0
        ? new Date(indexWire.valid_until).getTime()
        : fetchedAt + ttlMs;

    return {
      keys,
      revoked_kids: revokedKids,
      fetched_at: fetchedAt,
      expires_at: Number.isFinite(expiresAt) ? expiresAt : fetchedAt + ttlMs,
      ...(revocationsUnreadable ? { revocations_unreadable: true as const } : {}),
    };
  } catch (err) {
    if (pinnedSnapshot !== undefined) {
      // Silent fallback to the pinned snapshot (ADR-005 D2 refresh-failure policy).
      return pinnedSnapshot;
    }
    throw err;
  }
}

/**
 * Returns true when the snapshot should be treated as expired.
 *
 * A snapshot is expired when EITHER:
 *   1. `expires_at` is in the past, OR
 *   2. `fetched_at + ttlMs` is in the past (age-based eviction).
 *
 * The stricter of the two checks wins so a snapshot that was fetched
 * recently but carries an already-expired `expires_at` is still rejected.
 *
 * ADR-005 D3: callers in the verify() path MUST treat an expired
 * snapshot as a denial (`failClosedOnExpiry` is honoured by the client
 * integration — see verify.ts).
 *
 * @param snapshot  The snapshot to check.
 * @param ttlMs     Maximum age in ms from `fetched_at` (default: 24 hours).
 * @param nowMs     Override for `Date.now()` (for testing).
 */
export function isTrustSnapshotExpired(
  snapshot: TrustSnapshot,
  ttlMs: number = DEFAULT_TRUST_TTL_MS,
  nowMs: number = Date.now(),
): boolean {
  // Check explicit expiry timestamp
  if (nowMs > snapshot.expires_at) return true;
  // Check age-based TTL from when the snapshot was fetched
  if (nowMs > snapshot.fetched_at + ttlMs) return true;
  return false;
}

/**
 * Returns true when the given KID appears in the snapshot's revocation list.
 *
 * Used by the verify() path before accepting a permit's signature:
 * ```ts
 * if (isKidRevoked(snapshot, permit.kid)) {
 *   return { valid: false, reason: 'SIGNING_KEY_REVOKED' };
 * }
 * ```
 *
 * @param snapshot  Trust snapshot to consult.
 * @param kid       Key identifier from the permit or audit bundle header.
 */
export function isKidRevoked(snapshot: TrustSnapshot, kid: string): boolean {
  return snapshot.revoked_kids.includes(kid);
}
