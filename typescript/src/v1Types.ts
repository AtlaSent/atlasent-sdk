/**
 * Shared V1 API wire types used across multiple SDK modules.
 *
 * These reflect the canonical domain objects returned by the
 * atlasent-control-plane V1 API. Import from here to avoid circular
 * dependencies between proof.ts, overrides.ts, and types.ts.
 */

/**
 * Canonical Permit domain object as returned by the V1 API.
 *
 * All timestamps are ISO-8601 UTC strings.
 *
 * This is the richer V1 shape returned by `GET /v1-permits/:id` and
 * embedded in proof bundles. It differs from the legacy `PermitRecord`
 * in `types.ts` which uses snake_case and legacy fields from the
 * Supabase function surface.
 */
export interface PermitV1 {
  id: string;
  orgId: string;
  /** Who the permit was issued for (actor or agent ID). */
  subject: string;
  /** What the permit grants (action/resource scope). */
  scope: string;
  status: "active" | "revoked" | "expired";
  /** The evaluation that produced this permit, or `null` for admin issuance. */
  evaluationId: string | null;
  /** Actor who issued the permit (system or admin). */
  issuedBy: string;
  /** Actor who revoked the permit, or `null`. */
  revokedBy: string | null;
  /** ISO-8601 issuance timestamp. */
  issuedAt: string;
  /** ISO-8601 revocation timestamp, or `null`. */
  revokedAt: string | null;
  /** ISO-8601 expiry timestamp, or `null` if the permit does not expire. */
  expiresAt: string | null;
  /** Arbitrary key/value metadata. `null` when none. */
  metadata: Record<string, unknown> | null;
}

/**
 * Canonical governance event as stored in the event log.
 *
 * `type` is a dotted domain-prefixed string, e.g. `override.created`,
 * `permit.revoked`, `evaluation.decided`.
 *
 * `actorId` is `null` for system-emitted events (expiry sweeps, etc.).
 */
export interface GovernanceEvent {
  id: string;
  type: string;
  actorId: string | null;
  orgId: string;
  /** ISO-8601 timestamp. */
  at: string;
  /** Event-type-specific payload. Optional — shape varies by `type`. */
  payload?: Record<string, unknown>;
}
