/**
 * Offline verifier for pt.v4.* COSE Sign1 permit tokens (ADR-050).
 *
 * pt.v4.{base64url(COSE_Sign1_bytes)} where COSE_Sign1_bytes is a CBOR-encoded
 * COSE_Sign1 structure (RFC 9052, CBOR tag 18):
 *   #6.18([bstr(protected_header), {}, bstr(permit_claims_cbor), bstr(sig)])
 *
 * The bytes signed by Ed25519 are the COSE Sig_Structure (RFC 9052 §4.4):
 *   ["Signature1", bstr(protected_header), bstr(""), bstr(permit_claims_cbor)]
 *
 * Protected header: { 1: -8 } (COSE algorithm EdDSA, RFC 8037), optionally with
 * { 4: bstr(kid) } (COSE key identifier). The runtime mints `{1:-8}` today;
 * accepting a kid now lets it start stamping one without breaking verifiers
 * already in the field. Any other label, a duplicate label, an alg other than
 * EdDSA, or a non-bstr kid is rejected (fail closed).
 *
 * Key selection: pass ONE pinned key (base64 raw Ed25519) and it is used
 * whatever the header says; or pass a key set (the trust root's
 * atlasent-verifier-keys.json document, or `{ keys: [...] }`) and the header
 * kid selects the R2_permit key. With a key set and no kid, the single
 * eligible key is used, or `defaultKid`; anything else is `kid_required`.
 * Permit claims: CBOR integer-keyed map (keys 4/6/7/–1..–35, see PermitClaimsV4).
 * Cross-language parity: contract/vectors/permit-v4/vectors.json, generated from
 * atlasent-api's own signPermitV4 (contract/tools/gen_permit_v4_vectors.ts).
 *
 * Offline by design: with a pinned Ed25519 public key this function needs no
 * network. It is the SDK mirror of the atlasent-api `_shared/cose.ts` decode path.
 *
 * Uses the Web Crypto API (`crypto.subtle`) — available in browsers, Node ≥18,
 * Deno, and Bun. No external dependencies.
 */

export type PermitV4VerifyReason =
  | 'bad_format'
  | 'bad_prefix'
  | 'cose_decode_failed'
  | 'wrong_protected_header'
  | 'claims_decode_failed'
  | 'signature_invalid'
  | 'expired'
  | 'unknown_kid'
  | 'key_revoked'
  | 'key_not_valid_for_permit'
  | 'kid_required';

export class PermitV4VerifyError extends Error {
  readonly reason: PermitV4VerifyReason;
  constructor(reason: PermitV4VerifyReason, message: string) {
    super(`${reason}: ${message}`);
    this.name = 'PermitV4VerifyError';
    this.reason = reason;
  }
}

/**
 * Canonical `agent_runtime_identity.v1` evidence carried in claim key -24
 * (a canonical-JSON text string the COSE signature covers).
 */
export interface AgentRuntimeIdentityClaim {
  version: string;
  binding_id: string;
  agent_identity_id: string;
  agent_registry_id: string;
  agent_version: string;
  agent_deployment_id: string;
  deployment_digest: string;
  provider_proof: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Every claim the runtime signs into a pt.v4 permit (atlasent-api
 * `_shared/cose.ts` encodePermitClaimsV4, keys 4/6/7 and -1..-35). Optional
 * claims are present only when the runtime bound them; absence means "not
 * bound", never "bound to empty". Unknown future keys are skipped.
 */
export interface PermitClaimsV4 {
  permit_id: string;    // UUID (from key 7 / CWT cti — 16-byte bstr)
  exp: number;          // Unix epoch seconds (key 4)
  iat: number;          // Unix epoch seconds (key 6)
  decision_id: string;  // tstr (key -1)
  org_id: string;       // UUID (key -2 — 16-byte bstr)
  action_type: string;  // tstr (key -3)
  actor_id: string;     // tstr (key -4)
  environment: string;  // "live" | "test" (key -5)
  cdo_hash?: string;    // 64-char hex sha256 (key -6, optional)
  policy_hash?: string; // 64-char hex sha256 (key -7, optional)
  // P4 delegation lineage (keys -8..-11)
  parent_permit_hash?: string;   // 64-char hex (key -8)
  parent_permit_id?: string;     // UUID (key -9)
  delegation_depth?: number;     // uint (key -10)
  delegating_actor_id?: string;  // tstr (key -11)
  // Execution binding (keys -12, -13)
  execution_hash_expected?: string; // 64-char hex (key -12)
  envelope_hash?: string;           // 64-char hex (key -13)
  // ADR-063 exceptional authority (keys -14, -15)
  exception_id?: string;   // UUID (key -14)
  exception_type?: string; // tstr (key -15)
  // AWS locus (keys -16, -17)
  aws_account_id?: string; // tstr (key -16)
  aws_region?: string;     // tstr (key -17)
  operation_intent_id?: string; // tstr (key -18)
  // Change brief (keys -19, -20)
  change_brief_id?: string;     // tstr (key -19)
  change_brief_digest?: string; // tstr, "sha256:..." (key -20)
  // H8 canonical authorization identity (keys -21..-23)
  authorization_identity_id?: string; // UUID (key -21)
  authorization_issuance_id?: string; // UUID (key -22)
  authorization_generation?: number;  // uint (key -23)
  agent_runtime_identity?: AgentRuntimeIdentityClaim; // canonical JSON tstr (key -24)
  // Entra acceptance slice (keys -25..-32, -35)
  entra_tenant_id?: string;               // tstr (key -25)
  entra_org_binding_id?: string;          // UUID (key -26)
  entra_request_mapping_id?: string;      // UUID (key -27)
  entra_request_mapping_version?: number; // uint (key -28)
  entra_approve_mapping_id?: string;      // UUID (key -29)
  entra_approve_mapping_version?: number; // uint (key -30)
  pep_audience_executor_id?: string;      // tstr (key -31)
  entra_approve_principal_oid?: string;   // tstr (key -32)
  // Azure locus (keys -33, -34)
  azure_subscription_id?: string; // tstr (key -33)
  azure_resource_group?: string;  // tstr (key -34)
  entra_request_principal_oid?: string; // tstr (key -35)
}

export interface PermitV4VerifyResult {
  ok: true;
  claims: PermitClaimsV4;
  /** kid from the COSE protected header; null when the header carries none. */
  kid: string | null;
  /** kid of the key-set entry that verified the token; null for a pinned key. */
  verifiedWithKid: string | null;
}

/**
 * One verification key, in the trust root's atlasent-verifier-keys.json
 * shape. `x` is the raw 32-byte Ed25519 public key, base64url (JWK).
 * Entries with a `role` other than `R2_permit`, or not OKP/Ed25519, are
 * never used for permits.
 */
export interface PermitVerificationKey {
  kid: string;
  x: string;
  kty?: string;
  crv?: string;
  role?: string;
  revoked?: boolean;
  /**
   * ISO-8601; when set, the permit's iat must be inside the window.
   * `null` (an open-ended side, as the trust root publishes) is unbounded.
   */
  valid_from?: string | null;
  valid_until?: string | null;
  [key: string]: unknown;
}

/**
 * A key set: the trust root's verifier-keys document or any `{ keys }`.
 *
 * Revocation is read from every place the trust root records it: an entry's
 * own `revoked: true`, the revocation ledger's `revoked_keys: [{ kid }]`
 * (atlasent-revocations.json / a trust-root snapshot), and a flat
 * `revoked_kids` list (the `TrustSnapshot` shape). Merge the revocations
 * document into the key set you pass; a kid revoked in ANY of them is refused.
 */
export interface PermitVerificationKeySet {
  keys: PermitVerificationKey[];
  revoked_keys?: Array<{ kid: string; [key: string]: unknown }>;
  revoked_kids?: string[];
  [key: string]: unknown;
}

// ─── CBOR primitives ──────────────────────────────────────────────────────────

class CborReader {
  private pos = 0;
  constructor(private readonly b: Uint8Array) {}

  private readByte(): number {
    if (this.pos >= this.b.length) throw new Error('cbor: unexpected end');
    return this.b[this.pos++]!;
  }

  private readUintVal(add: number): number {
    if (add <= 23) return add;
    if (add === 24) return this.readByte();
    if (add === 25) return (this.readByte() << 8) | this.readByte();
    if (add === 26) {
      // `>>> 0` on the WHOLE expression: `|` yields a signed int32, so
      // without it 0xfffffff8 read back as -8 (an alg/label alias).
      return ((this.readByte() << 24) | (this.readByte() << 16) | (this.readByte() << 8) | this.readByte()) >>> 0;
    }
    throw new Error('cbor: unsupported additional value ' + add);
  }

  private readHead(): { major: number; n: number } {
    const b = this.readByte();
    return { major: (b >> 5) & 7, n: this.readUintVal(b & 0x1f) };
  }

  readBstr(): Uint8Array {
    const { major, n } = this.readHead();
    if (major !== 2) throw new Error('cbor: expected bstr, got major ' + major);
    const out = this.b.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  readArrayLen(): number {
    const { major, n } = this.readHead();
    if (major !== 4) throw new Error('cbor: expected array, got major ' + major);
    return n;
  }

  readMapLen(): number {
    const { major, n } = this.readHead();
    if (major !== 5) throw new Error('cbor: expected map, got major ' + major);
    return n;
  }

  readInt(): number {
    const { major, n } = this.readHead();
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    throw new Error('cbor: expected int, got major ' + major);
  }

  readTstr(): string {
    const { major, n } = this.readHead();
    if (major !== 3) throw new Error('cbor: expected tstr, got major ' + major);
    const bytes = this.b.slice(this.pos, this.pos + n);
    this.pos += n;
    return new TextDecoder().decode(bytes);
  }

  skip(): void {
    const { major, n } = this.readHead();
    if (major <= 1) return;
    if (major === 2 || major === 3) { this.pos += n; return; }
    if (major === 4) { for (let i = 0; i < n; i++) this.skip(); return; }
    if (major === 5) { for (let i = 0; i < n * 2; i++) this.skip(); return; }
    if (major === 6) { this.skip(); return; }
    throw new Error('cbor: unsupported major ' + major);
  }

  peekMajor(): number { return (this.b[this.pos]! >> 5) & 7; }

  atEnd(): boolean { return this.pos === this.b.length; }

  readTagNum(): number {
    const { major, n } = this.readHead();
    if (major !== 6) throw new Error('cbor: expected tag, got major ' + major);
    return n;
  }
}

// ─── Base64url helpers ────────────────────────────────────────────────────────

function fromB64url(s: string): Uint8Array {
  // Pad to multiple of 4 and convert url-safe chars.
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice((s.length + 3) % 4 === 0 ? 2 : (s.length + 3) % 4 === 1 ? 0 : (s.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesHex(b: Uint8Array): string {
  let out = '';
  for (const byte of b) out += byte.toString(16).padStart(2, '0');
  return out;
}

function uuidFromBytes(b: Uint8Array): string {
  return [
    bytesHex(b.slice(0, 4)),
    bytesHex(b.slice(4, 6)),
    bytesHex(b.slice(6, 8)),
    bytesHex(b.slice(8, 10)),
    bytesHex(b.slice(10, 16)),
  ].join('-');
}

// ─── COSE Sign1 decode ────────────────────────────────────────────────────────

function decodeCoseSign1(bytes: Uint8Array): {
  protectedBytes: Uint8Array;
  payloadBytes: Uint8Array;
  sig: Uint8Array;
} {
  const r = new CborReader(bytes);
  if (r.peekMajor() === 6) r.readTagNum(); // optional tag 18
  const len = r.readArrayLen();
  if (len !== 4) throw new Error('cose: expected 4-element array, got ' + len);
  const protectedBytes = r.readBstr();
  r.skip(); // unprotected map {}
  const payloadBytes = r.readBstr();
  const sig = r.readBstr();
  return { protectedBytes, payloadBytes, sig };
}

function buildSigStructure(protectedBytes: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  // Sig_Structure = ["Signature1", bstr(protected), bstr(""), bstr(payload)]
  // CBOR encode inline: array(4) + tstr("Signature1") + bstr(protected) + bstr("") + bstr(payload)
  const enc = new TextEncoder();
  const context = enc.encode('Signature1');
  const empty = new Uint8Array(0);

  function cborUint(n: number): Uint8Array {
    if (n <= 23) return Uint8Array.of(n);
    if (n <= 0xff) return Uint8Array.of(24, n);
    if (n <= 0xffff) return Uint8Array.of(25, n >> 8, n & 0xff);
    return Uint8Array.of(26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }

  function cborBstr(b: Uint8Array): Uint8Array {
    const head = cborUint(b.length);
    head[0]! |= 0x40;
    return concat([head, b]);
  }

  function cborTstr(s: Uint8Array): Uint8Array {
    const head = cborUint(s.length);
    head[0]! |= 0x60;
    return concat([head, s]);
  }

  const arrayHead = Uint8Array.of(0x84); // array(4)
  return concat([
    arrayHead,
    cborTstr(context),
    cborBstr(protectedBytes),
    cborBstr(empty),
    cborBstr(payloadBytes),
  ]);
}

function concat(arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// ─── Permit claims decode ─────────────────────────────────────────────────────

function decodePermitClaims(bytes: Uint8Array): PermitClaimsV4 {
  const r = new CborReader(bytes);
  const len = r.readMapLen();
  const result: Partial<PermitClaimsV4> = {};
  for (let i = 0; i < len; i++) {
    const key = r.readInt();
    switch (key) {
      case 4:  result.exp = r.readInt(); break;
      case 6:  result.iat = r.readInt(); break;
      case 7:  result.permit_id = uuidFromBytes(r.readBstr()); break;
      case -1: result.decision_id = r.readTstr(); break;
      case -2: result.org_id = uuidFromBytes(r.readBstr()); break;
      case -3: result.action_type = r.readTstr(); break;
      case -4: result.actor_id = r.readTstr(); break;
      case -5: result.environment = r.readTstr(); break;
      case -6: result.cdo_hash = bytesHex(r.readBstr()); break;
      case -7: result.policy_hash = bytesHex(r.readBstr()); break;
      case -8: result.parent_permit_hash = bytesHex(r.readBstr()); break;
      case -9: result.parent_permit_id = uuidFromBytes(r.readBstr()); break;
      case -10: result.delegation_depth = r.readInt(); break;
      case -11: result.delegating_actor_id = r.readTstr(); break;
      case -12: result.execution_hash_expected = bytesHex(r.readBstr()); break;
      case -13: result.envelope_hash = bytesHex(r.readBstr()); break;
      case -14: result.exception_id = uuidFromBytes(r.readBstr()); break;
      case -15: result.exception_type = r.readTstr(); break;
      case -16: result.aws_account_id = r.readTstr(); break;
      case -17: result.aws_region = r.readTstr(); break;
      case -18: result.operation_intent_id = r.readTstr(); break;
      case -19: result.change_brief_id = r.readTstr(); break;
      case -20: result.change_brief_digest = r.readTstr(); break;
      case -21: result.authorization_identity_id = uuidFromBytes(r.readBstr()); break;
      case -22: result.authorization_issuance_id = uuidFromBytes(r.readBstr()); break;
      case -23: result.authorization_generation = r.readInt(); break;
      case -24: {
        const parsed: unknown = JSON.parse(r.readTstr());
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('agent_runtime_identity claim is not a JSON object');
        }
        result.agent_runtime_identity = parsed as AgentRuntimeIdentityClaim;
        break;
      }
      case -25: result.entra_tenant_id = r.readTstr(); break;
      case -26: result.entra_org_binding_id = uuidFromBytes(r.readBstr()); break;
      case -27: result.entra_request_mapping_id = uuidFromBytes(r.readBstr()); break;
      case -28: result.entra_request_mapping_version = r.readInt(); break;
      case -29: result.entra_approve_mapping_id = uuidFromBytes(r.readBstr()); break;
      case -30: result.entra_approve_mapping_version = r.readInt(); break;
      case -31: result.pep_audience_executor_id = r.readTstr(); break;
      case -32: result.entra_approve_principal_oid = r.readTstr(); break;
      case -33: result.azure_subscription_id = r.readTstr(); break;
      case -34: result.azure_resource_group = r.readTstr(); break;
      case -35: result.entra_request_principal_oid = r.readTstr(); break;
      default: r.skip();
    }
  }
  const required = ['exp', 'iat', 'permit_id', 'decision_id', 'org_id', 'action_type', 'actor_id', 'environment'] as const;
  for (const f of required) {
    if (result[f] === undefined) throw new Error(`missing required claim: ${f}`);
  }
  return result as PermitClaimsV4;
}

// ─── Protected header + key selection ────────────────────────────────────────

/**
 * Parse the COSE protected header. Accepts exactly `{1: -8}` or
 * `{1: -8, 4: bstr(kid)}` in either order; returns the kid or null.
 */
function parseProtectedHeader(bytes: Uint8Array): string | null {
  const r = new CborReader(bytes);
  const n = r.readMapLen();
  let alg: number | undefined;
  let kid: string | null = null;
  const seen = new Set<number>();
  for (let i = 0; i < n; i++) {
    const label = r.readInt();
    if (seen.has(label)) throw new Error(`duplicate protected header label ${label}`);
    seen.add(label);
    if (label === 1) {
      alg = r.readInt();
    } else if (label === 4) {
      const raw = r.readBstr();
      if (raw.length === 0) throw new Error('empty kid');
      kid = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    } else {
      throw new Error(`unexpected protected header label ${label}`);
    }
  }
  if (!r.atEnd()) throw new Error('trailing bytes after protected header');
  if (alg !== -8) throw new Error('expected EdDSA protected header { 1: -8 }');
  return kid;
}

function isPermitKey(k: PermitVerificationKey): boolean {
  return (
    typeof k?.kid === 'string' &&
    typeof k.x === 'string' &&
    (k.role === undefined || k.role === 'R2_permit') &&
    (k.kty === undefined || k.kty === 'OKP') &&
    (k.crv === undefined || k.crv === 'Ed25519')
  );
}

function isRevokedKid(set: PermitVerificationKeySet, k: PermitVerificationKey): boolean {
  if (k.revoked === true) return true;
  if (Array.isArray(set.revoked_kids) && set.revoked_kids.includes(k.kid)) return true;
  return Array.isArray(set.revoked_keys) && set.revoked_keys.some((r) => r?.kid === k.kid);
}

/**
 * Revoked when the entry's kid is revoked OR any revoked entry in the set
 * carries the same key material (`x`): otherwise the holder of a revoked
 * private key could sign under a live alias kid.
 */
function isRevoked(set: PermitVerificationKeySet, k: PermitVerificationKey): boolean {
  if (isRevokedKid(set, k)) return true;
  const all = Array.isArray(set?.keys) ? set.keys : [];
  return all.some((o) => o?.x === k.x && typeof o.kid === 'string' && isRevokedKid(set, o));
}

function selectKey(
  set: PermitVerificationKeySet,
  kid: string | null,
  iat: number,
  defaultKid: string | undefined,
): PermitVerificationKey {
  const keys = Array.isArray(set?.keys) ? set.keys.filter(isPermitKey) : [];
  let entry: PermitVerificationKey | undefined;
  const wanted = kid ?? defaultKid ?? null;
  if (wanted !== null) {
    const matches = keys.filter((k) => k.kid === wanted);
    if (matches.length !== 1) {
      throw new PermitV4VerifyError(
        'unknown_kid',
        matches.length === 0
          ? `no permit key with kid ${JSON.stringify(wanted)}`
          : `kid ${JSON.stringify(wanted)} is ambiguous in the key set`,
      );
    }
    entry = matches[0]!;
  } else {
    const live = keys.filter((k) => !isRevoked(set, k));
    if (live.length !== 1) {
      throw new PermitV4VerifyError(
        'kid_required',
        `token carries no kid and the key set has ${live.length} usable permit keys`,
      );
    }
    entry = live[0]!;
  }
  if (isRevoked(set, entry)) {
    throw new PermitV4VerifyError('key_revoked', `permit key ${entry.kid} is revoked`);
  }
  const iatMs = iat * 1000;
  const bound = (v: string | null | undefined) =>
    v === undefined || v === null ? undefined : Date.parse(v);
  const from = bound(entry.valid_from);
  const until = bound(entry.valid_until);
  if (
    (from !== undefined && (Number.isNaN(from) || iatMs < from)) ||
    (until !== undefined && (Number.isNaN(until) || iatMs > until))
  ) {
    throw new PermitV4VerifyError(
      'key_not_valid_for_permit',
      `permit issued outside the validity window of key ${entry.kid}`,
    );
  }
  return entry;
}

// ─── Main API ─────────────────────────────────────────────────────────────────

/**
 * Verify a pt.v4.* COSE Sign1 permit token offline.
 *
 * Decodes the base64url payload, verifies the EdDSA signature against the
 * supplied Ed25519 public key (raw 32 bytes, standard base64), and returns
 * the decoded permit claims.
 *
 * Does NOT verify `exp` — pass `checkExpiry: true` to enable that check.
 * The permit may still be revoked server-side even when this returns `ok: true`.
 *
 * @param token       - Full pt.v4.* token string
 * @param key         - Either one pinned key (raw 32-byte Ed25519, standard
 *                      base64) or a key set (trust-root verifier-keys document)
 * @param opts.checkExpiry - If true, throws if claims.exp ≤ now (default false)
 * @param opts.defaultKid  - With a key set, the kid to use when the token's
 *                      header carries none and the set has several permit keys
 */
export async function verifyPermitV4(
  token: string,
  key: string | PermitVerificationKeySet,
  opts?: { checkExpiry?: boolean; defaultKid?: string },
): Promise<PermitV4VerifyResult> {
  if (typeof token !== 'string') {
    throw new PermitV4VerifyError('bad_format', 'token must be a string');
  }
  if (!token.startsWith('pt.v4.')) {
    throw new PermitV4VerifyError('bad_prefix', `expected pt.v4.* prefix, got: ${token.slice(0, 12)}`);
  }

  const b64Payload = token.slice('pt.v4.'.length);
  let coseBytes: Uint8Array;
  try {
    coseBytes = fromB64url(b64Payload);
  } catch {
    throw new PermitV4VerifyError('bad_format', 'base64url decode failed');
  }

  let protectedBytes: Uint8Array, payloadBytes: Uint8Array, sig: Uint8Array;
  try {
    ({ protectedBytes, payloadBytes, sig } = decodeCoseSign1(coseBytes));
  } catch (e) {
    throw new PermitV4VerifyError('cose_decode_failed', (e as Error).message);
  }

  let headerKid: string | null;
  try {
    headerKid = parseProtectedHeader(protectedBytes);
  } catch (e) {
    throw new PermitV4VerifyError('wrong_protected_header', (e as Error).message);
  }

  let claims: PermitClaimsV4;
  try {
    claims = decodePermitClaims(payloadBytes);
  } catch (e) {
    throw new PermitV4VerifyError('claims_decode_failed', (e as Error).message);
  }

  // Select the key: a pinned key is used as-is; a key set is indexed by kid.
  let rawKey: Uint8Array;
  let verifiedWithKid: string | null = null;
  if (typeof key === 'string') {
    rawKey = fromB64(key);
  } else {
    const entry = selectKey(key, headerKid, claims.iat, opts?.defaultKid);
    rawKey = fromB64url(entry.x);
    verifiedWithKid = entry.kid;
  }

  // Build Sig_Structure and verify Ed25519 signature.
  const toVerify = buildSigStructure(protectedBytes, payloadBytes);
  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      'raw',
      rawKey as unknown as ArrayBuffer,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
  } catch {
    throw new PermitV4VerifyError('signature_invalid', 'invalid Ed25519 public key');
  }

  const ok = await crypto.subtle.verify(
    { name: 'Ed25519' },
    cryptoKey,
    sig as unknown as ArrayBuffer,
    toVerify as unknown as ArrayBuffer,
  );
  if (!ok) {
    throw new PermitV4VerifyError('signature_invalid', 'Ed25519 signature did not verify');
  }

  if (opts?.checkExpiry) {
    const nowSec = Math.floor(Date.now() / 1000);
    if (claims.exp <= nowSec) {
      throw new PermitV4VerifyError('expired', `permit expired at ${new Date(claims.exp * 1000).toISOString()}`);
    }
  }

  return { ok: true, claims, kid: headerKid, verifiedWithKid };
}
