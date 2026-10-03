"""Approval artifact models — wire-stable as ``approval_artifact.v1``.

Mirrors the TypeScript SDK
(``atlasent-sdk/typescript/src/approvalArtifact.ts``) and the JSON
Schema (``contract/schemas/approval-artifact.schema.json``). Verifier
behavior lives server-side inside ``/v1-evaluate``; the Python SDK
just *carries* the artifact and surfaces the binding back from
``/v1-verify-permit``.

Why this matters: the calling agent cannot self-declare authority
by passing reviewer flags in ``context``. The artifact is bound to
the exact action via ``action_hash``, signed by a trusted issuer,
and replay-protected via ``nonce``. See ``contract/APPROVAL_DENY_REASONS.md``
for the verifier's 13-step check order.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    model_validator,
)

PrincipalKind = Literal["human", "agent", "service_account"]
"""What kind of principal performed the approval. The verifier
requires ``"human"``; the other variants exist so the schema can
describe declined approvals (e.g. an agent attempted to self-approve).
"""


class ApprovalReviewer(BaseModel):
    """Identity of the reviewer recorded inside the artifact."""

    principal_id: str
    principal_kind: PrincipalKind
    email: str | None = None
    groups: list[str] | None = None
    roles: list[str] | None = None

    model_config = ConfigDict(extra="forbid")


class ApprovalIssuer(BaseModel):
    """Trusted issuer identification — used to look up the verification key."""

    type: Literal["oidc", "approval_service"]
    issuer_id: str
    kid: str
    """Key id (for rotation)."""

    model_config = ConfigDict(extra="forbid")


class IdentitySubject(BaseModel):
    """Identity-attested subject of the assertion. Verifier requires
    ``principal_kind == "human"``; the other variants are present so
    the schema can structurally describe denied / declined assertions.
    """

    principal_id: str = Field(min_length=1)
    principal_kind: PrincipalKind

    model_config = ConfigDict(extra="forbid")


class IdentityAssertionBinding(BaseModel):
    """Cryptographic binding tying the assertion to a specific approval."""

    approval_id: str = Field(min_length=1)
    """Must equal artifact.approval_id."""
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    """Must equal the canonical action hash."""
    tenant_id: str = Field(min_length=1)
    """Must equal the request's tenant_id."""
    environment: str
    """Must equal the request's environment. Empty string allowed
    when the verifier was not given one (explicit equality, no
    implicit broadening)."""

    model_config = ConfigDict(extra="forbid")


class IdentityIssuer(BaseModel):
    """Identity issuer (the IdP). Always OIDC-shaped."""

    type: Literal["oidc"]
    issuer_id: str = Field(min_length=1)
    kid: str = Field(min_length=1)
    """Key id for rotation; looked up in IDENTITY_TRUSTED_ISSUERS."""

    model_config = ConfigDict(extra="forbid")


class IdentityAssertionV1(BaseModel):
    """A complete signed identity assertion.

    Wire-stable as ``identity_assertion.v1``. Verified server-side
    inside ``/v1-evaluate``; the SDK only carries it. Schema lives in
    ``contract/schemas/identity-assertion.schema.json``.
    """

    version: Literal["identity_assertion.v1"] = "identity_assertion.v1"
    subject: IdentitySubject
    role: str = Field(min_length=1)
    """Required role attested by the IdP (e.g. "qa_reviewer"). The
    verifier checks this equals the effective_required_role used to
    gate the action."""
    binding: IdentityAssertionBinding
    issuer: IdentityIssuer
    issued_at: str
    expires_at: str
    nonce: str | None = Field(default=None, min_length=8)
    """Optional anti-replay nonce. The approval-artifact nonce is
    the primary defence; deployments that want assertion-level
    replay protection ledger this separately."""
    signature: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class ApproverGrantSubject(BaseModel):
    """The console principal: ``(issuer.issuer_id, subject.principal_id)``."""

    principal_id: str = Field(pattern=_UUID_PATTERN)
    """Console user id (lower-case UUID)."""
    principal_kind: Literal["human"]

    model_config = ConfigDict(extra="forbid")


class ApproverGrantBinding(BaseModel):
    """Binds the assertion to exactly one approval."""

    approval_id: str = Field(min_length=1)
    action_hash: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    environment: str

    model_config = ConfigDict(extra="forbid")


class ApproverGrantIssuer(BaseModel):
    """The console's approver issuer (runtime ``APPROVER_GRANT_TRUSTED_ISSUERS``)."""

    issuer_id: str = Field(min_length=1)
    kid: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class ApproverGrantAuthContext(BaseModel):
    """Console session assurance and step-up recorded as evidence."""

    acr: Literal["aal1", "aal2"]
    amr: list[str] = Field(min_length=1, max_length=16)
    step_up: Literal["aal2", "password_reauth"]
    step_up_at: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class ApproverGrantAssertionV1(BaseModel):
    """Console-signed assertion that a console user holding approver
    grant ``grant_id`` approved one specific approval after a
    server-side step-up. Evidence for the ``atlasent_approver_grant``
    basis (atlasent-api#3863); in an approval artifact it takes the
    place of ``identity_assertion``, never alongside it.

    Wire-stable as ``approver_grant_assertion.v1``. Schema lives in
    ``contract/schemas/approver-grant-assertion.schema.json``. The SDK
    only carries it; signing and verification are server-side. Added
    2026-10-03 (atlasent-api#3876), additive.
    """

    version: Literal["approver_grant_assertion.v1"] = "approver_grant_assertion.v1"
    basis: Literal["atlasent_approver_grant"] = "atlasent_approver_grant"
    subject: ApproverGrantSubject
    grant_id: str = Field(pattern=_UUID_PATTERN)
    binding: ApproverGrantBinding
    issuer: ApproverGrantIssuer
    auth_context: ApproverGrantAuthContext
    issued_at: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    nonce: str = Field(min_length=16, max_length=256)
    signature: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


SignatureMeaning = Literal["approved", "reviewed", "authored"]
"""21 CFR Part 11 §11.50(a)(2) signature meaning carried by an approval
artifact. Absent means the runtime records the historical implied
meaning ``approved``."""

ApprovalKind = Literal["single_human_over_machine"]
"""ADR CROSS-056 approval kind. Absent means an ordinary human approval."""

_UUID_PATTERN_CI = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class EntraProvenanceV1(BaseModel):
    """Entra tenant-binding and authority-mapping facts the runtime's
    ``v1-idp-broker`` resolved when it minted an envelope through Entra
    ID. Carried inside the signed envelope. ``relation`` is ``approve``
    on ``approval_artifact.v1`` and ``request`` on ``actor_identity.v1``.

    Schema: ``contract/schemas/entra-provenance.schema.json``. The SDK
    only carries it. Added 2026-10-03, additive.
    """

    tenant_id: str = Field(min_length=1)
    """Verified Entra tenant id (the ``tid`` claim)."""
    org_binding_id: str = Field(min_length=1)
    mapping_id: str = Field(min_length=1)
    mapping_version: StrictInt | StrictFloat
    """Version of the authority mapping at mint time (an integer in
    the runtime database; the runtime guard accepts any finite number)."""
    relation: Literal["request", "approve"]

    model_config = ConfigDict(extra="forbid")


class IdentityIssuerKey(BaseModel):
    """One entry in ``IDENTITY_TRUSTED_ISSUERS[issuer_id][kid]``.

    Server-side config only; the SDK exposes the model so operators
    can lint the JSON in CI. Independent trust root from
    ``APPROVAL_TRUSTED_ISSUERS`` — by design.
    """

    alg: Literal["HS256", "Ed25519"]
    key: str = Field(min_length=1)
    """Hex-encoded HS256 secret or Ed25519 raw public key (32
    bytes / 64 hex chars). Ed25519 signatures may be hex or
    base64url; HS256 signatures are hex."""
    allowed_roles: list[str] | None = None
    """Per-issuer scope: roles this kid may attest. Empty/missing = unscoped."""
    allowed_environments: list[str] | None = None
    """Per-issuer scope: environments this kid may attest in.
    Empty/missing = unscoped.
    """

    model_config = ConfigDict(extra="forbid")


class IdentityTrustedIssuersConfig(BaseModel):
    """JSON shape of the ``IDENTITY_TRUSTED_ISSUERS`` env var. Keyed
    by ``issuer_id`` then ``kid``."""

    root: dict[str, dict[str, IdentityIssuerKey]]

    model_config = ConfigDict(extra="forbid")

    def to_env_dict(self) -> dict[str, Any]:
        return {
            issuer_id: {
                kid: entry.model_dump(exclude_none=True) for kid, entry in kids.items()
            }
            for issuer_id, kids in self.root.items()
        }

    @classmethod
    def from_env_dict(cls, data: dict[str, Any]) -> IdentityTrustedIssuersConfig:
        return cls(root=data)  # type: ignore[arg-type]


class ApprovalArtifactV1(BaseModel):
    """The full signed approval artifact.

    Producers (approval services) compute ``action_hash`` over the
    canonical action payload and sign the artifact with the
    ``signature`` field stripped; the SDK does not sign or verify, it
    only carries the artifact to the server. Field order matches the
    JSON Schema; ``extra="forbid"`` so an unexpected key fails fast
    at SDK boundaries instead of silently propagating to the wire.

    ``identity_assertion`` is REQUIRED on the wire whenever
    ``/v1-evaluate`` calls the verifier with
    ``requireIdentityAssertion: true`` (i.e. when human approval is
    required). Without it the server returns deny: ``missing
    identity assertion``. The SDK keeps the field optional so shadow
    / preflight flows that don't verify can still construct
    artifacts.
    """

    version: Literal["approval_artifact.v1"] = "approval_artifact.v1"
    approval_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    action_type: str = Field(min_length=1, max_length=256)
    resource_id: str = Field(min_length=1, max_length=512)
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer: ApprovalReviewer
    issuer: ApprovalIssuer
    issued_at: str
    expires_at: str
    nonce: str = Field(min_length=8)
    signature: str = Field(min_length=1)
    identity_assertion: IdentityAssertionV1 | None = None
    approver_grant_assertion: ApproverGrantAssertionV1 | None = None
    """Optional, additive (atlasent-api#3876): the approver-grant basis
    alternative to ``identity_assertion``. Carrying both is rejected,
    as the runtime verifier and the JSON Schema reject it."""
    meaning: SignatureMeaning | None = None
    """Optional, additive (2026-10-03): §11.50(a)(2) signature meaning.
    Signed. Absent means ``approved``."""
    entra_provenance: EntraProvenanceV1 | None = None
    """Optional, additive (2026-10-03): present only on artifacts minted
    through Entra ID for a governed action type. ``relation`` must be
    ``approve`` here. Signed."""
    approval_kind: ApprovalKind | None = None
    """Optional, additive (ADR CROSS-056, 2026-10-03). Signed. Present
    together with ``subject_agent_identity_id`` or not at all."""
    subject_agent_identity_id: str | None = Field(
        default=None, pattern=_UUID_PATTERN_CI
    )
    """agent_identities.id (uuid) the approval is FOR. Required when
    ``approval_kind`` is present; rejected without it. Signed."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _assertions_are_alternatives(self) -> ApprovalArtifactV1:
        if (
            self.identity_assertion is not None
            and self.approver_grant_assertion is not None
        ):
            raise ValueError(
                "approval artifact carries both an identity assertion and an "
                "approver grant assertion"
            )
        return self

    @model_validator(mode="after")
    def _kind_and_subject_together(self) -> ApprovalArtifactV1:
        # Mirrors the runtime verifier: a kind requires a uuid subject,
        # and a subject is only valid with a kind.
        if (self.approval_kind is None) != (self.subject_agent_identity_id is None):
            raise ValueError(
                "approval_kind and subject_agent_identity_id must be present "
                "together"
            )
        return self

    @model_validator(mode="after")
    def _entra_relation_is_approve(self) -> ApprovalArtifactV1:
        if (
            self.entra_provenance is not None
            and self.entra_provenance.relation != "approve"
        ):
            raise ValueError(
                "entra_provenance.relation must be 'approve' on an approval artifact"
            )
        return self


class ApprovalReference(BaseModel):
    """Optional ``approval`` field on an evaluate request.

    Either embed the full artifact (``artifact=...``), or pass an
    ``approval_id`` and let the server resolve it from a side channel
    (preferred when the artifact is large).
    """

    approval_id: str | None = None
    artifact: ApprovalArtifactV1 | None = None

    model_config = ConfigDict(extra="forbid")


class PermitApprovalBinding(BaseModel):
    """Cryptographic permit ↔ approval-artifact linkage.

    Set when the evaluate path verified an ``approval_artifact.v1``
    before issuing a permit; persisted on the permit row so
    ``/v1-verify-permit`` can enforce the full chain on consume.
    Returned on ``EvaluateResult.permit.approval`` and on
    ``VerifyResult.approval``.
    """

    approval_id: str
    """``approval_artifact.approval_id`` from the verified artifact."""

    artifact_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    """SHA-256 over the artifact's canonical signing payload (i.e. the
    artifact with the ``signature`` field stripped). Lets a stored
    permit row prove which artifact authorized it without retaining
    the full artifact body."""

    reviewer_id: str
    """``reviewer.principal_id`` from the verified artifact."""

    issuer_id: str
    """``issuer.issuer_id`` from the verified artifact."""

    kid: str
    """``issuer.kid`` used to verify the signature (key id, for rotation)."""

    model_config = ConfigDict(extra="forbid")


# ── Trusted-issuer config (server-side, never on the wire) ────────────


class TrustedIssuerKey(BaseModel):
    """One entry in ``APPROVAL_TRUSTED_ISSUERS[issuer_id][kid]``.

    Server-side config only — read by the verifier inside
    ``/v1-evaluate``. The Python SDK exposes the model so operators
    can construct / lint / round-trip the env-var JSON.
    """

    alg: Literal["HS256", "Ed25519"]
    """Signature algorithm. HS256 = HMAC-SHA-256 with a hex-encoded
    shared secret. Ed25519 = detached signature with a hex-encoded
    32-byte raw public key."""

    key: str = Field(min_length=1)
    """Hex-encoded HS256 secret (any byte length) or Ed25519 raw
    public key (32 bytes / 64 hex chars). Ed25519 signatures may be
    hex or base64url; HS256 signatures are hex only."""

    allowed_action_types: list[str] | None = None
    """Per-issuer scope: ``action_types`` this kid may approve.
    Entries match exactly OR with a trailing ``.*`` wildcard (e.g.
    ``production.*`` matches ``production.deploy``).
    Empty / missing = unscoped on action types."""

    allowed_environments: list[str] | None = None
    """Per-issuer scope: environments this kid may approve in (e.g.
    ``["production"]``). Empty / missing = unscoped."""

    required_role: str | None = None
    """When set, the issuer's ``required_role`` wins over the caller's
    ``requiredRole``. A misconfigured caller cannot broaden this
    issuer's authority."""

    model_config = ConfigDict(extra="forbid")


class ApprovalTrustedIssuersConfig(BaseModel):
    """JSON shape of the ``APPROVAL_TRUSTED_ISSUERS`` env var.

    Keyed by ``issuer_id`` then by ``kid``::

        {
          "issuer.qa": {
            "kid-1": {
              "alg": "HS256",
              "key": "<hex>",
              "allowed_action_types": ["production.deploy.*"],
              "allowed_environments": ["production"],
              "required_role": "qa_reviewer"
            }
          }
        }

    Use :meth:`from_env_str` to parse the JSON bytes that the server
    process reads from the environment. Validation surfaces config
    errors at deploy time rather than at the first denied evaluate.
    """

    root: dict[str, dict[str, TrustedIssuerKey]]
    """``issuer_id`` → ``kid`` → key entry."""

    model_config = ConfigDict(extra="forbid")

    def to_env_dict(self) -> dict[str, Any]:
        """Render to the plain dict shape stored in the env var."""
        return {
            issuer_id: {
                kid: entry.model_dump(exclude_none=True) for kid, entry in kids.items()
            }
            for issuer_id, kids in self.root.items()
        }

    @classmethod
    def from_env_dict(cls, data: dict[str, Any]) -> ApprovalTrustedIssuersConfig:
        """Parse the plain dict shape stored in the env var."""
        return cls(root=data)  # type: ignore[arg-type]


# ── Quorum (additive on top of single-approval) ──────────────────────


class QuorumRoleRequirement(BaseModel):
    """One ``role × count`` requirement in a quorum policy."""

    role: str = Field(min_length=1)
    min: int = Field(ge=1)
    """Minimum approvals carrying this role."""

    model_config = ConfigDict(extra="forbid")


class QuorumIndependence(BaseModel):
    """Independence constraints on a quorum policy. Duplicate
    ``reviewer.principal_id`` is ALWAYS rejected regardless of
    these flags; these strengthen the requirement further."""

    distinct_approval_issuers: bool | None = None
    """When true, requires distinct approval-issuer identities."""
    distinct_identity_issuers: bool | None = None
    """When true, requires distinct identity-issuer identities."""

    model_config = ConfigDict(extra="forbid")


class QuorumPolicy(BaseModel):
    """Quorum policy describing what counts as passing."""

    required_count: int = Field(ge=1)
    required_role_mix: list[QuorumRoleRequirement] | None = None
    independence: QuorumIndependence | None = None
    max_age_seconds: int | None = Field(default=None, ge=1)
    """Optional package-level staleness window. Layered on each
    artifact's own ``expires_at`` — both must be in the future."""

    model_config = ConfigDict(extra="forbid")


class ApprovalQuorumV1(BaseModel):
    """A signed quorum package carrying multiple approvals.

    Wire-stable as ``approval_quorum.v1``. Verified server-side
    inside ``/v1-evaluate``. The SDK exposes the type so callers
    can construct a quorum payload before submitting.

    Locked invariant: quorum does NOT relax artifact verification.
    Every approval inside MUST first pass the single-approval
    verifier (artifact signature + identity assertion + every
    binding). If any single approval fails, the whole package is
    denied with that approval's exact reason — no fallthrough.
    """

    version: Literal["approval_quorum.v1"] = "approval_quorum.v1"
    tenant_id: str = Field(min_length=1, max_length=256)
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment: str
    issued_at: str
    policy: QuorumPolicy
    approvals: list[ApprovalArtifactV1] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class QuorumProof(BaseModel):
    """Proof material returned on a passing quorum. Persisted on
    the audit row so external auditors can reconstruct WHO
    approved together without per-approval joins."""

    quorum_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    """sha256 over the canonical (policy + tenant + action +
    environment + issued_at + sorted approval_hashes)."""
    approval_ids: list[str]
    """approval_id of every counted approval, in submitted order."""

    model_config = ConfigDict(extra="forbid")


__all__ = [
    "ApprovalArtifactV1",
    "ApprovalIssuer",
    "ApprovalKind",
    "ApprovalQuorumV1",
    "ApprovalReference",
    "ApprovalReviewer",
    "ApprovalTrustedIssuersConfig",
    "ApproverGrantAssertionV1",
    "ApproverGrantAuthContext",
    "ApproverGrantBinding",
    "ApproverGrantIssuer",
    "ApproverGrantSubject",
    "EntraProvenanceV1",
    "IdentityAssertionBinding",
    "IdentityAssertionV1",
    "IdentityIssuer",
    "IdentityIssuerKey",
    "IdentitySubject",
    "IdentityTrustedIssuersConfig",
    "PermitApprovalBinding",
    "PrincipalKind",
    "QuorumIndependence",
    "QuorumPolicy",
    "QuorumProof",
    "QuorumRoleRequirement",
    "SignatureMeaning",
    "TrustedIssuerKey",
]
