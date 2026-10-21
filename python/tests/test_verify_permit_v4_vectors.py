"""Cross-language parity for pt.v4 permits.

Every vector in contract/vectors/permit-v4/vectors.json was minted by
atlasent-api's own signPermitV4 and decoded by its own decodePermitClaimsV4
(contract/tools/gen_permit_v4_vectors.ts). The Python decoder must return
exactly the runtime's claim bag. typescript/test/verify-permit-v4-vectors.test.ts
runs the same file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from atlasent.verify_permit_v4 import PermitV4VerifyError, verify_permit_v4

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "contract"
        / "vectors"
        / "permit-v4"
        / "vectors.json"
    ).read_text()
)


def test_full_vector_covers_every_runtime_claim_key() -> None:
    full = next(v for v in _VECTORS["vectors"] if v["name"] == "full")
    assert len(full["expected_claims"]) == 38  # 3 CWT + 35 private keys


@pytest.mark.parametrize("vector", _VECTORS["vectors"], ids=lambda v: v["name"])
def test_decodes_exactly_as_the_runtime(vector: dict) -> None:
    res = verify_permit_v4(vector["token"], _VECTORS["public_key_b64"])
    assert res.claims.present_claims() == vector["expected_claims"]


@pytest.mark.parametrize("vector", _VECTORS["negative"], ids=lambda v: v["name"])
def test_rejects_negative_vectors(vector: dict) -> None:
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(vector["token"], _VECTORS["public_key_b64"])
    assert exc.value.reason == vector["expected_reason"]
