"""Tests for atlasent.authority_intelligence — the integrity-audit sub-route.

First SDK exposure of the ``v1-authority-intelligence`` edge function. These
tests pin the request shape (query params, and the *absence* of them), the
field-for-field response mapping, the open value vocabulary, fail-closed error
propagation, and the three-way classification counting helper.
"""

from __future__ import annotations

import importlib
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from atlasent import AtlaSentClient
from atlasent.authority_intelligence import (
    INTEGRITY_AUDIT_PATH,
    KNOWN_CLASSIFICATIONS,
    AuthorityIntelligenceClient,
    IntegrityFinding,
    IntegrityReport,
    authority_intelligence,
    count_findings_by_classification,
)
from atlasent.exceptions import AtlaSentError

API_KEY = "ask_test_authint"
BASE_URL = "https://api.atlasent.io/functions/v1"

WIRE_FINDING: dict[str, Any] = {
    "finding_type": "authority_without_action_class",
    "classification": "defect",
    "severity": "high",
    "subject_id": "did:key:z6Mk",
    "source_table": "authorities",
    "source_id": "auth-1",
    "related_source_ids": ["ac-1", "ac-2"],
    "effective_at": "2026-08-01T00:00:00Z",
    "evidence_posture": "observed",
    "reason": "Authority declares no action classes and cannot be exercised.",
}

WIRE_REPORT: dict[str, Any] = {
    "schema_version": "authority_intelligence.integrity_report.v1",
    "query": "integrity-audit",
    "organization_id": "org-1",
    "evaluated_at": "2026-08-22T12:00:00Z",
    "produced_by": ["authority_integrity_auditor@1.0.0"],
    "summary": {
        "audited_scope": {"decision_window_days": 90},
        "counts_by_classification": {"defect": 1},
    },
    "findings": [WIRE_FINDING],
    "nodes": [{"id": "auth-1", "kind": "authority"}],
    "edges": [{"from": "auth-1", "to": "ac-1", "kind": "grants"}],
}


def _client() -> AtlaSentClient:
    return AtlaSentClient(api_key=API_KEY, base_url=BASE_URL, max_retries=0)


def _mock_response(body: Any, *, status: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json = MagicMock(return_value=body)
    m.text = json.dumps(body)
    m.headers = {"X-Request-ID": "req_test"}
    return m


def _run(
    body: Any,
    *,
    status: int = 200,
    **kwargs: Any,
) -> tuple[IntegrityReport, MagicMock]:
    """Call ``integrity_audit(**kwargs)`` against a mocked httpx GET."""
    client = _client()
    with patch.object(
        client._client, "get", return_value=_mock_response(body, status=status)
    ) as mock_get:
        report = client.authority_intelligence.integrity_audit(**kwargs)
    return report, mock_get


# ── request shape ─────────────────────────────────────────────────────────────


def test_gets_the_integrity_audit_sub_route():
    _, mock_get = _run(WIRE_REPORT)
    url = mock_get.call_args[0][0]
    assert url == f"{BASE_URL}{INTEGRITY_AUDIT_PATH}"


def test_path_names_the_edge_function_and_sub_route():
    assert INTEGRITY_AUDIT_PATH == "/v1-authority-intelligence/integrity-audit"


def test_sends_no_query_params_when_window_omitted():
    _, mock_get = _run(WIRE_REPORT)
    assert mock_get.call_args.kwargs["params"] is None


def test_never_client_side_defaults_the_window():
    """An omitted window must reach the server as *absent*, never as a guess."""
    _, mock_get = _run(WIRE_REPORT, decision_window_days=None)
    assert mock_get.call_args.kwargs["params"] is None


def test_passes_decision_window_days_as_snake_case_param():
    _, mock_get = _run(WIRE_REPORT, decision_window_days=90)
    assert mock_get.call_args.kwargs["params"] == {"decision_window_days": "90"}


@pytest.mark.parametrize("days", [1, 30, 365, 3650])
def test_passes_window_boundary_values_through(days: int):
    _, mock_get = _run(WIRE_REPORT, decision_window_days=days)
    assert mock_get.call_args.kwargs["params"] == {"decision_window_days": str(days)}


def test_does_not_range_validate_client_side():
    """1–3650 is the server's constraint; the SDK does not second-guess it."""
    report, mock_get = _run(WIRE_REPORT, decision_window_days=99999)
    assert mock_get.call_args.kwargs["params"] == {"decision_window_days": "99999"}
    assert isinstance(report, IntegrityReport)


def test_does_not_send_organization_id():
    """The org is derived server-side from the API key, never client-supplied."""
    _, mock_get = _run(WIRE_REPORT, decision_window_days=90)
    params = mock_get.call_args.kwargs["params"]
    assert "organization_id" not in params
    assert set(params) == {"decision_window_days"}


def test_window_is_keyword_only():
    client = _client()
    with pytest.raises(TypeError):
        client.authority_intelligence.integrity_audit(90)  # type: ignore[misc]


# ── response mapping ──────────────────────────────────────────────────────────


def test_maps_every_top_level_field():
    report, _ = _run(WIRE_REPORT)
    assert report.schema_version == "authority_intelligence.integrity_report.v1"
    assert report.query == "integrity-audit"
    assert report.organization_id == "org-1"
    assert report.evaluated_at == "2026-08-22T12:00:00Z"
    assert report.produced_by == ("authority_integrity_auditor@1.0.0",)
    assert len(report.findings) == 1


def test_maps_every_finding_field_verbatim():
    report, _ = _run(WIRE_REPORT)
    f = report.findings[0]
    assert f.finding_type == "authority_without_action_class"
    assert f.classification == "defect"
    assert f.severity == "high"
    assert f.subject_id == "did:key:z6Mk"
    assert f.source_table == "authorities"
    assert f.source_id == "auth-1"
    assert f.related_source_ids == ("ac-1", "ac-2")
    assert f.effective_at == "2026-08-01T00:00:00Z"
    assert f.evidence_posture == "observed"
    assert f.reason.startswith("Authority declares no action classes")


def test_summary_is_an_open_ended_bag():
    summary = {
        "audited_scope": {"decision_window_days": 30, "from": "2026-07-23"},
        "a_key_this_sdk_has_never_heard_of": [1, 2, 3],
    }
    report, _ = _run({**WIRE_REPORT, "summary": summary})
    assert report.summary == summary


def test_summary_echoes_the_server_scope_not_the_requested_window():
    report, _ = _run(
        {**WIRE_REPORT, "summary": {"audited_scope": {"decision_window_days": 365}}},
        decision_window_days=90,
    )
    assert report.summary["audited_scope"] == {"decision_window_days": 365}


def test_nodes_and_edges_pass_through_as_opaque_records():
    report, _ = _run(WIRE_REPORT)
    assert report.nodes == ({"id": "auth-1", "kind": "authority"},)
    assert report.edges == ({"from": "auth-1", "to": "ac-1", "kind": "grants"},)


def test_nullable_finding_fields_stay_none():
    nulled = {
        **WIRE_FINDING,
        "subject_id": None,
        "source_table": None,
        "source_id": None,
        "effective_at": None,
    }
    report, _ = _run({**WIRE_REPORT, "findings": [nulled]})
    f = report.findings[0]
    assert f.subject_id is None
    assert f.source_table is None
    assert f.source_id is None
    assert f.effective_at is None


def test_absent_collections_default_to_empty():
    report, _ = _run(
        {
            "schema_version": "v1",
            "query": "integrity-audit",
            "organization_id": "org-1",
            "evaluated_at": "2026-08-22T12:00:00Z",
            "findings": [],
        }
    )
    assert report.produced_by == ()
    assert report.nodes == ()
    assert report.edges == ()
    assert report.summary == {}


def test_null_collections_default_to_empty():
    report, _ = _run(
        {
            **WIRE_REPORT,
            "produced_by": None,
            "findings": [],
            "nodes": None,
            "edges": None,
            "summary": None,
        }
    )
    assert report.produced_by == ()
    assert report.summary == {}


# `findings` is required by the committed wire schema and is NOT defaulted
# like the other collections above: a response missing it is malformed, not
# "an audit that found nothing". This was the actual bug (caught in review)
# — an earlier version of this parser silently defaulted a missing/malformed
# `findings` to an empty tuple, which would have manufactured a clean audit
# out of a truncated or misconfigured-proxy 200 response.
def test_raises_rather_than_manufacturing_an_empty_report_when_findings_is_missing():
    with pytest.raises(AtlaSentError) as exc_info:
        _run(
            {
                "schema_version": "v1",
                "query": "integrity-audit",
                "organization_id": "org-1",
                "evaluated_at": "2026-08-22T12:00:00Z",
                # findings omitted entirely
            }
        )
    assert exc_info.value.code == "bad_response"


def test_raises_when_findings_is_present_but_not_a_list():
    with pytest.raises(AtlaSentError) as exc_info:
        _run({**WIRE_REPORT, "findings": None})
    assert exc_info.value.code == "bad_response"


def test_null_related_source_ids_defaults_to_empty_tuple():
    report, _ = _run(
        {**WIRE_REPORT, "findings": [{**WIRE_FINDING, "related_source_ids": None}]}
    )
    assert report.findings[0].related_source_ids == ()


def test_empty_findings_is_data_not_an_error():
    report, _ = _run({**WIRE_REPORT, "findings": []})
    assert report.findings == ()
    assert report.organization_id == "org-1"


def test_report_and_finding_are_frozen():
    report, _ = _run(WIRE_REPORT)
    with pytest.raises(Exception):
        report.organization_id = "other"  # type: ignore[misc]
    with pytest.raises(Exception):
        report.findings[0].classification = "defect"  # type: ignore[misc]


# ── open vocabulary ───────────────────────────────────────────────────────────


def test_unrecognized_classification_passes_through():
    report, _ = _run(
        {
            **WIRE_REPORT,
            "findings": [{**WIRE_FINDING, "classification": "future_fourth_value"}],
        }
    )
    assert report.findings[0].classification == "future_fourth_value"


def test_unrecognized_severity_passes_through():
    report, _ = _run(
        {**WIRE_REPORT, "findings": [{**WIRE_FINDING, "severity": "catastrophic"}]}
    )
    assert report.findings[0].severity == "catastrophic"


def test_unrecognized_evidence_posture_passes_through():
    report, _ = _run(
        {
            **WIRE_REPORT,
            "findings": [{**WIRE_FINDING, "evidence_posture": "attested"}],
        }
    )
    assert report.findings[0].evidence_posture == "attested"


def test_known_classifications_are_the_documented_three():
    assert KNOWN_CLASSIFICATIONS == ("defect", "non_exercisable", "unresolved")


# ── fail-closed error propagation ─────────────────────────────────────────────


def test_5xx_raises_rather_than_returning_a_partial_report():
    with pytest.raises(AtlaSentError) as exc:
        _run({"error": "audit could not complete"}, status=500)
    assert exc.value.status_code == 500
    assert exc.value.code == "server_error"


def test_403_missing_scope_raises():
    with pytest.raises(AtlaSentError) as exc:
        _run({"error": "forbidden"}, status=403)
    assert exc.value.status_code == 403
    assert exc.value.code == "forbidden"


def test_401_invalid_key_raises():
    with pytest.raises(AtlaSentError) as exc:
        _run({"error": "bad key"}, status=401)
    assert exc.value.code == "invalid_api_key"


def test_error_is_not_swallowed_into_an_empty_report():
    """A refused audit must never be indistinguishable from a clean one."""
    with pytest.raises(AtlaSentError):
        _run({"error": "boom"}, status=503)


# ── count_findings_by_classification ──────────────────────────────────────────


def _report(*classifications: str) -> IntegrityReport:
    return IntegrityReport(
        schema_version="v1",
        query="integrity-audit",
        organization_id="org-1",
        evaluated_at="2026-08-22T12:00:00Z",
        findings=tuple(
            IntegrityFinding(
                finding_type="t",
                classification=c,
                severity="info",
                subject_id=None,
                source_table=None,
                source_id=None,
                related_source_ids=(),
                effective_at=None,
                evidence_posture="derived",
                reason="r",
            )
            for c in classifications
        ),
    )


def test_counts_zero_fill_all_three_known_classifications():
    assert count_findings_by_classification(_report()) == {
        "defect": 0,
        "non_exercisable": 0,
        "unresolved": 0,
    }


def test_counts_each_classification_separately():
    counts = count_findings_by_classification(
        _report("defect", "defect", "non_exercisable", "unresolved")
    )
    assert counts["defect"] == 2
    assert counts["non_exercisable"] == 1
    assert counts["unresolved"] == 1


def test_non_exercisable_never_folded_into_defect():
    """``non_exercisable`` is frequently the correct, healthy state."""
    counts = count_findings_by_classification(
        _report("non_exercisable", "non_exercisable")
    )
    assert counts["non_exercisable"] == 2
    assert counts["defect"] == 0


def test_unresolved_never_reads_as_clean():
    counts = count_findings_by_classification(_report("unresolved"))
    assert counts["unresolved"] == 1
    assert counts["defect"] == 0
    assert counts["non_exercisable"] == 0


def test_unknown_classification_gets_its_own_key():
    counts = count_findings_by_classification(
        _report("future_fourth_value", "future_fourth_value", "defect")
    )
    assert counts["future_fourth_value"] == 2
    assert counts["defect"] == 1
    assert counts["non_exercisable"] == 0


def test_no_boolean_pass_fail_convenience_is_exposed():
    """Guard against a future ``is_healthy`` / ``has_errors`` regression."""
    counts = count_findings_by_classification(_report("defect"))
    assert "is_healthy" not in counts
    assert "has_errors" not in counts
    # importlib rather than a second `import atlasent.authority_intelligence`
    # statement — this file already has `from atlasent.authority_intelligence
    # import (...)` at module scope, and CodeQL's "module imported with both
    # 'import' and 'import from'" note flags a file combining both forms for
    # the same module.
    mod = importlib.import_module("atlasent.authority_intelligence")

    assert not hasattr(mod, "is_healthy")
    assert not hasattr(mod, "has_errors")
    assert not hasattr(IntegrityReport, "is_healthy")


def test_counts_on_a_parsed_wire_report():
    report, _ = _run(WIRE_REPORT)
    assert count_findings_by_classification(report)["defect"] == 1


# ── wiring ────────────────────────────────────────────────────────────────────


def test_exposed_on_the_client_as_authority_intelligence():
    client = _client()
    assert isinstance(client.authority_intelligence, AuthorityIntelligenceClient)


def test_factory_returns_a_bound_client():
    client = _client()
    ai = authority_intelligence(client)
    assert isinstance(ai, AuthorityIntelligenceClient)
    with patch.object(client._client, "get", return_value=_mock_response(WIRE_REPORT)):
        assert ai.integrity_audit().organization_id == "org-1"


def test_direct_construction_around_an_existing_client():
    client = _client()
    ai = AuthorityIntelligenceClient(client)
    with patch.object(client._client, "get", return_value=_mock_response(WIRE_REPORT)):
        assert ai.integrity_audit().query == "integrity-audit"


def test_top_level_lazy_exports_resolve():
    # importlib rather than `import atlasent` — this file already has
    # `from atlasent import AtlaSentClient` at module scope; see the comment
    # in test_no_boolean_pass_fail_convenience_is_exposed above.
    top = importlib.import_module("atlasent")

    assert top.AuthorityIntelligenceClient is AuthorityIntelligenceClient
    assert top.IntegrityReport is IntegrityReport
    assert top.IntegrityFinding is IntegrityFinding
    assert top.count_findings_by_classification is count_findings_by_classification


def test_sibling_sub_routes_are_not_wrapped_in_this_slice():
    """sod-eligibility / blast-radius / explain-authority are out of scope."""
    for absent in ("sod_eligibility", "blast_radius", "explain_authority"):
        assert not hasattr(AuthorityIntelligenceClient, absent)
