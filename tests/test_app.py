from datetime import timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module
from app import _parse_iso_dt, _normalize_severity, app


def test_parse_iso_dt_accepts_lowercase_z_suffix():
    dt = _parse_iso_dt("2026-02-18T00:31:10z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2026
    assert dt.minute == 31


def test_parse_iso_dt_rejects_invalid_text():
    assert _parse_iso_dt("not-a-date") is None


def test_severity_normalization_variants():
    assert _normalize_severity("crit") == "Critical"
    assert _normalize_severity("medium") == "Moderate"
    assert _normalize_severity("") == "Low"


def test_healthz_endpoint_ok():
    client = app.test_client()
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True}


def test_heartbeat_supports_since_seq(monkeypatch):
    def fake_search_safe(**kwargs):
        return {"hits": {"hits": [{"_source": {"Timestamp": "2026-01-01T00:00:00Z", "sequence": 42}}]}}

    monkeypatch.setattr(app_module, "es_search_safe", fake_search_safe)
    monkeypatch.setattr(app_module, "es_count_safe", lambda **kwargs: 3)

    client = app.test_client()
    r = client.get("/api/heartbeat?since_seq=40")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["latest_seq"] == 42
    assert payload["new_count"] == 3


def test_heartbeat_supports_since_ts_alias(monkeypatch):
    def fake_search_safe(**kwargs):
        return {"hits": {"hits": [{"_source": {"Timestamp": "2026-01-01T00:00:00z", "sequence": None}}]}}

    monkeypatch.setattr(app_module, "es_search_safe", fake_search_safe)
    monkeypatch.setattr(app_module, "es_count_safe", lambda **kwargs: 2)

    client = app.test_client()
    r = client.get("/api/heartbeat?since=2025-12-31T00:00:00Z")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["latest_ts"] == "2026-01-01T00:00:00Z"
    assert payload["new_count"] == 2


def test_compute_ui_now_uses_mode_utc(monkeypatch):
    monkeypatch.setattr(app_module, "UI_NOW_MODE", "utc")
    monkeypatch.setattr(app_module, "UI_NOW_FIXED", "")
    out = app_module.compute_ui_now("2026-01-01T00:00:00Z")
    assert out.endswith("Z")


def test_compute_ui_now_latest_applies_positive_offset(monkeypatch):
    monkeypatch.setattr(app_module, "UI_NOW_MODE", "latest")
    monkeypatch.setattr(app_module, "UI_NOW_FIXED", "")
    monkeypatch.setattr(app_module, "UI_NOW_LATEST_OFFSET_DAYS", 2)
    out = app_module.compute_ui_now("2026-01-01T00:00:00Z")
    assert out == "2026-01-03T00:00:00Z"


def test_freshness_meta_flags_stale(monkeypatch):
    monkeypatch.setattr(app_module, "DATA_STALE_SECONDS", 10)
    fresh = app_module._freshness_meta("2099-01-01T00:00:00Z")
    assert fresh["is_stale"] is False
    stale = app_module._freshness_meta("2000-01-01T00:00:00Z")
    assert stale["is_stale"] is True


def test_healthz_deps_reports_es_status(monkeypatch):
    class DummyES:
        def ping(self):
            return True

    monkeypatch.setattr(app_module, "es", DummyES())
    monkeypatch.setattr(app_module, "es_count_safe", lambda **kwargs: 7)

    client = app.test_client()
    r = client.get("/healthz/deps")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["es"]["sample_count"] == 7


def test_bootstrap_includes_freshness_meta(monkeypatch):
    def fake_search_safe(**kwargs):
        return {
            "hits": {
                "hits": [
                    {
                        "_id": "1",
                        "_index": "idx",
                        "_source": {"Timestamp": "2026-01-01T00:00:00Z", "Title": "x", "Analyses": []},
                    }
                ]
            }
        }

    monkeypatch.setattr(app_module, "es_search_safe", fake_search_safe)
    monkeypatch.setattr(app_module, "build_catalog_for_docs", lambda docs, hints: {"tactic_order": [], "techniques": {}})

    client = app.test_client()
    r = client.get("/api/bootstrap")
    assert r.status_code == 200
    payload = r.get_json()
    assert "data_freshness" in payload["meta"]
    assert "ui_now_mode" in payload["meta"]


def test_normalize_doc_enriches_tools_and_scores():
    hit = {
        "_id": "1",
        "_index": "idx",
        "_source": {
            "Timestamp": "2026-01-01T00:00:00Z",
            "Title": "x",
            "Severity": "High",
            "Threat_Actors": ["Unknown threat actor"],
            "Capability": {"Tools": ["XRedRAT"]},
            "Pyramid_Of_Pain": {"Tools": ["SnipVex"]},
            "Extracted_Entities": {"Software": ["Procolored printer software"]},
            "Analyses": [{"Stage": "Delivery", "Techniques": [{"technique_id": "T1195.002"}], "Detection": ["monitor"], "Remediation": ["audit"]}],
            "Detection_Rules_And_Indicators": ["rule1"],
            "Post_Incident_Recommendations": ["rec1"],
        },
    }
    doc, _ = app_module.normalize_doc(hit)
    assert "XRedRAT" in doc["Tools"]
    assert "SnipVex" in doc["Tools"]
    assert doc["priority_score"] > 0
    assert doc["relevance_score"] > 0


def test_detection_backlog_endpoint(monkeypatch):
    def fake_search_safe(**kwargs):
        return {
            "hits": {
                "hits": [
                    {
                        "_id": "1",
                        "_index": "idx",
                        "_source": {
                            "Timestamp": "2026-01-01T00:00:00Z",
                            "Title": "x",
                            "Severity": "High",
                            "Analyses": [{"Stage": "Delivery", "Techniques": [{"technique_id": "T1195.002"}], "Detection": ["monitor channel"], "Remediation": ["audit supply chain"]}],
                            "Detection_Rules_And_Indicators": ["rule1"],
                        },
                    }
                ]
            }
        }

    monkeypatch.setattr(app_module, "es_search_safe", fake_search_safe)

    client = app.test_client()
    r = client.get("/api/detection_backlog")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is True
    assert payload["count"] >= 1
    assert payload["items"][0]["priority_score"] > 0
