# app.py
import os
import json
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify, render_template, request
from elasticsearch import Elasticsearch

app = Flask(__name__)

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_INDEX = os.getenv("ES_INDEX", "data_cached_*")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")

ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "true").lower() in ("1", "true", "yes")
ES_CA_CERTS = os.getenv("ES_CA_CERTS") or None

BOOTSTRAP_SIZE = int(os.getenv("BOOTSTRAP_SIZE", "2000"))

# UI time anchor behavior:
# - "latest" (default): ui_now is based on latest plausible doc timestamp
# - "now": ui_now = server UTC now
# - ISO string: fixed ui_now
UI_NOW_FIXED = os.getenv("UI_NOW_FIXED", "latest").strip()
UI_NOW_LATEST_OFFSET_DAYS = int(os.getenv("UI_NOW_LATEST_OFFSET_DAYS", "0"))

# Clamp: treat timestamps too far in future as outliers for UI anchor.
UI_NOW_FUTURE_CLAMP_DAYS = int(os.getenv("UI_NOW_FUTURE_CLAMP_DAYS", "2"))

ATTACK_STIX_URL = os.getenv(
    "ATTACK_STIX_URL",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
)
ATTACK_CACHE_PATH = os.getenv("ATTACK_CACHE_PATH", "/app/data/attack_enterprise.json")
ATTACK_CACHE_TTL_DAYS = int(os.getenv("ATTACK_CACHE_TTL_DAYS", "14"))

BOOTSTRAP_CACHE_SECONDS = int(os.getenv("BOOTSTRAP_CACHE_SECONDS", "8"))
UA = os.getenv("HTTP_USER_AGENT", "living-mitre-repo/1.0")

# ------------------------------------------------------------
# Elasticsearch client (v7/v8 compatible auth)
# ------------------------------------------------------------
def make_es_client() -> Elasticsearch:
    base_kwargs: Dict[str, Any] = {
        "verify_certs": ES_VERIFY_CERTS,
        "ca_certs": ES_CA_CERTS,
    }
    if ES_USER and ES_PASS:
        try:
            return Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), **base_kwargs)
        except TypeError:
            return Elasticsearch(ES_URL, http_auth=(ES_USER, ES_PASS), **base_kwargs)  # type: ignore
    return Elasticsearch(ES_URL, **base_kwargs)

es = make_es_client()

# ------------------------------------------------------------
# ATT&CK mapping
# ------------------------------------------------------------
PHASE_TO_TACTIC: Dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TACTIC_ORDER_DEFAULT: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Other",
]

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _norm(x: Any) -> str:
    return ("" if x is None else str(x)).strip()

def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def _parse_iso_dt(s: Any) -> Optional[datetime]:
    s = _norm(s)
    if not s:
        return None
    # Normalize Z to +00:00 for Python parsing
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        # Try trimming fractional seconds if they are weirdly long
        # e.g. 2026-02-18T00:31:10.932979+00:00 -> ok in py, but keep fallback
        try:
            if "." in s:
                head, tail = s.split(".", 1)
                # keep only first 6 microsecond digits if present, then timezone
                # tail like "932979+00:00"
                tz_idx = max(tail.find("+"), tail.find("-"))
                if tz_idx > 0:
                    frac = tail[:tz_idx]
                    tz = tail[tz_idx:]
                    frac = frac[:6]
                    s2 = f"{head}.{frac}{tz}"
                    dt = datetime.fromisoformat(s2)
                else:
                    dt = datetime.fromisoformat(head)
            else:
                return None
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def iso_z(dt: datetime) -> str:
    """
    Browser-safe ISO timestamp: seconds precision, UTC 'Z'
    (Avoids 6-digit microseconds which can break JS Date parsing on some browsers.)
    """
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _clean_str_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        out: List[str] = []
        for i in x:
            s = _norm(i)
            if s and s != "[]":
                out.append(s)
        return out
    if isinstance(x, str):
        s = _norm(x)
        if not s or s == "[]":
            return []
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                v = json.loads(s)
                return _clean_str_list(v)
            except Exception:
                return [s]
        return [s]
    s = _norm(x)
    return [s] if s and s != "[]" else []

def _normalize_severity(sev: Any) -> str:
    s = _norm(sev).lower()
    if not s:
        return "Low"
    if s in ("critical", "crit", "severe"):
        return "Critical"
    if s in ("high", "h"):
        return "High"
    if s in ("moderate", "medium", "med", "m"):
        return "Moderate"
    if s in ("low", "l", "info", "informational"):
        return "Low"
    return s[:1].upper() + s[1:]

def _normalize_analysis_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, list):
        items = [_norm(i) for i in x if _norm(i) and _norm(i) != "[]"]
        return " • ".join(items)
    s = _norm(x)
    if s == "[]":
        return ""
    return s

# ------------------------------------------------------------
# ES compatibility wrappers
# ------------------------------------------------------------
def es_search_safe(
    *,
    index: str,
    size: int,
    query: Dict[str, Any],
    sort: Optional[List[Any]] = None,
    source: Any = True,
    source_includes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Works with ES python clients that support either:
      - es.search(index=..., query=..., sort=...)
      - es.search(index=..., body={...})
    """
    try:
        kwargs: Dict[str, Any] = {
            "index": index,
            "size": size,
            "query": query,
            "_source": source,
        }
        if sort is not None:
            kwargs["sort"] = sort
        if source_includes is not None:
            kwargs["_source_includes"] = source_includes
        return es.search(**kwargs)  # type: ignore
    except TypeError:
        body: Dict[str, Any] = {"query": query}
        if sort is not None:
            body["sort"] = sort
        if source_includes is not None:
            body["_source"] = source_includes
        else:
            body["_source"] = source
        return es.search(index=index, body=body, size=size)  # type: ignore

def es_count_safe(*, index: str, query: Dict[str, Any]) -> int:
    try:
        r = es.count(index=index, query=query)  # type: ignore
        return int(r.get("count") or 0)
    except TypeError:
        r = es.count(index=index, body={"query": query})  # type: ignore
        return int(r.get("count") or 0)
    except Exception:
        return 0

# ------------------------------------------------------------
# UI "now" calculation (fixed + plausible-anchor)
# ------------------------------------------------------------
def compute_ui_now(
    *,
    latest_plausible_ts: Optional[str],
) -> str:
    fixed = _norm(UI_NOW_FIXED).lower()
    offset = timedelta(days=max(0, UI_NOW_LATEST_OFFSET_DAYS))

    # explicit override
    if fixed and fixed not in ("latest", "auto", "1"):
        if fixed in ("now", "utcnow"):
            return iso_z(utcnow())
        dt = _parse_iso_dt(UI_NOW_FIXED)
        return iso_z(dt) if dt else iso_z(utcnow())

    # default: latest plausible (already filtered for future outliers)
    dt_latest = _parse_iso_dt(latest_plausible_ts or "")
    if dt_latest:
        candidate = dt_latest - offset
        return iso_z(candidate)

    return iso_z(utcnow())

def latest_plausible_timestamp(docs: List[Dict[str, Any]]) -> Optional[str]:
    """
    Scan docs (already in descending sort order) for the latest timestamp
    that is not an outlier in the future relative to server time.
    """
    if not docs:
        return None
    real_now = utcnow()
    ceiling = real_now + timedelta(days=UI_NOW_FUTURE_CLAMP_DAYS)

    for d in docs:
        dt = _parse_iso_dt(d.get("Timestamp"))
        if dt and dt <= ceiling:
            return iso_z(dt)

    # If everything is "future", fall back to server now so UI still works.
    return iso_z(real_now)

# ------------------------------------------------------------
# ATT&CK catalog loader (cached)
# ------------------------------------------------------------
_attack_lock = threading.Lock()
_attack_map: Optional[Dict[str, Dict[str, Any]]] = None

def _attack_cache_fresh(path: str) -> bool:
    try:
        st = os.stat(path)
        age = time.time() - st.st_mtime
        return age < (ATTACK_CACHE_TTL_DAYS * 24 * 3600)
    except Exception:
        return False

def _download_attack_stix(url: str, path: str) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, timeout=45, headers={"User-Agent": UA})
        r.raise_for_status()
        data = r.json()
        _ensure_dir(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return data
    except Exception:
        return None

def _load_attack_stix_from_disk(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _build_attack_map(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    objs = bundle.get("objects") or []
    if not isinstance(objs, list):
        return out

    for o in objs:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") is True or o.get("x_mitre_deprecated") is True:
            continue

        tid = ""
        for ref in (o.get("external_references") or []):
            if not isinstance(ref, dict):
                continue
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid = _norm(ref.get("external_id"))
                break
        if not tid:
            continue

        name = _norm(o.get("name")) or tid

        tactics: List[str] = []
        for ph in (o.get("kill_chain_phases") or []):
            if not isinstance(ph, dict):
                continue
            if ph.get("kill_chain_name") != "mitre-attack":
                continue
            phase = _norm(ph.get("phase_name"))
            if not phase:
                continue
            tactics.append(PHASE_TO_TACTIC.get(phase, phase.replace("-", " ").title()))

        seen = set()
        tactics_clean: List[str] = []
        for t in tactics:
            if t in seen:
                continue
            seen.add(t)
            tactics_clean.append(t)

        out[tid] = {"name": name, "tactics": tactics_clean}

    return out

def get_attack_map() -> Dict[str, Dict[str, Any]]:
    global _attack_map
    with _attack_lock:
        if _attack_map is not None:
            return _attack_map

        bundle: Optional[Dict[str, Any]] = None
        if _attack_cache_fresh(ATTACK_CACHE_PATH):
            bundle = _load_attack_stix_from_disk(ATTACK_CACHE_PATH)
        if bundle is None:
            bundle = _download_attack_stix(ATTACK_STIX_URL, ATTACK_CACHE_PATH)
        if bundle is None:
            bundle = _load_attack_stix_from_disk(ATTACK_CACHE_PATH)

        _attack_map = _build_attack_map(bundle) if bundle else {}
        return _attack_map

# ------------------------------------------------------------
# Bootstrap cache
# ------------------------------------------------------------
_bootstrap_lock = threading.Lock()
_bootstrap_cache: Optional[Dict[str, Any]] = None
_bootstrap_cache_at: float = 0.0
_bootstrap_cache_size: int = 0

# ------------------------------------------------------------
# Doc normalization
# ------------------------------------------------------------
def normalize_doc(hit: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    src = hit.get("_source") or {}
    doc_id = hit.get("_id")
    idx = hit.get("_index")

    # Timestamp normalize -> browser-safe "Z" format
    ts_raw = src.get("Timestamp")
    ts_dt = _parse_iso_dt(ts_raw)
    ts_norm = iso_z(ts_dt) if ts_dt else (_norm(ts_raw) or None)

    tech_name_hints: Dict[str, str] = {}
    analyses_in = src.get("Analyses") or []
    analyses_out: List[Dict[str, Any]] = []

    if isinstance(analyses_in, list):
        for a in analyses_in:
            if not isinstance(a, dict):
                continue
            stage = _norm(a.get("Stage")) or "Unknown"
            desc = _normalize_analysis_text(a.get("Description"))
            det = _normalize_analysis_text(a.get("Detection"))
            rem = _normalize_analysis_text(a.get("Remediation"))

            techs_raw = a.get("Techniques") or []
            techs: List[str] = []

            if isinstance(techs_raw, list):
                for t in techs_raw:
                    if isinstance(t, str):
                        tid = _norm(t)
                        if tid:
                            techs.append(tid)
                    elif isinstance(t, dict):
                        tid = _norm(t.get("technique_id") or t.get("id") or t.get("technique"))
                        tnm = _norm(t.get("technique_name") or t.get("name"))
                        if tid:
                            techs.append(tid)
                            if tnm and tid not in tech_name_hints:
                                tech_name_hints[tid] = tnm

            analyses_out.append(
                {
                    "Stage": stage,
                    "Description": desc,
                    "Detection": det,
                    "Remediation": rem,
                    "Techniques": list(dict.fromkeys(techs)),
                }
            )

    # sequence normalization
    seq = src.get("sequence")
    try:
        if seq is not None:
            seq = int(seq)
    except Exception:
        seq = None

    doc = {
        "id": doc_id,
        "index": idx,
        "Timestamp": ts_norm,
        "Title": src.get("Title") or "(no title)",
        "Severity": _normalize_severity(src.get("Severity")),

        "Threat_Actors": _clean_str_list(src.get("Threat_Actors")),
        "Tools": _clean_str_list(src.get("Tools")),
        "CVEs": _clean_str_list(src.get("cveID") or src.get("CVEs")),

        "source": src.get("source") or None,
        "enrichment": src.get("enrichment") or None,
        "sequence": seq,

        "doc_summary": src.get("doc_summary") or "",
        "diamond_model_summary": src.get("diamond_model_summary") or "",
        "kill_chain_summary": src.get("kill_chain_summary") or "",
        "pyramid_of_pain_summary": src.get("pyramid_of_pain_summary") or "",

        "Adversary": src.get("Adversary") or {},
        "Capability": src.get("Capability") or {},
        "Infrastructure": src.get("Infrastructure") or {},
        "Victim": src.get("Victim") or {},
        "Pyramid_Of_Pain": src.get("Pyramid_Of_Pain") or {},

        "Recommended_Tools_And_Techniques_For_Analysis": _clean_str_list(
            src.get("Recommended_Tools_And_Techniques_For_Analysis")
        ),
        "Detection_Rules_And_Indicators": _clean_str_list(src.get("Detection_Rules_And_Indicators")),
        "Detection_Hints": _clean_str_list(src.get("Detection_Hints")),
        "Data_Exfiltration_Indicators": _clean_str_list(src.get("Data_Exfiltration_Indicators")),
        "Post_Incident_Recommendations": _clean_str_list(src.get("Post_Incident_Recommendations")),
        "Behavioral_Indicators_of_Attackers": _clean_str_list(src.get("Behavioral_Indicators_of_Attackers")),

        "Extracted_Entities": src.get("Extracted_Entities") or {},
        "Analyses": analyses_out,
    }
    return doc, tech_name_hints

def build_catalog_for_docs(docs: List[Dict[str, Any]], name_hints: Dict[str, str]) -> Dict[str, Any]:
    attack = get_attack_map()

    used: List[str] = []
    seen = set()
    for d in docs:
        for a in (d.get("Analyses") or []):
            for tid in (a.get("Techniques") or []):
                tid = _norm(tid)
                if not tid or tid in seen:
                    continue
                seen.add(tid)
                used.append(tid)

    techniques: Dict[str, Any] = {}
    for tid in used:
        info = attack.get(tid) or {}
        nm = _norm(info.get("name")) or name_hints.get(tid) or tid
        tactics = info.get("tactics") or []
        if not isinstance(tactics, list):
            tactics = []

        primary = "Other"
        for t in TACTIC_ORDER_DEFAULT:
            if t in tactics:
                primary = t
                break
        if primary == "Other" and tactics:
            primary = _norm(tactics[0]) or "Other"

        techniques[tid] = {"name": nm, "tactic": primary, "tactics": tactics}

    order = [t for t in TACTIC_ORDER_DEFAULT]
    if "Other" not in order:
        order.append("Other")

    return {"tactic_order": order, "techniques": techniques}

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/")
def home():
    return render_template("index.html")

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})

@app.get("/api/bootstrap")
def api_bootstrap():
    global _bootstrap_cache, _bootstrap_cache_at, _bootstrap_cache_size

    try:
        size_q = int(request.args.get("size", str(BOOTSTRAP_SIZE)))
    except Exception:
        size_q = BOOTSTRAP_SIZE
    size = max(50, min(size_q, 5000))

    now_s = time.time()
    with _bootstrap_lock:
        if (
            _bootstrap_cache is not None
            and _bootstrap_cache_size == size
            and (now_s - _bootstrap_cache_at) < max(1, BOOTSTRAP_CACHE_SECONDS)
        ):
            return jsonify(_bootstrap_cache)

    # Sort: prefer ingestion-like cursor fields if present, then Timestamp
    sort = [
        {"sequence": {"order": "desc", "unmapped_type": "long"}},
        {"enrichment.processed_at": {"order": "desc", "unmapped_type": "date"}},
        {"Timestamp": {"order": "desc", "unmapped_type": "date"}},
    ]

    try:
        resp = es_search_safe(
            index=ES_INDEX,
            size=size,
            sort=sort,
            query={"match_all": {}},
            source=True,
        )
    except Exception as e:
        return jsonify({"error": "es_search_failed", "details": str(e)}), 502

    hits = (resp.get("hits") or {}).get("hits") or []
    docs: List[Dict[str, Any]] = []
    name_hints: Dict[str, str] = {}

    for h in hits:
        d, hints = normalize_doc(h)
        docs.append(d)
        for k, v in hints.items():
            if k not in name_hints and v:
                name_hints[k] = v

    # latest cursor values
    latest_ts = docs[0].get("Timestamp") if docs else None
    latest_seq = None
    if docs:
        seqs = [d.get("sequence") for d in docs if isinstance(d.get("sequence"), int)]
        latest_seq = max(seqs) if seqs else None

    # choose UI anchor time that ignores future outliers
    anchor_ts = latest_plausible_timestamp(docs)
    ui_now = compute_ui_now(latest_plausible_ts=anchor_ts)

    catalog = build_catalog_for_docs(docs, name_hints)

    payload = {
        "meta": {
            "index": ES_INDEX,
            "size": size,
            "latest_ts": latest_ts,
            "latest_seq": latest_seq,
            "anchor_ts": anchor_ts,  # for debugging / transparency
            "ui_now": ui_now,
            "fetched_at": iso_z(utcnow()),
        },
        "count": len(docs),
        "docs": docs,
        "catalog": catalog,
    }

    with _bootstrap_lock:
        _bootstrap_cache = payload
        _bootstrap_cache_at = time.time()
        _bootstrap_cache_size = size

    return jsonify(payload)

@app.get("/api/heartbeat")
def api_heartbeat():
    """
    Light poll: return new_count since a cursor.
    Prefer sequence cursor if provided, else timestamp.
    """
    since_ts = _norm(request.args.get("since_ts"))
    since_seq = _norm(request.args.get("since_seq"))

    # get current latest (by same sort logic)
    sort = [
        {"sequence": {"order": "desc", "unmapped_type": "long"}},
        {"enrichment.processed_at": {"order": "desc", "unmapped_type": "date"}},
        {"Timestamp": {"order": "desc", "unmapped_type": "date"}},
    ]

    try:
        resp = es_search_safe(
            index=ES_INDEX,
            size=1,
            sort=sort,
            query={"match_all": {}},
            source_includes=["Timestamp", "sequence", "enrichment.processed_at"],
        )
        hits = (resp.get("hits") or {}).get("hits") or []
        top_src = (hits[0].get("_source") or {}) if hits else {}
        latest_ts_raw = top_src.get("Timestamp")
        latest_ts_dt = _parse_iso_dt(latest_ts_raw)
        latest_ts_norm = iso_z(latest_ts_dt) if latest_ts_dt else (_norm(latest_ts_raw) or None)

        latest_seq = None
        try:
            if top_src.get("sequence") is not None:
                latest_seq = int(top_src.get("sequence"))
        except Exception:
            latest_seq = None

    except Exception as e:
        return jsonify({"ok": False, "error": "es_failed", "details": str(e)}), 502

    new_count = 0

    # Prefer sequence-based delta if caller has it
    if since_seq:
        try:
            sseq = int(since_seq)
            new_count = es_count_safe(index=ES_INDEX, query={"range": {"sequence": {"gt": sseq}}})
        except Exception:
            new_count = 0
    elif since_ts:
        new_count = es_count_safe(index=ES_INDEX, query={"range": {"Timestamp": {"gt": since_ts}}})

    return jsonify(
        {
            "ok": True,
            "latest_ts": latest_ts_norm,
            "latest_seq": latest_seq,
            "new_count": new_count,
        }
    )

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8970"))
    app.run(host="0.0.0.0", port=port, debug=True)
