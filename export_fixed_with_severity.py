#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from dateutil import parser as dtparser
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==========================================================
# CONFIGURAÇÃO (substitua!)
# ==========================================================
AST_BASE = "https://eu.ast.checkmarx.net"  # Coloque url do cliente (US,US2,EU,EU2) 
IAM_BASE = "https://eu.iam.checkmarx.net"  # Coloque url do cliente (US,US2,EU,EU2)

TENANT = " "  # Tenant do Cliente 
CLIENT_ID = " " # Adicione ID do Cliente - OAuth 
CLIENT_SECRET = " " # Adicione Secret do Cliente - OAuth 

AUTH_URL = f"{IAM_BASE}/auth/realms/{TENANT}/protocol/openid-connect/token"

FIXED_URL = f"{AST_BASE}/api/data_analytics/drilldown/fixedResults"
PROJECTS_URL = f"{AST_BASE}/api/projects"
SCANS_URL = f"{AST_BASE}/api/scans"
RESULTS_URL = f"{AST_BASE}/api/results"

# Igual UI
DEFINED_RANGE = "30d" # Substitua pela quantidade de dias
STEP = "1d"

# Paginação / performance
FIXED_LIMIT = 500
PAGE_SIZE = 200

# Rulemap (scanner+rule/query -> severity)
RULEMAP_SCANS_PER_PROJECT = 12
RULEMAP_MAX_PROJECTS = 0

# Tentativas por linha do Analytics
MAX_SCAN_TRIES_PER_ANALYTICS_ROW = 30

SLEEP = 0.0

# Saídas
OUT_RELIABLE_CSV = "fixed_with_severity.csv"
OUT_ANALYTICS_ONLY_CSV = "fixed_analytics_only.csv"
OUT_DEBUG_JSON = "fixed_enrichment_debug.json"


# ==========================================================
# HTTP session com retry
# ==========================================================
session = requests.Session()
session.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
    ),
)

_token = None
_exp = 0


def die(msg: str):
    print(f"[ERRO] {msg}", file=sys.stderr)
    sys.exit(1)


def auth_headers() -> Dict[str, str]:
    global _token, _exp
    if _token and time.time() < _exp:
        return {"Authorization": f"Bearer {_token}", "Accept": "application/json", "Content-Type": "application/json"}

    if not TENANT or not CLIENT_ID or not CLIENT_SECRET:
        die("Preencha TENANT, CLIENT_ID e CLIENT_SECRET")

    r = session.post(
        AUTH_URL,
        data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        timeout=(5, 60),
    )
    if r.status_code != 200:
        die(f"Erro ao obter token ({r.status_code}): {r.text}")

    j = r.json()
    _token = j["access_token"]
    _exp = time.time() + j.get("expires_in", 3600) - 60
    return {"Authorization": f"Bearer {_token}", "Accept": "application/json", "Content-Type": "application/json"}


def http_error_dump(url: str, status: int, payload_or_params: Any, body: str):
    print("\n========== HTTP ERROR ==========")
    print("URL     :", url)
    print("STATUS  :", status)
    try:
        print("PAYLOAD :", json.dumps(payload_or_params, indent=2)[:9000])
    except Exception:
        print("PAYLOAD :", str(payload_or_params)[:9000])
    print("BODY    :", body[:12000])
    print("================================\n")


def get_json(url: str, params: Optional[Dict[str, Any]] = None) -> Any:
    r = session.get(url, headers=auth_headers(), params=params or {}, timeout=(5, 120))
    if r.status_code != 200:
        http_error_dump(url, r.status_code, params or {}, r.text)
        r.raise_for_status()
    return r.json()


def post_json(url: str, payload: Dict[str, Any]) -> Any:
    r = session.post(url, headers=auth_headers(), json=payload, timeout=(5, 120))
    if r.status_code != 200:
        http_error_dump(url, r.status_code, payload, r.text)
        r.raise_for_status()
    return r.json()


def deep_get_first_list(obj: Any) -> Optional[List[Any]]:
    if isinstance(obj, dict):
        for k in ("items", "data", "results", "rows", "fixedResults", "scans", "projects"):
            v = obj.get(k)
            if isinstance(v, list):
                return v
        for v in obj.values():
            got = deep_get_first_list(v)
            if got is not None:
                return got
    elif isinstance(obj, list):
        return obj
    return None


def deep_find_first(obj: Any, keys: List[str]) -> Optional[Any]:
    if isinstance(obj, dict):
        for k in keys:
            if k in obj:
                return obj[k]
        for v in obj.values():
            got = deep_find_first(v, keys)
            if got is not None:
                return got
    elif isinstance(obj, list):
        for it in obj:
            got = deep_find_first(it, keys)
            if got is not None:
                return got
    return None


def parse_dt(s: Any) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = dtparser.parse(str(s))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def normalize_text(s: Any) -> str:
    if s is None:
        return ""
    t = str(s).strip().lower()
    t = t.replace("_", " ")
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^a-z0-9 ]+", "", t)
    t = t.replace(" ", "")
    return t


def normalize_severity(v: Any) -> str:
    if v is None:
        return "UNKNOWN"
    s = str(v).strip()
    if not s:
        return "UNKNOWN"
    low = s.lower()
    if low in ("critical", "high", "medium", "low", "info", "informational"):
        return "INFO" if low == "informational" else low.upper()
    return s.upper()


def export_csv(rows: List[Dict[str, Any]], out_path: str) -> None:
    if not rows:
        print(f"[WARN] Nenhuma linha para exportar em {out_path}")
        return
    keys = sorted({k for row in rows for k in row.keys()})
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def base_filters() -> Dict[str, Any]:
    return {
        "tags": [],
        "states": [],
        "groups": [],
        "projects": [],
        "applications": [],
        "scanners": [],
        "branchNames": [],
        "severities": [],
        "queryNames": [],
        "aging": [],
        "environments": [],
    }


def build_fixed_payload(offset: int, limit: int) -> Dict[str, Any]:
    # payload bem parecido com o da UI
    return {
        "range": {"definedRange": DEFINED_RANGE},
        "filters": base_filters(),
        "pagination": {"limit": limit, "offset": offset},
        "limit": limit,
        "offset": offset,
        "step": STEP,
        "dastScanType": "instance",
    }


def fetch_all_fixed_analytics() -> List[Dict[str, Any]]:
    all_rows: List[Dict[str, Any]] = []
    offset = 0
    page = 0
    while True:
        payload = build_fixed_payload(offset, FIXED_LIMIT)
        resp = post_json(FIXED_URL, payload)

        items = resp.get("results") if isinstance(resp, dict) else None
        if not isinstance(items, list):
            items = deep_get_first_list(resp) or []

        if not items:
            print(f"[OK] Analytics fixedResults acabou. Total FIXED={len(all_rows)}")
            break

        for it in items:
            all_rows.append(it if isinstance(it, dict) else {"value": it})

        print(f"[ANALYTICS] page={page} offset={offset} got={len(items)} total={len(all_rows)}")
        offset += FIXED_LIMIT
        page += 1
        if SLEEP:
            time.sleep(SLEEP)

    return all_rows


def list_projects() -> List[Dict[str, Any]]:
    acc, offset = [], 0
    while True:
        r = get_json(PROJECTS_URL, params={"limit": PAGE_SIZE, "offset": offset})
        batch = r.get("projects") or r.get("items") or r.get("data") or []
        if not batch:
            break
        acc.extend(batch)
        offset += PAGE_SIZE
    return acc


def build_project_name_to_id(projects: List[Dict[str, Any]]) -> Dict[str, str]:
    out = {}
    for p in projects:
        name = p.get("name") or p.get("projectName")
        pid = p.get("id") or p.get("projectId")
        if name and pid:
            out[str(name)] = str(pid)
    return out


def list_scans(project_id: str) -> List[Dict[str, Any]]:
    acc, offset = [], 0
    while True:
        r = get_json(SCANS_URL, params={"project-id": project_id, "limit": PAGE_SIZE, "offset": offset})
        batch = r.get("scans") or r.get("items") or r.get("data") or []
        if not batch:
            break
        acc.extend(batch)
        offset += PAGE_SIZE

    def keyfn(s: Dict[str, Any]) -> float:
        dt = parse_dt(s.get("createdAt") or s.get("createdOn") or s.get("date"))
        return dt.timestamp() if dt else 0.0

    acc.sort(key=keyfn)
    return acc


def list_results(scan_id: str) -> List[Dict[str, Any]]:
    acc, offset = [], 0
    while True:
        r = get_json(RESULTS_URL, params={"scan-id": scan_id, "limit": PAGE_SIZE, "offset": offset})
        batch = r.get("results") or r.get("items") or r.get("data") or []
        if not batch:
            break
        acc.extend(batch)
        offset += PAGE_SIZE
    return acc


def norm_scanner(s: Any) -> str:
    t = (str(s or "").strip().lower())
    if "sast" in t:
        return "sast"
    if "iac" in t:
        return "iac"
    if "kics" in t:
        return "kics"
    if "sca" in t:
        return "sca"
    if "container" in t:
        return "sca"
    if "iac security" in t:
        return "iac"
    return t


def extract_query_like_name(r: Dict[str, Any]) -> str:
    for k in ("queryName", "riskName", "vulnerabilityName", "name", "title", "ruleName", "ruleId"):
        v = r.get(k)
        if isinstance(v, str) and v.strip():
            return v
    got = deep_find_first(r, ["queryName", "riskName", "vulnerabilityName", "name", "title", "ruleId"])
    return str(got) if got else ""


def extract_severity(r: Dict[str, Any]) -> str:
    pred = r.get("predicate")
    if isinstance(pred, dict) and pred.get("severity") is not None:
        return normalize_severity(pred.get("severity"))
    preds = r.get("predicates")
    if isinstance(preds, list):
        for p in preds:
            if isinstance(p, dict) and p.get("severity") is not None:
                return normalize_severity(p.get("severity"))
    sev = r.get("severity") or r.get("severityLevel") or r.get("riskLevel")
    if sev is None:
        sev = deep_find_first(r, ["severity", "severityLevel", "riskLevel"])
    return normalize_severity(sev)


def looks_like_internal_sca_id(q: str) -> bool:
    return bool(re.match(r"^Cx[0-9a-f]{4,}-[0-9a-f]{2,}$", (q or "").strip(), re.IGNORECASE))


def token_set(s: str) -> List[str]:
    # tokens p/ overlap (IaC/KICS varia muito)
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    toks = [t for t in s.split() if len(t) >= 3]
    return toks


def token_overlap(a: str, b: str) -> float:
    A = set(token_set(a))
    B = set(token_set(b))
    if not A or not B:
        return 0.0
    return len(A & B) / max(1, len(A | B))


def candidate_ids_for_match(r: Dict[str, Any]) -> List[str]:
    ids = []
    for k in ("id", "similarityId", "alternateId", "queryId", "ruleId"):
        v = r.get(k)
        if isinstance(v, str) and v.strip():
            ids.append(v.strip())
    # às vezes vem dentro
    got = deep_find_first(r, ["queryId", "ruleId", "similarityId", "alternateId"])
    if isinstance(got, str) and got.strip():
        ids.append(got.strip())
    # unique
    out = []
    seen = set()
    for x in ids:
        nx = normalize_text(x)
        if nx and nx not in seen:
            out.append(x)
            seen.add(nx)
    return out


def severity_and_method_from_results(results: List[Dict[str, Any]], fixed_query: str, scanner_hint: str) -> Tuple[str, str]:
    fq = (fixed_query or "").strip()
    fq_up = fq.upper()
    fq_norm = normalize_text(fq)
    sh = norm_scanner(scanner_hint)

    # ------------- CVE (SCA) -------------
    if fq_up.startswith("CVE-"):
        for r in results:
            sim = str(r.get("similarityId") or "").upper()
            if sim == fq_up:
                s = extract_severity(r)
                if s != "UNKNOWN":
                    return s, "results:cve=similarityId"
        for r in results:
            alt = str(r.get("alternateId") or "").upper()
            if alt == fq_up:
                s = extract_severity(r)
                if s != "UNKNOWN":
                    return s, "results:cve=alternateId"
        for r in results:
            rid = str(r.get("id") or "").upper()
            if rid == fq_up:
                s = extract_severity(r)
                if s != "UNKNOWN":
                    return s, "results:cve=id"
        for r in results:
            vd = r.get("vulnerabilityDetails") or {}
            cve = str(vd.get("cveName") or "").upper()
            if cve == fq_up:
                s = extract_severity(r)
                if s != "UNKNOWN":
                    return s, "results:cve=vulnerabilityDetails.cveName"

    # ------------- IDs diretos (forte) -------------
    for r in results:
        for rid in candidate_ids_for_match(r):
            if normalize_text(rid) == fq_norm and fq_norm:
                s = extract_severity(r)
                if s != "UNKNOWN":
                    return s, "results:match_id"

    # ------------- Nome exato / contains -------------
    for r in results:
        qn = extract_query_like_name(r)
        if qn and normalize_text(qn) == fq_norm and fq_norm:
            s = extract_severity(r)
            if s != "UNKNOWN":
                return s, "results:exact_name"

    for r in results:
        qn = extract_query_like_name(r)
        if not qn:
            continue
        qn_norm = normalize_text(qn)
        if fq_norm and (fq_norm in qn_norm or qn_norm in fq_norm):
            s = extract_severity(r)
            if s != "UNKNOWN":
                return s, "results:contains_name"

    # ------------- Token overlap (principalmente IaC/KICS) -------------
    if sh in {"iac", "kics"} and fq:
        best = (0.0, None)
        for r in results:
            qn = extract_query_like_name(r)
            if not qn:
                continue
            score = token_overlap(fq, qn)
            if score > best[0]:
                best = (score, r)
        if best[1] is not None and best[0] >= 0.55:
            s = extract_severity(best[1])
            if s != "UNKNOWN":
                return s, f"results:token_overlap={best[0]:.2f}"

    return "UNKNOWN", "no_match"


def scan_neighbors(scans: List[Dict[str, Any]], target_dt: datetime) -> List[str]:
    """
    Retorna [scan_antes_mais_proximo, scan_depois_mais_proximo] se existirem.
    Isso aumenta MUITO acerto em FIXED (o finding existia antes do fix).
    """
    before = None  # (dt, id)
    after = None
    for s in scans:
        sid = s.get("id") or s.get("scanId")
        dt = parse_dt(s.get("createdAt") or s.get("createdOn") or s.get("date"))
        if not sid or not dt:
            continue
        if dt <= target_dt:
            if before is None or dt > before[0]:
                before = (dt, str(sid))
        if dt >= target_dt:
            if after is None or dt < after[0]:
                after = (dt, str(sid))
    out = []
    if before:
        out.append(before[1])
    if after and (not before or after[1] != before[1]):
        out.append(after[1])
    return out


def ranked_scans(scans: List[Dict[str, Any]], target_dt: datetime) -> List[str]:
    scored: List[Tuple[float, str]] = []
    for s in scans:
        sid = s.get("id") or s.get("scanId")
        dt = parse_dt(s.get("createdAt") or s.get("createdOn") or s.get("date"))
        if not sid or not dt:
            continue
        diff = (target_dt - dt).total_seconds()
        before = diff >= 0
        dist = abs(diff)
        score = dist + (-1000.0 if before else 0.0)  # prefere scan antes
        scored.append((score, str(sid)))
    scored.sort(key=lambda x: x[0])
    return [sid for _, sid in scored]


# ==========================================================
# RULEMAP: (scanner + queryName) -> severity
# ==========================================================
def build_rule_severity_map(projects: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    rulemap: Dict[Tuple[str, str], str] = {}
    used_projects = 0

    for p in projects:
        pid = p.get("id") or p.get("projectId")
        pname = p.get("name") or p.get("projectName")
        if not pid or not pname:
            continue

        used_projects += 1
        if RULEMAP_MAX_PROJECTS and used_projects > RULEMAP_MAX_PROJECTS:
            break

        scans = list_scans(str(pid))
        if not scans:
            continue

        recent = scans[-RULEMAP_SCANS_PER_PROJECT:] if len(scans) > RULEMAP_SCANS_PER_PROJECT else scans

        for s in reversed(recent):
            sid = s.get("id") or s.get("scanId")
            if not sid:
                continue
            results = list_results(str(sid))
            for r in results:
                scn = norm_scanner(r.get("type") or "")
                qn = extract_query_like_name(r)
                sev = extract_severity(r)
                if not qn or sev == "UNKNOWN":
                    continue
                rulemap.setdefault((scn, normalize_text(qn)), sev)

                # bônus: ruleId/queryId também como “nome”
                for rid in candidate_ids_for_match(r):
                    rulemap.setdefault((scn, normalize_text(rid)), sev)

        if SLEEP:
            time.sleep(SLEEP)

    return rulemap


# ==========================================================
# MAIN
# ==========================================================
def main():
    print("[OK] Token...")
    auth_headers()

    print("[1/4] FIXED do Analytics...")
    analytics = fetch_all_fixed_analytics()
    if not analytics:
        die("Nenhum FIXED retornado no range.")

    print("[2/4] Projetos...")
    projects = list_projects()
    name_to_id = build_project_name_to_id(projects)

    print("[3/4] Construindo rule severity map...")
    rulemap = build_rule_severity_map(projects)
    print(f"[INFO] rulemap keys: {len(rulemap)}")

    print("[4/4] Enriquecendo severidade...")
    scans_cache: Dict[str, List[Dict[str, Any]]] = {}
    results_cache: Dict[str, List[Dict[str, Any]]] = {}

    reliable: List[Dict[str, Any]] = []
    analytics_only: List[Dict[str, Any]] = []
    merged: List[Dict[str, Any]] = []

    for i, fr in enumerate(analytics, start=1):
        project_name = fr.get("projectName")
        query_name = fr.get("queryName")
        scanner = fr.get("scanner")
        date_fixed = fr.get("dateFixed")

        row = dict(fr)
        row["severity"] = "UNKNOWN"
        row["severity_source"] = "analytics_only"
        row["match_method"] = "no_match"
        row["scanId_used"] = ""
        row["note"] = ""

        pid = name_to_id.get(str(project_name)) if project_name else None
        target_dt = parse_dt(date_fixed) if date_fixed else None

        # -------------------------
        # CAMADA 1: scans vizinhos (antes/depois)
        # -------------------------
        tried = []
        if pid and target_dt and query_name:
            if pid not in scans_cache:
                scans_cache[pid] = list_scans(pid)

            neighbors = scan_neighbors(scans_cache[pid], target_dt)
            ranked = ranked_scans(scans_cache[pid], target_dt)

            candidates = []
            for sid in neighbors + ranked:
                if sid not in candidates:
                    candidates.append(sid)

            candidates = candidates[:MAX_SCAN_TRIES_PER_ANALYTICS_ROW]

            for sid in candidates:
                tried.append(sid)
                if sid not in results_cache:
                    results_cache[sid] = list_results(sid)

                sev, method = severity_and_method_from_results(results_cache[sid], str(query_name), str(scanner or ""))
                if sev != "UNKNOWN":
                    row["severity"] = sev
                    row["severity_source"] = "results"
                    row["match_method"] = method
                    row["scanId_used"] = sid
                    break

            if not row["scanId_used"] and tried:
                row["scanId_used"] = tried[0]

        # -------------------------
        # CAMADA 2: rulemap (scanner+queryName ou ids)
        # -------------------------
        if row["severity"] == "UNKNOWN" and scanner and query_name:
            if not (str(scanner).strip().upper() == "SCA" and looks_like_internal_sca_id(str(query_name))):
                key = (norm_scanner(scanner), normalize_text(query_name))
                sev2 = rulemap.get(key)
                if sev2 in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                    row["severity"] = sev2
                    row["severity_source"] = "rulemap"
                    row["match_method"] = "rulemap:scanner+query"
                    row["note"] = "filled_from_rule_severity_map"

        merged.append(row)

        if row["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} and row["severity_source"] != "analytics_only":
            reliable.append(row)
        else:
            analytics_only.append(row)

        if i % 200 == 0:
            print(f"[PROGRESS] {i}/{len(analytics)} reliable={len(reliable)} analytics_only={len(analytics_only)}")
        if SLEEP:
            time.sleep(SLEEP)

    export_csv(reliable, OUT_RELIABLE_CSV)
    export_csv(analytics_only, OUT_ANALYTICS_ONLY_CSV)

    with open(OUT_DEBUG_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {
                "rulemap_size": len(rulemap),
                "merged": merged,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    print("\n✅ Finalizado")
    print(f"- {OUT_RELIABLE_CSV} (linhas={len(reliable)})")
    print(f"- {OUT_ANALYTICS_ONLY_CSV} (linhas={len(analytics_only)})")
    print(f"- Debug: {OUT_DEBUG_JSON}")


if __name__ == "__main__":
    main()
