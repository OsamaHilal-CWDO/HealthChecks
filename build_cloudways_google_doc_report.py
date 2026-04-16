#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import html
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse


def choose_traffic_json(explicit_path: str | None) -> str:
    if explicit_path and Path(explicit_path).exists():
        return explicit_path

    candidates = [
        "/tmp/top5_backend_traffic_summary.json",
        "/tmp/top5_backend_traffic_nogeo_summary.json",
    ]
    for p in candidates:
        if Path(p).exists():
            return p

    raise FileNotFoundError(
        "Could not find traffic JSON. Provide --traffic-json or place one at "
        "/tmp/top5_backend_traffic_summary.json or /tmp/top5_backend_traffic_nogeo_summary.json"
    )


def read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_health_log(path: str) -> dict:
    txt = Path(path).read_text(encoding="utf-8", errors="ignore")

    def g(pattern: str, default: str = "N/A") -> str:
        m = re.search(pattern, txt, re.MULTILINE)
        return m.group(1).strip() if m else default

    critical = re.findall(r"^\s*❌\s+(.*)$", txt, re.MULTILINE)
    warnings = re.findall(r"^\s*⚠️\s+(.*)$", txt, re.MULTILINE)

    # Try to infer DB size from multiline "Database Size" section.
    db_size = g(r"^Database Size:\s*(.+)$")
    m_db_next = re.search(r"Database Size:\s*(?:Name\s+Size)?\s*\n\s*([^\n]+)", txt, re.MULTILINE)
    if m_db_next:
        db_size = m_db_next.group(1).strip()

    report_json = g(r"^Report saved to:\s*(/tmp/wp_health_report_[0-9_]+\.json)$", default="")

    # Try to infer app name from log filename if possible.
    app_guess = Path(path).stem
    return {
        "source": path,
        "source_type": "log",
        "app_guess": app_guess,
        "site": g(r"^Site:\s*(.+)$"),
        "report_generated": g(r"^Report Generated:\s*(.+)$"),
        "ttfb_ms": g(r"^Average TTFB:\s*([0-9.]+ms)$"),
        "page_load_ms": g(r"^Page Load Time:\s*([0-9.]+ms)$"),
        "throughput": g(r"^Throughput:\s*([0-9.]+\s*req/sec)$"),
        "max_concurrent_users": g(r"^Estimated Max Concurrent Users:\s*([0-9]+)$"),
        "daily_capacity": g(r"^Estimated Daily Capacity:\s*(.+)$"),
        "db_size": db_size,
        "report_json_path": report_json,
        "critical_issues": critical,
        "warnings": warnings,
    }


def parse_health_json(path: str) -> dict:
    data = read_json(path)

    def deep_get(obj, keys):
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).lower()
                if any(p in kl for p in keys):
                    return v
                nested = deep_get(v, keys)
                if nested is not None:
                    return nested
        elif isinstance(obj, list):
            for x in obj:
                nested = deep_get(x, keys)
                if nested is not None:
                    return nested
        return None

    def deep_collect_list(obj, keys):
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).lower()
                if any(p in kl for p in keys):
                    if isinstance(v, list):
                        found.extend([str(x) for x in v])
                    elif isinstance(v, str):
                        found.append(v)
                found.extend(deep_collect_list(v, keys))
        elif isinstance(obj, list):
            for x in obj:
                found.extend(deep_collect_list(x, keys))
        return found

    site = (
        data.get("site")
        or data.get("url")
        or deep_get(data, ["site", "url", "domain"])
        or "N/A"
    )
    ttfb = data.get("ttfb_ms") or deep_get(data, ["ttfb"])
    page_load = data.get("page_load_ms") or deep_get(data, ["page_load"])
    throughput = data.get("throughput_rps") or deep_get(data, ["throughput"])
    max_users = data.get("estimated_max_concurrent_users") or deep_get(data, ["max_concurrent_users"])
    daily_cap = data.get("estimated_daily_capacity") or deep_get(data, ["daily_capacity"])
    db_size = data.get("database_size") or deep_get(data, ["database_size", "db_size", "size_mb"])
    report_generated = data.get("report_generated") or data.get("generated_at") or "N/A"
    critical = deep_collect_list(data, ["critical_issues", "critical"])
    warnings = deep_collect_list(data, ["warnings", "warning"])

    return {
        "source": path,
        "source_type": "json",
        "app_guess": "",
        "site": str(site),
        "report_generated": str(report_generated),
        "ttfb_ms": str(ttfb if ttfb is not None else "N/A"),
        "page_load_ms": str(page_load if page_load is not None else "N/A"),
        "throughput": str(throughput if throughput is not None else "N/A"),
        "max_concurrent_users": str(max_users if max_users is not None else "N/A"),
        "daily_capacity": str(daily_cap if daily_cap is not None else "N/A"),
        "db_size": str(db_size if db_size is not None else "N/A"),
        "report_json_path": path,
        "critical_issues": critical,
        "warnings": warnings,
    }


def collect_health_records(source_mode: str = "merge") -> List[dict]:
    records: List[dict] = []
    if source_mode in ("merge", "log"):
        for p in sorted(glob.glob("/tmp/wp_health_runs/*.log")):
            try:
                records.append(parse_health_log(p))
            except Exception:
                continue
    if source_mode in ("merge", "json"):
        for p in sorted(glob.glob("/tmp/wp_health_report_*.json")):
            try:
                records.append(parse_health_json(p))
            except Exception:
                continue
    return records


def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    if "://" not in v:
        v = "https://" + v
    try:
        v = urlparse(v).netloc.lower()
    except Exception:
        v = re.sub(r"^https?://", "", v).split("/")[0]
    v = v.split(":")[0]
    return v


def health_score(record: dict) -> int:
    fields = [
        "site",
        "ttfb_ms",
        "page_load_ms",
        "throughput",
        "max_concurrent_users",
        "daily_capacity",
        "db_size",
    ]
    score = 0
    for f in fields:
        v = str(record.get(f, "")).strip()
        if v and v != "N/A":
            score += 1
    score += len(record.get("critical_issues", []) or [])
    score += len(record.get("warnings", []) or [])
    if record.get("source_type") == "log":
        score += 1
    return score


def merge_health(primary: dict, secondary: dict) -> dict:
    merged = dict(primary)
    for k in [
        "site",
        "report_generated",
        "ttfb_ms",
        "page_load_ms",
        "throughput",
        "max_concurrent_users",
        "daily_capacity",
        "db_size",
        "report_json_path",
    ]:
        pv = str(merged.get(k, "")).strip()
        sv = str(secondary.get(k, "")).strip()
        if (not pv or pv == "N/A") and sv and sv != "N/A":
            merged[k] = secondary.get(k)

    crit = list(merged.get("critical_issues", []) or [])
    warn = list(merged.get("warnings", []) or [])
    for x in secondary.get("critical_issues", []) or []:
        if x not in crit:
            crit.append(x)
    for x in secondary.get("warnings", []) or []:
        if x not in warn:
            warn.append(x)
    merged["critical_issues"] = crit
    merged["warnings"] = warn
    return merged


def map_health_to_apps(top5: List[dict], records: List[dict], source_mode: str = "log") -> Dict[str, dict]:
    by_app: Dict[str, dict] = {}

    # Pre-index by normalized site domain
    rec_by_domain: Dict[str, List[dict]] = {}
    for r in records:
        d = normalize_domain(r.get("site", ""))
        if d:
            rec_by_domain.setdefault(d, []).append(r)

    for app in top5:
        name = app.get("app", "")
        domain = normalize_domain(app.get("domain", ""))
        candidates = []

        # 1) direct app log has highest trust when log source is enabled.
        if source_mode in ("merge", "log"):
            direct = f"/tmp/wp_health_runs/{name}.log"
            if Path(direct).exists():
                try:
                    direct_rec = parse_health_log(direct)
                    candidates.append(direct_rec)
                    # Only merge linked JSON when explicitly in merge mode.
                    if source_mode == "merge":
                        report_json = direct_rec.get("report_json_path", "")
                        if report_json and Path(report_json).exists():
                            try:
                                candidates.append(parse_health_json(report_json))
                            except Exception:
                                pass
                except Exception:
                    pass

        # 2) domain match candidates
        if domain and domain in rec_by_domain:
            candidates.extend(rec_by_domain[domain])

        chosen = None
        if candidates:
            candidates = sorted(candidates, key=health_score, reverse=True)
            chosen = candidates[0]
            # For single-source modes, keep one best record only.
            if source_mode == "merge":
                for extra in candidates[1:]:
                    chosen = merge_health(chosen, extra)

        # 3) fallback empty
        if not chosen:
            chosen = {
                "source": "N/A",
                "source_type": "none",
                "site": app.get("domain", "N/A"),
                "report_generated": "N/A",
                "ttfb_ms": "N/A",
                "page_load_ms": "N/A",
                "throughput": "N/A",
                "max_concurrent_users": "N/A",
                "daily_capacity": "N/A",
                "db_size": "N/A",
                "critical_issues": [],
                "warnings": [],
            }
        by_app[name] = chosen
    return by_app


def render_kv_table(title: str, rows: List[Tuple[str, str]]) -> str:
    out = [f"<table><tr><th colspan='2'>{html.escape(title)}</th></tr>"]
    for k, v in rows:
        out.append(f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>")
    out.append("</table>")
    return "\n".join(out)


def render_top_table(title: str, items: List[List], col1: str = "Item", col2: str = "Count") -> str:
    out = [f"<table><tr><th colspan='2'>{html.escape(title)}</th></tr><tr><th>{html.escape(col1)}</th><th>{html.escape(col2)}</th></tr>"]
    if not items:
        out.append("<tr><td colspan='2'>N/A</td></tr>")
    else:
        for pair in items:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                out.append(f"<tr><td>{html.escape(str(pair[0]))}</td><td>{html.escape(str(pair[1]))}</td></tr>")
    out.append("</table>")
    return "\n".join(out)


def build_report_html(traffic: dict, health_by_app: Dict[str, dict], output_path: str) -> None:
    top5 = traffic.get("top5", [])
    all_sorted = traffic.get("all_applications_sorted", [])

    out = []
    out.append("<html><head><meta charset='utf-8'><style>")
    out.append("body{font-family:Arial,sans-serif;font-size:11pt;line-height:1.4}")
    out.append("h1,h2,h3{margin:14px 0 8px}")
    out.append("table{border-collapse:collapse;width:100%;margin:8px 0 16px}")
    out.append("th,td{border:1px solid #bbb;padding:6px;vertical-align:top}")
    out.append("th{background:#f2f2f2}")
    out.append("</style></head><body>")

    out.append("<h1>Cloudways Traffic + Health Consolidated Report</h1>")
    out.append(f"<p><b>Generated:</b> {html.escape(traffic.get('generated_at', datetime.now().astimezone().isoformat()))}</p>")

    # Executive overview table
    out.append("<h2>Executive Overview (Top 5 by traffic)</h2>")
    out.append(
        "<table><tr>"
        "<th>Rank</th><th>App</th><th>Total Requests</th><th>Error Rate %</th>"
        "<th>Top Endpoint</th><th>Top Non-browser UA</th><th>TTFB</th><th>Max Concurrent Users</th><th>Observation Notes</th>"
        "</tr>"
    )
    for i, app in enumerate(top5, 1):
        name = app.get("app", "")
        h = health_by_app.get(name, {})
        top_ep = app.get("top_endpoints", [])
        top_ua = app.get("top_non_browser_user_agents", [])
        out.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td>{html.escape(name)}</td>"
            f"<td>{app.get('total_requests', 'N/A')}</td>"
            f"<td>{app.get('error_rate_percent', 'N/A')}</td>"
            f"<td>{html.escape(str(top_ep[0][0])) if top_ep else 'N/A'}</td>"
            f"<td>{html.escape(str(top_ua[0][0])) if top_ua else 'N/A'}</td>"
            f"<td>{html.escape(str(h.get('ttfb_ms', 'N/A')))}</td>"
            f"<td>{html.escape(str(h.get('max_concurrent_users', 'N/A')))}</td>"
            "<td>[Add notes]</td>"
            "</tr>"
        )
    out.append("</table>")

    # Per-app detailed sections
    for i, app in enumerate(top5, 1):
        name = app.get("app", "")
        h = health_by_app.get(name, {})
        out.append(f"<h2>{i}. Application: {html.escape(name)}</h2>")

        out.append(
            render_kv_table(
                "Traffic Reference",
                [
                    ("Total Requests", str(app.get("total_requests", "N/A"))),
                    ("Error Count (4xx+5xx)", str(app.get("error_count", "N/A"))),
                    ("Error Rate %", str(app.get("error_rate_percent", "N/A"))),
                ],
            )
        )

        # full lists (not only top1)
        out.append(render_top_table("Top Countries", app.get("top_countries", []), "Country", "Count"))
        out.append(render_top_table("Top ASN", app.get("top_asn", []), "ASN", "Count"))
        out.append(render_top_table("Top Endpoints", app.get("top_endpoints", []), "Endpoint", "Count"))
        out.append(
            render_top_table(
                "Top Non-browser User Agents",
                app.get("top_non_browser_user_agents", []),
                "User Agent",
                "Count",
            )
        )
        out.append(render_top_table("Status Breakdown", app.get("status_breakdown", []), "Status", "Count"))

        daily = app.get("daily_requests", [])
        if daily:
            out.append("<table><tr><th colspan='4'>Daily Requests Reference</th></tr>")
            out.append("<tr><th>Day</th><th>Log File</th><th>Requests</th><th>Avg Req/Min</th></tr>")
            for d in daily:
                out.append(
                    "<tr>"
                    f"<td>{html.escape(str(d.get('day_index', '')))}</td>"
                    f"<td>{html.escape(str(d.get('log_file', '')))}</td>"
                    f"<td>{html.escape(str(d.get('requests', '')))}</td>"
                    f"<td>{html.escape(str(d.get('avg_requests_per_minute', '')))}</td>"
                    "</tr>"
                )
            out.append("</table>")

        out.append(
            render_kv_table(
                "Health Check Reference",
                [
                    ("Site", str(h.get("site", "N/A"))),
                    ("Report Generated", str(h.get("report_generated", "N/A"))),
                    ("TTFB", str(h.get("ttfb_ms", "N/A"))),
                    ("Page Load", str(h.get("page_load_ms", "N/A"))),
                    ("Throughput", str(h.get("throughput", "N/A"))),
                    ("Max Concurrent Users", str(h.get("max_concurrent_users", "N/A"))),
                    ("Estimated Daily Capacity", str(h.get("daily_capacity", "N/A"))),
                    ("Database Size", str(h.get("db_size", "N/A"))),
                    ("Critical Issues", "; ".join(h.get("critical_issues", [])) or "None listed"),
                    ("Warnings", "; ".join(h.get("warnings", [])) or "None listed"),
                    ("Health Source File", str(h.get("source", "N/A"))),
                    ("Health JSON File", str(h.get("report_json_path", "N/A"))),
                ],
            )
        )

        out.append(
            "<table><tr><th>Observation Notes (manual)</th><th>Priority</th><th>Owner</th><th>Target Date</th><th>Status</th></tr>"
            "<tr><td>[Add observation]</td><td>[High/Med/Low]</td><td>[Name]</td><td>[Date]</td><td>[Open/In Progress/Done]</td></tr></table>"
        )

    out.append("<h2>All Applications by Traffic</h2>")
    out.append("<table><tr><th>Rank</th><th>App</th><th>Total Requests</th></tr>")
    for i, row in enumerate(all_sorted, 1):
        out.append(
            f"<tr><td>{i}</td><td>{html.escape(str(row.get('app','')))}</td><td>{html.escape(str(row.get('total_requests','')))}</td></tr>"
        )
    out.append("</table>")

    out.append("</body></html>")
    Path(output_path).write_text("\n".join(out), encoding="utf-8")


def build_notes_csv(top5: List[dict], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["App", "Observation", "Priority", "Owner", "Target Date", "Status"])
        for app in top5:
            w.writerow([app.get("app", ""), "", "", "", "", ""])


def build_reference_csv(top5: List[dict], health_by_app: Dict[str, dict], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["App", "Section", "Metric", "Value"])
        for app in top5:
            name = app.get("app", "")
            w.writerow([name, "traffic", "total_requests", app.get("total_requests", "")])
            w.writerow([name, "traffic", "error_count", app.get("error_count", "")])
            w.writerow([name, "traffic", "error_rate_percent", app.get("error_rate_percent", "")])
            for k, v in app.get("top_countries", []) or []:
                w.writerow([name, "top_countries", str(k), str(v)])
            for k, v in app.get("top_asn", []) or []:
                w.writerow([name, "top_asn", str(k), str(v)])
            for k, v in app.get("top_endpoints", []) or []:
                w.writerow([name, "top_endpoints", str(k), str(v)])
            for k, v in app.get("top_non_browser_user_agents", []) or []:
                w.writerow([name, "top_non_browser_user_agents", str(k), str(v)])
            for k, v in app.get("status_breakdown", []) or []:
                w.writerow([name, "status_breakdown", str(k), str(v)])
            for d in app.get("daily_requests", []) or []:
                w.writerow([name, "daily_requests", f"day_{d.get('day_index', '')}_file", d.get("log_file", "")])
                w.writerow([name, "daily_requests", f"day_{d.get('day_index', '')}_requests", d.get("requests", "")])
                w.writerow([name, "daily_requests", f"day_{d.get('day_index', '')}_avg_req_min", d.get("avg_requests_per_minute", "")])

            h = health_by_app.get(name, {})
            for metric in [
                "site",
                "report_generated",
                "ttfb_ms",
                "page_load_ms",
                "throughput",
                "max_concurrent_users",
                "daily_capacity",
                "db_size",
                "source",
                "report_json_path",
            ]:
                w.writerow([name, "health", metric, h.get(metric, "N/A")])
            for idx, item in enumerate(h.get("critical_issues", []) or [], 1):
                w.writerow([name, "health_critical_issues", str(idx), item])
            for idx, item in enumerate(h.get("warnings", []) or [], 1):
                w.writerow([name, "health_warnings", str(idx), item])


def main():
    parser = argparse.ArgumentParser(description="Build Google-Doc-ready Cloudways report from traffic + health outputs")
    parser.add_argument("--traffic-json", default="", help="Path to traffic summary JSON")
    parser.add_argument("--output-html", default="/tmp/cloudways_consolidated_report.html")
    parser.add_argument("--output-csv", default="/tmp/cloudways_observation_notes_template.csv")
    parser.add_argument("--output-reference-csv", default="/tmp/cloudways_reference_tables.csv")
    parser.add_argument(
        "--health-source",
        choices=["log", "json", "merge"],
        default="log",
        help="Choose health source: log only, json only, or merge both",
    )
    args = parser.parse_args()

    traffic_path = choose_traffic_json(args.traffic_json or None)
    traffic = read_json(traffic_path)
    top5 = traffic.get("top5", [])

    health_records = collect_health_records(args.health_source)
    health_by_app = map_health_to_apps(top5, health_records, args.health_source)

    build_report_html(traffic, health_by_app, args.output_html)
    build_notes_csv(top5, args.output_csv)
    build_reference_csv(top5, health_by_app, args.output_reference_csv)

    print("Created:")
    print(args.output_html)
    print(args.output_csv)
    print(args.output_reference_csv)
    print(f"Traffic source: {traffic_path}")
    print(f"Health source mode: {args.health_source}")
    print(f"Health records discovered: {len(health_records)}")


if __name__ == "__main__":
    main()
