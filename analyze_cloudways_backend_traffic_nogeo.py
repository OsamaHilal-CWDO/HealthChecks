#!/usr/bin/env python3
import argparse
import gzip
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import subprocess

BROWSER_UA_MARKERS = ("mozilla", "chrome", "chromium", "safari")
REQUEST_RE = re.compile(r'"([A-Z]+)\s+([^\s"]+)\s+HTTP/[0-9.]+"')
STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
IP_RE = re.compile(r'^(\S+)\s')


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_progress(enabled: bool, message: str):
    if enabled:
        print(f"[{now_utc_iso()}] {message}", file=sys.stderr, flush=True)


def iter_log_lines(path: Path):
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line.rstrip("\n")
        else:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line.rstrip("\n")
    except Exception:
        return


def parse_log_line(line: str):
    ip = "UNKNOWN"
    endpoint = "UNKNOWN"
    status = "UNKNOWN"
    user_agent = "UNKNOWN"

    m_ip = IP_RE.search(line)
    if m_ip:
        ip = m_ip.group(1)

    m_req = REQUEST_RE.search(line)
    if m_req:
        endpoint = m_req.group(2)

    m_status = STATUS_RE.search(line)
    if m_status:
        status = m_status.group(1)

    quoted = re.findall(r'"([^"]*)"', line)
    if quoted:
        user_agent = (quoted[-1] or "UNKNOWN").strip() or "UNKNOWN"

    return ip, endpoint, status, user_agent


def parse_server_name(conf_path: Path) -> str:
    if not conf_path.exists():
        return ""

    preferred = []
    fallback = []
    try:
        for raw in conf_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line.startswith("server_name"):
                continue
            line = line.rstrip(";")
            parts = line.split()
            if len(parts) < 2:
                continue
            for host in parts[1:]:
                host = host.strip().lower()
                if not host or host == "_":
                    continue
                if host.startswith("*."):
                    host = host[2:]
                fallback.append(host)
                if "cloudwaysapps.com" not in host:
                    preferred.append(host)
    except Exception:
        return ""

    return (preferred or fallback or [""])[0]


def fallback_domain_from_wp(public_html: Path) -> str:
    cmd = ["wp", "option", "get", "siteurl", "--allow-root"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(public_html),
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
        out = (proc.stdout or "").strip()
        if out:
            parsed = urlparse(out)
            if parsed.netloc:
                return parsed.netloc.lower()
            return out.replace("https://", "").replace("http://", "").split("/")[0].lower()
    except Exception:
        pass
    return ""


def run_health_script(public_html: Path, domain: str) -> dict:
    out_dir = Path("/tmp/wp_health_runs")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / f"{public_html.parent.name}.log"
    cmd = (
        "curl -sS https://raw.githubusercontent.com/OsamaHilal-CWDO/wooAuditor/refs/heads/main/wp_health_manager.py "
        f"| python3 - https://{domain} --log-path ../logs/ --output-path /tmp/"
    )

    try:
        proc = subprocess.run(
            ["bash", "-lc", cmd],
            cwd=str(public_html),
            capture_output=True,
            text=True,
            timeout=1200,
            check=False,
        )
        log_file.write_text(
            f"COMMAND: {cmd}\nEXIT: {proc.returncode}\n\nSTDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}\n",
            encoding="utf-8",
        )
        return {"exit_code": proc.returncode, "log_file": str(log_file)}
    except Exception as e:
        log_file.write_text(f"Exception while running health script: {e}\n", encoding="utf-8")
        return {"exit_code": -1, "error": str(e), "log_file": str(log_file)}


def detect_roots(requested_root: Path):
    def root_has_apps(root: Path) -> bool:
        if not root.exists() or not root.is_dir():
            return False
        for child in root.iterdir():
            if child.is_dir() and (child / "logs").is_dir() and (child / "public_html").is_dir():
                return True
        return False

    roots = []
    if root_has_apps(requested_root):
        roots.append(requested_root)

    home = Path("/home")
    if home.exists():
        for item in home.iterdir():
            if not item.is_dir():
                continue
            if root_has_apps(item):
                roots.append(item)
            app_dir = item / "applications"
            if root_has_apps(app_dir):
                roots.append(app_dir)

    uniq = []
    seen = set()
    for r in roots:
        rp = str(r.resolve())
        if rp not in seen:
            seen.add(rp)
            uniq.append(r)
    return uniq


def collect_apps(roots):
    apps = {}
    for root in roots:
        for app_dir in root.iterdir():
            if not app_dir.is_dir():
                continue
            logs = app_dir / "logs"
            if not logs.is_dir():
                continue
            files = sorted(logs.glob("backend*.access.log*"))
            files = [f for f in files if f.is_file()]
            if files:
                apps[app_dir.name] = {"app_dir": app_dir, "log_files": files}
    return apps


def count_requests(log_files):
    total = 0
    for lf in log_files:
        for line in iter_log_lines(lf):
            if line.strip():
                total += 1
    return total


def summarize_app_no_geo(app: str, app_dir: Path, log_files, progress: bool = False):
    total = 0
    endpoints = Counter()
    statuses = Counter()
    ua_non_browser = Counter()
    unique_ips = set()

    log_progress(progress, f"[{app}] parsing {len(log_files)} log files")
    for idx, lf in enumerate(log_files, 1):
        line_count = 0
        for line in iter_log_lines(lf):
            if not line.strip():
                continue
            total += 1
            line_count += 1
            ip, endpoint, status, ua = parse_log_line(line)

            unique_ips.add(ip)
            endpoints[endpoint] += 1
            statuses[status] += 1

            ua_l = ua.lower()
            if (
                ua not in {"UNKNOWN", "-", ""}
                and not any(marker in ua_l for marker in BROWSER_UA_MARKERS)
            ):
                ua_non_browser[ua] += 1
        log_progress(progress, f"[{app}] parsed file {idx}/{len(log_files)}: {lf.name} ({line_count} lines)")

    error_count = sum(v for k, v in statuses.items() if k.isdigit() and (k.startswith("4") or k.startswith("5")))
    error_rate = (error_count / total * 100.0) if total else 0.0

    log_progress(progress, f"[{app}] summary complete (error_rate={round(error_rate, 2)}%, unique_ips={len(unique_ips)})")
    return {
        "app": app,
        "app_dir": str(app_dir),
        "total_requests": total,
        "unique_ip_count": len(unique_ips),
        "top_endpoints": endpoints.most_common(10),
        "top_non_browser_user_agents": ua_non_browser.most_common(10),
        "status_breakdown": sorted(statuses.items(), key=lambda x: x[0]),
        "error_count": error_count,
        "error_rate_percent": round(error_rate, 2),
    }


def render_report(top5, all_sorted, roots, out_json_path):
    out = []
    out.append("Cloudways Backend Access Traffic Summary (No Geo/ASN)")
    out.append(f"Generated: {now_utc_iso()}")
    out.append(f"Roots scanned: {', '.join(str(r) for r in roots)}")
    out.append("GeoIP/ASN: disabled")
    out.append("")

    out.append("Top 5 applications by total traffic")
    for idx, row in enumerate(top5, 1):
        out.append(f"{idx}. {row['app']} - {row['total_requests']} requests")

    out.append("")
    for row in top5:
        out.append("=" * 80)
        out.append(f"Application: {row['app']}")
        out.append(f"Directory: {row['app_dir']}")
        out.append(f"Total Requests: {row['total_requests']}")
        out.append(f"Unique IP Count: {row['unique_ip_count']}")
        out.append(f"Error Count (4xx+5xx): {row['error_count']}")
        out.append(f"Error Rate: {row['error_rate_percent']}%")

        out.append("\nTop Endpoints:")
        for k, v in row["top_endpoints"]:
            out.append(f"  - {k}: {v}")

        out.append("\nTop Non-browser User Agents:")
        if row["top_non_browser_user_agents"]:
            for k, v in row["top_non_browser_user_agents"]:
                out.append(f"  - {k}: {v}")
        else:
            out.append("  - None found")

        out.append("\nStatus Breakdown:")
        for code, cnt in row["status_breakdown"]:
            out.append(f"  - {code}: {cnt}")

        domain = row.get("domain", "")
        hc = row.get("health_check", {})
        out.append(f"\nDomain for health check: {domain or 'N/A'}")
        out.append(f"Health check exit: {hc.get('exit_code', 'N/A')}")
        if hc.get("log_file"):
            out.append(f"Health check log: {hc['log_file']}")

        out.append("")

    out.append("=" * 80)
    out.append("All applications by traffic")
    for idx, row in enumerate(all_sorted, 1):
        out.append(f"{idx}. {row['app']} - {row['total_requests']} requests")
    out.append("")
    out.append(f"JSON output: {out_json_path}")
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Analyze Cloudways backend logs without geo/asn lookups")
    parser.add_argument("--applications-root", default="/home/master/applications")
    parser.add_argument("--output-json", default="/tmp/top5_backend_traffic_nogeo_summary.json")
    parser.add_argument("--output-txt", default="/tmp/top5_backend_traffic_nogeo_summary.txt")
    parser.add_argument("--skip-health", action="store_true")
    parser.add_argument("--progress", action="store_true", help="Print progress updates to stderr")
    args = parser.parse_args()

    log_progress(args.progress, "Starting backend no-geo analysis")
    roots = detect_roots(Path(args.applications_root))
    if not roots:
        payload = {
            "generated_at": now_utc_iso(),
            "error": "No valid applications root found",
            "requested_root": args.applications_root,
            "hint": "Expected /home/master/applications or /home/<id>.cloudwaysapps.com",
        }
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        Path(args.output_txt).write_text(
            "No valid applications root found.\n"
            f"Requested: {args.applications_root}\n"
            "Expected one of: /home/master/applications or /home/<id>.cloudwaysapps.com\n",
            encoding="utf-8",
        )
        print(Path(args.output_txt).read_text(encoding="utf-8"))
        return 1

    log_progress(args.progress, f"Discovered {len(roots)} applications roots")
    apps = collect_apps(roots)
    if not apps:
        payload = {
            "generated_at": now_utc_iso(),
            "error": "No backend access logs found",
            "roots": [str(x) for x in roots],
            "pattern": "logs/backend*.access.log*",
        }
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        Path(args.output_txt).write_text(
            "No backend access logs found under scanned roots.\n"
            + "\n".join(str(x) for x in roots)
            + "\n",
            encoding="utf-8",
        )
        print(Path(args.output_txt).read_text(encoding="utf-8"))
        return 1

    log_progress(args.progress, f"Found {len(apps)} applications with backend logs")
    ranked_apps = []
    log_progress(args.progress, "Pass 1/2: ranking all applications by request count")
    for idx, (app, data) in enumerate(apps.items(), 1):
        total = count_requests(data["log_files"])
        ranked_apps.append(
            {
                "app": app,
                "app_dir": str(data["app_dir"]),
                "log_files": data["log_files"],
                "total_requests": total,
            }
        )
        log_progress(args.progress, f"[rank {idx}/{len(apps)}] {app}: {total} requests")

    ranked_apps.sort(key=lambda x: x["total_requests"], reverse=True)
    top5_candidates = ranked_apps[:5]
    log_progress(args.progress, "Top 5 by traffic: " + ", ".join(row["app"] for row in top5_candidates))

    log_progress(args.progress, "Pass 2/2: summarizing top 5 (no geo/asn)")
    top5 = []
    for idx, row in enumerate(top5_candidates, 1):
        log_progress(args.progress, f"[top {idx}/{len(top5_candidates)}] processing {row['app']}")
        top5.append(
            summarize_app_no_geo(
                row["app"],
                Path(row["app_dir"]),
                row["log_files"],
                progress=args.progress,
            )
        )
    log_progress(args.progress, "Top 5 summary complete")

    if not args.skip_health:
        for row in top5:
            app_dir = Path(row["app_dir"])
            domain = parse_server_name(app_dir / "conf" / "server.nginx")
            if not domain:
                domain = fallback_domain_from_wp(app_dir / "public_html")
            row["domain"] = domain
            if domain and (app_dir / "public_html").exists():
                log_progress(args.progress, f"[health] running for {row['app']} ({domain})")
                row["health_check"] = run_health_script(app_dir / "public_html", domain)
                log_progress(args.progress, f"[health] completed for {row['app']} exit={row['health_check'].get('exit_code')}")
            else:
                row["health_check"] = {
                    "exit_code": -1,
                    "error": "Could not determine domain or public_html missing",
                }
                log_progress(args.progress, f"[health] skipped for {row['app']} (domain/public_html unavailable)")

    payload = {
        "generated_at": now_utc_iso(),
        "roots_scanned": [str(x) for x in roots],
        "geoip_enabled": False,
        "geoip_backend": "disabled",
        "whois_asn_enabled": False,
        "total_applications_found": len(ranked_apps),
        "top5": top5,
        "all_applications_sorted": [
            {"app": x["app"], "total_requests": x["total_requests"], "app_dir": x["app_dir"]}
            for x in ranked_apps
        ],
    }

    Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    report_txt = render_report(top5, ranked_apps, roots, args.output_json)
    Path(args.output_txt).write_text(report_txt, encoding="utf-8")
    log_progress(args.progress, f"Wrote outputs: {args.output_json} and {args.output_txt}")

    print(report_txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
