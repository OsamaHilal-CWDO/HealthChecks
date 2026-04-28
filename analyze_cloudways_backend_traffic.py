#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

BROWSER_UA_MARKERS = ("mozilla", "chrome", "chromium", "safari")
REQUEST_RE = re.compile(r'"([A-Z]+)\s+([^\s"]+)\s+HTTP/[0-9.]+"')
STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
IP_RE = re.compile(r'^(\S+)\s')
BACKEND_LOG_DAY_RE = re.compile(r"\.access\.log(?:\.(\d+)(?:\.gz)?)?$")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def progress_log(enabled: bool, message: str):
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


class GeoResolver:
    def __init__(
        self,
        country_db: Path | None = None,
        asn_db: Path | None = None,
        country_dat_v4: Path | None = None,
        country_dat_v6: Path | None = None,
        enable_whois_asn: bool = True,
    ):
        self.country_reader = None
        self.asn_reader = None
        self.legacy_country_v4 = None
        self.legacy_country_v6 = None
        self.geoiplookup_cmd = shutil.which("geoiplookup")
        self.geoiplookup6_cmd = shutil.which("geoiplookup6")
        self.whois_cmd = shutil.which("whois")
        self.enable_whois_asn = enable_whois_asn
        self.enabled = False
        self.backend = "none"
        self._country_cache = {}
        self._asn_cache = {}

        try:
            import geoip2.database  # type: ignore

            if country_db and country_db.exists():
                self.country_reader = geoip2.database.Reader(str(country_db))
            if asn_db and asn_db.exists():
                self.asn_reader = geoip2.database.Reader(str(asn_db))
            if self.country_reader or self.asn_reader:
                self.enabled = True
                self.backend = "mmdb"
        except Exception:
            self.enabled = False

        # Fallback to legacy .dat country DB (GeoIP.dat / GeoIPv6.dat).
        # This fallback can provide country but not ASN.
        if not self.enabled:
            try:
                import pygeoip  # type: ignore

                if country_dat_v4 and country_dat_v4.exists():
                    self.legacy_country_v4 = pygeoip.GeoIP(str(country_dat_v4))
                if country_dat_v6 and country_dat_v6.exists():
                    self.legacy_country_v6 = pygeoip.GeoIP(str(country_dat_v6))
                if self.legacy_country_v4 or self.legacy_country_v6:
                    self.enabled = True
                    self.backend = "legacy-dat"
            except Exception:
                self.enabled = False

        # Fallback to system CLIs (geoip-bin + whois), no Python packages needed.
        # Country comes from geoiplookup{,6}; ASN from whois (Team Cymru first).
        if not self.enabled and (self.geoiplookup_cmd or self.geoiplookup6_cmd or self.whois_cmd):
            self.enabled = True
            if self.geoiplookup_cmd or self.geoiplookup6_cmd:
                self.backend = "cli-geoip"
            else:
                self.backend = "cli-whois-only"

    def _lookup_country_cli(self, ip: str) -> str:
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except Exception:
            return "UNKNOWN"

        cmd = self.geoiplookup6_cmd if parsed_ip.version == 6 else self.geoiplookup_cmd
        if not cmd:
            return "UNKNOWN"

        try:
            proc = subprocess.run(
                [cmd, ip],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            out = f"{proc.stdout}\n{proc.stderr}"
            if "IP Address not found" in out:
                return "UNKNOWN"
            m = re.search(r":\s*([A-Z]{2})\b", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "UNKNOWN"

    def _lookup_asn_whois(self, ip: str) -> str:
        if not self.whois_cmd or not self.enable_whois_asn:
            return "UNKNOWN"

        # Try Team Cymru first; it's concise and consistent for ASN lookup.
        try:
            proc = subprocess.run(
                [self.whois_cmd, "-h", "whois.cymru.com", f" -v {ip}"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            out = f"{proc.stdout}\n{proc.stderr}"
            for line in out.splitlines():
                if "|" not in line or "AS" in line.upper():
                    continue
                m = re.match(r"\s*(\d+)\s*\|", line)
                if m:
                    return f"AS{m.group(1)}"
        except Exception:
            pass

        # Fallback to standard whois parsing.
        try:
            proc = subprocess.run(
                [self.whois_cmd, ip],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            out = f"{proc.stdout}\n{proc.stderr}"
            m = re.search(r"(?im)^\s*(?:origin|originas|aut-num)\s*:\s*(AS\d+)\b", out)
            if m:
                return m.group(1).upper()
            m = re.search(r"\bAS(\d{1,10})\b", out)
            if m:
                return f"AS{m.group(1)}"
        except Exception:
            pass
        return "UNKNOWN"

    def _bulk_lookup_asn_whois(self, ips):
        """
        Resolve ASN for many IPs in fewer whois calls.
        Uses Team Cymru bulk mode and caches all queried IPs.
        """
        if not self.whois_cmd or not self.enable_whois_asn:
            return

        to_query = [ip for ip in ips if ip not in self._asn_cache]
        if not to_query:
            return

        chunk_size = 300
        for i in range(0, len(to_query), chunk_size):
            chunk = to_query[i : i + chunk_size]
            payload = "begin\nverbose\n" + "\n".join(chunk) + "\nend\n"
            resolved = {}

            try:
                proc = subprocess.run(
                    [self.whois_cmd, "-h", "whois.cymru.com"],
                    input=payload,
                    capture_output=True,
                    text=True,
                    timeout=25,
                    check=False,
                )
                out = f"{proc.stdout}\n{proc.stderr}"
                for line in out.splitlines():
                    if "|" not in line:
                        continue
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) < 2:
                        continue
                    asn_num = parts[0]
                    ip_val = parts[1]
                    if not asn_num.isdigit():
                        continue
                    if ip_val:
                        resolved[ip_val] = f"AS{asn_num}"
            except Exception:
                pass

            # Ensure every queried IP gets cached to avoid repeated slow fallbacks.
            for ip in chunk:
                self._asn_cache[ip] = resolved.get(ip, "UNKNOWN")

    def prewarm_asn(self, ips):
        if self.backend in ("cli-geoip", "cli-whois-only"):
            self._bulk_lookup_asn_whois(ips)

    @lru_cache(maxsize=200000)
    def lookup(self, ip: str):
        country = "UNKNOWN"
        asn = "UNKNOWN"

        try:
            ipaddress.ip_address(ip)
        except Exception:
            return country, asn

        if not self.enabled:
            return country, asn

        if self.backend == "mmdb":
            try:
                if self.country_reader:
                    res = self.country_reader.country(ip)
                    cc = (res.country.iso_code or "").strip().upper()
                    if cc:
                        country = cc
            except Exception:
                pass

            try:
                if self.asn_reader:
                    res = self.asn_reader.asn(ip)
                    if res.autonomous_system_number:
                        asn = f"AS{res.autonomous_system_number}"
            except Exception:
                pass
        elif self.backend == "legacy-dat":
            try:
                parsed_ip = ipaddress.ip_address(ip)
                reader = self.legacy_country_v6 if parsed_ip.version == 6 else self.legacy_country_v4
                if reader:
                    cc = (reader.country_code_by_addr(ip) or "").strip().upper()
                    if cc:
                        country = cc
            except Exception:
                pass
        elif self.backend in ("cli-geoip", "cli-whois-only"):
            if ip in self._country_cache:
                country = self._country_cache[ip]
            else:
                country = self._lookup_country_cli(ip)
                self._country_cache[ip] = country

            if ip in self._asn_cache:
                asn = self._asn_cache[ip]
            else:
                asn = self._lookup_asn_whois(ip)
                self._asn_cache[ip] = asn

        return country, asn

    def close(self):
        try:
            if self.country_reader:
                self.country_reader.close()
            if self.asn_reader:
                self.asn_reader.close()
        except Exception:
            pass


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


def safe_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except (PermissionError, OSError):
        return False


def detect_roots(requested_root: Path, strict_root: bool = False):
    def root_has_apps(root: Path) -> bool:
        if not root.exists() or not safe_is_dir(root):
            return False
        try:
            children = list(root.iterdir())
        except (PermissionError, OSError):
            return False
        for child in children:
            if safe_is_dir(child) and safe_is_dir(child / "logs") and safe_is_dir(child / "public_html"):
                return True
        return False

    roots = []
    if root_has_apps(requested_root):
        roots.append(requested_root)
    if strict_root:
        return roots

    home = Path("/home")
    if home.exists():
        try:
            items = list(home.iterdir())
        except (PermissionError, OSError):
            items = []
        for item in items:
            if not safe_is_dir(item):
                continue
            # /home/<id>.cloudwaysapps.com/<app>
            if root_has_apps(item):
                roots.append(item)
            # /home/<user>/applications/<app>
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
            files = sorted(logs.glob("backend*.access.log*"), key=backend_log_day_index)
            files = [f for f in files if f.is_file()]
            if files:
                apps[app_dir.name] = {"app_dir": app_dir, "log_files": files}
    return apps


def backend_log_day_index(path: Path) -> int:
    """
    Map rotated backend logs to day slots:
      backend*.access.log      -> 1 day
      backend*.access.log.1    -> 2 days
      backend*.access.log.2.gz -> 3 days
      ...
    """
    m = BACKEND_LOG_DAY_RE.search(path.name)
    if not m:
        return 999999
    idx = m.group(1)
    if idx is None:
        return 1
    try:
        return int(idx) + 1
    except ValueError:
        return 999999


def select_log_files_by_days(log_files, days: int | None):
    ordered = sorted(log_files, key=backend_log_day_index)
    if days is None:
        return ordered
    return [lf for lf in ordered if backend_log_day_index(lf) <= days]


def summarize_app(app: str, app_dir: Path, log_files, geo: GeoResolver, progress: bool = False):
    total = 0
    ip_hits = Counter()
    countries = Counter()
    asns = Counter()
    endpoints = Counter()
    statuses = Counter()
    ua_non_browser = Counter()
    daily_stats = []

    progress_log(progress, f"[{app}] parsing {len(log_files)} log files")
    for idx, lf in enumerate(log_files, start=1):
        file_lines = 0
        for line in iter_log_lines(lf):
            if not line.strip():
                continue
            total += 1
            file_lines += 1
            ip, endpoint, status, ua = parse_log_line(line)

            endpoints[endpoint] += 1
            statuses[status] += 1
            ip_hits[ip] += 1

            ua_l = ua.lower()
            if (
                ua not in {"UNKNOWN", "-", ""}
                and not any(marker in ua_l for marker in BROWSER_UA_MARKERS)
            ):
                ua_non_browser[ua] += 1
        day_num = backend_log_day_index(lf)
        daily_stats.append(
            {
                "day_number": day_num,
                "file_name": lf.name,
                "requests": file_lines,
                "avg_requests_per_minute": round(file_lines / 1440.0, 4),
            }
        )
        progress_log(progress, f"[{app}] parsed file {idx}/{len(log_files)}: {lf.name} ({file_lines} lines)")

    # Batch ASN lookups for CLI backend to avoid one whois call per unique IP.
    progress_log(progress, f"[{app}] collected {len(ip_hits)} unique IPs from {total} requests")
    geo.prewarm_asn(tuple(ip_hits.keys()))
    progress_log(progress, f"[{app}] ASN prewarm completed")
    processed_ips = 0
    for ip, cnt in ip_hits.items():
        cc, asn = geo.lookup(ip)
        countries[cc] += cnt
        asns[asn] += cnt
        processed_ips += 1
        if progress and processed_ips % 1000 == 0:
            progress_log(progress, f"[{app}] geo-enriched {processed_ips}/{len(ip_hits)} unique IPs")

    error_count = sum(v for k, v in statuses.items() if k.isdigit() and (k.startswith("4") or k.startswith("5")))
    error_rate = (error_count / total * 100.0) if total else 0.0
    progress_log(progress, f"[{app}] summary complete (error_rate={round(error_rate, 2)}%)")

    return {
        "app": app,
        "app_dir": str(app_dir),
        "total_requests": total,
        "top_countries": countries.most_common(10),
        "top_asn": asns.most_common(10),
        "top_endpoints": endpoints.most_common(10),
        "top_non_browser_user_agents": ua_non_browser.most_common(10),
        "status_breakdown": sorted(statuses.items(), key=lambda x: x[0]),
        "error_count": error_count,
        "error_rate_percent": round(error_rate, 2),
        "daily_request_stats": sorted(daily_stats, key=lambda x: x["day_number"]),
    }


def count_requests(log_files):
    total = 0
    for lf in log_files:
        for line in iter_log_lines(lf):
            if line.strip():
                total += 1
    return total


def render_report(top5, all_sorted, roots, geo_backend, out_json_path):
    out = []
    out.append("Cloudways Backend Access Traffic Summary")
    out.append(f"Generated: {now_utc_iso()}")
    out.append(f"Roots scanned: {', '.join(str(r) for r in roots)}")
    out.append(f"GeoIP backend: {geo_backend}")
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
        out.append(f"Error Count (4xx+5xx): {row['error_count']}")
        out.append(f"Error Rate: {row['error_rate_percent']}%")
        out.append("\nDaily Requests & Avg Requests/Minute:")
        for d in row.get("daily_request_stats", []):
            out.append(
                f"  - Day {d['day_number']} ({d['file_name']}): "
                f"{d['requests']} requests, avg/min {d['avg_requests_per_minute']}"
            )

        out.append("\nTop Countries:")
        for k, v in row["top_countries"]:
            out.append(f"  - {k}: {v}")

        out.append("\nTop ASN:")
        for k, v in row["top_asn"]:
            out.append(f"  - {k}: {v}")

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


def find_default_geoip_path(candidates):
    for p in candidates:
        pp = Path(p)
        if pp.exists() and pp.is_file():
            return pp
    return None


def main():
    parser = argparse.ArgumentParser(description="Analyze Cloudways backend access logs")
    parser.add_argument("--applications-root", default="/home/master/applications")
    parser.add_argument("--output-json", default="/tmp/top5_backend_traffic_summary.json")
    parser.add_argument("--output-txt", default="/tmp/top5_backend_traffic_summary.txt")
    parser.add_argument("--skip-health", action="store_true")
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print progress updates to stderr",
    )
    parser.add_argument(
        "--disable-whois-asn",
        action="store_true",
        help="Disable whois ASN resolution to speed up analysis",
    )
    parser.add_argument("--country-mmdb", default="")
    parser.add_argument("--asn-mmdb", default="")
    parser.add_argument("--country-dat", default="")
    parser.add_argument("--countryv6-dat", default="")
    parser.add_argument(
        "--strict-root",
        action="store_true",
        help="Scan only --applications-root and do not auto-discover other /home roots",
    )
    day_group = parser.add_mutually_exclusive_group()
    day_group.add_argument(
        "--days",
        type=int,
        default=None,
        help=(
            "Limit to N day-slots of rotated logs per app "
            "(1=access.log, 2=access.log+access.log.1, 3=...+access.log.2.gz, etc)"
        ),
    )
    day_group.add_argument(
        "--all-days",
        action="store_true",
        help="Use all available rotated logs (default behavior)",
    )
    args = parser.parse_args()
    if args.days is not None and args.days < 1:
        parser.error("--days must be >= 1")
    if args.all_days:
        args.days = None

    progress = args.progress
    progress_log(progress, "Starting backend access log analysis")
    roots = detect_roots(Path(args.applications_root), strict_root=args.strict_root)
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

    progress_log(progress, f"Discovered {len(roots)} applications roots")
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

    country_db = Path(args.country_mmdb) if args.country_mmdb else find_default_geoip_path([
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
        "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
        "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    ])
    asn_db = Path(args.asn_mmdb) if args.asn_mmdb else find_default_geoip_path([
        "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
        "/usr/local/share/GeoIP/GeoLite2-ASN.mmdb",
        "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    ])
    country_dat = Path(args.country_dat) if args.country_dat else find_default_geoip_path([
        "/usr/share/GeoIP/GeoIP.dat",
        "/usr/local/share/GeoIP/GeoIP.dat",
        "/var/lib/GeoIP/GeoIP.dat",
    ])
    countryv6_dat = Path(args.countryv6_dat) if args.countryv6_dat else find_default_geoip_path([
        "/usr/share/GeoIP/GeoIPv6.dat",
        "/usr/local/share/GeoIP/GeoIPv6.dat",
        "/var/lib/GeoIP/GeoIPv6.dat",
    ])

    progress_log(progress, f"Found {len(apps)} applications with backend logs")
    # First pass: rank all apps by total request count only (fast).
    progress_log(progress, "Pass 1/2: ranking all applications by request count")
    ranked_apps = []
    for idx, (app, data) in enumerate(apps.items(), start=1):
        selected_logs = select_log_files_by_days(data["log_files"], args.days)
        if not selected_logs:
            progress_log(progress, f"[rank {idx}/{len(apps)}] {app}: skipped (no logs in selected day window)")
            continue
        total = count_requests(selected_logs)
        ranked_apps.append(
            {
                "app": app,
                "app_dir": str(data["app_dir"]),
                "log_files": selected_logs,
                "total_requests": total,
            }
        )
        progress_log(
            progress,
            f"[rank {idx}/{len(apps)}] {app}: {total} requests across {len(selected_logs)} log files",
        )
    if not ranked_apps:
        payload = {
            "generated_at": now_utc_iso(),
            "error": "No backend access logs matched selected day window",
            "days_filter": args.days if args.days is not None else "all",
            "roots": [str(x) for x in roots],
        }
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        Path(args.output_txt).write_text(
            "No backend access logs matched selected day window.\n"
            f"Days filter: {args.days if args.days is not None else 'all'}\n",
            encoding="utf-8",
        )
        print(Path(args.output_txt).read_text(encoding="utf-8"))
        return 1
    ranked_apps.sort(key=lambda x: x["total_requests"], reverse=True)
    top5_candidates = ranked_apps[:5]
    progress_log(progress, "Top 5 by traffic: " + ", ".join(x["app"] for x in top5_candidates))

    # Second pass: full enrichment only for top 5 apps.
    progress_log(progress, "Pass 2/2: enriching top 5 applications")
    geo = GeoResolver(
        country_db,
        asn_db,
        country_dat,
        countryv6_dat,
        enable_whois_asn=not args.disable_whois_asn,
    )
    progress_log(progress, f"Geo backend selected: {geo.backend} (whois_asn_enabled={not args.disable_whois_asn})")
    top5 = []
    for idx, row in enumerate(top5_candidates, start=1):
        progress_log(progress, f"[top {idx}/{len(top5_candidates)}] processing {row['app']}")
        top5.append(
            summarize_app(
                row["app"],
                Path(row["app_dir"]),
                row["log_files"],
                geo,
                progress=progress,
            )
        )
    geo.close()
    progress_log(progress, "Top 5 enrichment complete")

    if not args.skip_health:
        progress_log(progress, "Starting health checks for top 5 applications")
        for row in top5:
            app_dir = Path(row["app_dir"])
            domain = parse_server_name(app_dir / "conf" / "server.nginx")
            if not domain:
                domain = fallback_domain_from_wp(app_dir / "public_html")
            row["domain"] = domain
            if domain and (app_dir / "public_html").exists():
                progress_log(progress, f"[health] running for {row['app']} ({domain})")
                row["health_check"] = run_health_script(app_dir / "public_html", domain)
                progress_log(
                    progress,
                    f"[health] {row['app']} exit={row['health_check'].get('exit_code', 'N/A')}",
                )
            else:
                row["health_check"] = {
                    "exit_code": -1,
                    "error": "Could not determine domain or public_html missing",
                }
                progress_log(progress, f"[health] skipped for {row['app']} (missing domain/public_html)")

    payload = {
        "generated_at": now_utc_iso(),
        "roots_scanned": [str(x) for x in roots],
        "geoip_enabled": geo.enabled,
        "geoip_backend": geo.backend,
        "whois_asn_enabled": not args.disable_whois_asn,
        "days_filter": args.days if args.days is not None else "all",
        "geoip_country_db": str(country_db) if country_db else "",
        "geoip_asn_db": str(asn_db) if asn_db else "",
        "geoip_country_dat": str(country_dat) if country_dat else "",
        "geoip_countryv6_dat": str(countryv6_dat) if countryv6_dat else "",
        "total_applications_found": len(ranked_apps),
        "top5": top5,
        "all_applications_sorted": [
            {"app": x["app"], "total_requests": x["total_requests"], "app_dir": x["app_dir"]}
            for x in ranked_apps
        ],
    }

    Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    report_txt = render_report(top5, ranked_apps, roots, geo.backend, args.output_json)
    Path(args.output_txt).write_text(report_txt, encoding="utf-8")

    progress_log(progress, f"Wrote outputs: {args.output_json} and {args.output_txt}")
    print(report_txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
