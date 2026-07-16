#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import gzip
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

BROWSER_UA_MARKERS = ("mozilla", "chrome", "chromium", "safari")
REQUEST_RE = re.compile(r'"([A-Z]+)\s+([^\s"]+)\s+HTTP/[0-9.]+"')
STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
IP_RE = re.compile(r'^(\S+)\s')
TIME_RE = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s")
BACKEND_LOG_DAY_RE = re.compile(r"\.access\.log(?:\.(\d+)(?:\.gz)?)?$")

MONTH_NUM = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Matches desktop Chrome, mobile Chrome on iOS (CriOS) and raw Chromium builds.
CHROME_VERSION_RE = re.compile(r"(?:chrome|crios|chromium)/(\d+)", re.IGNORECASE)
# Chrome 126 shipped on 2024-06-11; majors advance roughly every ~40 days.
# Used only to *estimate* the newest plausible major when no override is given.
CHROME_REFERENCE_MAJOR = 126
CHROME_REFERENCE_DATE = datetime(2024, 6, 11, tzinfo=timezone.utc)
CHROME_DAYS_PER_MAJOR = 40.5

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
    timestamp = None
    hour_key = ""
    minute = -1

    m_ip = IP_RE.search(line)
    if m_ip:
        ip = m_ip.group(1)

    m_req = REQUEST_RE.search(line)
    if m_req:
        endpoint = m_req.group(2)

    m_status = STATUS_RE.search(line)
    if m_status:
        status = m_status.group(1)

    m_time = TIME_RE.search(line)
    if m_time:
        day, mon, year, hh, mm, ss = m_time.groups()
        month = MONTH_NUM.get(mon)
        if month:
            try:
                timestamp = datetime(int(year), month, int(day), int(hh), int(mm), int(ss))
                hour_key = f"{day}/{mon}/{year}:{hh}"
                minute = int(mm)
            except ValueError:
                timestamp = None

    quoted = re.findall(r'"([^"]*)"', line)
    if quoted:
        user_agent = (quoted[-1] or "UNKNOWN").strip() or "UNKNOWN"

    return ip, endpoint, status, user_agent, timestamp, hour_key, minute


def parse_line_timestamp(line: str) -> datetime | None:
    m = TIME_RE.search(line)
    if not m:
        return None
    day, mon, year, hh, mm, ss = m.groups()
    month = MONTH_NUM.get(mon)
    if not month:
        return None
    try:
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None


def in_time_window(ts: datetime | None, start: datetime | None, end: datetime | None) -> bool:
    if start is None and end is None:
        return True
    if ts is None:
        return False
    if start is not None and ts < start:
        return False
    if end is not None and ts > end:
        return False
    return True


def subnet_for_ip(ip: str) -> str | None:
    """Aggregate IPv4 into /24 and IPv6 into /48 subnets."""
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    prefix = 24 if addr.version == 4 else 48
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except Exception:
        return None


def estimate_latest_chrome_major(now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    days = (now - CHROME_REFERENCE_DATE).days
    return CHROME_REFERENCE_MAJOR + max(0, int(days / CHROME_DAYS_PER_MAJOR))


def analyze_chrome_versions(
    chrome_majors: Counter,
    total_requests: int,
    headless_requests: int,
    latest_major: int,
    obsolete_margin: int,
):
    claimed = sum(chrome_majors.values())
    percent = (claimed / total_requests * 100.0) if total_requests else 0.0
    obsolete_cutoff = latest_major - obsolete_margin

    obsolete = {v: c for v, c in chrome_majors.items() if v <= obsolete_cutoff}
    nonexistent = {v: c for v, c in chrome_majors.items() if v > latest_major}

    def version_span(versions) -> str:
        if not versions:
            return ""
        lo, hi = min(versions), max(versions)
        return f"v{lo}" if lo == hi else f"v{lo}-v{hi}"

    return {
        "claimed_chrome_requests": claimed,
        "claimed_chrome_percent": round(percent, 2),
        "distinct_major_versions": len(chrome_majors),
        "estimated_latest_major": latest_major,
        "obsolete_cutoff_major": obsolete_cutoff,
        "top_major_versions": [[f"v{v}", c] for v, c in chrome_majors.most_common(10)],
        "spoofing_indicators": {
            "obsolete_versions": {
                "range": version_span(obsolete),
                "distinct_versions": len(obsolete),
                "requests": sum(obsolete.values()),
            },
            "nonexistent_versions": {
                "range": version_span(nonexistent),
                "distinct_versions": len(nonexistent),
                "requests": sum(nonexistent.values()),
            },
            "headless_chrome_requests": headless_requests,
        },
    }


def analyze_query_strings(param_hits: Counter, requests_with_query: int, total_requests: int, top_n: int = 25):
    """Generic parameter frequency: whatever appears after '?' gets counted, no
    platform-specific assumptions (works for WooCommerce, Magento, custom, etc)."""
    percent = (requests_with_query / total_requests * 100.0) if total_requests else 0.0
    return {
        "requests_with_query_string": requests_with_query,
        "percent_of_total": round(percent, 2),
        "distinct_parameters": len(param_hits),
        "top_parameters": [[k, v] for k, v in param_hits.most_common(top_n)],
    }


def build_hourly_stats(hourly_minute_counts, hourly_ips):
    rows = []
    for hour_key, minute_counts in hourly_minute_counts.items():
        try:
            sort_key = datetime.strptime(hour_key, "%d/%b/%Y:%H")
        except ValueError:
            sort_key = datetime.max
        counts = list(minute_counts.values())
        total = sum(counts)
        rows.append(
            {
                "_sort": sort_key,
                "hour": hour_key,
                "min_per_minute": min(counts),
                "avg_per_minute": round(total / len(counts), 1),
                "max_per_minute": max(counts),
                "total_requests": total,
                "unique_ips": len(hourly_ips.get(hour_key, ())),
            }
        )
    rows.sort(key=lambda r: r["_sort"])
    for r in rows:
        r.pop("_sort", None)
    return rows


# --- PHP-FPM max_children breach & OOM analysis -------------------------------

FPM_BREACH_RE = re.compile(
    r"\[(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\]\s+WARNING:\s+\[pool ([^\]]+)\]\s+"
    r"server reached pm\.max_children setting \((\d+)\)"
)
OOM_KILLED_RE = re.compile(r"Out of memory: Killed process \d+ \(([^)]+)\)", re.IGNORECASE)
OOM_REAPED_RE = re.compile(r"oom_reaper: reaped process \d+ \(([^)]+)\)", re.IGNORECASE)
SYSLOG_ISO_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
SYSLOG_CLASSIC_TS_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
FPM_CLUSTER_GAP_SECONDS = 120
OOM_CLUSTER_GAP_SECONDS = 600
EVENT_TS_FMT = "%d/%b/%Y %H:%M:%S"


def scan_fpm_breach_logs(pattern: str, time_start: datetime | None, time_end: datetime | None):
    events = []
    files = sorted(glob.glob(pattern))
    for fp in files:
        for line in iter_log_lines(Path(fp)):
            m = FPM_BREACH_RE.search(line)
            if not m:
                continue
            day, mon, year, hh, mm, ss, pool, limit = m.groups()
            month = MONTH_NUM.get(mon)
            if not month:
                continue
            try:
                dt = datetime(int(year), month, int(day), int(hh), int(mm), int(ss))
            except ValueError:
                continue
            if not in_time_window(dt, time_start, time_end):
                continue
            events.append({"dt": dt, "pool": pool.strip(), "limit": int(limit)})
    events.sort(key=lambda e: e["dt"])
    return events, files


def parse_syslog_timestamp(line: str, now: datetime) -> datetime | None:
    m = SYSLOG_ISO_TS_RE.match(line)
    if m:
        y, mo, d, hh, mm, ss = (int(x) for x in m.groups())
        try:
            return datetime(y, mo, d, hh, mm, ss)
        except ValueError:
            return None
    m = SYSLOG_CLASSIC_TS_RE.match(line)
    if m:
        month = MONTH_NUM.get(m.group(1))
        if not month:
            return None
        try:
            dt = datetime(now.year, month, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
        except ValueError:
            return None
        # Classic syslog has no year; a "future" date means it was last year.
        if dt > now + timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return dt
    return None


def scan_oom_events(pattern: str, time_start: datetime | None, time_end: datetime | None):
    """Collect OOM kill events from syslog. A single OOM produces several kernel
    lines ('invoked oom-killer', 'Out of memory: Killed process', 'oom_reaper');
    dedupe on (process, minute) so each kill is counted once."""
    events = []
    seen = set()
    files = sorted(glob.glob(pattern))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for fp in files:
        for line in iter_log_lines(Path(fp)):
            m = OOM_KILLED_RE.search(line) or OOM_REAPED_RE.search(line)
            if not m:
                continue
            dt = parse_syslog_timestamp(line, now)
            if dt is None or not in_time_window(dt, time_start, time_end):
                continue
            process = m.group(1)
            key = (process, dt.strftime("%Y-%m-%d %H:%M"))
            if key in seen:
                continue
            seen.add(key)
            events.append({"dt": dt, "process": process})
    events.sort(key=lambda e: e["dt"])
    return events, files


def cluster_events(events, gap_seconds: int):
    clusters = []
    current = []
    for e in events:
        if current and (e["dt"] - current[-1]["dt"]).total_seconds() > gap_seconds:
            clusters.append(current)
            current = []
        current.append(e)
    if current:
        clusters.append(current)
    return clusters


def analyze_fpm_breaches(events, log_files):
    pools = Counter(e["pool"] for e in events)
    pool_limits = {}
    for e in events:
        pool_limits[e["pool"]] = e["limit"]

    per_hour = Counter(e["dt"].strftime("%d/%b/%Y:%H") for e in events)
    per_hour_sorted = sorted(
        per_hour.items(),
        key=lambda kv: datetime.strptime(kv[0], "%d/%b/%Y:%H"),
    )

    incidents = []
    for pool in pools:
        pool_events = [e for e in events if e["pool"] == pool]
        for c in cluster_events(pool_events, FPM_CLUSTER_GAP_SECONDS):
            start, end = c[0]["dt"], c[-1]["dt"]
            incidents.append(
                {
                    "_start_dt": start,
                    "pool": pool,
                    "type": "burst" if len(c) > 1 else "isolated",
                    "start": start.strftime(EVENT_TS_FMT),
                    "end": end.strftime(EVENT_TS_FMT),
                    "duration_seconds": int((end - start).total_seconds()),
                    "breach_count": len(c),
                }
            )
    incidents.sort(key=lambda i: i["_start_dt"])
    top_surges = sorted(incidents, key=lambda i: i["breach_count"], reverse=True)[:5]
    top_surges = [{k: v for k, v in i.items() if k != "_start_dt"} for i in top_surges]
    incidents = [{k: v for k, v in i.items() if k != "_start_dt"} for i in incidents]

    return {
        "log_files_scanned": log_files,
        "total_breaches": len(events),
        "pools_affected": len(pools),
        "most_common_pool": pools.most_common(1)[0][0] if pools else "",
        "breaches_per_pool": [[p, c] for p, c in pools.most_common()],
        "pool_limits": pool_limits,
        "breaches_per_hour": [[k, v] for k, v in per_hour_sorted],
        "cluster_gap_seconds": FPM_CLUSTER_GAP_SECONDS,
        "incident_count": len(incidents),
        "burst_incidents": sum(1 for i in incidents if i["type"] == "burst"),
        "isolated_incidents": sum(1 for i in incidents if i["type"] == "isolated"),
        "incidents": incidents[:50],
        "top_surges": top_surges,
    }


def analyze_oom_events(events, log_files):
    clusters = []
    for c in cluster_events(events, OOM_CLUSTER_GAP_SECONDS):
        if len(c) < 2:
            continue
        start, end = c[0]["dt"], c[-1]["dt"]
        clusters.append(
            {
                "start": start.strftime(EVENT_TS_FMT),
                "end": end.strftime(EVENT_TS_FMT),
                "duration_seconds": int((end - start).total_seconds()),
                "kill_count": len(c),
            }
        )
    return {
        "log_files_scanned": log_files,
        "oom_kill_count": len(events),
        "killed_processes": [[p, c] for p, c in Counter(e["process"] for e in events).most_common()],
        "timestamps": [e["dt"].strftime(EVENT_TS_FMT) for e in events][:100],
        "cluster_gap_seconds": OOM_CLUSTER_GAP_SECONDS,
        "clusters": clusters,
    }


class GeoResolver:
    def __init__(
        self,
        country_db: Path | None = None,
        country_dat_v4: Path | None = None,
        country_dat_v6: Path | None = None,
    ):
        self.country_reader = None
        self.legacy_country_v4 = None
        self.legacy_country_v6 = None
        self.geoiplookup_cmd = shutil.which("geoiplookup")
        self.geoiplookup6_cmd = shutil.which("geoiplookup6")
        self.enabled = False
        self.backend = "none"
        self._country_cache = {}

        try:
            import geoip2.database  # type: ignore

            if country_db and country_db.exists():
                self.country_reader = geoip2.database.Reader(str(country_db))
            if self.country_reader:
                self.enabled = True
                self.backend = "mmdb"
        except Exception:
            self.enabled = False

        # Fallback to legacy .dat country DB (GeoIP.dat / GeoIPv6.dat).
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

        # Fallback to system CLI (geoip-bin), no Python packages needed.
        if not self.enabled and (self.geoiplookup_cmd or self.geoiplookup6_cmd):
            self.enabled = True
            self.backend = "cli-geoip"

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

    @lru_cache(maxsize=200000)
    def lookup(self, ip: str) -> str:
        country = "UNKNOWN"

        try:
            ipaddress.ip_address(ip)
        except Exception:
            return country

        if not self.enabled:
            return country

        if self.backend == "mmdb":
            try:
                if self.country_reader:
                    res = self.country_reader.country(ip)
                    cc = (res.country.iso_code or "").strip().upper()
                    if cc:
                        country = cc
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
        elif self.backend == "cli-geoip":
            if ip in self._country_cache:
                country = self._country_cache[ip]
            else:
                country = self._lookup_country_cli(ip)
                self._country_cache[ip] = country

        return country

    def close(self):
        try:
            if self.country_reader:
                self.country_reader.close()
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
        f"| python3 - https://{domain} --log-path ../logs/ --output-path /tmp/ --skip-plugins"
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


def summarize_app(
    app: str,
    app_dir: Path,
    log_files,
    geo: GeoResolver,
    progress: bool = False,
    chrome_latest_major: int = 0,
    chrome_obsolete_margin: int = 40,
    time_start: datetime | None = None,
    time_end: datetime | None = None,
):
    time_filtered = time_start is not None or time_end is not None
    total = 0
    ip_hits = Counter()
    countries = Counter()
    endpoints = Counter()
    statuses = Counter()
    ua_non_browser = Counter()
    daily_stats = []

    chrome_majors = Counter()
    headless_chrome_requests = 0

    query_param_hits = Counter()
    requests_with_query = 0

    hourly_minute_counts = defaultdict(Counter)
    hourly_ips = defaultdict(set)

    progress_log(progress, f"[{app}] parsing {len(log_files)} log files")
    for idx, lf in enumerate(log_files, start=1):
        file_lines = 0
        for line in iter_log_lines(lf):
            if not line.strip():
                continue
            ip, endpoint, status, ua, timestamp, hour_key, minute = parse_log_line(line)
            if time_filtered and not in_time_window(timestamp, time_start, time_end):
                continue
            total += 1
            file_lines += 1

            endpoints[endpoint] += 1
            statuses[status] += 1
            ip_hits[ip] += 1

            if hour_key:
                hourly_minute_counts[hour_key][minute] += 1
                hourly_ips[hour_key].add(ip)

            if "?" in endpoint:
                requests_with_query += 1
                query = endpoint.split("?", 1)[1]
                try:
                    names = {name for name, _ in parse_qsl(query, keep_blank_values=True)}
                except Exception:
                    names = set()
                for name in names:
                    query_param_hits[name] += 1

            ua_l = ua.lower()
            m_chrome = CHROME_VERSION_RE.search(ua)
            if m_chrome:
                try:
                    chrome_majors[int(m_chrome.group(1))] += 1
                except ValueError:
                    pass
                if "headless" in ua_l:
                    headless_chrome_requests += 1

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
        progress_log(
            progress,
            f"[{app}] parsed file {idx}/{len(log_files)}: {lf.name} ({file_lines} matching lines)",
        )

    progress_log(progress, f"[{app}] collected {len(ip_hits)} unique IPs from {total} requests")

    # Aggregate unique IPs into subnets (/24 IPv4, /48 IPv6).
    subnet_hits = Counter()
    subnet_unique_ips = Counter()
    processed_ips = 0
    for ip, cnt in ip_hits.items():
        countries[geo.lookup(ip)] += cnt
        subnet = subnet_for_ip(ip)
        if subnet:
            subnet_hits[subnet] += cnt
            subnet_unique_ips[subnet] += 1
        processed_ips += 1
        if progress and processed_ips % 1000 == 0:
            progress_log(progress, f"[{app}] geo-enriched {processed_ips}/{len(ip_hits)} unique IPs")

    top_ip_subnets = [
        {"subnet": subnet, "requests": cnt, "unique_ips": subnet_unique_ips[subnet]}
        for subnet, cnt in subnet_hits.most_common(10)
    ]

    latest_major = chrome_latest_major if chrome_latest_major > 0 else estimate_latest_chrome_major()
    user_agent_analysis = analyze_chrome_versions(
        chrome_majors,
        total,
        headless_chrome_requests,
        latest_major,
        chrome_obsolete_margin,
    )
    query_string_analysis = analyze_query_strings(query_param_hits, requests_with_query, total)
    hourly_traffic = build_hourly_stats(hourly_minute_counts, hourly_ips)

    error_count = sum(v for k, v in statuses.items() if k.isdigit() and (k.startswith("4") or k.startswith("5")))
    error_rate = (error_count / total * 100.0) if total else 0.0
    progress_log(progress, f"[{app}] summary complete (error_rate={round(error_rate, 2)}%)")

    return {
        "app": app,
        "app_dir": str(app_dir),
        "total_requests": total,
        "top_countries": countries.most_common(10),
        "top_ip_subnets": top_ip_subnets,
        "top_endpoints": endpoints.most_common(10),
        "top_non_browser_user_agents": ua_non_browser.most_common(10),
        "user_agent_analysis": user_agent_analysis,
        "query_string_analysis": query_string_analysis,
        "hourly_traffic": hourly_traffic,
        "status_breakdown": sorted(statuses.items(), key=lambda x: x[0]),
        "error_count": error_count,
        "error_rate_percent": round(error_rate, 2),
        "daily_request_stats": sorted(daily_stats, key=lambda x: x["day_number"]),
    }


def count_requests(log_files, time_start: datetime | None = None, time_end: datetime | None = None):
    time_filtered = time_start is not None or time_end is not None
    total = 0
    for lf in log_files:
        for line in iter_log_lines(lf):
            if not line.strip():
                continue
            if time_filtered and not in_time_window(parse_line_timestamp(line), time_start, time_end):
                continue
            total += 1
    return total


def parse_user_time(value: str) -> datetime | None:
    """Accept 'DD-MM-YYYY:HH' or 'DD-MM-YYYY:HH:MM' (UTC). Returns None if invalid."""
    for fmt in ("%d-%m-%Y:%H:%M", "%d-%m-%Y:%H"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def describe_time_window(time_start: datetime | None, time_end: datetime | None, hours: int | None) -> str:
    if hours is not None:
        return f"last {hours} hour(s) (since {time_start:%d/%b/%Y %H:%M} UTC)"
    if time_start is not None or time_end is not None:
        start_s = f"{time_start:%d/%b/%Y %H:%M}" if time_start else "beginning of logs"
        end_s = f"{time_end:%d/%b/%Y %H:%M}" if time_end else "end of logs"
        return f"from {start_s} to {end_s} (UTC)"
    return "all available log data"


def render_fpm_oom_section(fpm: dict | None, oom: dict | None, only_app: str = "") -> list[str]:
    out = []
    out.append("=" * 80)
    out.append("PHP-FPM max_children Breaches & OOM Events (server logs)")
    if only_app:
        out.append(f"(FPM breaches filtered to pool: {only_app})")

    out.append("\nFPM max_children breaches:")
    if fpm is None:
        out.append("  - Skipped")
    elif not fpm["log_files_scanned"]:
        out.append("  - No FPM log files found/readable")
    elif not fpm["total_breaches"]:
        out.append("  - No breaches found")
    else:
        out.append(
            f"  Total breaches: {fpm['total_breaches']} across {fpm['pools_affected']} pool(s), "
            f"{fpm['incident_count']} incidents ({fpm['burst_incidents']} burst / {fpm['isolated_incidents']} isolated)"
        )
        if fpm["most_common_pool"]:
            mc = fpm["most_common_pool"]
            mc_count = dict((p, c) for p, c in fpm["breaches_per_pool"]).get(mc, 0)
            out.append(
                f"  Most affected pool: {mc} ({mc_count} breaches, "
                f"pm.max_children={fpm['pool_limits'].get(mc, '?')})"
            )
        out.append("  Breaches per pool:")
        for pool, cnt in fpm["breaches_per_pool"]:
            out.append(f"    - {pool}: {cnt} (pm.max_children={fpm['pool_limits'].get(pool, '?')})")
        out.append("  Breaches per hour:")
        out.append(f"    {'Hour':<20}{'Breaches':>10}")
        for hour, cnt in fpm["breaches_per_hour"]:
            out.append(f"    {hour:<20}{cnt:>10}")
        out.append(f"  Top surges (clustered within {fpm['cluster_gap_seconds']}s):")
        for inc in fpm["top_surges"]:
            out.append(
                f"    - [{inc['type']}] pool {inc['pool']}: {inc['start']} -> {inc['end']} "
                f"({inc['breach_count']} breaches in {inc['duration_seconds']}s)"
            )

    out.append("\nOOM killer events (syslog):")
    if oom is None:
        out.append("  - Skipped")
    elif not oom["log_files_scanned"]:
        out.append("  - No syslog files found/readable")
    elif not oom["oom_kill_count"]:
        out.append("  - No OOM kills found")
    else:
        out.append(f"  Total OOM kills: {oom['oom_kill_count']}")
        out.append(
            "  Killed processes: "
            + ", ".join(f"{p} ({c})" for p, c in oom["killed_processes"])
        )
        out.append("  Kill timestamps:")
        for ts in oom["timestamps"][:20]:
            out.append(f"    - {ts}")
        if len(oom["timestamps"]) > 20:
            out.append(f"    ... and {oom['oom_kill_count'] - 20} more")
        if oom["clusters"]:
            out.append(f"  Clustered kills (within {oom['cluster_gap_seconds']}s of each other):")
            for c in oom["clusters"]:
                out.append(
                    f"    - {c['start']} -> {c['end']} ({c['kill_count']} kills in {c['duration_seconds']}s)"
                )
        else:
            out.append("  Clustered kills: none (no kills close together)")

    out.append("")
    return out


def render_report(
    top5,
    all_sorted,
    roots,
    geo_backend,
    out_json_path,
    only_app: str = "",
    time_window_desc: str = "",
    fpm_analysis: dict | None = None,
    oom_analysis: dict | None = None,
):
    out = []
    out.append("Cloudways Backend Access Traffic Summary")
    out.append(f"Generated: {now_utc_iso()}")
    out.append(f"Roots scanned: {', '.join(str(r) for r in roots)}")
    out.append(f"GeoIP backend: {geo_backend}")
    if time_window_desc:
        out.append(f"Time window: {time_window_desc}")
    out.append("")

    if only_app:
        out.append(f"Single application mode (--only-app {only_app})")
    else:
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

        out.append("\nTop IP Subnets (/24 IPv4, /48 IPv6):")
        if row["top_ip_subnets"]:
            out.append(f"  {'Subnet':<28}{'Requests':>10}{'Unique IPs':>12}")
            for s in row["top_ip_subnets"]:
                out.append(f"  {s['subnet']:<28}{s['requests']:>10}{s['unique_ips']:>12}")
        else:
            out.append("  - None found")

        out.append("\nTop Endpoints:")
        for k, v in row["top_endpoints"]:
            out.append(f"  - {k}: {v}")

        out.append("\nTop Non-browser User Agents:")
        if row["top_non_browser_user_agents"]:
            for k, v in row["top_non_browser_user_agents"]:
                out.append(f"  - {k}: {v}")
        else:
            out.append("  - None found")

        ua = row.get("user_agent_analysis", {})
        spoof = ua.get("spoofing_indicators", {})
        out.append("\nUser-Agent (Chrome/Chromium) Analysis:")
        out.append(
            f"  Claimed Chrome traffic: {ua.get('claimed_chrome_requests', 0)} requests "
            f"({ua.get('claimed_chrome_percent', 0)}%)"
        )
        out.append(f"  Distinct Chrome major versions: {ua.get('distinct_major_versions', 0)}")
        out.append(
            f"  Latest known Chrome major used for checks: v{ua.get('estimated_latest_major', '?')} "
            f"(obsolete cutoff: v{ua.get('obsolete_cutoff_major', '?')} and older)"
        )
        out.append("  Spoofing indicators:")
        obsolete = spoof.get("obsolete_versions", {})
        nonexistent = spoof.get("nonexistent_versions", {})
        if obsolete.get("requests"):
            out.append(
                f"    - Obsolete Chrome {obsolete.get('range', '')}: {obsolete['requests']} requests "
                f"across {obsolete.get('distinct_versions', 0)} outdated major versions"
            )
        else:
            out.append("    - Obsolete Chrome versions: none detected")
        if nonexistent.get("requests"):
            out.append(
                f"    - Non-existent Chrome {nonexistent.get('range', '')}: {nonexistent['requests']} requests "
                f"(versions above latest known release)"
            )
        else:
            out.append("    - Non-existent (future) Chrome versions: none detected")
        if spoof.get("headless_chrome_requests"):
            out.append(f"    - HeadlessChrome: {spoof['headless_chrome_requests']} requests")
        if ua.get("top_major_versions"):
            out.append("  Top claimed Chrome majors:")
            for ver, cnt in ua["top_major_versions"]:
                out.append(f"    - {ver}: {cnt}")

        qs = row.get("query_string_analysis", {})
        out.append("\nQuery String Analysis:")
        out.append(
            f"  Requests with query strings: {qs.get('requests_with_query_string', 0)} "
            f"({qs.get('percent_of_total', 0)}% of total)"
        )
        if qs.get("top_parameters"):
            out.append(f"  Distinct parameters seen: {qs.get('distinct_parameters', 0)}")
            out.append(f"  {'Parameter':<44}{'Hits':>8}")
            for name, hits in qs["top_parameters"]:
                out.append(f"  {name:<44}{hits:>8}")
        else:
            out.append("  - No query string traffic found")

        out.append("\nHourly Traffic (requests/minute stats + unique IPs):")
        hourly = row.get("hourly_traffic", [])
        if hourly:
            out.append(f"  {'Hour':<20}{'Min/min':>9}{'Avg/min':>9}{'Max/min':>9}{'Total':>10}{'Unique IPs':>12}")
            for h in hourly:
                out.append(
                    f"  {h['hour']:<20}{h['min_per_minute']:>9}{h['avg_per_minute']:>9}"
                    f"{h['max_per_minute']:>9}{h['total_requests']:>10}{h['unique_ips']:>12}"
                )
        else:
            out.append("  - No timestamps parsed from logs")

        fpm = row.get("fpm_breaches")
        if fpm is not None:
            out.append(f"\nFPM max_children Breaches (pool {row['app']}):")
            if fpm["total_breaches"]:
                limit = fpm["pool_limits"].get(row["app"], "?")
                out.append(
                    f"  Total: {fpm['total_breaches']} breaches (pm.max_children={limit}), "
                    f"{fpm['burst_incidents']} burst / {fpm['isolated_incidents']} isolated incidents"
                )
                busiest = sorted(fpm["breaches_per_hour"], key=lambda kv: kv[1], reverse=True)[:3]
                if busiest:
                    out.append("  Busiest hours: " + ", ".join(f"{h} ({c})" for h, c in busiest))
                for inc in fpm["top_surges"][:3]:
                    out.append(
                        f"  - [{inc['type']}] {inc['start']} -> {inc['end']} "
                        f"({inc['breach_count']} breaches in {inc['duration_seconds']}s)"
                    )
            else:
                out.append("  - None found in scanned FPM logs")

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

    if fpm_analysis is not None or oom_analysis is not None:
        out.extend(render_fpm_oom_section(fpm_analysis, oom_analysis, only_app=only_app))

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
    parser.add_argument("--country-mmdb", default="")
    parser.add_argument("--country-dat", default="")
    parser.add_argument("--countryv6-dat", default="")
    parser.add_argument(
        "--chrome-latest-major",
        type=int,
        default=0,
        help=(
            "Latest released Chrome major version, used to flag non-existent/spoofed versions. "
            "Default 0 = auto-estimate from release cadence"
        ),
    )
    parser.add_argument(
        "--chrome-obsolete-margin",
        type=int,
        default=40,
        help="Chrome majors this far (or more) behind the latest are flagged as obsolete",
    )
    parser.add_argument(
        "--strict-root",
        action="store_true",
        help="Scan only --applications-root and do not auto-discover other /home roots",
    )
    parser.add_argument(
        "--only-app",
        default="",
        help=(
            "Analyze only this application (directory name under the applications root, "
            "e.g. abcdefghij). Skips ranking/processing of all other apps"
        ),
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
    day_group.add_argument(
        "--hour",
        type=int,
        default=None,
        help=(
            "Only analyze the last N hours of traffic (UTC, based on log timestamps). "
            "e.g. --hour 1 = last hour, --hour 12 = last 12 hours. Cannot be combined with --days"
        ),
    )
    parser.add_argument(
        "--skip-fpm-oom",
        action="store_true",
        help="Skip PHP-FPM max_children breach and OOM killer analysis",
    )
    parser.add_argument(
        "--fpm-log-glob",
        default="/var/log/php*log*",
        help="Glob for PHP-FPM logs incl. rotated .gz (default: /var/log/php*log*)",
    )
    parser.add_argument(
        "--syslog-glob",
        default="/var/log/syslog*",
        help="Glob for syslog files incl. rotated .gz (default: /var/log/syslog*)",
    )
    parser.add_argument(
        "--from-time",
        default="",
        help="Start of scan window in UTC, format DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM (e.g. 10-07-2026:00)",
    )
    parser.add_argument(
        "--to-time",
        default="",
        help="End of scan window in UTC, format DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM (e.g. 10-07-2026:14:30)",
    )
    args = parser.parse_args()
    if args.days is not None and args.days < 1:
        parser.error("--days must be >= 1")
    if args.all_days:
        args.days = None
    if args.hour is not None and args.hour < 1:
        parser.error("--hour must be >= 1")
    if args.hour is not None and (args.from_time or args.to_time):
        parser.error("--hour cannot be combined with --from-time/--to-time")
    if args.days is not None and (args.from_time or args.to_time):
        parser.error("--days cannot be combined with --from-time/--to-time (the window may span rotated files)")

    time_start = None
    time_end = None
    if args.hour is not None:
        time_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=args.hour)
        # Timestamp filtering makes the day-slot file limit unnecessary; scan all
        # rotated files so windows spanning rotation boundaries are fully covered.
        args.days = None
    if args.from_time:
        time_start = parse_user_time(args.from_time)
        if time_start is None:
            parser.error(f"Invalid --from-time '{args.from_time}'. Expected DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM (UTC)")
    if args.to_time:
        time_end = parse_user_time(args.to_time)
        if time_end is None:
            parser.error(f"Invalid --to-time '{args.to_time}'. Expected DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM (UTC)")
        if len(args.to_time.strip().split(":")) == 2:
            # Hour-only end bound: include the whole hour.
            time_end = time_end.replace(minute=59, second=59)
    if time_start and time_end and time_start > time_end:
        parser.error("--from-time must be earlier than --to-time")

    time_window_desc = describe_time_window(time_start, time_end, args.hour)

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

    if args.only_app:
        if args.only_app in apps:
            apps = {args.only_app: apps[args.only_app]}
            progress_log(progress, f"Single-app mode: only analyzing {args.only_app}")
        else:
            available = ", ".join(sorted(apps.keys()))
            payload = {
                "generated_at": now_utc_iso(),
                "error": f"Application '{args.only_app}' not found",
                "roots": [str(x) for x in roots],
                "available_applications": sorted(apps.keys()),
            }
            Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            Path(args.output_txt).write_text(
                f"Application '{args.only_app}' not found under scanned roots.\n"
                f"Available applications: {available}\n",
                encoding="utf-8",
            )
            print(Path(args.output_txt).read_text(encoding="utf-8"))
            return 1

    # First pass: rank all apps by total request count only (fast).
    progress_log(progress, f"Pass 1/2: ranking all applications by request count ({time_window_desc})")
    ranked_apps = []
    for idx, (app, data) in enumerate(apps.items(), start=1):
        selected_logs = select_log_files_by_days(data["log_files"], args.days)
        if not selected_logs:
            progress_log(progress, f"[rank {idx}/{len(apps)}] {app}: skipped (no logs in selected day window)")
            continue
        total = count_requests(selected_logs, time_start, time_end)
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
    geo = GeoResolver(country_db, country_dat, countryv6_dat)
    progress_log(progress, f"Geo backend selected: {geo.backend}")
    chrome_latest = args.chrome_latest_major if args.chrome_latest_major > 0 else estimate_latest_chrome_major()
    progress_log(
        progress,
        f"Chrome version checks: latest_major=v{chrome_latest} "
        f"({'override' if args.chrome_latest_major > 0 else 'auto-estimated'}), "
        f"obsolete_margin={args.chrome_obsolete_margin}",
    )
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
                chrome_latest_major=chrome_latest,
                chrome_obsolete_margin=args.chrome_obsolete_margin,
                time_start=time_start,
                time_end=time_end,
            )
        )
    geo.close()
    progress_log(progress, "Top 5 enrichment complete")

    fpm_analysis = None
    oom_analysis = None
    if not args.skip_fpm_oom:
        progress_log(progress, f"Scanning FPM logs ({args.fpm_log_glob}) for max_children breaches")
        fpm_events, fpm_files = scan_fpm_breach_logs(args.fpm_log_glob, time_start, time_end)
        progress_log(progress, f"Found {len(fpm_events)} FPM breach lines in {len(fpm_files)} files")
        progress_log(progress, f"Scanning syslog ({args.syslog_glob}) for OOM killer events")
        oom_events, syslog_files = scan_oom_events(args.syslog_glob, time_start, time_end)
        progress_log(progress, f"Found {len(oom_events)} OOM kill events in {len(syslog_files)} files")

        # Attach each app's own pool breaches to its per-app summary.
        for row in top5:
            app_events = [e for e in fpm_events if e["pool"] == row["app"]]
            row["fpm_breaches"] = analyze_fpm_breaches(app_events, fpm_files)

        server_events = fpm_events
        if args.only_app:
            server_events = [e for e in fpm_events if e["pool"] == args.only_app]
        fpm_analysis = analyze_fpm_breaches(server_events, fpm_files)
        oom_analysis = analyze_oom_events(oom_events, syslog_files)

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
        "days_filter": args.days if args.days is not None else "all",
        "geoip_country_db": str(country_db) if country_db else "",
        "geoip_country_dat": str(country_dat) if country_dat else "",
        "geoip_countryv6_dat": str(countryv6_dat) if countryv6_dat else "",
        "chrome_latest_major": chrome_latest,
        "chrome_obsolete_margin": args.chrome_obsolete_margin,
        "only_app": args.only_app,
        "time_window": time_window_desc,
        "time_window_start_utc": time_start.isoformat() if time_start else "",
        "time_window_end_utc": time_end.isoformat() if time_end else "",
        "fpm_breach_analysis": fpm_analysis,
        "oom_analysis": oom_analysis,
        "total_applications_found": len(ranked_apps),
        "top5": top5,
        "all_applications_sorted": [
            {"app": x["app"], "total_requests": x["total_requests"], "app_dir": x["app_dir"]}
            for x in ranked_apps
        ],
    }

    Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    report_txt = render_report(
        top5,
        ranked_apps,
        roots,
        geo.backend,
        args.output_json,
        only_app=args.only_app,
        time_window_desc=time_window_desc,
        fpm_analysis=fpm_analysis,
        oom_analysis=oom_analysis,
    )
    Path(args.output_txt).write_text(report_txt, encoding="utf-8")

    progress_log(progress, f"Wrote outputs: {args.output_json} and {args.output_txt}")
    print(report_txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
