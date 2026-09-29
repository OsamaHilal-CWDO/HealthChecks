#!/usr/bin/env python3
"""
PHP-FPM performance analyzer for Cloudways applications.

Parses each app's PHP-FPM logs (same directory as the backend access logs):
  logs/php-app.access.log*   request log incl. duration, peak memory, CPU
  logs/php-app.slow.log*     slow-request stack traces

Reports per application:
  - Memory overview: average / max peak memory, top memory-consuming requests
  - Slowest pages (individual transactions) with the memory consumed by that
    exact transaction, correlated where possible with the slow-log function
    that was executing
  - Slowest pages aggregated by path (hits, avg/max duration, avg/max memory)
  - Slowest functions from the slow log (top stack frame + first app-level
    frame, aggregated with counts and plugin/component attribution)
  - Text time-series chart + table of memory usage over time (spot gradual
    leaks before they become OOM kills)

Filtering:
  --method GET,POST         filter by HTTP method
  --status 200,500,503|5xx  filter by status code(s) or class (4xx/5xx)
  --request-type ajax,json  filter by request type
                            (page,ajax,json,rest,pdf,static,cron,login,admin,other)

Time windows (same semantics as analyze_cloudways_backend_traffic.py):
  --days N | --hour N | --from-time DD-MM-YYYY:HH[:MM] --to-time ... (UTC)

Examples:
  python3 analyze_php_fpm_performance.py --only-app abcdefghij --hour 6
  python3 analyze_php_fpm_performance.py --method POST --status 5xx --days 1
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

MONTH_NUM = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# 150.228.25.72 - [29/Sep/2026:08:56:33 +0000] "GET /x/index.php?id=1" 200 0 - 24747 16153 0.175 27525120 62.75% 28.52% "/x/view.json?id=1"
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+'
    r'\[(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s*(?P<tz>[+-]\d{4})?\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<script>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<length>\S+)\s+\S+\s+\S+\s+\S+\s+'
    r'(?P<duration>\d+(?:\.\d+)?)\s+(?P<memory>\d+)\s+'
    r'(?P<cpu_user>[\d.]+)%\s+(?P<cpu_sys>[\d.]+)%\s+'
    r'"(?P<uri>[^"]*)"\s*$'
)

BRACKET_TS_RE = re.compile(
    r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?"
)
QUOTED_RE = re.compile(r'"[^"]*"')
STATUS_TOKEN_RE = re.compile(r"[1-5]\d{2}")
FLOAT_TOKEN_RE = re.compile(r"\d+\.\d+")
INT_TOKEN_RE = re.compile(r"\d{4,}")


def make_ts(year, mon, day, hh, mi, ss, tz):
    """Build a naive-UTC datetime from log fields, normalizing any TZ offset."""
    month = MONTH_NUM.get(mon)
    if not month:
        return None
    try:
        ts = datetime(int(year), month, int(day), int(hh), int(mi), int(ss))
    except ValueError:
        return None
    if tz and tz != "+0000":
        sign = 1 if tz[0] == "+" else -1
        ts -= timedelta(minutes=sign * (int(tz[1:3]) * 60 + int(tz[3:5])))
    return ts

SLOW_HEADER_RE = re.compile(
    r"^\[(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\]\s+\[pool ([^\]]+)\]\s+pid\s+(\d+)"
)
SLOW_SCRIPT_RE = re.compile(r"^script_filename\s*=\s*(.+)$")
SLOW_FRAME_RE = re.compile(r"^\[0x[0-9a-fA-F]+\]\s+(.+?)\(\)\s+(.+?):(\d+)\s*$")

LOG_DAY_RE = re.compile(r"\.log(?:\.(\d+)(?:\.gz)?)?$")

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map", ".txt", ".xml",
)
REQUEST_TYPES = ("page", "ajax", "json", "rest", "pdf", "static", "cron", "login", "admin", "other")


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


def log_day_slot(path: Path) -> int:
    m = LOG_DAY_RE.search(path.name)
    if not m:
        return 999999
    return 1 if m.group(1) is None else int(m.group(1)) + 1


def file_meta(path: Path) -> str:
    try:
        st = path.stat()
        mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc)
        size = st.st_size
        if size >= 1024 * 1024:
            size_s = f"{size / (1024 * 1024):.1f}MB"
        elif size >= 1024:
            size_s = f"{size / 1024:.1f}KB"
        else:
            size_s = f"{size}B"
        return f"{path.name} ({size_s}, modified {mtime:%d/%b/%Y %H:%M} UTC)"
    except OSError:
        return path.name


def select_log_files(logs_dir: Path, base_name: str, days: int | None, time_start: datetime | None):
    """Return (kept, skipped) where skipped is a list of (file, reason) pairs."""
    all_files = sorted(
        (f for f in logs_dir.glob(f"{base_name}*") if f.is_file()),
        key=log_day_slot,
    )
    kept, skipped = [], []
    for f in all_files:
        slot = log_day_slot(f)
        if days is not None and slot > days:
            skipped.append((f, f"rotation slot {slot} outside --days/--hour window"))
            continue
        if time_start is not None:
            try:
                mt = f.stat().st_mtime
                if mt < time_start.replace(tzinfo=timezone.utc).timestamp():
                    mtime = datetime.fromtimestamp(mt, timezone.utc)
                    skipped.append((f, f"last modified {mtime:%d/%b/%Y %H:%M} UTC, older than window start"))
                    continue
            except OSError:
                pass
        kept.append(f)
    return kept, skipped


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


def parse_user_time(value: str) -> datetime | None:
    for fmt in ("%d-%m-%Y:%H:%M", "%d-%m-%Y:%H"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def describe_time_window(time_start, time_end, hours) -> str:
    if hours is not None:
        return f"last {hours} hour(s) (since {time_start:%d/%b/%Y %H:%M} UTC)"
    if time_start is not None or time_end is not None:
        start_s = f"{time_start:%d/%b/%Y %H:%M}" if time_start else "beginning of logs"
        end_s = f"{time_end:%d/%b/%Y %H:%M}" if time_end else "end of logs"
        return f"from {start_s} to {end_s} (UTC)"
    return "all available log data"


def classify_request(uri: str) -> str:
    u = uri.lower()
    path = u.split("?", 1)[0]
    if "admin-ajax.php" in u or "ajax=true" in u or "wc-ajax" in u:
        return "ajax"
    if "/wp-json/" in path:
        return "rest"
    if path.endswith(".json") or ".json" in path:
        return "json"
    if path.endswith(".pdf") or ".pdf" in path:
        return "pdf"
    if "wp-cron.php" in path:
        return "cron"
    if "wp-login" in path or path.endswith("/login"):
        return "login"
    if path.endswith(STATIC_EXTENSIONS):
        return "static"
    if "/wp-admin/" in path:
        return "admin"
    if path.endswith(".php") or "/" in path:
        return "page"
    return "other"


def mb(n_bytes: float) -> float:
    return n_bytes / (1024.0 * 1024.0)


def render_box_table(headers, rows, right_align=None, indent="  ") -> list[str]:
    right_align = right_align or set()
    widths = []
    for i, h in enumerate(headers):
        cells = [len(str(r[i])) for r in rows] if rows else []
        widths.append(max(len(str(h)), *cells) if cells else len(str(h)))

    def fmt(cells):
        parts = []
        for i, c in enumerate(cells):
            s = str(c)
            parts.append(s.rjust(widths[i]) if i in right_align else s.ljust(widths[i]))
        return indent + "│ " + " │ ".join(parts) + " │"

    top = indent + "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    sep = indent + "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bottom = indent + "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"
    return [top, fmt(headers), sep] + [fmt(r) for r in rows] + [bottom]


def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def component_of(path: str) -> str:
    m = re.search(r"wp-content/plugins/([^/]+)/", path)
    if m:
        return f"plugin:{m.group(1)}"
    m = re.search(r"wp-content/themes/([^/]+)/", path)
    if m:
        return f"theme:{m.group(1)}"
    m = re.search(r"/vendor/([^/]+/[^/]+)/", path)
    if m:
        return f"vendor:{m.group(1)}"
    if "/wp-includes/" in path or "/wp-admin/" in path:
        return "wordpress-core"
    return "app"


def short_location(path: str, line: str) -> str:
    marker = "public_html/"
    idx = path.find(marker)
    short = path[idx + len(marker):] if idx >= 0 else path
    return f"{short}:{line}"


# --- parsing ------------------------------------------------------------------

def parse_access_line_strict(line):
    m = ACCESS_RE.match(line)
    if not m:
        return None
    ts = make_ts(m.group("year"), m.group("mon"), m.group("day"),
                 m.group("hh"), m.group("mm"), m.group("ss"), m.group("tz"))
    if ts is None:
        return None
    uri = m.group("uri") or m.group("script")
    return {
        "ts": ts,
        "ip": m.group("ip"),
        "method": m.group("method"),
        "script": m.group("script"),
        "status": m.group("status"),
        "duration": float(m.group("duration")),
        "memory": int(m.group("memory")),
        "cpu_user": float(m.group("cpu_user")),
        "cpu_sys": float(m.group("cpu_sys")),
        "uri": uri,
        "type": classify_request(uri),
    }


def parse_access_line_flex(line):
    """Tolerant fallback for FPM access.format variations.

    Relies only on the stable landmarks: leading IP, [timestamp], a quoted
    "METHOD script" section, a 3-digit status right after it, duration+memory
    immediately before the CPU %% columns, and an optional trailing quoted URI.
    """
    qspans = list(QUOTED_RE.finditer(line))
    if not qspans:
        return None
    first_q = qspans[0].group(0)[1:-1]
    method, _, script = first_q.partition(" ")
    if not (2 <= len(method) <= 10 and method.isalpha() and method.isupper()):
        return None
    tsm = BRACKET_TS_RE.search(line[: qspans[0].start()])
    if not tsm:
        return None
    day, mon, year, hh, mi, ss, tz = tsm.groups()
    ts = make_ts(year, mon, day, hh, mi, ss, tz)
    if ts is None:
        return None

    middle = line[qspans[0].end(): qspans[-1].start()] if len(qspans) > 1 else line[qspans[0].end():]
    tokens = middle.split()
    if not tokens:
        return None
    status = tokens[0] if STATUS_TOKEN_RE.fullmatch(tokens[0]) else next(
        (t for t in tokens if STATUS_TOKEN_RE.fullmatch(t)), None)
    if status is None:
        return None

    duration = memory = None
    cpu_user = cpu_sys = 0.0
    pct_idx = [i for i, t in enumerate(tokens) if t.endswith("%")]
    if pct_idx:
        i = pct_idx[0]
        try:
            cpu_user = float(tokens[i].rstrip("%"))
            if len(pct_idx) > 1:
                cpu_sys = float(tokens[pct_idx[1]].rstrip("%"))
        except ValueError:
            pass
        if i >= 2:
            try:
                duration = float(tokens[i - 2])
                memory = int(float(tokens[i - 1]))
            except ValueError:
                duration = memory = None
    if duration is None or memory is None:
        floats = [t for t in tokens if FLOAT_TOKEN_RE.fullmatch(t)]
        ints = [t for t in tokens if INT_TOKEN_RE.fullmatch(t)]
        if floats and duration is None:
            try:
                duration = float(floats[-1])
            except ValueError:
                pass
        if ints and memory is None:
            memory = int(ints[-1])
    if duration is None or memory is None:
        return None

    uri = script
    if len(qspans) > 1:
        last_q = qspans[-1].group(0)[1:-1]
        if last_q.startswith("/"):
            uri = last_q
    return {
        "ts": ts,
        "ip": line.split(None, 1)[0],
        "method": method,
        "script": script,
        "status": status,
        "duration": duration,
        "memory": memory,
        "cpu_user": cpu_user,
        "cpu_sys": cpu_sys,
        "uri": uri,
        "type": classify_request(uri),
    }


def parse_access_logs(files, time_start, time_end):
    requests = []
    stats = {
        "lines_read": 0,
        "parsed": 0,
        "parsed_flex_format": 0,
        "out_of_window": 0,
        "unparsed": 0,
        "ts_min": None,
        "ts_max": None,
        "unparsed_samples": [],
    }
    for f in files:
        for line in iter_log_lines(f):
            if not line.strip():
                continue
            stats["lines_read"] += 1
            rec = parse_access_line_strict(line)
            if rec is None:
                rec = parse_access_line_flex(line)
                if rec is not None:
                    stats["parsed_flex_format"] += 1
            if rec is None:
                stats["unparsed"] += 1
                if len(stats["unparsed_samples"]) < 3:
                    stats["unparsed_samples"].append(line[:220])
                continue
            stats["parsed"] += 1
            ts = rec["ts"]
            if stats["ts_min"] is None or ts < stats["ts_min"]:
                stats["ts_min"] = ts
            if stats["ts_max"] is None or ts > stats["ts_max"]:
                stats["ts_max"] = ts
            if not in_time_window(ts, time_start, time_end):
                stats["out_of_window"] += 1
                continue
            requests.append(rec)
    return requests, stats


def parse_slow_logs(files, time_start, time_end):
    entries = []
    for f in files:
        current = None
        for line in iter_log_lines(f):
            header = SLOW_HEADER_RE.match(line)
            if header:
                if current and current.get("top_frame"):
                    entries.append(current)
                d, mon, y, hh, mi, ss, pool, pid = header.groups()
                month = MONTH_NUM.get(mon)
                ts = None
                if month:
                    try:
                        ts = datetime(int(y), month, int(d), int(hh), int(mi), int(ss))
                    except ValueError:
                        ts = None
                current = {"ts": ts, "pool": pool, "pid": pid, "script": "", "frames": [], "top_frame": None, "app_frame": None}
                continue
            if current is None:
                continue
            m = SLOW_SCRIPT_RE.match(line)
            if m:
                current["script"] = m.group(1).strip()
                continue
            m = SLOW_FRAME_RE.match(line)
            if m:
                func, fpath, fline = m.groups()
                frame = {"function": func, "file": fpath, "line": fline}
                current["frames"].append(frame)
                if current["top_frame"] is None:
                    current["top_frame"] = frame
                if current["app_frame"] is None and "/vendor/" not in fpath:
                    current["app_frame"] = frame
        if current and current.get("top_frame"):
            entries.append(current)

    return [
        e for e in entries
        if in_time_window(e["ts"], time_start, time_end) or (e["ts"] is None and time_start is None and time_end is None)
    ]


def correlate_slow_functions(requests, slow_entries):
    """Attach the slow-log function that was executing to the matching request:
    same script basename, slow timestamp within [request start, start+duration+2s]."""
    by_basename = defaultdict(list)
    for e in slow_entries:
        if e["ts"] is None:
            continue
        base = Path(e["script"]).name if e["script"] else ""
        by_basename[base].append(e)

    for r in requests:
        base = Path(r["script"].split("?", 1)[0]).name
        candidates = by_basename.get(base, [])
        best = None
        for e in candidates:
            start, end = r["ts"], r["ts"] + timedelta(seconds=r["duration"] + 2)
            if start <= e["ts"] <= end:
                if best is None or abs((e["ts"] - start).total_seconds()) < abs((best["ts"] - start).total_seconds()):
                    best = e
        if best is not None:
            frame = best.get("app_frame") or best.get("top_frame")
            if frame:
                r["slow_function"] = f"{frame['function']}() {short_location(frame['file'], frame['line'])}"


# --- analysis -----------------------------------------------------------------

def pick_bucket_minutes(requests, forced: str) -> int:
    if forced == "minute":
        return 1
    if forced == "10min":
        return 10
    if forced == "hour":
        return 60
    if not requests:
        return 60
    span = (max(r["ts"] for r in requests) - min(r["ts"] for r in requests)).total_seconds()
    if span <= 2 * 3600:
        return 1
    if span <= 12 * 3600:
        return 10
    return 60


def build_memory_timeseries(requests, bucket_minutes: int):
    buckets = defaultdict(lambda: {"count": 0, "mem_sum": 0.0, "mem_max": 0.0, "dur_sum": 0.0, "dur_max": 0.0})
    for r in requests:
        ts = r["ts"].replace(second=0)
        ts = ts.replace(minute=(ts.minute // bucket_minutes) * bucket_minutes) if bucket_minutes < 60 else ts.replace(minute=0)
        b = buckets[ts]
        b["count"] += 1
        b["mem_sum"] += r["memory"]
        b["mem_max"] = max(b["mem_max"], r["memory"])
        b["dur_sum"] += r["duration"]
        b["dur_max"] = max(b["dur_max"], r["duration"])

    rows = []
    for ts in sorted(buckets):
        b = buckets[ts]
        rows.append(
            {
                "bucket": ts.strftime("%d/%b/%Y %H:%M"),
                "requests": b["count"],
                "avg_memory_mb": round(mb(b["mem_sum"] / b["count"]), 2),
                "max_memory_mb": round(mb(b["mem_max"]), 2),
                "avg_duration_s": round(b["dur_sum"] / b["count"], 3),
                "max_duration_s": round(b["dur_max"], 3),
            }
        )
    return rows


def leak_hint(series) -> str:
    """Compare avg memory of the first vs last third of buckets."""
    if len(series) < 6:
        return ""
    third = len(series) // 3
    first = sum(r["avg_memory_mb"] for r in series[:third]) / third
    last = sum(r["avg_memory_mb"] for r in series[-third:]) / third
    if first <= 0:
        return ""
    change = (last - first) / first * 100.0
    if change >= 15:
        return (
            f"  ⚠ Possible gradual memory increase: avg {first:.1f}MB (first third) -> "
            f"{last:.1f}MB (last third), +{change:.0f}%"
        )
    return ""


def render_memory_chart(series, width: int = 36) -> list[str]:
    out = []
    peak = max((r["max_memory_mb"] for r in series), default=0) or 1
    out.append(f"  (█ avg, ░ up to max; scale: {peak:.1f}MB = {width} cols)")
    for r in series:
        avg_w = int(round(r["avg_memory_mb"] / peak * width))
        max_w = int(round(r["max_memory_mb"] / peak * width))
        bar = "█" * avg_w + "░" * max(0, max_w - avg_w)
        out.append(
            f"  {r['bucket']} │{bar:<{width}}│ avg {r['avg_memory_mb']:7.2f}M "
            f"max {r['max_memory_mb']:7.2f}M  n={r['requests']}"
        )
    return out


def analyze_app(app, logs_dir, args, time_start, time_end, progress):
    access_files, access_skipped = select_log_files(logs_dir, "php-app.access.log", args.days, time_start)
    slow_files, slow_skipped = select_log_files(logs_dir, "php-app.slow.log", args.days, time_start)
    if not (access_files or slow_files or access_skipped or slow_skipped):
        return None

    progress_log(progress, f"[{app}] parsing {len(access_files)} access + {len(slow_files)} slow log files")
    requests, access_stats = parse_access_logs(access_files, time_start, time_end)
    slow_entries = parse_slow_logs(slow_files, time_start, time_end)
    total_parsed = len(requests)

    # Interactive filters (access-log analysis).
    methods = {m.strip().upper() for m in args.method.split(",") if m.strip()} if args.method else None
    types = {t.strip().lower() for t in args.request_type.split(",") if t.strip()} if args.request_type else None
    statuses = set()
    status_classes = set()
    if args.status:
        for s in args.status.split(","):
            s = s.strip().lower()
            if not s:
                continue
            if s.endswith("xx") and len(s) == 3:
                status_classes.add(s[0])
            else:
                statuses.add(s)

    def keep(r):
        if methods and r["method"] not in methods:
            return False
        if types and r["type"] not in types:
            return False
        if statuses or status_classes:
            if r["status"] in statuses:
                return True
            if r["status"][0] in status_classes:
                return True
            return False
        return True

    requests = [r for r in requests if keep(r)]
    correlate_slow_functions(requests, slow_entries)

    result = {
        "app": app,
        "logs_dir": str(logs_dir),
        "access_log_files": [f.name for f in access_files],
        "access_log_files_detail": [file_meta(f) for f in access_files],
        "access_log_files_skipped": [f"{f.name}: {reason}" for f, reason in access_skipped],
        "slow_log_files": [f.name for f in slow_files],
        "slow_log_files_skipped": [f"{f.name}: {reason}" for f, reason in slow_skipped],
        "requests_parsed_total": total_parsed,
        "requests_after_filters": len(requests),
        "unparsed_lines": access_stats["unparsed"],
        "access_parse_stats": {
            "lines_read": access_stats["lines_read"],
            "parsed": access_stats["parsed"],
            "parsed_flex_format": access_stats["parsed_flex_format"],
            "out_of_window": access_stats["out_of_window"],
            "unparsed": access_stats["unparsed"],
            "log_ts_min": access_stats["ts_min"].strftime("%d/%b/%Y %H:%M:%S") if access_stats["ts_min"] else None,
            "log_ts_max": access_stats["ts_max"].strftime("%d/%b/%Y %H:%M:%S") if access_stats["ts_max"] else None,
            "unparsed_samples": access_stats["unparsed_samples"],
        },
        "slow_log_entries": len(slow_entries),
    }

    if requests:
        durations = sorted(r["duration"] for r in requests)
        memories = [r["memory"] for r in requests]
        p95 = durations[int(len(durations) * 0.95) - 1] if len(durations) >= 2 else durations[-1]
        max_req = max(requests, key=lambda r: r["memory"])
        result["memory_overview"] = {
            "avg_peak_memory_mb": round(mb(sum(memories) / len(memories)), 2),
            "max_peak_memory_mb": round(mb(max(memories)), 2),
            "max_memory_request": {
                "time": max_req["ts"].strftime("%d/%b/%Y %H:%M:%S"),
                "method": max_req["method"],
                "status": max_req["status"],
                "uri": max_req["uri"],
                "memory_mb": round(mb(max_req["memory"]), 2),
            },
            "avg_duration_s": round(sum(durations) / len(durations), 3),
            "p95_duration_s": round(p95, 3),
        }

        def req_row(r, include_slow=False):
            row = {
                "time": r["ts"].strftime("%d/%b/%Y %H:%M:%S"),
                "method": r["method"],
                "status": r["status"],
                "duration_s": round(r["duration"], 3),
                "memory_mb": round(mb(r["memory"]), 2),
                "type": r["type"],
                "uri": r["uri"],
            }
            if include_slow:
                row["slow_function"] = r.get("slow_function", "")
            return row

        result["top_memory_requests"] = [
            req_row(r) for r in sorted(requests, key=lambda r: r["memory"], reverse=True)[: args.top]
        ]
        result["slowest_requests"] = [
            req_row(r, include_slow=True)
            for r in sorted(requests, key=lambda r: r["duration"], reverse=True)[: args.top]
        ]

        pages = defaultdict(lambda: {"hits": 0, "dur_sum": 0.0, "dur_max": 0.0, "mem_sum": 0.0, "mem_max": 0.0})
        for r in requests:
            key = r["uri"].split("?", 1)[0]
            p = pages[key]
            p["hits"] += 1
            p["dur_sum"] += r["duration"]
            p["dur_max"] = max(p["dur_max"], r["duration"])
            p["mem_sum"] += r["memory"]
            p["mem_max"] = max(p["mem_max"], r["memory"])
        agg = [
            {
                "page": k,
                "hits": v["hits"],
                "avg_duration_s": round(v["dur_sum"] / v["hits"], 3),
                "max_duration_s": round(v["dur_max"], 3),
                "avg_memory_mb": round(mb(v["mem_sum"] / v["hits"]), 2),
                "max_memory_mb": round(mb(v["mem_max"]), 2),
            }
            for k, v in pages.items()
        ]
        agg.sort(key=lambda x: x["avg_duration_s"], reverse=True)
        result["slowest_pages_aggregated"] = agg[: args.top]

        result["requests_by_type"] = Counter(r["type"] for r in requests).most_common()
        result["requests_by_method"] = Counter(r["method"] for r in requests).most_common()
        result["requests_by_status"] = sorted(Counter(r["status"] for r in requests).items())

        bucket_minutes = pick_bucket_minutes(requests, args.bucket)
        series = build_memory_timeseries(requests, bucket_minutes)
        result["memory_timeseries"] = {"bucket_minutes": bucket_minutes, "series": series}

    if slow_entries:
        func_counter = Counter()
        func_meta = {}
        comp_counter = Counter()
        for e in slow_entries:
            frame = e.get("app_frame") or e.get("top_frame")
            if not frame:
                continue
            label = f"{frame['function']}()"
            loc = short_location(frame["file"], frame["line"])
            key = (label, loc)
            func_counter[key] += 1
            func_meta[key] = component_of(frame["file"])
            comp_counter[component_of(frame["file"])] += 1
        result["slowest_functions"] = [
            {"function": k[0], "location": k[1], "traces": c, "component": func_meta[k]}
            for k, c in func_counter.most_common(args.top)
        ]
        result["slow_components"] = comp_counter.most_common()
        result["slow_scripts"] = Counter(
            Path(e["script"]).name for e in slow_entries if e["script"]
        ).most_common(10)

    return result


# --- rendering ----------------------------------------------------------------

def render_app_report(res, filters_desc: str) -> list[str]:
    out = []
    out.append("=" * 80)
    out.append(f"Application: {res['app']}")
    out.append(f"Logs: {res['logs_dir']}")
    out.append(
        f"Access requests parsed: {res['requests_parsed_total']}"
        + (f" -> {res['requests_after_filters']} after filters ({filters_desc})" if filters_desc else "")
        + f" | slow-log entries: {res['slow_log_entries']}"
        + (f" | unparsed lines: {res['unparsed_lines']}" if res["unparsed_lines"] else "")
    )

    mo = res.get("memory_overview")
    if not mo:
        out.append("\n▸ Memory / Duration Profiling (php-app.access.log)")
        out.append("  No usable requests in this window — memory profiling and avg/max duration")
        out.append("  come from php-app.access.log. Diagnostics:")
        st = res.get("access_parse_stats", {})
        if res.get("access_log_files_detail"):
            out.append("    Access files read:  " + ", ".join(res["access_log_files_detail"]))
        else:
            out.append("    Access files read:  none")
        if res.get("access_log_files_skipped"):
            out.append("    Files skipped:      " + "; ".join(res["access_log_files_skipped"]))
        if not res.get("access_log_files") and not res.get("access_log_files_skipped"):
            out.append("    No php-app.access.log* files exist in this logs directory —")
            out.append("    the FPM access log may be disabled for this app.")
        if st.get("lines_read"):
            out.append(
                f"    Lines read: {st['lines_read']} | parsed: {st['parsed']}"
                + (f" ({st['parsed_flex_format']} via fallback format)" if st.get("parsed_flex_format") else "")
                + f" | outside time window: {st['out_of_window']} | unparsed: {st['unparsed']}"
            )
            if st.get("log_ts_min"):
                out.append(f"    Timestamps seen in log: {st['log_ts_min']} -> {st['log_ts_max']} UTC")
            if st.get("parsed") and st.get("out_of_window") == st.get("parsed"):
                out.append("    All parsed requests fall outside the requested window — widen the window")
                out.append("    (e.g. --hour 24) or check the timestamp range above.")
            filtered_out = res["requests_parsed_total"] - res["requests_after_filters"]
            if res["requests_parsed_total"] and filtered_out == res["requests_parsed_total"]:
                out.append(f"    All {filtered_out} in-window requests were excluded by the active filters ({filters_desc}).")
            for s in st.get("unparsed_samples", []):
                out.append(f"    Sample unparsed line: {s}")
        elif res.get("access_log_files"):
            out.append("    Access log file(s) contained no lines in the selected rotation slots.")
        out.append("  Slow-log analysis below is independent and unaffected.")
    else:
        out.append("\n▸ Memory Overview")
        mr = mo["max_memory_request"]
        out.append(f"  Average peak memory: {mo['avg_peak_memory_mb']} MB")
        out.append(
            f"  Max peak memory:     {mo['max_peak_memory_mb']} MB "
            f"({mr['time']} {mr['method']} {mr['status']} {truncate(mr['uri'], 60)})"
        )
        out.append(f"  Avg duration: {mo['avg_duration_s']}s | p95 duration: {mo['p95_duration_s']}s")

        out.append("\n▸ Top Memory-Consuming Requests")
        rows = [
            [r["time"], r["method"], r["status"], f"{r['duration_s']:.3f}", f"{r['memory_mb']:.2f}", r["type"], truncate(r["uri"], 48)]
            for r in res["top_memory_requests"]
        ]
        out.extend(render_box_table(
            ["Time", "Method", "St", "Sec", "Mem MB", "Type", "Page"], rows, right_align={3, 4}))

        out.append("\n▸ Slowest Pages (individual transactions, with memory + slow function)")
        rows = [
            [
                r["time"], r["method"], r["status"], f"{r['duration_s']:.3f}", f"{r['memory_mb']:.2f}",
                truncate(r["uri"], 40), truncate(r.get("slow_function", "") or "-", 52),
            ]
            for r in res["slowest_requests"]
        ]
        out.extend(render_box_table(
            ["Time", "Method", "St", "Sec", "Mem MB", "Page", "Slow function (from slow.log)"],
            rows, right_align={3, 4}))

        out.append("\n▸ Slowest Pages (aggregated by path)")
        rows = [
            [p["page"] if len(p["page"]) <= 44 else truncate(p["page"], 44), p["hits"],
             f"{p['avg_duration_s']:.3f}", f"{p['max_duration_s']:.3f}",
             f"{p['avg_memory_mb']:.2f}", f"{p['max_memory_mb']:.2f}"]
            for p in res["slowest_pages_aggregated"]
        ]
        out.extend(render_box_table(
            ["Page", "Hits", "Avg s", "Max s", "Avg MB", "Max MB"], rows, right_align={1, 2, 3, 4, 5}))

        out.append("\n▸ Requests by Type / Method / Status")
        out.append("  Type:   " + ", ".join(f"{k} ({v})" for k, v in res["requests_by_type"]))
        out.append("  Method: " + ", ".join(f"{k} ({v})" for k, v in res["requests_by_method"]))
        out.append("  Status: " + ", ".join(f"{k} ({v})" for k, v in res["requests_by_status"]))

    funcs = res.get("slowest_functions")
    out.append("\n▸ Slowest Functions (php-app.slow.log stack traces)")
    if funcs:
        rows = [
            [f["function"], truncate(f["location"], 64), f["traces"], f["component"]]
            for f in funcs
        ]
        out.extend(render_box_table(["Function", "Location", "Traces", "Component"], rows, right_align={2}))
        out.append("  Components: " + ", ".join(f"{k} ({v})" for k, v in res.get("slow_components", [])))
        out.append("  Scripts:    " + ", ".join(f"{k} ({v})" for k, v in res.get("slow_scripts", [])))
    else:
        out.append("  - No slow-log entries found (php-app.slow.log empty or absent in window)")

    ts = res.get("memory_timeseries")
    if ts and ts["series"]:
        out.append(f"\n▸ Memory Over Time ({ts['bucket_minutes']}-minute buckets)")
        out.extend(render_memory_chart(ts["series"]))
        hint = leak_hint(ts["series"])
        if hint:
            out.append(hint)
        out.append("")
        rows = [
            [r["bucket"], r["requests"], f"{r['avg_memory_mb']:.2f}", f"{r['max_memory_mb']:.2f}",
             f"{r['avg_duration_s']:.3f}", f"{r['max_duration_s']:.3f}"]
            for r in ts["series"]
        ]
        out.extend(render_box_table(
            ["Bucket (UTC)", "Reqs", "Avg MB", "Max MB", "Avg s", "Max s"], rows,
            right_align={1, 2, 3, 4, 5}))

    out.append("")
    return out


# --- app discovery (same layout as the traffic analyzer) -----------------------

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
            if safe_is_dir(child) and safe_is_dir(child / "logs"):
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze PHP-FPM access/slow logs per Cloudways application")
    parser.add_argument("--applications-root", default="/home/master/applications")
    parser.add_argument("--strict-root", action="store_true",
                        help="Scan only --applications-root, no auto-discovery of other /home roots")
    parser.add_argument("--only-app", default="", help="Analyze only this application directory name")
    parser.add_argument("--output-json", default="/tmp/php_fpm_performance.json")
    parser.add_argument("--output-txt", default="/tmp/php_fpm_performance.txt")
    parser.add_argument("--top", type=int, default=10, help="Rows per table (default 10)")
    parser.add_argument("--progress", action="store_true", help="Print progress to stderr")

    parser.add_argument("--method", default="", help="Filter: HTTP methods, e.g. GET,POST")
    parser.add_argument("--status", default="", help="Filter: status codes, e.g. 200,500,503 or 4xx,5xx")
    parser.add_argument("--request-type", default="",
                        help=f"Filter: request types ({','.join(REQUEST_TYPES)})")
    parser.add_argument("--bucket", choices=["auto", "minute", "10min", "hour"], default="auto",
                        help="Time-series bucket size (default: auto from window span)")

    day_group = parser.add_mutually_exclusive_group()
    day_group.add_argument("--days", type=int, default=None,
                           help="Limit to N day-slots of rotated logs (1=current, 2=+.1, ...)")
    day_group.add_argument("--all-days", action="store_true", help="Use all rotated logs (default)")
    day_group.add_argument("--hour", type=int, default=None,
                           help="Only analyze the last N hours (UTC, line-level timestamp filter)")
    parser.add_argument("--from-time", default="",
                        help="Start of scan window, UTC, DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM")
    parser.add_argument("--to-time", default="",
                        help="End of scan window, UTC, DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM")
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
        parser.error("--days cannot be combined with --from-time/--to-time")
    if args.request_type:
        bad = [t for t in args.request_type.split(",") if t.strip() and t.strip().lower() not in REQUEST_TYPES]
        if bad:
            parser.error(f"Unknown --request-type value(s): {', '.join(bad)}. Valid: {', '.join(REQUEST_TYPES)}")

    time_start = None
    time_end = None
    if args.hour is not None:
        time_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=args.hour)
        args.days = (args.hour + 23) // 24
    if args.from_time:
        time_start = parse_user_time(args.from_time)
        if time_start is None:
            parser.error(f"Invalid --from-time '{args.from_time}'. Expected DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM (UTC)")
    if args.to_time:
        time_end = parse_user_time(args.to_time)
        if time_end is None:
            parser.error(f"Invalid --to-time '{args.to_time}'. Expected DD-MM-YYYY:HH or DD-MM-YYYY:HH:MM (UTC)")
        if len(args.to_time.strip().split(":")) == 2:
            time_end = time_end.replace(minute=59, second=59)
    if time_start and time_end and time_start > time_end:
        parser.error("--from-time must be earlier than --to-time")

    window_desc = describe_time_window(time_start, time_end, args.hour)
    filters = []
    if args.method:
        filters.append(f"method={args.method}")
    if args.status:
        filters.append(f"status={args.status}")
    if args.request_type:
        filters.append(f"type={args.request_type}")
    filters_desc = ", ".join(filters)

    roots = detect_roots(Path(args.applications_root), strict_root=args.strict_root)
    if not roots:
        print(f"No valid applications root found (requested: {args.applications_root})", file=sys.stderr)
        return 1

    apps = {}
    for root in roots:
        for app_dir in sorted(root.iterdir()):
            logs_dir = app_dir / "logs"
            if not safe_is_dir(logs_dir):
                continue
            if not (list(logs_dir.glob("php-app.access.log*")) or list(logs_dir.glob("php-app.slow.log*"))):
                continue
            apps[app_dir.name] = logs_dir

    if args.only_app:
        if args.only_app not in apps:
            print(
                f"Application '{args.only_app}' not found with php-app logs. "
                f"Available: {', '.join(sorted(apps)) or 'none'}",
                file=sys.stderr,
            )
            return 1
        apps = {args.only_app: apps[args.only_app]}

    if not apps:
        print("No applications with php-app.access.log / php-app.slow.log found.", file=sys.stderr)
        return 1

    progress_log(args.progress, f"Analyzing {len(apps)} application(s), window: {window_desc}")
    results = []
    for app, logs_dir in apps.items():
        res = analyze_app(app, logs_dir, args, time_start, time_end, args.progress)
        if res:
            results.append(res)

    out = []
    out.append("PHP-FPM Performance Summary (php-app.access.log + php-app.slow.log)")
    out.append(f"Generated: {now_utc_iso()}")
    out.append(f"Roots scanned: {', '.join(str(r) for r in roots)}")
    out.append(f"Time window: {window_desc}")
    if filters_desc:
        out.append(f"Filters: {filters_desc}")
    out.append("")
    for res in results:
        out.extend(render_app_report(res, filters_desc))

    report = "\n".join(out) + "\n"
    payload = {
        "generated_at": now_utc_iso(),
        "roots_scanned": [str(r) for r in roots],
        "time_window": window_desc,
        "filters": {"method": args.method, "status": args.status, "request_type": args.request_type},
        "applications": results,
    }
    Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    Path(args.output_txt).write_text(report, encoding="utf-8")
    print(report)
    progress_log(args.progress, f"Wrote {args.output_json} and {args.output_txt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
