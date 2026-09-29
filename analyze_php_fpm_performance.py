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

Performance: logs are aggregated in a single streaming pass (running sums,
bounded top-N heaps, per-minute buckets) so memory stays flat and multi-day
runs scale linearly with line count. The previous implementation is kept as
analyze_php_fpm_performance_OG.py.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from array import array
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from heapq import heappush, heapreplace
from pathlib import Path

MONTH_NUM = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# 150.228.25.72 - [29/Sep/2026:08:56:33 +0000] "GET /x/index.php?id=1" 200 0 - 24747 16153 0.175 27525120 62.75% 28.52% "/x/view.json?id=1"
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+'
    r'\[(?P<ts>(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s*(?P<tz>[+-]\d{4})?)\]\s+'
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


# --- parsing (single streaming pass, constant memory) --------------------------

def stream_access_logs(files, time_start, time_end, methods, types, statuses, status_classes, top_n):
    """Aggregate access-log lines in one pass without retaining per-request records.

    Returns (agg, stats). Heap items are (sort_key, seq, record_tuple) where
    record_tuple = (ts, method, status, duration, memory, rtype, uri, script).
    """
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
    agg = {
        "in_window": 0,
        "kept": 0,
        "mem_sum": 0.0,
        "mem_max": -1.0,
        "max_rec": None,
        "dur_sum": 0.0,
        "durations": array("d"),
        "mem_heap": [],
        "dur_heap": [],
        "pages": {},          # path -> [hits, dur_sum, dur_max, mem_sum, mem_max]
        "types": Counter(),
        "methods": Counter(),
        "statuses": Counter(),
        "minutes": {},        # minute datetime -> [count, mem_sum, mem_max, dur_sum, dur_max]
        "kept_ts_min": None,
        "kept_ts_max": None,
    }
    ts_cache: dict = {}
    type_cache: dict = {}
    mem_heap = agg["mem_heap"]
    dur_heap = agg["dur_heap"]
    pages = agg["pages"]
    minutes = agg["minutes"]
    durations = agg["durations"]
    c_types, c_methods, c_statuses = agg["types"], agg["methods"], agg["statuses"]
    filter_status = bool(statuses or status_classes)
    flex_first = False
    strict_fail_streak = 0

    def cached_ts(key, year, mon, day, hh, mi, ss, tz):
        pair = ts_cache.get(key)
        if pair is not None:
            return pair
        ts = make_ts(year, mon, day, hh, mi, ss, tz)
        if ts is None:
            return None
        if len(ts_cache) > 400000:
            ts_cache.clear()
        pair = (ts, ts.replace(second=0))
        ts_cache[key] = pair
        return pair

    def parse_strict(line):
        m = ACCESS_RE.match(line)
        if m is None:
            return None
        pair = cached_ts(m.group("ts"), m.group("year"), m.group("mon"), m.group("day"),
                         m.group("hh"), m.group("mm"), m.group("ss"), m.group("tz"))
        if pair is None:
            return None
        script = m.group("script")
        return (pair, m.group("method"), script, m.group("status"),
                float(m.group("duration")), int(m.group("memory")),
                m.group("uri") or script)

    def parse_flex(line):
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
        pair = cached_ts(tsm.group(0), year, mon, day, hh, mi, ss, tz)
        if pair is None:
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
        pct_idx = [i for i, t in enumerate(tokens) if t.endswith("%")]
        if pct_idx and pct_idx[0] >= 2:
            i = pct_idx[0]
            try:
                duration = float(tokens[i - 2])
                memory = int(float(tokens[i - 1]))
            except ValueError:
                duration = memory = None
        if duration is None or memory is None:
            floats = [t for t in tokens if FLOAT_TOKEN_RE.fullmatch(t)]
            ints = [t for t in tokens if INT_TOKEN_RE.fullmatch(t)]
            if floats and duration is None:
                duration = float(floats[-1])
            if ints and memory is None:
                memory = int(ints[-1])
        if duration is None or memory is None:
            return None

        uri = script
        if len(qspans) > 1:
            last_q = qspans[-1].group(0)[1:-1]
            if last_q.startswith("/"):
                uri = last_q
        return (pair, method, script, status, duration, memory, uri)

    for f in files:
        for line in iter_log_lines(f):
            if not line.strip():
                continue
            stats["lines_read"] += 1
            if flex_first:
                rec = parse_flex(line)
                if rec is not None:
                    stats["parsed_flex_format"] += 1
                else:
                    rec = parse_strict(line)
            else:
                rec = parse_strict(line)
                if rec is None:
                    rec = parse_flex(line)
                    if rec is not None:
                        stats["parsed_flex_format"] += 1
                        strict_fail_streak += 1
                        if strict_fail_streak >= 200:
                            # This log clearly uses a non-standard format; stop
                            # paying for a failing strict match on every line.
                            flex_first = True
                else:
                    strict_fail_streak = 0
            if rec is None:
                stats["unparsed"] += 1
                if len(stats["unparsed_samples"]) < 3:
                    stats["unparsed_samples"].append(line[:220])
                continue
            stats["parsed"] += 1
            (ts, minute_ts), method, script, status, duration, memory, uri = rec
            if stats["ts_min"] is None or ts < stats["ts_min"]:
                stats["ts_min"] = ts
            if stats["ts_max"] is None or ts > stats["ts_max"]:
                stats["ts_max"] = ts
            if not in_time_window(ts, time_start, time_end):
                stats["out_of_window"] += 1
                continue
            agg["in_window"] += 1

            if methods and method not in methods:
                continue
            rtype = type_cache.get(uri)
            if rtype is None:
                if len(type_cache) > 200000:
                    type_cache.clear()
                rtype = classify_request(uri)
                type_cache[uri] = rtype
            if types and rtype not in types:
                continue
            if filter_status and status not in statuses and status[0] not in status_classes:
                continue

            seq = agg["kept"] = agg["kept"] + 1
            agg["mem_sum"] += memory
            if memory > agg["mem_max"]:
                agg["mem_max"] = memory
                agg["max_rec"] = (ts, method, status, uri, memory)
            agg["dur_sum"] += duration
            durations.append(duration)
            if agg["kept_ts_min"] is None or ts < agg["kept_ts_min"]:
                agg["kept_ts_min"] = ts
            if agg["kept_ts_max"] is None or ts > agg["kept_ts_max"]:
                agg["kept_ts_max"] = ts

            # Heap entries carry -seq so that, among equal keys, the LATEST
            # arrival sits at the root and is evicted first — reproducing the
            # stable "keep earliest ties" behaviour of a full descending sort.
            rec_t = None
            if len(mem_heap) < top_n:
                rec_t = (ts, method, status, duration, memory, rtype, uri, script)
                heappush(mem_heap, (memory, -seq, rec_t))
            elif memory > mem_heap[0][0]:
                rec_t = (ts, method, status, duration, memory, rtype, uri, script)
                heapreplace(mem_heap, (memory, -seq, rec_t))
            if len(dur_heap) < top_n:
                if rec_t is None:
                    rec_t = (ts, method, status, duration, memory, rtype, uri, script)
                heappush(dur_heap, (duration, -seq, rec_t))
            elif duration > dur_heap[0][0]:
                if rec_t is None:
                    rec_t = (ts, method, status, duration, memory, rtype, uri, script)
                heapreplace(dur_heap, (duration, -seq, rec_t))

            page = uri.split("?", 1)[0]
            p = pages.get(page)
            if p is None:
                pages[page] = [1, duration, duration, memory, memory]
            else:
                p[0] += 1
                p[1] += duration
                if duration > p[2]:
                    p[2] = duration
                p[3] += memory
                if memory > p[4]:
                    p[4] = memory

            c_types[rtype] += 1
            c_methods[method] += 1
            c_statuses[status] += 1

            b = minutes.get(minute_ts)
            if b is None:
                minutes[minute_ts] = [1, float(memory), float(memory), duration, duration]
            else:
                b[0] += 1
                b[1] += memory
                if memory > b[2]:
                    b[2] = memory
                b[3] += duration
                if duration > b[4]:
                    b[4] = duration

    return agg, stats


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


def slow_entries_by_basename(slow_entries):
    by_basename = defaultdict(list)
    for e in slow_entries:
        if e["ts"] is None:
            continue
        base = Path(e["script"]).name if e["script"] else ""
        by_basename[base].append(e)
    return by_basename


def find_slow_function(ts, duration, script, by_basename) -> str:
    """Slow-log function executing during [ts, ts+duration+2s] for the same script.

    Only called for the top-N slowest transactions, so this stays O(top_n x entries)
    instead of O(all_requests x entries)."""
    base = Path(script.split("?", 1)[0]).name
    best = None
    end = ts + timedelta(seconds=duration + 2)
    for e in by_basename.get(base, ()):
        if ts <= e["ts"] <= end:
            if best is None or (e["ts"] - ts) < (best["ts"] - ts):
                best = e
    if best is not None:
        frame = best.get("app_frame") or best.get("top_frame")
        if frame:
            return f"{frame['function']}() {short_location(frame['file'], frame['line'])}"
    return ""


# --- analysis -----------------------------------------------------------------

def pick_bucket_minutes(span_seconds, forced: str) -> int:
    if forced == "minute":
        return 1
    if forced == "10min":
        return 10
    if forced == "hour":
        return 60
    if span_seconds is None:
        return 60
    if span_seconds <= 2 * 3600:
        return 1
    if span_seconds <= 12 * 3600:
        return 10
    return 60


def build_memory_timeseries(minutes, bucket_minutes: int):
    """Re-bucket the streamed per-minute aggregates into the display bucket size."""
    buckets = {}
    for mts, (count, mem_sum, mem_max, dur_sum, dur_max) in minutes.items():
        if bucket_minutes >= 60:
            key = mts.replace(minute=0)
        elif bucket_minutes > 1:
            key = mts.replace(minute=(mts.minute // bucket_minutes) * bucket_minutes)
        else:
            key = mts
        b = buckets.get(key)
        if b is None:
            buckets[key] = [count, mem_sum, mem_max, dur_sum, dur_max]
        else:
            b[0] += count
            b[1] += mem_sum
            if mem_max > b[2]:
                b[2] = mem_max
            b[3] += dur_sum
            if dur_max > b[4]:
                b[4] = dur_max

    rows = []
    for ts in sorted(buckets):
        count, mem_sum, mem_max, dur_sum, dur_max = buckets[ts]
        rows.append(
            {
                "bucket": ts.strftime("%d/%b/%Y %H:%M"),
                "requests": count,
                "avg_memory_mb": round(mb(mem_sum / count), 2),
                "max_memory_mb": round(mb(mem_max), 2),
                "avg_duration_s": round(dur_sum / count, 3),
                "max_duration_s": round(dur_max, 3),
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

    # Interactive filters (applied inline during the streaming pass).
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

    progress_log(progress, f"[{app}] parsing {len(access_files)} access + {len(slow_files)} slow log files")
    agg, access_stats = stream_access_logs(
        access_files, time_start, time_end, methods, types, statuses, status_classes, args.top
    )
    slow_entries = parse_slow_logs(slow_files, time_start, time_end)

    last_activity = None
    for f in access_files + [f for f, _ in access_skipped]:
        try:
            mt = f.stat().st_mtime
        except OSError:
            continue
        if last_activity is None or mt > last_activity:
            last_activity = mt
    last_activity_s = (
        datetime.fromtimestamp(last_activity, timezone.utc).strftime("%d/%b/%Y %H:%M")
        if last_activity else None
    )

    result = {
        "app": app,
        "logs_dir": str(logs_dir),
        "access_log_files": [f.name for f in access_files],
        "access_log_files_detail": [file_meta(f) for f in access_files],
        "access_log_files_skipped": [f"{f.name}: {reason}" for f, reason in access_skipped],
        "slow_log_files": [f.name for f in slow_files],
        "slow_log_files_skipped": [f"{f.name}: {reason}" for f, reason in slow_skipped],
        "access_log_last_activity": last_activity_s,
        "requests_parsed_total": agg["in_window"],
        "requests_after_filters": agg["kept"],
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

    if agg["kept"]:
        n = agg["kept"]
        durations = agg["durations"]
        durations = sorted(durations)
        p95 = durations[int(len(durations) * 0.95) - 1] if len(durations) >= 2 else durations[-1]
        max_ts, max_method, max_status, max_uri, max_mem = agg["max_rec"]
        result["memory_overview"] = {
            "avg_peak_memory_mb": round(mb(agg["mem_sum"] / n), 2),
            "max_peak_memory_mb": round(mb(agg["mem_max"]), 2),
            "max_memory_request": {
                "time": max_ts.strftime("%d/%b/%Y %H:%M:%S"),
                "method": max_method,
                "status": max_status,
                "uri": max_uri,
                "memory_mb": round(mb(max_mem), 2),
            },
            "avg_duration_s": round(agg["dur_sum"] / n, 3),
            "p95_duration_s": round(p95, 3),
        }

        # Heap items: (sort_key, -seq, (ts, method, status, duration, memory, rtype, uri, script)).
        # Sorting by (-key, -(-seq)) reproduces a stable descending sort (ties in arrival order).
        def req_row(rec, slow_by_base=None):
            ts, method, status, duration, memory, rtype, uri, script = rec
            row = {
                "time": ts.strftime("%d/%b/%Y %H:%M:%S"),
                "method": method,
                "status": status,
                "duration_s": round(duration, 3),
                "memory_mb": round(mb(memory), 2),
                "type": rtype,
                "uri": uri,
            }
            if slow_by_base is not None:
                row["slow_function"] = find_slow_function(ts, duration, script, slow_by_base)
            return row

        result["top_memory_requests"] = [
            req_row(item[2]) for item in sorted(agg["mem_heap"], key=lambda t: (-t[0], -t[1]))
        ]
        slow_by_base = slow_entries_by_basename(slow_entries)
        result["slowest_requests"] = [
            req_row(item[2], slow_by_base=slow_by_base)
            for item in sorted(agg["dur_heap"], key=lambda t: (-t[0], -t[1]))
        ]

        pages_agg = [
            {
                "page": k,
                "hits": hits,
                "avg_duration_s": round(dur_sum / hits, 3),
                "max_duration_s": round(dur_max, 3),
                "avg_memory_mb": round(mb(mem_sum / hits), 2),
                "max_memory_mb": round(mb(mem_max), 2),
            }
            for k, (hits, dur_sum, dur_max, mem_sum, mem_max) in agg["pages"].items()
        ]
        pages_agg.sort(key=lambda x: x["avg_duration_s"], reverse=True)
        result["slowest_pages_aggregated"] = pages_agg[: args.top]

        result["requests_by_type"] = agg["types"].most_common()
        result["requests_by_method"] = agg["methods"].most_common()
        result["requests_by_status"] = sorted(agg["statuses"].items())

        span = None
        if agg["kept_ts_min"] is not None and agg["kept_ts_max"] is not None:
            span = (agg["kept_ts_max"] - agg["kept_ts_min"]).total_seconds()
        bucket_minutes = pick_bucket_minutes(span, args.bucket)
        series = build_memory_timeseries(agg["minutes"], bucket_minutes)
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
        st = res.get("access_parse_stats", {})
        have_files = bool(res.get("access_log_files") or res.get("access_log_files_skipped"))
        filtered_out = res["requests_parsed_total"] - res["requests_after_filters"]
        if not have_files:
            out.append("  No php-app.access.log found for this app (FPM access log may be disabled).")
        elif res["requests_parsed_total"] and filtered_out == res["requests_parsed_total"]:
            out.append(
                f"  No traffic matched: all {filtered_out} request(s) in this window were "
                f"excluded by the active filters ({filters_desc})."
            )
        elif st.get("unparsed") and not st.get("parsed"):
            out.append(f"  {st['unparsed']} access-log line(s) did not match any known format.")
            for s in st.get("unparsed_samples", []):
                out.append(f"    Sample line: {s}")
        else:
            out.append("  No traffic observed during this time window.")
            if st.get("log_ts_min"):
                out.append(f"  (access-log activity spans {st['log_ts_min']} -> {st['log_ts_max']} UTC)")
            elif res.get("access_log_last_activity"):
                out.append(f"  (latest access-log activity: {res['access_log_last_activity']} UTC)")
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
