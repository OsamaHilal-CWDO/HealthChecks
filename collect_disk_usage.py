#!/usr/bin/env python3
"""
Collect per-application disk usage on a Cloudways server.

For every app under the applications root that has a public_html directory,
reports the total size plus the largest sub-paths (depth-limited), sorted
largest-first — the structured equivalent of:

    du -s /home/master/applications/*/public_html | sort -rn
    du -h --max-depth=3 <app>/public_html | sort -rh | head -10

Outputs JSON (for the compile pipeline) and CSV, and prints a human-readable
summary to stdout.

Usage:
    python3 collect_disk_usage.py
    python3 collect_disk_usage.py --applications-root /home/master/applications \
        --output-json /tmp/cloudways_disk_usage.json \
        --output-csv /tmp/cloudways_disk_usage.csv \
        --max-depth 3 --top 10
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def human_size(n: float) -> str:
    if n < 1024:
        return f"{int(n)}B"
    for unit in ("K", "M", "G", "T", "P"):
        n /= 1024.0
        if n < 1024 or unit == "P":
            return f"{n:.1f}{unit}"
    return f"{n:.1f}P"


def du_bytes_summary(path: Path, timeout: int) -> int | None:
    """Total size of a tree in bytes (du -sb)."""
    try:
        proc = subprocess.run(
            ["du", "-sb", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        first = (proc.stdout or "").split("\t", 1)[0].strip()
        return int(first)
    except Exception:
        return None


def du_depth_breakdown(path: Path, max_depth: int, timeout: int):
    """[(bytes, subpath)] for directories under path, excluding path itself."""
    rows = []
    try:
        proc = subprocess.run(
            ["du", "-b", f"--max-depth={max_depth}", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        root = str(path).rstrip("/")
        for line in (proc.stdout or "").splitlines():
            if "\t" not in line:
                continue
            size_s, p = line.split("\t", 1)
            p = p.rstrip("/")
            if p == root:
                continue
            try:
                rows.append((int(size_s), p[len(root) + 1 :] if p.startswith(root + "/") else p))
            except ValueError:
                continue
    except Exception:
        pass
    rows.sort(key=lambda r: r[0], reverse=True)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect per-app public_html disk usage")
    parser.add_argument("--applications-root", default="/home/master/applications")
    parser.add_argument("--output-json", default="/tmp/cloudways_disk_usage.json")
    parser.add_argument("--output-csv", default="/tmp/cloudways_disk_usage.csv")
    parser.add_argument("--max-depth", type=int, default=3, help="du --max-depth for the per-app breakdown")
    parser.add_argument("--top", type=int, default=10, help="Largest sub-paths to keep per app")
    parser.add_argument("--du-timeout", type=int, default=1800, help="Timeout in seconds per du invocation")
    args = parser.parse_args()

    root = Path(args.applications_root)
    if not root.is_dir():
        payload = {
            "generated_at": now_utc_iso(),
            "error": "Applications root not found",
            "applications_root": str(root),
        }
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Applications root not found: {root}", file=sys.stderr)
        return 1

    apps = []
    try:
        candidates = sorted(root.iterdir())
    except OSError as e:
        print(f"Cannot list {root}: {e}", file=sys.stderr)
        return 1

    for app_dir in candidates:
        public_html = app_dir / "public_html"
        if not app_dir.is_dir() or not public_html.is_dir():
            continue
        total = du_bytes_summary(public_html, args.du_timeout)
        if total is None:
            continue
        breakdown = du_depth_breakdown(public_html, args.max_depth, args.du_timeout)[: args.top]
        apps.append(
            {
                "app": app_dir.name,
                "path": str(public_html),
                "total_bytes": total,
                "total_human": human_size(total),
                "top_paths": [
                    {"path": p, "bytes": b, "human": human_size(b)} for b, p in breakdown
                ],
            }
        )

    apps.sort(key=lambda a: a["total_bytes"], reverse=True)
    grand_total = sum(a["total_bytes"] for a in apps)

    payload = {
        "generated_at": now_utc_iso(),
        "applications_root": str(root),
        "max_depth": args.max_depth,
        "applications_found": len(apps),
        "total_bytes": grand_total,
        "total_human": human_size(grand_total),
        "applications": apps,
    }
    Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with open(args.output_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["App", "Path", "Bytes", "Human"])
        for a in apps:
            w.writerow([a["app"], "TOTAL (public_html)", a["total_bytes"], a["total_human"]])
            for tp in a["top_paths"]:
                w.writerow([a["app"], tp["path"], tp["bytes"], tp["human"]])

    print(f"Disk usage under {root} — {human_size(grand_total)} across {len(apps)} applications")
    print()
    for a in apps:
        print(f"=== {a['app']} ({a['path']}) — {a['total_human']} ===")
        for tp in a["top_paths"]:
            print(f"  {tp['human']:>8}  {tp['path']}")
        print()
    print(f"JSON: {args.output_json}")
    print(f"CSV:  {args.output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
