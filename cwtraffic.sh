#!/usr/bin/env bash
# cwtraffic: run the Cloudways backend traffic analyzer, then send the JSON
# summary to a DigitalOcean Gradient endpoint and print its text analysis.
#
# Setup: paste this function into ~/.bashrc / ~/.bash_aliases (or `source` this
# file from there), then set GRADIENT_URL and GRADIENT_API_KEY below.
#
# Usage (all arguments pass straight through to the analyzer):
#   cwtraffic --days 1
#   cwtraffic --hour 12
#   cwtraffic --only-app abcdefghij --hour 6
#   cwtraffic --from-time 20-07-2026:00 --to-time 20-07-2026:23

cwtraffic() {
    # ------------------------- configure these two -------------------------
    local GRADIENT_URL="https://YOUR-AGENT-ID.agents.do-ai.run"
    local GRADIENT_API_KEY="YOUR_API_KEY"
    # Optional: only needed for the serverless inference endpoint
    # (https://inference.do-ai.run/v1/chat/completions). Leave empty for agents.
    local GRADIENT_MODEL=""
    # ------------------------------------------------------------------------

    local script_url="https://raw.githubusercontent.com/OsamaHilal-CWDO/HealthChecks/Custom-New-Tooling/analyze_cloudways_backend_traffic.py"
    local json_out="/tmp/top5_backend_traffic_summary.json"

    echo "[cwtraffic] running traffic analysis..." >&2
    curl -sS "$script_url" | python3 - --skip-health --output-json "$json_out" "$@" > /dev/null || {
        echo "[cwtraffic] analysis failed" >&2
        return 1
    }

    echo "[cwtraffic] sending summary to Gradient..." >&2
    GRADIENT_URL="$GRADIENT_URL" GRADIENT_API_KEY="$GRADIENT_API_KEY" GRADIENT_MODEL="$GRADIENT_MODEL" \
    python3 - "$json_out" <<'PYEOF'
import json
import os
import sys
import urllib.request

json_path = sys.argv[1]
url = os.environ["GRADIENT_URL"].rstrip("/")
key = os.environ["GRADIENT_API_KEY"]
model = os.environ.get("GRADIENT_MODEL", "").strip()

with open(json_path, encoding="utf-8") as f:
    data = json.load(f)


def cap_lists(obj, limit=200):
    """Keep the payload inside the model's context window: very long arrays
    (e.g. months of breaches_per_hour) are trimmed to their most recent items."""
    if isinstance(obj, dict):
        return {k: cap_lists(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        items = obj[-limit:] if len(obj) > limit else obj
        return [cap_lists(x, limit) for x in items]
    return obj


data = cap_lists(data)

prompt = (
    "You are a senior sysadmin reviewing a Cloudways/WooCommerce server. Below is a JSON "
    "traffic and health summary (per-app traffic, IP subnets, Chrome user-agent spoofing "
    "indicators, query strings, hourly traffic, PHP-FPM max_children breaches, OOM kills).\n"
    "Write a concise plain-text report covering: 1) overall traffic health, 2) suspicious or "
    "bot traffic and likely user-agent spoofing, 3) FPM/OOM stability problems and which app "
    "is responsible, 4) concrete recommendations. Quote figures from the data.\n\n"
    + json.dumps(data, separators=(",", ":"))
)

# Gradient agents expose <agent-url>/api/v1/chat/completions; if the configured
# URL already points at a chat/completions endpoint, use it as-is.
endpoint = url if url.endswith("/chat/completions") else url + "/api/v1/chat/completions"
payload = {"messages": [{"role": "user", "content": prompt}], "stream": False}
if model:
    payload["model"] = model

req = urllib.request.Request(
    endpoint,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    },
)
try:
    with urllib.request.urlopen(req, timeout=300) as resp:
        body = json.load(resp)
except Exception as e:
    sys.stderr.write(f"[cwtraffic] Gradient request failed: {e}\n")
    sys.exit(1)

try:
    print(body["choices"][0]["message"]["content"])
except (KeyError, IndexError, TypeError):
    # Unexpected response shape: show it raw so nothing is silently lost.
    print(json.dumps(body, indent=2))
PYEOF
}
