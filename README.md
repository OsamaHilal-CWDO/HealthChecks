# HealthChecks

Utilities for Cloudways traffic analysis and WordPress health reporting.

## Included scripts

- `analyze_cloudways_backend_traffic.py`  
  Geo-enabled backend access log analyzer for Cloudways applications.
- `analyze_cloudways_backend_traffic_nogeo.py`  
  Same analyzer without GeoIP/ASN enrichment (faster).
- `build_cloudways_google_doc_report.py`  
  Builds Google Doc-ready HTML and CSV outputs from traffic + health JSON/log artifacts.

## What the analyzer does

For backend logs under `/home/master/applications/*/logs/backend*.access.log*`, it:

1. Ranks applications by total traffic.
2. Enriches top applications with:
   - top countries
   - top ASN
   - top endpoints
   - top non-browser user agents
   - HTTP status breakdown + error rate
3. Optionally runs health checks for top apps and writes outputs to `/tmp`.

## Quick usage

### Geo-enabled analyzer

```bash
python3 analyze_cloudways_backend_traffic.py \
  --applications-root /home/master/applications \
  --strict-root \
  --all-days \
  --disable-whois-asn \
  --country-dat /usr/share/GeoIP/GeoIP.dat \
  --countryv6-dat /usr/share/GeoIP/GeoIPv6.dat \
  --output-json /tmp/top5_backend_traffic_summary.json \
  --output-txt /tmp/top5_backend_traffic_summary.txt \
  --progress
```

### Build consolidated report

```bash
python3 build_cloudways_google_doc_report.py \
  --traffic-json /tmp/top5_backend_traffic_summary.json \
  --health-source json \
  --output-html /tmp/cloudways_consolidated_report.html \
  --output-csv /tmp/cloudways_observation_notes_template.csv \
  --output-reference-csv /tmp/cloudways_reference_tables.csv
```

## Output files

Common `/tmp` artifacts:

- `/tmp/top5_backend_traffic_summary.json`
- `/tmp/top5_backend_traffic_summary.txt`
- `/tmp/cloudways_consolidated_report.html`
- `/tmp/cloudways_observation_notes_template.csv`
- `/tmp/cloudways_reference_tables.csv`

Health artifacts (if health checks are executed):

- `/tmp/wp_health_report_*.json`
- `/tmp/wp_health_runs/*.log`

## Notes

- Use `--strict-root` to avoid scanning unintended `/home/*` paths.
- `--health-source` supports `log`, `json`, or `merge` in report builder.
- For large multi-server runs, push report artifacts to a central API and compile there.
