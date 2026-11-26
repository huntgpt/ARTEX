---
name: opendoor-recon
description: "Use OpenDoor for authorized HTTP path discovery in ARTEX with conservative rate controls, soft-404 calibration, resumable JSON output, and typed ingestion of accepted URLs while filtered responses remain excluded."
---

# OpenDoor path discovery

OpenDoor is installed at `/usr/local/bin/opendoor`. Run it only after ownership,
scope, DNS, port and HTTP validation have identified the exact in-scope origin.
One origin per intent keeps rate limits, evidence and blockers attributable.

Start with the low-noise profile:

```sh
opendoor --host https://app.example.com \
  --method GET --threads 5 --delay 0.5 --timeout 30 --retries 2 \
  --auto-calibrate --waf-detect --waf-guard \
  --include-status 200-299,301,302,307,308,401,403 \
  --exclude-status 404,429,500-599 \
  --sniff endpoint,skipempty,collation,indexof,file,stacktrace \
  --session-save opendoor-session.json \
  --reports json --reports-dir opendoor-reports
```

Lower threads/increase delay when the program has a tighter limit. Do not add
`shadow`, `openredirect`, bypass, crawl, subdomain, transport or aggressive
features unless that specific behavior is authorized and planned as a separate
intent. Stop and record a blocker when WAF guard, repeated 429s or instability
shows the target cannot safely sustain the profile.

Find the generated `.json` filename by listing filenames only, then call
`ingest_scan_output` with `format: "opendoor-json"` and its relative path.
ARTEX imports only `report_items` (or the accepted `items` fallback) as URL
assets/facts. `filtered_items`, including calibrated soft-404/catch-all results,
are counted as skipped and never become assets or findings.

Path discovery is not a vulnerability by itself. Validate interesting paths in
a follow-up intent with the task's HTTP evidence controls before reporting.
