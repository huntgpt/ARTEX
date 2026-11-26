---
name: trufflehog-secrets
description: "Use TruffleHog in an authorized ARTEX task to find secrets in public repositories, a checked-out repository, or task files; route JSONL directly into the encrypted task secret vault without exposing plaintext to the model, logs, facts, or reports."
---

# TruffleHog secret discovery

TruffleHog is installed at `/usr/local/bin/trufflehog`. Use it only for a task
whose rules explicitly authorize the source. Keep output inside the current
intent working directory and never read, print, summarize, grep, `cat`, or pass
the JSONL back to the model: it contains the real secret values.

## Modes

- Passive detection without provider validation:
  `trufflehog git file://$PWD/repository --json --no-verification > trufflehog.jsonl`
- Authorized validation: omit `--no-verification`. This contacts the relevant
  provider and may create authentication/audit events; use it only when the
  rules authorize credential validation.
- Files already collected into the intent directory:
  `trufflehog filesystem collected --json --no-verification > trufflehog.jsonl`

Do not put a token in a command line. For private GitHub sources, use the task's
credential mechanism or an already authenticated checkout. Never scan the
server's home directory, ARTEX data directory, OAuth profile directory, or an
unbounded filesystem path.

## Ingestion

Immediately call `ingest_scan_output` with:

```json
{"format":"trufflehog-jsonl","path":"trufflehog.jsonl"}
```

ARTEX stores `Raw` and `RawV2` encrypted in the task vault. Model-visible facts
contain only detector and location. The Credentials tab lists a value with the
last 30 percent replaced by stars; revealing the real value requires a reason
and writes an audit row. Do not copy the plaintext into a fact, finding, chat,
activity, report, or tool argument. Use the explicit audited reveal/validation
flow when the engagement requires the credential.

Treat a detector match as a lead. Verification state comes from TruffleHog; a
reportable finding still needs source ownership, exposure, impact and evidence
that does not disclose the complete value.
