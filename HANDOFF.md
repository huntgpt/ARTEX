# ARTEX Red-Team Platform Handoff

Snapshot: 2026-11-27 14:20 Asia/Bangkok

Repository: `huntgpt/ARTEX`

Branch: `feat/ad-red-team-foundation`

Code baseline before this handoff: `b8980388326ad14514a290328505a44c364c38c1`

This document is the durable, non-secret handoff for the next operator/agent. Live assessment data remains in ARTEX/PostgreSQL and in the ignored task evidence directories. Do not copy OAuth tokens, passwords, secret values, JWTs, private keys, or raw credential-bearing artifacts into Git.

## Start here

- UI: `http://127.0.0.1:3000`
- API: `http://127.0.0.1:18787/api`
- External assessment: Task `325`, `http://127.0.0.1:3000/function/tasks/detail?id=325`
- Internal assume-breach assessment: Task `326`, `http://127.0.0.1:3000/function/tasks/detail?id=326`
- Never resume or inherit old Task `2`. The user explicitly requires a fresh assessment.
- The exact local-only operational snapshot is in `data-range-poc/HANDOFF.private.md` (ignored by Git, mode `0600`).

## Runtime topology

- Frontend: host Next.js development server on `127.0.0.1:3000`.
- Backend: host `go run ./cmd/artex -addr 127.0.0.1:18787 -proxy 127.0.0.1:18788 -data .../data-range-poc`.
- Database: Docker Desktop container `range-artex-poc-postgres-1`, PostgreSQL 16, host port `5434`, persistent volume `range-artex-poc_pgdata`.
- Active Docker context is `desktop-linux` (Docker Desktop), not OrbStack.
- Evidence directories are ignored by Git:
  - `data-range-poc/tasks/325` (about 350 MiB at snapshot)
  - `data-range-poc/tasks/326` (about 435 MiB at snapshot)
- The database volume and evidence directories are the authoritative persistent state. No second plaintext database dump was created because the live database contains restricted credentials/secrets.

Generate a short-lived API token without printing it:

```sh
ARTEX_TOKEN=$(node -e 'const fs=require("fs"),c=require("crypto");const b=x=>Buffer.from(JSON.stringify(x)).toString("base64url");const n=Math.floor(Date.now()/1000);const body=b({alg:"HS256",typ:"JWT"})+"."+b({pwd:2,sub:"ARTEX",exp:n+3600,iat:n});const key=fs.readFileSync("keys-range-poc/jwt.key","utf8").trim();process.stdout.write(body+"."+c.createHmac("sha256",key).update(body).digest("base64url"))')
```

Never log or commit the generated token or `keys-range-poc/`.

## Assessment state at snapshot

| Task | ARTEX state | Intents | Findings | Coverage ledger | Immediate interpretation |
|---|---|---:|---:|---:|---|
| `325` External | `done`, completed 14:05 | 40 done | 8 (3 high, 4 medium, 1 low) | 19/441 (4.31%) | Goal closed, but coverage is too low to claim exhaustive external coverage. Audit the disposition ledger before accepting completion. |
| `326` Internal | `running`, 5 in flight | 70 done, 5 running, 1 exhausted | 7 (1 high, 6 medium) | 7/180 (3.89%) | Work is live. Do not pause or recreate. Monitor the five workers and replan when slots free. |

Task `325` currently has 151 scope rows (1 root domain, 145 subdomains, 5 IPs). Its report/finding lifecycle completed, including independent retest and final report intent, but the workflow-phase ledger still reports 28 phases as pending and only passive discovery as ready. Treat this as a platform state-reconciliation defect and validate the actual per-asset/route disposition ledger.

Task `326` currently has 138 scope rows (1 internal root domain, 1 CIDR, 129 IPs, 7 subdomains). One credential exists in the task Credential Vault and the required internal vantage is present; no password is stored in this handoff. Five workers were actively covering:

1. EFSRPC coercion-prerequisite finding/report lifecycle without triggering authentication.
2. Password-not-required principal ACL/effective-rights resolution.
3. Machine-account quota/domain-join/RBCD prerequisites through read-only directory checks.
4. Low-impact host/service discovery on the authorized user segment.
5. Domain-wide NTLM hardening and relay-prerequisite posture.

Supervisor round `27` started at 14:19 and had not completed at snapshot. The internal AD API still returned zero graph entities, zero graph edges, and zero collection runs even though AD-derived facts/findings exist. This is a critical ingestion/lineage gap: do not claim BloodHound/AD graph completion until collection provenance and graph data are present in the AD APIs.

## LLM topology

- Project supervision for both fresh tasks is `single` Codex profile `4`, model `gpt-5.6-sol`, checkpoint policy `strategic`.
- Runtime Main Agent/Planner/Worker currently resolve to Claude profile `3`, `claude-cli`, model `claude-opus-4-8`.
- Task chain is `[4, 3]` with rotation enabled so Codex and Claude remain available.
- Duo-lead `every_round` was tried and removed because supervisor/arbiter latency reduced throughput.
- Codex CLI calls have intermittently hung or returned neither text nor an ARTEX tool call. The branch contains timeout/CLI-resolution fixes, but continue monitoring for stuck `codex exec` children and use failover rather than allowing the scheduler to stall.

## Non-negotiable assessment/evidence contract

- Use only fresh evidence produced by Task `325` or Task `326`; do not inherit Task `2`.
- Work through ARTEX. If a capability is missing, implement it in ARTEX or perform the senior-operator step while preserving provenance back into ARTEX.
- Parallelize independent source families; enforce dependencies for attack chains.
- Evidence must be real: raw executed command output and actual browser/application screenshots from the run, with UTC timestamp, tool version, provenance, and SHA-256. No mockups, generated screenshots, or reconstructed evidence.
- Put relevant screenshots inline at the exact discussion point in every Detailed Report. Do not rely on a detached “Verified visual evidence” section.
- Every material finding requires a Detailed Report and an independent retest/disposition.
- Publicly committed secrets remain findings even if current validity is unknown. Keep full values only in the restricted vault/evidence store. Customer-facing reports mask the final approximately 30% with `*`.
- Internal coverage must include evidence-supported paths across core AD/Kerberos, BloodHound collection lifecycle, AD CS, SCCM/MECM, MSSQL, Exchange/ADFS/hybrid identity, relay/coercion prerequisites, GPO/ACL abuse, delegation, shadow credentials, LAPS/gMSA/DPAPI, trusts, privileged sessions, lateral movement, and privilege escalation.
- Stop and report before actions that delete/modify customer data, change production accounts/permissions, establish persistence, induce authentication where operationally risky, relay credentials, or materially affect availability.

## Known gaps and caveats

1. External Task `325` is marked complete despite only 4.31% aggregate coverage. Completion means the run ended normally, not that untested surfaces are clean.
2. The workflow-phase ledger is stale/inconsistent with actual intents and findings on both fresh tasks.
3. Internal Task `326` has AD-derived results but no AD graph entities/edges or registered AD collection runs.
4. One internal intent is `exhausted`; inspect it and create a materially different retry only if its objective remains uncovered.
5. Asset totals returned by the generic stats endpoint were identical for both tasks; use task scope/coverage endpoints and evidence lineage rather than assuming generic totals are task-isolated.
6. Agent isolation is degraded in development mode: host shell/file tools run with the server identity. Production service must fail closed into isolated workers before customer use.
7. Tool availability is incomplete. Known missing binaries include `naabu`, `gau`, `waybackurls`, `bbot`, `dirsearch`, `gobuster`, OpenDoor, BloodHound CE collector, several Impacket entry points, `coercer`, `petitpotam`, `bloodyAD`, `enum4linux-ng`, `responder`, `mitm6`, `roadrecon`, and `sccmhunter`. Do not silently claim their coverage; install/use a controlled Linux worker or record a precise gap.

## Continuation checklist

1. Confirm backend, frontend, PostgreSQL, and active Docker context. Do not restart healthy services unless required.
2. Query Task `326` live state, intents, supervisor rounds, coverage, findings, evidence bindings, AD graph, and AD collection runs. The snapshot will age while workers continue.
3. Let the five running internal intents finish. Inspect the exhausted intent and any worker failures. When capacity frees, require the Planner to schedule only uncovered, prerequisite-ready work.
4. Populate and verify the BloodHound-compatible collection lifecycle, collection provenance, freshness, graph entities/edges, and attack-path linkage. The empty AD APIs are not acceptable completion evidence.
5. Reconcile every internal finding with raw artifacts, traffic/evidence bindings, genuine inline screenshot, Detailed Report, and independent retest. Never inflate a prerequisite into a demonstrated exploit chain.
6. Audit External Task `325`: compare its 441-surface denominator to explicit tested/duplicate/out-of-scope/ownership-unverified/blocked/no-defect dispositions. Reopen or run corrective intents if the ledger is not defensible; do not create another fresh task merely to avoid the gap.
7. Repair workflow-phase state reconciliation so Progress reflects actual work, tools, agents, outputs, current blockers, and completion.
8. Run backend, frontend, migration, security-control, and E2E tests after code changes. Preserve unrelated user work.
9. Commit focused changes and push only to `feat/ad-red-team-foundation` after verification. Never commit `data-range-poc`, `.env`, `keys-range-poc`, OAuth material, vault data, or raw secrets.

## Useful read-only API checks

```sh
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" http://127.0.0.1:18787/api/tasks/326
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" 'http://127.0.0.1:18787/api/exploration/intents?task=326'
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" 'http://127.0.0.1:18787/api/exploration/findings?task=326'
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" http://127.0.0.1:18787/api/tasks/326/coverage
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" http://127.0.0.1:18787/api/tasks/326/ad/graph
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" http://127.0.0.1:18787/api/tasks/326/ad/runs
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" 'http://127.0.0.1:18787/api/tasks/326/supervisor/rounds?limit=10'
curl -fsS -H "Authorization: Bearer $ARTEX_TOKEN" http://127.0.0.1:18787/api/tasks/326/llm/resolution
```

Latest baseline commits before this handoff:

- `b898038` report backfill with inline evidence
- `47babc3` canonical artifact-link handling
- `70477ce` safe traffic-row closure before finding merges
- `0a4aad4` lossless duplicate-finding/evidence merge
- `efdbedd` atomic worker probe execution
- `2def112` bounded local CLI provider calls
- `e430864` local-shell interception target handling
- `d117f94` fail-closed production isolation
