# Production container deployment and agent isolation

Use `docker-compose.production.yml` for a customer environment. The ordinary
`docker-compose.yml` remains the developer path: it has source bind mounts and is
not the reviewed production boundary. Native macOS and a non-root native Linux
service cannot apply ARTEX's separate executor UID and will correctly show the red
**AGENT ISOLATION IS DEGRADED** banner.

The production topology keeps the ARTEX control plane as root inside its container
and explicitly starts every agent shell, custom tool, file tool and stdio MCP child
as numeric UID/GID `10001:10001`. Startup is fail-closed: if the executor can read
the signing/encryption keys, server environment, configuration or PostgreSQL
without the server password, ARTEX exits instead of serving traffic.

## Start and prove the boundary

Use a deployment-specific environment file, not an interactive shell profile:

```sh
install -m 600 /dev/null .env.production
printf '%s\n' 'POSTGRES_PASSWORD=replace-with-a-long-random-value' >>.env.production
docker compose --env-file .env.production -f docker-compose.production.yml up -d --build
python3 scripts/verify-production-isolation.py --env-file .env.production
```

The last command is required acceptance evidence. It checks the resolved Compose
configuration, runtime container controls, readiness, the fail-closed startup
self-test record, and a fresh process launched through the executor drop shim. A
successful result ends with:

```text
production ARTEX isolation: PASS (fail-closed startup + live executor probe)
```

CI or review can validate the deployment contract without starting containers:

```sh
python3 scripts/verify-production-isolation.py --config-only
```

Do not add `-dev-insecure-no-isolation`, change the service to a non-root user, or
remove `SETUID`/`SETGID`. Those changes do not make the server safer: they prevent
the root control plane from placing untrusted agent children under a different UID.
The explicit `-exec-uid` and `-exec-gid` flags make such a change fail at startup
rather than silently falling back to the server identity.

## What is isolated

- `/app/keys` and the immutable `/app/skills` tree are root-owned and unavailable
  to UID 10001. Data and key persistence use named volumes, so an agent does not see
  the source checkout or an operator home directory.
- PostgreSQL has no host port, is attached only to an internal control network and
  requires SCRAM for container-to-container TCP. ARTEX removes its database and LLM
  secrets from the server environment before agent work begins; the startup probe
  confirms the executor cannot connect without the removed database password.
- Both containers use a read-only root filesystem, `no-new-privileges`, an explicit
  capability allowlist and bounded tmpfs storage. ARTEX has no `SYS_ADMIN`,
  `NET_ADMIN`, `SYS_PTRACE`, raw-socket or mount capability.
- The browser/tool scratch directory `/tmp` must remain executable. Several scanners
  and browser components run temporary executables. It is bounded, non-persistent,
  `nosuid` and `nodev`; evidence must be written to the ARTEX data volume.

The unprivileged executor still writes its task workspaces and `exec-home` under
`/app/data`; the root data directory itself remains unwritable to it. ARTEX shares
only the per-run directories it creates. Do not replace the named data/key volumes
with a bind mount unless ownership and parent-directory replacement checks have
been reviewed and the live assertion passes.

## LLM credentials and OAuth profiles

Do not mount `~`, `~/.claude`, `~/.codex`, a developer SSH directory or a Docker
socket into the ARTEX container. An entire home mount turns prompt injection into
host-account compromise and defeats the purpose of the production profile.

Prefer API-backed LLM profiles whose secrets are stored by ARTEX. If local
Claude/Codex CLI OAuth is a service requirement, build a dedicated reviewed image
containing the CLI and provision only dedicated per-account profile directories in
root-only named volumes at fixed paths (read-only where the CLI supports it), with
no unrelated credentials. An intentional provider volume requires a corresponding
reviewed verifier update; the stock verifier rejects every host bind mount. Re-run
the live isolation assertion and a provider login test after that review. Never
share the operator's interactive profile with production.

## Network and operational tradeoffs

The database control network is isolated, but the ARTEX service also needs an
egress network to assess authorized targets. Docker cannot distinguish an approved
target from an unapproved one for UID 10001. Enforce the signed scope at an egress
firewall or authenticated proxy, ideally with per-engagement destination and port
allowlists. Publishing the UI beyond loopback also requires a reviewed TLS reverse
proxy, access control and trusted-proxy configuration.

The capability allowlist is deliberately small but not empty. `CHOWN`,
`DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` and `KILL` let the control plane create
protected/shared workspace layouts, drop child credentials, read their results and
cancel them. Removing one can break isolation setup or task cancellation; adding
one expands the blast radius and requires review plus a fresh acceptance run.

Back up all three named volumes (`pgdata`, `artex_data`, `artex_keys`) as one
consistent recovery set. Losing `artex_keys` invalidates sessions and can make
encrypted stored secrets unrecoverable. Keep `.env.production` outside backups that
are readable by ordinary users, and never paste the rendered Compose configuration
or environment file into a ticket because it contains database/LLM credentials.
