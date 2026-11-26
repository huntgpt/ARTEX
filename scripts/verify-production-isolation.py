#!/usr/bin/env python3
"""Assert the hardened Compose contract, then probe a running ARTEX executor.

The unauthenticated /api/health response intentionally hides isolation details.
This check therefore requires both the fail-closed startup success record and a
fresh process dropped through the same binary shim used by agent processes.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_COMPOSE = ROOT / "docker-compose.production.yml"
PASS_LOG = (
    "[isolation] self-test passed: agent processes and file tools run as the "
    "executor and cannot reach the server's secrets"
)


def fail(message: str) -> "NoReturn":
    print(f"production isolation assertion failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(argv: list[str], *, env: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            argv,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as exc:
        fail(f"required executable not found: {argv[0]} ({exc})")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "no diagnostic").strip()
        fail(f"{' '.join(argv)}: {detail}")
    return result.stdout


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def compose_prefix(
    compose_file: pathlib.Path,
    env_file: pathlib.Path | None,
    project_name: str | None,
) -> list[str]:
    prefix = ["docker", "compose"]
    if env_file is not None:
        prefix += ["--env-file", str(env_file)]
    # An unrelated checkout-level COMPOSE_PROJECT_NAME has higher precedence than
    # Compose's top-level `name:` field. Use -p when the operator selected a
    # production project so the live probe cannot silently inspect another stack.
    if project_name:
        prefix += ["--project-name", project_name]
    return prefix + ["-f", str(compose_file)]


def rendered_config(compose_file: pathlib.Path) -> dict:
    # Never consume the operator's .env for the static check and never print the
    # rendered environment. A synthetic password only satisfies Compose expansion.
    env = os.environ.copy()
    env["POSTGRES_PASSWORD"] = "static-isolation-assertion-only"
    output = run(
        [
            "docker",
            "compose",
            "--env-file",
            os.devnull,
            "-f",
            str(compose_file),
            "config",
            "--format",
            "json",
        ],
        env=env,
    )
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        fail(f"docker compose returned invalid config JSON: {exc}")


def assert_static_contract(config: dict) -> None:
    services = config.get("services", {})
    require({"artex", "postgres"} <= services.keys(), "compose must define artex and postgres")
    artex = services["artex"]
    postgres = services["postgres"]

    require(str(artex.get("user")) == "0:0", "artex control plane must explicitly run as 0:0")
    command = [str(value) for value in artex.get("command", [])]
    require("-exec-uid" in command and "10001" in command, "artex must explicitly use -exec-uid 10001")
    require("-exec-gid" in command and "10001" in command, "artex must explicitly use -exec-gid 10001")
    require("-dev-insecure-no-isolation" not in command, "development isolation escape must be absent")
    require(artex.get("read_only") is True, "artex root filesystem must be read-only")
    require("ALL" in set(artex.get("cap_drop", [])), "artex must drop all capabilities first")
    allowed_caps = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "SETGID", "SETUID"}
    actual_caps = set(artex.get("cap_add", []))
    require(actual_caps == allowed_caps, f"artex capability allowlist changed: {sorted(actual_caps)}")
    require(
        "no-new-privileges:true" in set(artex.get("security_opt", [])),
        "artex must enable no-new-privileges",
    )
    require(
        str(artex.get("environment", {}).get("ARTEX_UNTRUSTED_BOUNDARY")) == "1",
        "production must keep the untrusted-output boundary enabled",
    )

    mounts = {volume.get("target"): volume for volume in artex.get("volumes", [])}
    require(
        all(volume.get("type") != "bind" for volume in artex.get("volumes", [])),
        "production artex service must not have host bind mounts",
    )
    for target in ("/app/data", "/app/keys"):
        require(target in mounts, f"missing persistent mount {target}")
        require(mounts[target].get("type") == "volume", f"{target} must be a named volume, not a host bind")
    require("/app/skills" not in mounts, "production skills must remain immutable in the image")

    require(set(artex.get("networks", {})) == {"control", "egress"}, "artex network segmentation changed")
    require(set(postgres.get("networks", {})) == {"control"}, "postgres must be reachable only on control")
    require(not postgres.get("ports"), "postgres must not publish a host port")
    require(postgres.get("read_only") is True, "postgres root filesystem must be read-only")
    require(
        postgres.get("environment", {}).get("POSTGRES_HOST_AUTH_METHOD") == "scram-sha-256",
        "postgres TCP authentication must use SCRAM",
    )
    require(config.get("networks", {}).get("control", {}).get("internal") is True, "control network must be internal")


def assert_live(prefix: list[str]) -> None:
    container_id = run(prefix + ["ps", "--status", "running", "-q", "artex"]).strip()
    require(bool(container_id), "artex container is not running")
    require("\n" not in container_id, "compose returned more than one artex container")

    inspect = json.loads(run(["docker", "inspect", container_id]))[0]
    host = inspect["HostConfig"]
    runtime_config = inspect["Config"]
    require(runtime_config.get("User") == "0:0", "running control plane is not explicitly 0:0")
    runtime_command = [str(value) for value in (runtime_config.get("Cmd") or [])]
    require(
        "-exec-uid" in runtime_command and "-exec-gid" in runtime_command and runtime_command.count("10001") >= 2,
        "running command lacks the explicit 10001:10001 executor identity",
    )
    require("-dev-insecure-no-isolation" not in runtime_command, "running command enables the development escape")
    require(host.get("ReadonlyRootfs") is True, "running container root filesystem is writable")
    require("ALL" in set(host.get("CapDrop") or []), "running container did not drop all capabilities")
    runtime_caps = {
        str(cap)[4:] if str(cap).startswith("CAP_") else str(cap)
        for cap in (host.get("CapAdd") or [])
    }
    require(
        runtime_caps == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "SETGID", "SETUID"},
        "running container capability allowlist differs from the reviewed deployment",
    )
    require(
        "no-new-privileges:true" in set(host.get("SecurityOpt") or []),
        "running container lacks no-new-privileges",
    )
    bind_targets = [mount.get("Destination") for mount in inspect.get("Mounts", []) if mount.get("Type") == "bind"]
    require(not bind_targets, f"running container has unreviewed host bind mounts: {bind_targets}")

    # Probe from the container namespace so the assertion also works when the
    # operator binds the UI to a specific management interface on the host.
    run(
        prefix
        + [
            "exec",
            "-T",
            "artex",
            "curl",
            "-fsS",
            "--max-time",
            "5",
            "http://127.0.0.1:8787/api/ready",
        ]
    )

    logs = run(prefix + ["logs", "--no-color", "artex"])
    require(PASS_LOG in logs, "startup log has no successful isolation self-test")
    require("AGENT ISOLATION IS DEGRADED" not in logs, "startup log reports degraded isolation")
    require("agent isolation self-test failed" not in logs, "startup log reports a failed isolation self-test")

    # This invokes the exact privilege-drop shim used for agent child processes.
    # It validates the identity and the boundaries most likely to regress without
    # reading or printing any secret contents.
    probe = r'''
test "$(id -u)" = 10001
test "$(id -g)" = 10001
for secret in /app/keys/jwt.key /app/keys/secret.key; do
  test ! -e "$secret" || test ! -r "$secret"
done
test ! -r /proc/1/environ
test ! -w /app
test ! -w /app/keys
test ! -w /app/skills
test ! -w /app/data
test -w /app/data/exec-home
'''
    run(
        prefix
        + [
            "exec",
            "-T",
            "artex",
            "/app/artex",
            "__artex-exec-drop",
            "10001",
            "10001",
            "--",
            "/bin/sh",
            "-eu",
            "-c",
            probe,
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file", type=pathlib.Path, default=DEFAULT_COMPOSE)
    parser.add_argument("--env-file", type=pathlib.Path)
    parser.add_argument(
        "--project-name",
        default=os.environ.get("ARTEX_PRODUCTION_PROJECT"),
        help="Compose project to inspect (defaults to ARTEX_PRODUCTION_PROJECT)",
    )
    parser.add_argument("--config-only", action="store_true")
    args = parser.parse_args()

    compose_file = args.compose_file.resolve()
    require(compose_file.is_file(), f"compose file not found: {compose_file}")
    if args.env_file is not None:
        require(args.env_file.is_file(), f"env file not found: {args.env_file}")

    assert_static_contract(rendered_config(compose_file))
    if args.config_only:
        print("production compose isolation contract: PASS (configuration only)")
        return

    assert_live(compose_prefix(compose_file, args.env_file, args.project_name))
    print("production ARTEX isolation: PASS (fail-closed startup + live executor probe)")


if __name__ == "__main__":
    main()
