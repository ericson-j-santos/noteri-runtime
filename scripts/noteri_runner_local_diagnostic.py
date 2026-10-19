"""Read-only diagnosis of the configured Noteri runner; no raw credentials/logs."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import stat
from datetime import datetime, timezone
import re
import noteri_native_qualification as native
from noteri_actions_admission import require, guard, Blocked, REPOSITORY, RELATED, MAX_BYTES

def local_runner_diagnostic(metadata_path: Path, listener_detected: bool) -> dict:
    """Read only documented operational metadata and the latest runner log.

    Never open .credentials or print raw log lines, URLs, tokens or task actions.
    Local metadata is not proof of GitHub registration or current connectivity.
    """
    metadata = native.read_json(metadata_path)
    require(str(metadata.get("host", "")).casefold() == "noteri", "runner_metadata_host")
    home = Path(str(metadata.get("runner_home", "")))
    require(home.is_absolute(), "runner_home_unresolved")
    config = native.read_json(home / ".runner")
    raw_url = config.get("gitHubUrl", config.get("githubUrl", ""))
    from urllib.parse import urlsplit
    parsed = urlsplit(raw_url) if isinstance(raw_url, str) else urlsplit("")
    repository = parsed.path.strip("/").removesuffix(".git")
    scoped = parsed.scheme == "https" and parsed.netloc == "github.com" and repository in (REPOSITORY, RELATED)
    agent_id, agent_name = config.get("agentId"), config.get("agentName")
    require(type(agent_id) is int and agent_id > 0
            and isinstance(agent_name, str)
            and re.fullmatch(r"[A-Za-z0-9_. -]{1,100}", agent_name), "local_runner_identity_invalid")
    result = {"status": "observed", "host": "Noteri", "listener_process_detected": listener_detected,
              "configured_repository": repository if scoped else "unrecognized",
              "configured_agent_id": agent_id, "configured_agent_name": agent_name,
              "actions_qualified": False, "hml_verified": False, "repairs_executed": False}
    diag = home / "_diag"
    for part in (diag, *diag.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & 0x400, "runner_diag_reparse")
    logs = list(diag.glob("Runner_*.log"))
    if not logs:
        result["log_status"] = "no_runner_log"
        return result
    latest = max(logs, key=lambda p: p.stat().st_mtime)
    modified = latest.stat().st_mtime
    try:
        raw = native.read_regular(latest, 4 * MAX_BYTES)
    except (OSError, ValueError):
        result["log_status"] = "unreadable_or_oversized"
        return result
    tail = raw[-65536:].decode("utf-8", errors="replace").casefold()
    markers = {
        "session_conflict": ("taskagentsessionconflictexception", "a session for this runner already exists"),
        "registration_missing": ("registration was not found", "runner registration has been deleted"),
        "unauthorized": ("unauthorized", "http 401", "http status code 401"),
        "connection_failure": ("unable to connect", "connection timed out", "no such host is known",
                               "failed to create a session", "failed to create session"),
        "listening_seen": ("listening for jobs",),
        "shutdown_seen": ("listener exiting", "runner listener exit", "exiting runner listener"),
    }
    result.update(
        log_status="observed",
        log_modified_at=datetime.fromtimestamp(modified, timezone.utc).isoformat(),
        log_age_seconds=max(0, int(datetime.now(timezone.utc).timestamp()-modified)),
        log_markers={key: any(value in tail for value in values) for key, values in markers.items()},
        raw_logs_exported=False,
    )
    return result


def local_probe() -> dict:
    import noteri_control_plane_watchdog as watchdog
    import noteri_control_plane_probe as probe
    return local_runner_diagnostic(watchdog.metadata_path(), probe.runner_listener_detected())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()
    try:
        guard(args.expected_head, args.correlation_id)
        result = local_probe()
        result.update(source_sha=args.expected_head, correlation_id=args.correlation_id)
        code = 0
    except Exception as exc:
        result = {"status": "blocked",
                  "code": str(exc) if isinstance(exc, Blocked) else type(exc).__name__,
                  "actions_qualified": False, "hml_verified": False, "repairs_executed": False}
        code = 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return code

if __name__ == "__main__":
    raise SystemExit(main())
