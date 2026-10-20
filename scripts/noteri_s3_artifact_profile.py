"""Qualify the minimal Worker Pool S3 dependency profile on Noteri.

The physical entrypoint bootstraps a governed session. State-changing work is
then executed through Command Gateway. No storage credential is accepted and no
S3 client is created.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

HOST = "Noteri"
OWNER = "ericson-j-santos"
REPOSITORY = "ericson-j-santos/noteri-runtime"
WORKER_REPOSITORY = "ericson-j-santos/engineering-worker-pool"
WORKER_SHA = "5ef413c1c18996bd022c20987fb75dbb9ec47712"
RULES_SHA = "a430688c499077f5472841560f224c40766b0b78"
RULES_VERSION = "1.6.12"
GATEWAY_BUNDLE_NAME = "_gateway_bundle"
GATEWAY_BUNDLE_SCHEMA = "1.0.0"
GATEWAY_SOURCE_MAP = {
    "scripts/command_gateway.py": "bin/command_gateway.py",
    "scripts/host_health_check.py": "bin/host_health_check.py",
    "scripts/runner_version_preflight.py": "bin/runner_version_preflight.py",
    "scripts/session_bootstrap.py": "bin/session_bootstrap.py",
    "scripts/session_launcher.py": "bin/session_launcher.py",
    "scripts/session_preflight.py": "bin/session_preflight.py",
    "config/command-gateway.policy.json": "config/policy.json",
}
GATEWAY_FILES = {
    "bin/command_gateway.py": (
        "14f1389a5c2447e0ec3ae707fd468c224e0f9f492fd7541de65906918c8ac4d1",
        64_252,
    ),
    "bin/host_health_check.py": (
        "82a12ed90b8f922fb6a44677b3fcf450c9418ca133e9b45441f3fe798b797b3f",
        2_450,
    ),
    "bin/runner_version_preflight.py": (
        "4ec5f4af67d7b8e5b859d7093241c6bcfa2dee9d9e37ec73f593b9c40784e09f",
        12_120,
    ),
    "bin/session_bootstrap.py": (
        "2148b5e8885b9b5a223007bf0733282199a919cae57e1622b4e107b3d6a83b36",
        11_018,
    ),
    "bin/session_launcher.py": (
        "076c8670fde811233918767ad3fda15584735d38a20be2720951e5516e77b257",
        32_379,
    ),
    "bin/session_preflight.py": (
        "57774599e388c034b929686f3d72dbb872f9b97fb19879a6f880a908dbde25d6",
        6_957,
    ),
    "config/policy.json": (
        "5320d3a87e1bcdfdc1508db80fa4f48337c4e4717a59b662829c577b97753100",
        2_342,
    ),
}
REQUIREMENTS_NAME = "requirements-s3-artifact.txt"
REQUIREMENTS_BYTES = b"boto3==1.43.115\n"
REQUIREMENTS_URL = (
    "https://raw.githubusercontent.com/"
    f"{WORKER_REPOSITORY}/{WORKER_SHA}/{REQUIREMENTS_NAME}"
)
CONFIRM = "QUALIFY-NOTERI-S3-ARTIFACT-PROFILE"
SCHEMA_VERSION = "1.0.0"
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_ID = re.compile(r"[A-Za-z0-9_.-]{3,160}")
NATIVE_SUFFIXES = (".dll", ".dylib", ".pyd", ".so")


class Blocked(RuntimeError):
    """A bounded failure whose message is safe to emit."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Blocked(code)


def require_noteri() -> None:
    require(
        os.name == "nt" and socket.gethostname().casefold() == HOST.casefold(),
        "noteri_host_required",
    )


def valid_sha(value: str, code: str) -> str:
    require(isinstance(value, str) and SHA.fullmatch(value) is not None, code)
    return value


def valid_id(value: str, code: str) -> str:
    require(isinstance(value, str) and SAFE_ID.fullmatch(value) is not None, code)
    return value


def run_process(
    command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("dependency_process_failed") from None


def git(repo: Path, *arguments: str) -> str:
    process = run_process(["git", *arguments], cwd=repo, timeout=30)
    require(process.returncode == 0 and not process.stderr.strip(), "git_state_unavailable")
    return process.stdout.strip()


def validate_source(repo: Path, expected_sha: str) -> None:
    require(git(repo, "rev-parse", "HEAD") == expected_sha, "runtime_sha_mismatch")
    require(git(repo, "status", "--porcelain=v1") == "", "runtime_worktree_dirty")


def reject_reparse(path: Path) -> None:
    for item in (path, *path.parents):
        if not item.exists():
            continue
        info = item.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & 0x400),
            "reparse_path_rejected",
        )


def require_outside_git(path: Path) -> None:
    for item in (path, *path.parents):
        marker = item / ".git"
        require(
            not marker.exists() and not marker.is_symlink(),
            "asset_root_inside_git",
        )


def evidence_path(repo: Path, output: Path) -> Path:
    result = output if output.is_absolute() else repo / output
    result = result.resolve()
    expected_parent = (repo / "evidence" / "noteri-s3-artifact-profile").resolve()
    require(result.parent == expected_parent, "evidence_path_invalid")
    reject_reparse(repo)
    if expected_parent.exists():
        reject_reparse(expected_parent)
    return result


def default_asset_root(repo: Path) -> Path:
    workers = repo.resolve().parent
    require(workers.name.casefold() == "chatgpt-workers", "worker_namespace_invalid")
    reject_reparse(workers)
    root = workers / "runtime-assets"
    root.mkdir(exist_ok=True)
    reject_reparse(root)
    return root


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_reparse(path.parent)
    pending = path.with_name(f".{path.name}.{secrets.token_hex(8)}.pending")
    raw = (json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
    try:
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    except OSError:
        raise Blocked("evidence_write_failed") from None
    finally:
        try:
            pending.unlink(missing_ok=True)
        except OSError:
            pass


def download_requirements() -> bytes:
    request = urllib.request.Request(
        REQUIREMENTS_URL,
        headers={"User-Agent": "noteri-runtime-s3-profile/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            require(
                final.scheme == "https"
                and final.hostname == "raw.githubusercontent.com"
                and final.path.endswith(f"/{WORKER_SHA}/{REQUIREMENTS_NAME}"),
                "requirements_source_invalid",
            )
            data = response.read(4097)
    except Blocked:
        raise
    except Exception:
        raise Blocked("requirements_download_failed") from None
    require(data == REQUIREMENTS_BYTES, "requirements_contract_mismatch")
    return data


def isolated_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("AWS_", "CODEX_ARTIFACT_", "PYTHON"))
    }
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONNOUSERSITE="1",
        PIP_CONFIG_FILE=os.devnull,
        PIP_NO_CACHE_DIR="1",
    )
    return environment


def validate_probe(payload: object) -> dict[str, str]:
    require(isinstance(payload, dict), "import_probe_invalid")
    keys = {
        "boto3_version", "botocore_version", "modules_loaded_from_isolated_root",
        "native_extension_count", "s3_client_created", "storage_request_attempted",
        "credential_input_requested",
    }
    require(set(payload) == keys, "import_probe_invalid")
    require(payload["boto3_version"] == "1.43.115", "boto3_version_mismatch")
    require(
        isinstance(payload["botocore_version"], str)
        and re.fullmatch(r"1\.43\.\d+", payload["botocore_version"]) is not None,
        "botocore_version_mismatch",
    )
    require(payload["modules_loaded_from_isolated_root"] is True, "import_origin_invalid")
    require(payload["native_extension_count"] == 0, "native_dependency_detected")
    require(payload["s3_client_created"] is False, "s3_client_forbidden")
    require(payload["storage_request_attempted"] is False, "storage_request_forbidden")
    require(payload["credential_input_requested"] is False, "credential_input_forbidden")
    return {
        "boto3_version": payload["boto3_version"],
        "botocore_version": payload["botocore_version"],
    }


def probe_import(site_root: Path) -> dict[str, Any]:
    site_root = site_root.resolve()
    require(site_root.is_dir(), "isolated_site_missing")
    reject_reparse(site_root)
    native = [
        path for path in site_root.rglob("*")
        if path.is_file() and path.suffix.casefold() in NATIVE_SUFFIXES
    ]
    require(not native, "native_dependency_detected")
    sys.path.insert(0, str(site_root))
    try:
        import boto3  # type: ignore[import-not-found]
        import botocore  # type: ignore[import-not-found]
    except Exception:
        raise Blocked("dependency_import_failed") from None
    origins = [Path(boto3.__file__).resolve(), Path(botocore.__file__).resolve()]
    return {
        "boto3_version": str(boto3.__version__),
        "botocore_version": str(botocore.__version__),
        "modules_loaded_from_isolated_root": all(
            origin.is_relative_to(site_root) for origin in origins
        ),
        "native_extension_count": len(native),
        "s3_client_created": False,
        "storage_request_attempted": False,
        "credential_input_requested": False,
    }


def success_evidence(
    runtime_sha: str,
    rules_sha: str,
    correlation_id: str,
    environment_name: str,
    versions: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "result": "NOTERI_S3_ARTIFACT_PROFILE_PASSED",
        "host": HOST,
        "repository": REPOSITORY,
        "runtime_sha": runtime_sha,
        "rules_sha": rules_sha,
        "worker_repository": WORKER_REPOSITORY,
        "worker_sha": WORKER_SHA,
        "requirements_sha256": hashlib.sha256(REQUIREMENTS_BYTES).hexdigest(),
        "correlation_id": correlation_id,
        "python_version": ".".join(str(item) for item in sys.version_info[:3]),
        "boto3_version": versions["boto3_version"],
        "botocore_version": versions["botocore_version"],
        "environment_name": environment_name,
        "environment_outside_git": True,
        "temporary_environment_removed": True,
        "binary_only_install": True,
        "pip_configuration_disabled": True,
        "package_cache_used": False,
        "native_build_allowed": False,
        "native_extension_count": 0,
        "credential_input_requested": False,
        "s3_client_created": False,
        "storage_request_attempted": False,
        "task_executed": False,
        "worker_pool_started": False,
        "transport_ready": False,
        "secrets_exposed": False,
    }


def blocked_evidence(runtime_sha: str, rules_sha: str, correlation_id: str, code: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "result": "NOTERI_S3_ARTIFACT_PROFILE_BLOCKED",
        "host": HOST,
        "repository": REPOSITORY,
        "runtime_sha": runtime_sha if SHA.fullmatch(runtime_sha) else None,
        "rules_sha": rules_sha if SHA.fullmatch(rules_sha) else None,
        "worker_repository": WORKER_REPOSITORY,
        "worker_sha": WORKER_SHA,
        "correlation_id": correlation_id if SAFE_ID.fullmatch(correlation_id) else None,
        "code": code if SAFE_ID.fullmatch(code) else "qualification_failed",
        "credential_input_requested": False,
        "s3_client_created": False,
        "storage_request_attempted": False,
        "task_executed": False,
        "worker_pool_started": False,
        "transport_ready": False,
        "secrets_exposed": False,
    }


def qualify(
    *,
    repo: Path,
    output: Path,
    expected_runtime_sha: str,
    rules_sha: str,
    correlation_id: str,
    downloader: Callable[[], bytes] = download_requirements,
    runner: Callable[..., subprocess.CompletedProcess[str]] = run_process,
    asset_root: Path | None = None,
) -> dict[str, Any]:
    expected_runtime_sha = valid_sha(expected_runtime_sha, "runtime_sha_invalid")
    rules_sha = valid_sha(rules_sha, "rules_sha_invalid")
    require(rules_sha == RULES_SHA, "rules_sha_unapproved")
    correlation_id = valid_id(correlation_id, "correlation_id_invalid")
    require_noteri()
    repo = repo.resolve()
    validate_source(repo, expected_runtime_sha)
    destination = evidence_path(repo, output)
    root = (asset_root or default_asset_root(repo)).resolve()
    root.mkdir(parents=True, exist_ok=True)
    reject_reparse(root)
    require_outside_git(root)
    temporary: Path | None = None
    try:
        temporary = Path(tempfile.mkdtemp(prefix="noteri-s3-artifact-", dir=root))
        requirements = downloader()
        require(requirements == REQUIREMENTS_BYTES, "requirements_contract_mismatch")
        requirement_file = temporary / REQUIREMENTS_NAME
        requirement_file.write_bytes(requirements)
        site_root = temporary / "site"
        installed = runner(
            [
                    sys.executable, "-I", "-B", "-m", "pip", "--isolated", "install",
                "--disable-pip-version-check", "--no-input", "--only-binary=:all:",
                    "--no-compile", "--no-cache-dir", "--keyring-provider=disabled",
                "--index-url", "https://pypi.org/simple",
                "--target", str(site_root), "--requirement", str(requirement_file),
            ],
            cwd=repo,
            timeout=180,
            env=isolated_environment(),
        )
        require(installed.returncode == 0, "binary_dependency_install_failed")
        probe = runner(
            [
                sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                "probe-import", "--site-root", str(site_root),
            ],
            cwd=repo,
            timeout=45,
            env=isolated_environment(),
        )
        require(probe.returncode == 0 and not probe.stderr.strip(), "dependency_import_failed")
        try:
            probe_payload = json.loads(probe.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            raise Blocked("import_probe_invalid") from None
        versions = validate_probe(probe_payload)
        environment_name = temporary.name
    finally:
        if temporary is not None:
            try:
                shutil.rmtree(temporary)
            except OSError:
                raise Blocked("temporary_environment_cleanup_failed") from None
    require(temporary is not None and not temporary.exists(), "temporary_environment_cleanup_failed")
    result = success_evidence(
        expected_runtime_sha, rules_sha, correlation_id, environment_name, versions
    )
    write_json(destination, result)
    return result


def load_evidence(path: Path) -> dict[str, Any]:
    try:
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 16_384,
                "evidence_file_invalid")
        raw = path.read_bytes()
        require(len(raw) == info.st_size, "evidence_file_changed")
        value = json.loads(raw.decode("ascii"))
    except Blocked:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise Blocked("evidence_read_failed") from None
    require(isinstance(value, dict), "evidence_invalid")
    return value


def readback(
    *,
    repo: Path,
    output: Path,
    expected_runtime_sha: str,
    rules_sha: str,
    correlation_id: str,
    asset_root: Path | None = None,
) -> dict[str, Any]:
    expected_runtime_sha = valid_sha(expected_runtime_sha, "runtime_sha_invalid")
    rules_sha = valid_sha(rules_sha, "rules_sha_invalid")
    correlation_id = valid_id(correlation_id, "correlation_id_invalid")
    require_noteri()
    repo = repo.resolve()
    validate_source(repo, expected_runtime_sha)
    result = load_evidence(evidence_path(repo, output))
    expected = {
        "schema_version": SCHEMA_VERSION,
        "result": "NOTERI_S3_ARTIFACT_PROFILE_PASSED",
        "host": HOST,
        "repository": REPOSITORY,
        "runtime_sha": expected_runtime_sha,
        "rules_sha": rules_sha,
        "worker_repository": WORKER_REPOSITORY,
        "worker_sha": WORKER_SHA,
        "requirements_sha256": hashlib.sha256(REQUIREMENTS_BYTES).hexdigest(),
        "correlation_id": correlation_id,
        "boto3_version": "1.43.115",
        "environment_outside_git": True,
        "temporary_environment_removed": True,
        "binary_only_install": True,
        "pip_configuration_disabled": True,
        "package_cache_used": False,
        "native_build_allowed": False,
        "native_extension_count": 0,
        "credential_input_requested": False,
        "s3_client_created": False,
        "storage_request_attempted": False,
        "task_executed": False,
        "worker_pool_started": False,
        "transport_ready": False,
        "secrets_exposed": False,
    }
    for key, value in expected.items():
        require(result.get(key) == value, f"evidence_{key}_mismatch")
    require(
        isinstance(result.get("botocore_version"), str)
        and re.fullmatch(r"1\.43\.\d+", result["botocore_version"]) is not None,
        "evidence_botocore_version_mismatch",
    )
    require(
        isinstance(result.get("python_version"), str)
        and re.fullmatch(r"3\.\d+\.\d+", result["python_version"]) is not None,
        "evidence_python_version_mismatch",
    )
    name = result.get("environment_name")
    require(isinstance(name, str) and re.fullmatch(r"noteri-s3-artifact-[A-Za-z0-9_-]+", name),
            "evidence_environment_name_invalid")
    assets = (asset_root or default_asset_root(repo)).resolve()
    require(not (assets / name).exists(), "temporary_environment_still_present")
    return result


def verify_contract(worker_root: Path) -> dict[str, Any]:
    worker_root = worker_root.resolve()
    reject_reparse(worker_root)
    require(worker_root.is_dir(), "worker_contract_root_missing")
    require(git(worker_root, "rev-parse", "HEAD") == WORKER_SHA, "worker_sha_mismatch")
    require(git(worker_root, "status", "--porcelain=v1") == "", "worker_contract_dirty")
    path = worker_root / REQUIREMENTS_NAME
    require(path.is_file() and not path.is_symlink(), "requirements_contract_missing")
    raw = path.read_bytes()
    require(raw == REQUIREMENTS_BYTES, "requirements_contract_mismatch")
    return {
        "result": "S3_ARTIFACT_CONTRACT_VERIFIED",
        "worker_repository": WORKER_REPOSITORY,
        "worker_sha": WORKER_SHA,
        "requirements_sha256": hashlib.sha256(raw).hexdigest(),
        "secrets_read": False,
    }


def verify_gateway_contract(rules_root: Path) -> dict[str, Any]:
    unresolved = rules_root.absolute()
    reject_reparse(unresolved)
    root = unresolved.resolve()
    require(git(root, "rev-parse", "HEAD") == RULES_SHA, "rules_checkout_mismatch")
    require(
        git(root, "status", "--porcelain=v1", "--untracked-files=no") == "",
        "rules_checkout_dirty",
    )
    manifest_path = root / "MANIFEST.json"
    reject_reparse(manifest_path)
    try:
        info = manifest_path.stat()
        require(
            stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 1_048_576,
            "rules_manifest_invalid",
        )
        raw = manifest_path.read_bytes()
        require(len(raw) == info.st_size, "rules_manifest_changed")
        manifest = json.loads(raw.decode("utf-8"))
    except Blocked:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise Blocked("rules_manifest_invalid") from None
    require(
        isinstance(manifest, dict)
        and manifest.get("version") == RULES_VERSION
        and isinstance(manifest.get("files"), list),
        "rules_manifest_invalid",
    )
    index = {
        item.get("path"): item
        for item in manifest["files"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    require(len(index) == len(manifest["files"]), "rules_manifest_invalid")
    require(set(GATEWAY_SOURCE_MAP.values()) == set(GATEWAY_FILES),
            "gateway_source_map_invalid")
    for source, destination in GATEWAY_SOURCE_MAP.items():
        entry = index.get(source)
        expected_hash, expected_size = GATEWAY_FILES[destination]
        require(
            isinstance(entry, dict)
            and entry.get("sha256") == expected_hash
            and entry.get("size") == expected_size,
            "gateway_manifest_file_mismatch",
        )
    return {
        "result": "PERSISTENT_GATEWAY_CONTRACT_VERIFIED",
        "rules_sha": RULES_SHA,
        "rules_version": RULES_VERSION,
        "managed_file_count": len(GATEWAY_FILES),
        "secrets_read": False,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise Blocked("gateway_file_read_failed") from None
    return digest.hexdigest()


def same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(str(right.resolve()))


def validate_gateway_bundle_shape(root: Path) -> None:
    expected_files = set(GATEWAY_FILES) | {"bundle-manifest.json"}
    expected_directories = {
        str(Path(relative).parent).replace("\\", "/")
        for relative in GATEWAY_FILES
        if str(Path(relative).parent) != "."
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    try:
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            parent = Path(directory)
            for name in names:
                path = parent / name
                reject_reparse(path)
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode), "gateway_bundle_entry_invalid")
                observed_directories.add(path.relative_to(root).as_posix())
            for name in files:
                path = parent / name
                reject_reparse(path)
                info = path.lstat()
                require(
                    stat.S_ISREG(info.st_mode) and getattr(info, "st_nlink", 1) == 1,
                    "gateway_bundle_entry_invalid",
                )
                observed_files.add(path.relative_to(root).as_posix())
    except Blocked:
        raise
    except (OSError, ValueError):
        raise Blocked("gateway_bundle_shape_unavailable") from None
    require(observed_files == expected_files, "gateway_bundle_file_set_invalid")
    require(observed_directories == expected_directories,
            "gateway_bundle_directory_set_invalid")


def gateway_bundle_binding() -> dict[str, object]:
    sha, _branch, run, attempt = actions_context()
    return {
        "schema_version": GATEWAY_BUNDLE_SCHEMA,
        "repository": REPOSITORY,
        "runtime_sha": sha,
        "rules_sha": RULES_SHA,
        "rules_version": RULES_VERSION,
        "run_id": int(run),
        "run_attempt": int(attempt),
    }


def build_gateway_bundle(rules_root: Path, output: Path) -> dict[str, Any]:
    contract = verify_gateway_contract(rules_root)
    destination = output.absolute()
    require(not destination.exists() and not destination.is_symlink(),
            "gateway_bundle_destination_exists")
    reject_reparse(destination.parent)
    try:
        destination.mkdir()
        reject_reparse(destination)
        files: dict[str, dict[str, object]] = {}
        for source, relative in GATEWAY_SOURCE_MAP.items():
            source_path = rules_root.resolve().joinpath(*source.split("/"))
            reject_reparse(source_path)
            raw = source_path.read_bytes()
            expected_hash, expected_size = GATEWAY_FILES[relative]
            require(
                len(raw) == expected_size
                and hashlib.sha256(raw).hexdigest() == expected_hash,
                "gateway_source_changed",
            )
            target = destination.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            reject_reparse(target.parent)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            files[relative] = {"sha256": expected_hash, "size": expected_size}
        manifest = gateway_bundle_binding()
        manifest["files"] = files
        write_json(destination / "bundle-manifest.json", manifest)
    except Blocked:
        raise
    except OSError:
        raise Blocked("gateway_bundle_build_failed") from None
    return {
        **contract,
        "result": "TRANSIENT_GATEWAY_BUNDLE_BUILT",
        "bundle_name": GATEWAY_BUNDLE_NAME,
        "file_count": len(GATEWAY_FILES),
    }


def validate_gateway_bundle(
    gateway_root: Path,
    rules_sha: str,
    runtime_sha: str,
    run_id: str,
    run_attempt: str,
) -> tuple[Path, Path, Path, Path]:
    rules_sha = valid_sha(rules_sha, "rules_sha_invalid")
    require(rules_sha == RULES_SHA, "rules_sha_unapproved")
    unresolved = gateway_root.absolute()
    reject_reparse(unresolved)
    root = unresolved.resolve()
    try:
        root_info = root.stat()
    except OSError:
        raise Blocked("gateway_bundle_missing") from None
    require(stat.S_ISDIR(root_info.st_mode), "gateway_bundle_invalid")
    validate_gateway_bundle_shape(root)

    manifest_path = root / "bundle-manifest.json"
    reject_reparse(manifest_path)
    try:
        manifest_info = manifest_path.stat()
        require(
            stat.S_ISREG(manifest_info.st_mode) and 0 < manifest_info.st_size <= 65_536,
            "gateway_bundle_manifest_invalid",
        )
        manifest_raw = manifest_path.read_bytes()
        require(len(manifest_raw) == manifest_info.st_size, "gateway_bundle_manifest_changed")
        manifest = json.loads(manifest_raw.decode("ascii"))
    except Blocked:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise Blocked("gateway_bundle_manifest_invalid") from None
    expected_binding = {
        "schema_version": GATEWAY_BUNDLE_SCHEMA,
        "repository": REPOSITORY,
        "runtime_sha": runtime_sha,
        "rules_sha": rules_sha,
        "rules_version": RULES_VERSION,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
    }
    require(
        isinstance(manifest, dict)
        and all(type(manifest.get(key)) is type(value) and manifest.get(key) == value
                for key, value in expected_binding.items()),
        "gateway_bundle_binding_mismatch",
    )
    files = manifest.get("files")
    require(isinstance(files, dict) and set(files) == set(GATEWAY_FILES),
            "gateway_bundle_files_invalid")

    for relative, (expected_hash, expected_size) in GATEWAY_FILES.items():
        metadata = files.get(relative)
        require(
            isinstance(metadata, dict)
            and metadata.get("sha256") == expected_hash
            and metadata.get("size") == expected_size,
            "gateway_bundle_file_mismatch",
        )
        path = root.joinpath(*relative.split("/"))
        reject_reparse(path)
        try:
            info = path.stat()
        except OSError:
            raise Blocked("gateway_file_missing") from None
        require(
            stat.S_ISREG(info.st_mode) and info.st_size == expected_size,
            "gateway_file_invalid",
        )
        require(sha256_file(path) == expected_hash, "gateway_file_hash_mismatch")

    gateway_path = root / "bin" / "command_gateway.py"
    launcher_path = root / "bin" / "session_launcher.py"
    policy_path = root / "config" / "policy.json"
    return root, gateway_path, launcher_path, policy_path


def actions_context() -> tuple[str, str, str, str]:
    require(os.environ.get("GITHUB_ACTIONS") == "true", "github_actions_required")
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "repository_mismatch")
    require(os.environ.get("GITHUB_ACTOR") == OWNER, "actor_not_authorized")
    require(
        os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"},
        "event_not_authorized",
    )
    require(os.environ.get("GITHUB_REF_TYPE") == "branch", "branch_ref_required")
    sha = valid_sha(os.environ.get("GITHUB_SHA", ""), "github_sha_invalid")
    branch = os.environ.get("GITHUB_REF_NAME", "")
    require(re.fullmatch(r"[A-Za-z0-9_.\-/]+", branch) is not None and ".." not in branch,
            "branch_invalid")
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(run.isdigit() and int(run) > 0 and attempt.isdigit() and int(attempt) > 0,
            "run_identity_invalid")
    return sha, branch, run, attempt


def launch(gateway_root: Path, rules_sha: str, bundle_run_attempt: str) -> int:
    sha, branch, run, attempt = actions_context()
    rules_sha = valid_sha(rules_sha, "rules_sha_invalid")
    require(rules_sha == RULES_SHA, "rules_sha_unapproved")
    require(bundle_run_attempt.isdigit() and int(bundle_run_attempt) > 0,
            "gateway_bundle_attempt_invalid")
    require_noteri()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute(), "github_workspace_invalid")
    require(
        same_path(gateway_root, workspace / GATEWAY_BUNDLE_NAME),
        "gateway_bundle_root_unapproved",
    )
    gateway_root, gateway_path, launcher_path, policy_path = validate_gateway_bundle(
        gateway_root, rules_sha, sha, run, bundle_run_attempt
    )
    sys.path.insert(0, str(gateway_root / "bin"))
    try:
        import command_gateway as cg  # type: ignore[import-not-found]
    except ImportError:
        raise Blocked("command_gateway_import_failed") from None
    finally:
        sys.path.pop(0)
    require(
        Path(cg.__file__).resolve() == gateway_path.resolve(),
        "command_gateway_origin_mismatch",
    )
    validate_gateway_bundle(gateway_root, rules_sha, sha, run, bundle_run_attempt)
    correlation = f"noteri-s3-artifact-{run}-{attempt}"
    session_id = correlation
    launched = run_process(
        [
            sys.executable, "-I", "-B", str(launcher_path),
            "--policy", str(policy_path), "--repo", str(Path.cwd()),
            "--session-id", session_id, "--correlation-id", correlation,
            "--expected-head", sha, "--sync-ref", "origin/" + branch,
            "--require-runner-version-preflight",
        ],
        cwd=Path.cwd(),
        timeout=180,
        env=isolated_environment(),
    )
    require(launched.returncode == 0, "session_launch_failed")
    validate_gateway_bundle(gateway_root, rules_sha, sha, run, bundle_run_attempt)
    try:
        session = json.loads(launched.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        raise Blocked("session_receipt_invalid") from None
    require(
        session.get("result") == "SESSION_LAUNCH_OK"
        and session.get("head") == sha
        and session.get("state_validated") is True
        and str(session.get("host", "")).casefold() == HOST.casefold(),
        "session_not_qualified",
    )
    target = Path(session["target_path"])
    policy = cg.load_policy(policy_path)
    cg.enforce_session(policy, session_id, target, 2)
    output = target / "evidence" / "noteri-s3-artifact-profile" / f"{correlation}.json"
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    require(bool(github_output), "github_output_missing")
    with open(github_output, "a", encoding="utf-8") as stream:
        stream.write(f"evidence_path={output}\n")
        stream.write(f"target_path={target}\n")
        stream.write(f"session_id={session_id}\n")
    common = [
        "--output", str(output), "--expected-runtime-sha", sha,
        "--rules-sha", rules_sha, "--correlation-id", correlation,
    ]
    for mode, risk in (("qualify", 2), ("readback", 1)):
        code = cg.execute(
            cwd=target,
            policy=policy,
            args=[
                sys.executable, "-I", "-B",
                "scripts/noteri_s3_artifact_profile.py", mode, *common,
            ],
            risk=risk,
            timeout=240,
            expected_head=sha,
            allow_dirty=False,
            allow_head_change=False,
            correlation_id=f"{correlation}-{mode}",
            session_id=session_id,
        )
        if code != 0:
            return code
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="mode", required=True)
    launch_parser = subparsers.add_parser("launch")
    launch_parser.add_argument("--confirm", required=True)
    launch_parser.add_argument("--gateway-root", required=True, type=Path)
    launch_parser.add_argument("--bundle-run-attempt", required=True)
    launch_parser.add_argument("--rules-sha", required=True)
    contract_parser = subparsers.add_parser("verify-contract")
    contract_parser.add_argument("--worker-root", required=True, type=Path)
    gateway_contract_parser = subparsers.add_parser("verify-gateway-contract")
    gateway_contract_parser.add_argument("--rules-root", required=True, type=Path)
    bundle_parser = subparsers.add_parser("build-gateway-bundle")
    bundle_parser.add_argument("--rules-root", required=True, type=Path)
    bundle_parser.add_argument("--output", required=True, type=Path)
    probe_parser = subparsers.add_parser("probe-import")
    probe_parser.add_argument("--site-root", required=True, type=Path)
    for name in ("qualify", "readback"):
        operation = subparsers.add_parser(name)
        operation.add_argument("--output", required=True, type=Path)
        operation.add_argument("--expected-runtime-sha", required=True)
        operation.add_argument("--rules-sha", required=True)
        operation.add_argument("--correlation-id", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    output: Path | None = getattr(arguments, "output", None)
    runtime_sha = getattr(arguments, "expected_runtime_sha", "")
    rules_sha = getattr(arguments, "rules_sha", "")
    correlation = getattr(arguments, "correlation_id", "")
    try:
        if arguments.mode == "launch":
            require(arguments.confirm == CONFIRM, "confirmation_required")
            return launch(
                arguments.gateway_root, arguments.rules_sha, arguments.bundle_run_attempt
            )
        if arguments.mode == "verify-contract":
            result = verify_contract(arguments.worker_root)
        elif arguments.mode == "verify-gateway-contract":
            result = verify_gateway_contract(arguments.rules_root)
        elif arguments.mode == "build-gateway-bundle":
            result = build_gateway_bundle(arguments.rules_root, arguments.output)
        elif arguments.mode == "probe-import":
            result = probe_import(arguments.site_root)
        elif arguments.mode == "qualify":
            result = qualify(
                repo=Path.cwd(), output=arguments.output,
                expected_runtime_sha=arguments.expected_runtime_sha,
                rules_sha=arguments.rules_sha, correlation_id=arguments.correlation_id,
            )
        else:
            result = readback(
                repo=Path.cwd(), output=arguments.output,
                expected_runtime_sha=arguments.expected_runtime_sha,
                rules_sha=arguments.rules_sha, correlation_id=arguments.correlation_id,
            )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Blocked) else "qualification_failed"
        blocked = blocked_evidence(runtime_sha, rules_sha, correlation, code)
        if output is not None:
            try:
                write_json(evidence_path(Path.cwd().resolve(), output), blocked)
            except Exception:
                pass
        print(json.dumps(blocked, ensure_ascii=True, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
