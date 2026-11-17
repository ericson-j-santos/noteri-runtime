from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/physical-e2e.yml"


def data():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_existing_e2e_keeps_dispatch_default():
    doc = data()
    events = doc.get("on", doc.get(True))
    assert events["workflow_dispatch"]["inputs"]["mode"]["default"] == "e2e"
    assert doc["jobs"]["e2e"]["if"] == "github.event_name == 'workflow_dispatch' && inputs.mode == 'e2e'"


def test_one_shot_only_for_owner_and_specific_branch():
    doc = data()
    events = doc.get("on", doc.get(True))
    assert events["push"]["branches"] == ["fix/noteri-watchdog-transactional-upgrade-20261115"]
    job = doc["jobs"]["inventory"]
    gate = job["if"]
    assert "github.actor == 'ericson-j-santos'" in gate
    assert "contains(github.event.head_commit.message, '[risk1-inventory-once]')" in gate
    assert "inputs.mode == 'inventory'" in gate
    assert job["runs-on"] == ["self-hosted", "Windows", "X64", "noteri", "reqsys-dev"]


def test_no_mutating_gateway_command_in_readonly_job():
    doc = data()
    job = doc["jobs"]["inventory"]
    session = next(s for s in job["steps"] if s.get("id") == "session")["run"]
    cmd = next(s for s in job["steps"] if s.get("id") == "inventory")["run"]
    assert "SESSION_LAUNCH_OK" in session and "state_validated" in session
    assert "--require-runner-version-preflight" in session
    assert "'--risk', '1'" in cmd
    assert "noteri_watchdog_readonly_inventory.py" in cmd
    for banned in ("--risk', '2'", "--mode', 'upgrade'", "ShellExecuteW", "Start-Process", "schtasks /Create"):
        assert banned not in cmd
    assert "state_changed -ne $false" in cmd


def test_separate_readback_never_promotes_host():
    doc = data()
    job = doc["jobs"]["inventory_readback"]
    assert job["needs"] == "inventory"
    assert job["runs-on"] == "ubuntu-latest"
    step = job["steps"][0]["run"]
    assert "sha256sum" in step and "jq -e" in step
    assert ".installation_authorized == false" in step
    assert ".ready_for_builder == false" in step
    assert "installed_release_sha256, task_definition_sha256, task_action_verified" in step
    assert "jq -c" in step
    assert "metadata.json" not in step and "task.xml" not in step


def test_upgrade_preflight_only_readonly_on_exact_branch_sha_and_owner():
    doc = data()
    events = doc.get("on", doc.get(True))
    assert "upgrade-preflight" in events["workflow_dispatch"]["inputs"]["mode"]["options"]
    inventory = doc["jobs"]["inventory"]
    gate = inventory["if"]
    assert "github.actor == 'ericson-j-santos'" in gate
    assert "contains(github.event.head_commit.message, '[risk1-upgrade-preflight-once]')" in gate
    assert events["push"]["branches"] == ["fix/noteri-watchdog-transactional-upgrade-20261115"]
    step = next(s for s in inventory["steps"] if s.get("id") == "upgrade_preflight")
    assert step["shell"] == "powershell"
    cmd = step["run"]
    assert "'--risk', '1'" in cmd
    assert "SESSION_ID" in cmd and "TARGET_PATH" in cmd
    assert "noteri_watchdog_transactional_upgrade.py" in cmd
    assert "'--mode', 'preflight'" in cmd
    assert "PREFLIGHT_OK_NOT_AUTHORIZED" in cmd
    assert "installed_source_sha" in cmd and "installed_release_sha256" in cmd
    assert "task_action_verified -ne $true" in cmd
    assert "profile -ne 'NORMAL'" in cmd
    assert "installation_authorized = $false" in cmd
    assert "state_changed = $false" in cmd
    for forbidden in ("'--risk', '2'", "'--mode', 'upgrade'", "ShellExecuteW", "Start-Process", "schtasks /Create"):
        assert forbidden not in cmd


def test_upgrade_preflight_receipt_requires_hosted_independent_readback():
    doc = data()
    job = doc["jobs"]["upgrade_preflight_readback"]
    assert job["needs"] == "inventory"
    assert job["runs-on"] == "ubuntu-latest"
    code = job["steps"][0]["run"]
    assert "sha256sum" in code and "jq -e" in code
    assert ".target_sha == $source" in code
    assert ".installation_authorized == false" in code
    assert ".state_changed == false" in code
    assert "metadata.json" not in code and "task.xml" not in code
    assert "PREFLIGHT_OK_NOT_AUTHORIZED" in code


def test_workflow_structure_does_not_duplicate_jobs_or_split_powershell():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert raw.count("\n  inventory_readback:") == 1
    assert raw.count("\n  upgrade_preflight_readback:") == 1
    assert "if ($targetDigest -notmatch '^[0-9a-f]{64}$') {" in raw
    assert raw.count("NOTERI_WATCHDOG_INVENTORY_INDEPENDENT_READBACK_OK_NO_INSTALL") == 1


def test_preflight_failure_diagnostic_is_allowlisted_and_never_raw():
    doc = data()
    step = next(s for s in doc["jobs"]["inventory"]["steps"]
                if s.get("id") == "upgrade_preflight")["run"]
    assert "GATEWAY_OR_COMMAND_BLOCKED" in step
    assert "blocked.reason -cmatch '^[A-Z][A-Z0-9_]{3,80}$'" in step
    assert "envelope.stdout | ConvertFrom-Json" in step
    assert "throw \"NOTERI_WATCHDOG_UPGRADE_PREFLIGHT_$reason\"" in step
    assert "Write-Output $envelope" not in step
    assert "Write-Output $envelope.stderr" not in step


def test_python_compat_only_owner_only_readonly_and_independent_readback():
    doc = data()
    events = doc.get("on", doc.get(True))
    assert "python-compat" in events["workflow_dispatch"]["inputs"]["mode"]["options"]
    job = doc["jobs"]["inventory"]
    assert "github.actor == 'ericson-j-santos'" in job["if"]
    assert "[risk1-python-compat-once]" in job["if"]
    step = next(s for s in job["steps"] if s.get("id") == "python_compat")
    command = step["run"]
    assert "'--risk', '1'" in command
    assert "'--expected-head', $env:GITHUB_SHA" in command
    assert "noteri_watchdog_python_compat_readonly.py" in command
    assert "state_changed -ne $false" in command
    assert "installation_authorized -ne $false" in command
    assert "'--risk', '2'" not in command
    assert "pip install" not in command
    readback = doc["jobs"]["python_compat_readback"]
    assert readback["needs"] == "inventory"
    assert readback["runs-on"] == "ubuntu-latest"
    verify = readback["steps"][0]["run"]
    assert "sha256sum" in verify and "jq -e" in verify
    assert ".state_changed == false" in verify
    assert ".installation_authorized == false" in verify


def test_python_compat_does_not_duplicate_jobs_or_change_upgrade_gate():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert raw.count("\n  inventory_readback:") == 1
    assert raw.count("\n  upgrade_preflight_readback:") == 1
    assert raw.count("\n  python_compat_readback:") == 1
    assert raw.count("id: python_compat") == 1
    upgrade = next(s for s in data()["jobs"]["inventory"]["steps"] if s.get("id") == "upgrade_preflight")
    assert "inputs.mode == 'upgrade-preflight'" in upgrade["if"]
    assert "'--mode', 'preflight'" in upgrade["run"]


def test_task_python_upgrade_preflight_remains_risk1_and_fixed():
    doc = data()
    job = doc["jobs"]["inventory"]
    assert "[risk1-task-python-upgrade-preflight-once]" in job["if"]
    step = next(s for s in job["steps"] if s.get("id") == "python_compat")
    assert "[risk1-task-python-upgrade-preflight-once]" in step["if"]
    assert "'--probe-upgrade'" in step["run"]
    assert "'--risk', '1'" in step["run"]
    assert "upgrade_preflight -notmatch" in step["run"]
    assert "'--risk', '2'" not in step["run"]
    verify = doc["jobs"]["python_compat_readback"]["steps"][0]["run"]
    assert ".upgrade_preflight | type" in verify
    assert "PREFLIGHT_OK_NOT_AUTHORIZED" in verify
    assert ".state_changed == false" in verify
