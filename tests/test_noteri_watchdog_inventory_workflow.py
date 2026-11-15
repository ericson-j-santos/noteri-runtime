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
