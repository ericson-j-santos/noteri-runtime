from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_actuator_has_closed_allowlist():
 s=(ROOT/"scripts"/"noteri_admin_actuator.py").read_text(encoding="utf-8")
 assert 'CAPABILITIES={' in s and 'choices=sorted(CAPABILITIES)' in s
 assert 'add_argument("--command"' not in s and '"arbitrary_command":False' in s
def test_installer_requires_highest_and_fixed_task():
 s=(ROOT/"scripts"/"install_noteri_admin_actuator.py").read_text(encoding="utf-8")
 assert 'NoteriGovernedAdminActuator' in s and '"/RL","HIGHEST"' in s
 assert 'INSTALL-NOTERI-GOVERNED-ADMIN-ACTUATOR' in s
 assert "CAPS={'windows-health','runner-probe','gateway-health','appcontrol-read'}" in s
 assert "'request.json'" in s
