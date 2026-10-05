from pathlib import Path
def test_worker_is_fixed_diagnostics_only():
 s=(Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_admin.py").read_text(encoding="utf-8")
 assert 'dism.exe' in s and '/CheckHealth' in s and '/ScanHealth' in s and 'sfc.exe' in s and '/verifyonly' in s
 assert "add_argument(\"--command\"" not in s
def test_launcher_has_closed_states():
 s=(Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_uac_launcher.py").read_text(encoding="utf-8")
 for x in ("launch_failed","approval_or_execution_pending","completed"): assert x in s

def test_launcher_has_all_governed_uac_brokers():
 src=(Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_uac_launcher.py").read_text(encoding="utf-8")
 for name in ("shell_execute_runas","powershell_start_process_runas","shell_application_runas","fallbacks_exhausted"):
  assert name in src
