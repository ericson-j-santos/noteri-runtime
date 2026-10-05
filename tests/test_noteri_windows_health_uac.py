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

def test_broker_records_all_attempts_and_handles_timeout():
 src=(Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_uac_launcher.py").read_text(encoding="utf-8")
 assert "subprocess.TimeoutExpired" in src
 assert '"powershell":"not_run"' in src
 assert '"shell_application":"not_run"' in src
 assert '"attempts":attempts' in src
 assert "fallbacks_exhausted" in src

def test_uac_launcher_compiles():
 import py_compile
 target=Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_uac_launcher.py"
 py_compile.compile(str(target),doraise=True)

def test_uac_launcher_has_global_deadline_and_phase_receipt():
 src=(Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_uac_launcher.py").read_text(encoding="utf-8")
 assert "deadline=time.monotonic()" in src
 assert "phase_receipt" in src.replace("-","_")
 assert "shell_execute_done" in src and "powershell_done" in src and "shell_application_done" in src
 assert '"state":"fallbacks_exhausted"' in src

def test_shell_execute_is_isolated_and_bounded():
 src=(Path(__file__).resolve().parents[1]/"scripts"/"noteri_windows_health_uac_launcher.py").read_text(encoding="utf-8")
 assert "def shell_execute_isolated" in src
 assert "timeout=10" in src
 assert 'return "timeout"' in src
 assert "shell_state!=\"launched\"" in src
