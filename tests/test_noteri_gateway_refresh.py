from __future__ import annotations
import importlib.util, sys
from pathlib import Path
import pytest
P=Path(__file__).resolve().parents[1]/"scripts"/"noteri_gateway_refresh.py"
S=importlib.util.spec_from_file_location("noteri_gateway_refresh",P); m=importlib.util.module_from_spec(S); sys.modules[S.name]=m; S.loader.exec_module(m)

def test_contract_is_fixed():
    assert m.RULES_COMMIT=="92e927757c29396228d7c2a04bd3a0ebac21422c"
    assert m.RULES_VERSION=="1.6.11"
    assert m.INSTALL_ROOT==Path(r"C:\dev\chatgpt-command-gateway")
    assert m.INSTALL_SHA256=="f73d843c86953e5f1eaca791850b5b10ccb670389cef722c2b7d921ff381f561"
    assert m.UPDATE_SHA256=="fbed2c036415a4f97637c453c37e3060a580d549f68a519785d0a02926589103"
def test_rejects_other_host():
    with pytest.raises(m.RefreshError,match="host invalido"): m.validate("OTHER",m.CONFIRM,m.RULES_COMMIT)
def test_rejects_wrong_confirmation():
    with pytest.raises(m.RefreshError,match="confirmacao invalida"): m.validate("Noteri","WRONG",m.RULES_COMMIT)
def test_rejects_wrong_commit():
    with pytest.raises(m.RefreshError,match="commit divergente"): m.validate("Noteri",m.CONFIRM,"0"*40)
def test_idempotent_when_receipt_current(monkeypatch):
    monkeypatch.setattr(m.socket,"gethostname",lambda:"Noteri"); monkeypatch.setattr(m,"receipt_ok",lambda:True)
    assert m.run_elevated(m.CONFIRM,m.RULES_COMMIT)["result"]=="NOTERI_GATEWAY_ALREADY_CURRENT"
