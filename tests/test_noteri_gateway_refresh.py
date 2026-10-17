from __future__ import annotations
import importlib.util, sys
from pathlib import Path
import pytest
P=Path(__file__).resolve().parents[1]/"scripts"/"noteri_gateway_refresh.py"
S=importlib.util.spec_from_file_location("noteri_gateway_refresh",P); m=importlib.util.module_from_spec(S); sys.modules[S.name]=m; S.loader.exec_module(m)

def test_contract_is_fixed():
    assert m.RULES_COMMIT=="0381d3f7528e23ac6547872d9af6ca1f8473f151"
    assert m.RULES_VERSION=="1.6.11"
    assert m.INSTALL_ROOT==Path(r"C:\dev\chatgpt-command-gateway")
    assert m.INSTALL_SHA256=="5641be118743f90fb8b07e4d58fc7a5e4d6f32a0f6f0f9231c0239a89ef28801"
    assert m.UPDATE_SHA256=="c2f45c4b9ffbb7f1196abf49f3ca06ea6f9e041753b994e422f18683028c41c8"
def test_rejects_other_host():
    with pytest.raises(m.RefreshError,match="host invalido"): m.validate("OTHER",m.CONFIRM,m.RULES_COMMIT)
def test_rejects_wrong_confirmation():
    with pytest.raises(m.RefreshError,match="confirmacao invalida"): m.validate("Noteri","WRONG",m.RULES_COMMIT)
def test_rejects_wrong_commit():
    with pytest.raises(m.RefreshError,match="commit divergente"): m.validate("Noteri",m.CONFIRM,"0"*40)
def test_idempotent_when_receipt_current(monkeypatch):
    monkeypatch.setattr(m.socket,"gethostname",lambda:"Noteri"); monkeypatch.setattr(m,"receipt_ok",lambda:True)
    assert m.run_elevated(m.CONFIRM,m.RULES_COMMIT)["result"]=="NOTERI_GATEWAY_ALREADY_CURRENT"
