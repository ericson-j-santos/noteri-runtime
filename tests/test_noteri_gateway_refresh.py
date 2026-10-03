from __future__ import annotations
import importlib.util, sys
from pathlib import Path
import pytest
P=Path(__file__).resolve().parents[1]/"scripts"/"noteri_gateway_refresh.py"
S=importlib.util.spec_from_file_location("noteri_gateway_refresh",P); m=importlib.util.module_from_spec(S); sys.modules[S.name]=m; S.loader.exec_module(m)

def test_contract_is_fixed():
    assert m.RULES_COMMIT=="d26351458b17c917100efc3b736dcc6d53a646cb"
    assert m.RULES_VERSION=="1.6.10"
    assert m.INSTALL_ROOT==Path(r"C:\dev\chatgpt-command-gateway")
def test_rejects_other_host():
    with pytest.raises(m.RefreshError,match="host invalido"): m.validate("OTHER",m.CONFIRM,m.RULES_COMMIT)
def test_rejects_wrong_confirmation():
    with pytest.raises(m.RefreshError,match="confirmacao invalida"): m.validate("Noteri","WRONG",m.RULES_COMMIT)
def test_rejects_wrong_commit():
    with pytest.raises(m.RefreshError,match="commit divergente"): m.validate("Noteri",m.CONFIRM,"0"*40)
def test_idempotent_when_receipt_current(monkeypatch):
    monkeypatch.setattr(m.socket,"gethostname",lambda:"Noteri"); monkeypatch.setattr(m,"receipt_ok",lambda:True)
    assert m.run_elevated(m.CONFIRM,m.RULES_COMMIT)["result"]=="NOTERI_GATEWAY_ALREADY_CURRENT"
