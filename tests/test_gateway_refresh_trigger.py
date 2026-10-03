from pathlib import Path
import yaml


def test_gateway_refresh_has_narrow_push_trigger():
    p=Path(__file__).resolve().parents[1]/'.github/workflows/noteri-command-gateway-refresh.yml'
    data=yaml.safe_load(p.read_text(encoding='utf-8'))
    on=data.get('on') or data.get(True)
    push=on['push']
    assert push['branches']==['main']
    assert push['paths']==['.github/triggers/noteri-command-gateway-refresh']
