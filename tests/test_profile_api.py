import copy
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/web'))
from fastapi.testclient import TestClient
import pytest
import main as m
import profiles as p

@pytest.fixture
def api(monkeypatch,tmp_path):
    state=copy.deepcopy(m.DEFAULT_SETTINGS)
    state.update(profile='blocked_only',custom_rules={'always_direct':['domain:local.example'],'always_vpn':[]},vpn_servers=[{'id':'keep'}],dns={'upstream':['1.1.1.1']})
    calls=[]
    monkeypatch.setattr(m,'load_settings',lambda:copy.deepcopy(state))
    def save(value):
        state.clear();state.update(copy.deepcopy(value))
    monkeypatch.setattr(m,'save_settings',save)
    monkeypatch.setattr(m,'apply_config',lambda s,*a,**k:(calls.append(copy.deepcopy(s)) or True,''))
    m.app.dependency_overrides[m.auth_dep]=lambda:'test-user-'+tmp_path.name
    yield TestClient(m.app),state,calls
    m.app.dependency_overrides.clear()

def row(client,ident='blocked_only'):
    result=client.get('/api/profiles')
    assert result.status_code==200,result.text
    return next(x for x in result.json()['profiles'] if x['id']==ident)

def test_save_reset_undo_scoped(api):
    client,state,calls=api
    unrelated={k:copy.deepcopy(state[k]) for k in ('custom_rules','vpn_servers','dns')}
    r=row(client)
    response=client.put('/api/profiles/blocked_only',json={'revision':r['revision'],'config':{'default_route':'tunnel'}})
    assert response.status_code==200,response.text
    assert row(client)['modified']
    r=row(client)
    assert client.post('/api/profiles/blocked_only/reset',json={'revision':r['revision']}).status_code==200
    assert not row(client)['modified']
    r=row(client)
    assert client.post('/api/profiles/blocked_only/undo',json={'revision':r['revision']}).status_code==200
    assert row(client)['config']['default_route']=='tunnel'
    assert not row(client)['can_undo']
    assert all(state[k]==v for k,v in unrelated.items())
    assert len(calls)==3

def test_failed_apply_does_not_persist(api,monkeypatch):
    client,state,calls=api
    before=copy.deepcopy(state)
    monkeypatch.setattr(m,'apply_config',lambda *a,**k:(False,'missing list'))
    r=row(client)
    result=client.put('/api/profiles/blocked_only',json={'revision':r['revision'],'config':{'default_route':'tunnel'}})
    assert result.status_code==409
    assert state==before

def test_copy_is_inactive_and_can_activate(api):
    client,state,calls=api
    r=client.post('/api/profiles/blocked_only/copy',json={'name':'Мой профиль'})
    assert r.status_code==200,r.text
    ident=r.json()['created_id']
    assert state['profile']=='blocked_only' and not calls
    assert row(client,ident)['name']=='Мой профиль'
    r=client.post('/api/profile',json={'profile':ident})
    assert r.status_code==200 and r.json()['ok']
    assert state['profile']==ident

def test_stale_update_and_cross_origin_rejected(api):
    client,state,calls=api
    r=row(client)
    body={'revision':r['revision'],'config':{'default_route':'tunnel'}}
    assert client.put('/api/profiles/blocked_only',json=body,headers={'Origin':'https://evil.example'}).status_code==403
    assert client.put('/api/profiles/blocked_only',json=body).status_code==200
    assert client.put('/api/profiles/blocked_only',json=body).status_code==409

def test_bad_diagnostic_and_forged_apply_never_mutate(api):
    client,state,calls=api
    before=copy.deepcopy(state)
    assert client.post('/api/profiles/blocked_only/diagnose',json={'target':'http://127.0.0.1'}).status_code==400
    assert client.post('/api/profiles/blocked_only/apply-diagnosis',json={'report_id':'forged'}).status_code==409
    assert state==before and not calls

def test_preview_does_not_save_or_apply(api,monkeypatch):
    client,state,calls=api
    before=copy.deepcopy(state)
    def preview(host,settings,**kwargs):
        assert kwargs['profile_id']=='blocked_only'
        assert p.effective(settings,'blocked_only')['default_route']=='tunnel'
        return {'outbound':'proxy','matched_rule':'catch-all'}
    monkeypatch.setattr(m,'route_test',preview)
    r=client.post('/api/profiles/blocked_only/preview',json={'target':'https://example.org/path','config':{'default_route':'tunnel'}})
    assert r.status_code==200,r.text
    assert not r.json()['applied']
    assert state==before and not calls

@pytest.mark.parametrize('changed_exit',[False,True])
def test_diagnosis_applies_only_to_the_measured_exit(api,monkeypatch,changed_exit):
    import diagnostics
    client,state,calls=api
    monkeypatch.setattr(m._ft,'_probe_paths',lambda s:('eth0','127.0.0.1:1081'))
    monkeypatch.setattr(diagnostics,'diagnose',lambda *args:{'host':'example.org','recommendation':'tunnel','direct':{'state':'failed'},'tunnel':{'state':'ok'}})
    monkeypatch.setattr(m,'route_test',lambda *a,**kw:{'outbound':'proxy','matched_rule':'profile:extra_tunnel_domains'})
    response=client.post('/api/profiles/blocked_only/diagnose',json={'target':'example.org'})
    assert response.status_code==200,response.text
    if changed_exit: state['egress_active']='fptn'
    response=client.post('/api/profiles/blocked_only/apply-diagnosis',json={'report_id':response.json()['report_id']})
    if changed_exit:
        assert response.status_code==409
        assert not calls
    else:
        assert response.status_code==200,response.text
        assert p.effective(state,'blocked_only')['extra_tunnel_domains']==['example.org']
        assert state['custom_rules']['always_vpn']==[]
        assert row(client)['can_undo']
