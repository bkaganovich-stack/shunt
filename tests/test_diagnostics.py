import socket
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/web"))
from types import SimpleNamespace
import pytest
import diagnostics as d

@pytest.mark.parametrize('target', ['http://example.org','https://user:pass@example.org','https://example.org:22','127.0.0.1','localhost','https://-bad.example','https://example.org:bad'])
def test_bad_target(target):
    with pytest.raises(ValueError): d.hostname(target)

def test_private_mixed_dns_rejected():
    resolver=lambda *a,**k:[(0,0,0,'',('93.184.216.34',443)),(0,0,0,'',('127.0.0.1',443))]
    with pytest.raises(ValueError): d.public_addresses('example.org',resolver)

def test_probe_pins_ip_keeps_tls_and_never_follows_redirect():
    def run(cmd,**kw):
        assert '--resolve' in cmd and 'example.org:443:93.184.216.34' in cmd
        assert '--socks5' in cmd and '--socks5-hostname' not in cmd
        assert '-k' not in cmd and '-L' not in cmd and '--location' not in cmd
        assert cmd[-1]=='https://example.org/'
        return SimpleNamespace(stdout='302 0.1 0.2 0.3 0.4',stderr='',returncode=0)
    assert d.request('example.org','93.184.216.34',socks='127.0.0.1:1081',runner=run)['state']=='inconclusive'

@pytest.mark.parametrize('code,exitcode,state',[(200,0,'ok'),(403,0,'refused'),(451,0,'refused'),(500,0,'inconclusive'),(429,0,'inconclusive'),(200,63,'inconclusive'),(0,60,'failed')])
def test_classification(code,exitcode,state):
    run=lambda *a,**k:SimpleNamespace(stdout=f'{code:03} 0 0 0 1',stderr='',returncode=exitcode)
    assert d.request('example.org','93.184.216.34',interface='eth0',runner=run)['state']==state

@pytest.mark.parametrize('direct,tunnel,expected',[('failed','ok','tunnel'),('refused','ok','tunnel'),('inconclusive','ok',None),('failed','failed',None),('ok','ok',None),('unavailable','ok',None)])
def test_recommendation_is_evidence_scoped(direct,tunnel,expected):
    resolver=lambda *a,**k:[(0,0,0,'',('93.184.216.34',443))]
    probe=lambda h,a,**kw:{'state':tunnel if kw.get('socks') else direct}
    report=d.diagnose('https://example.org/path?secret=abc','eth0','localhost:1081',resolver,probe)
    assert report['recommendation']==expected
    assert report['host']=='example.org'
    assert 'secret' not in str(report)

@pytest.mark.parametrize('code',[429,500,502,503])
def test_background_probe_does_not_confirm_error_page(code):
    import blockprobe as bp
    direct=bp.probe('example.org', lambda h,t:(code,''))
    tunnel={'state':bp.OK,'code':200}
    assert direct['state']==bp.UNCERTAIN
    assert bp.classify(direct,tunnel)!=bp.BLOCKED
    assert bp.classify({'state':bp.FAILED},direct)!=bp.BLOCKED

def test_dns_worker_is_killed_after_deadline(monkeypatch):
    def timeout(*a,**kw):
        assert kw['timeout']==5
        raise d.subprocess.TimeoutExpired(a[0],5)
    monkeypatch.setattr(d.subprocess,'run',timeout)
    with pytest.raises(socket.gaierror): d.bounded_resolver('example.org',443)

def test_probe_uses_the_same_egress_as_routing(monkeypatch,tmp_path):
    import main as m
    import features as f
    monkeypatch.setattr(f,'BASE',tmp_path)
    settings={'egress_active':'fptn','fptn':{'enabled':True},'adguard':{'enabled':True}}
    assert f._probe_paths(settings)[1]=='192.168.244.2:1082'
    settings['fptn']['enabled']=False
    assert f._probe_paths(settings)[1]=='127.0.0.1:1081'
    settings['adguard']['enabled']=False
    assert f._probe_paths(settings)[1]==''
