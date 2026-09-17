"""Exercise staged updates with tiny protobuf fixtures and no network/services."""
import json
import os
from pathlib import Path
import subprocess
from test_geosite import _entry

ROOT=Path(__file__).resolve().parents[1]

def setup(tmp_path, name='ru-blocked'):
    cfg=tmp_path/'config';cfg.mkdir()
    cfg.joinpath('geoip.dat').write_bytes(b'old-ip')
    cfg.joinpath('geosite.dat').write_bytes(b'old-site')
    cfg.joinpath('xray.json').write_text(json.dumps({'routing':{'rules':[{'domain':['geosite:ru-blocked']}]}}))
    assets=tmp_path/'assets';assets.mkdir()
    assets.joinpath('geoip.dat').write_bytes(_entry('private'))
    assets.joinpath('geosite.dat').write_bytes(_entry(name))
    bins=tmp_path/'bin';bins.mkdir()
    bins.joinpath('flock').write_text('#!/bin/sh\nexit 0\n')
    bins.joinpath('curl').write_text('''#!/usr/bin/env python3
import json,sys,shutil,os
from pathlib import Path
args=sys.argv[1:]
if '-o' in args:
 shutil.copyfile(Path(os.environ['TEST_GEO_ASSETS'])/args[-1].split('/')[-1],args[args.index('-o')+1])
else: print(json.dumps({'tag_name':'test-release'}))
''')
    for f in bins.iterdir():f.chmod(0o755)
    env={**os.environ,'PATH':str(bins)+os.pathsep+os.environ['PATH'],'SHUNT_GEO_DIR':str(cfg),'SHUNT_WEB_DIR':str(ROOT/'src/web'),'SHUNT_XRAY_BIN':str(tmp_path/'no-xray'),'TEST_GEO_ASSETS':str(assets)}
    return cfg,env

def run(env):
    return subprocess.run(['bash',str(ROOT/'src/scripts/update-geo.sh')],env=env,capture_output=True,text=True,timeout=10)

def test_missing_list_keeps_previous_assets(tmp_path):
    cfg,env=setup(tmp_path,'wrong-list')
    result=run(env)
    assert result.returncode!=0
    assert cfg.joinpath('geosite.dat').read_bytes()==b'old-site'
    assert cfg.joinpath('geoip.dat').read_bytes()==b'old-ip'

def test_update_records_version_and_second_run_is_unchanged(tmp_path):
    cfg,env=setup(tmp_path)
    result=run(env)
    assert result.returncode==0,result.stderr
    assert json.loads(cfg.joinpath('geo-version.json').read_text())['tag']=='test-release'
    before=cfg.joinpath('geosite.dat').stat().st_mtime_ns
    result=run(env)
    assert result.returncode==0,result.stderr
    assert 'UNCHANGED:' in result.stdout
    assert cfg.joinpath('geosite.dat').stat().st_mtime_ns==before

def test_xray_validation_failure_preserves_assets(tmp_path):
    cfg,env=setup(tmp_path)
    binary=tmp_path/'xray';binary.write_text('#!/bin/sh\nexit 23\n');binary.chmod(0o755)
    env['SHUNT_XRAY_BIN']=str(binary)
    assert run(env).returncode==23
    assert cfg.joinpath('geosite.dat').read_bytes()==b'old-site'
