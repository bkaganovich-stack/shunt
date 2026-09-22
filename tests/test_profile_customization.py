"""User-defined profile routes must persist and predict the compiled route."""
import copy
import ipaddress
from unittest.mock import patch
import pytest
from test_profiles import base, m, p
from test_profile_api import api, row
from test_geosite import _dat, _entry


def test_replace_and_extend_lists_without_changing_defaults():
    original = base()
    edited = p.update(original, 'blocked_only', {'tunnel_lists': ['geosite:ru-blocked-all', 'geosite:github', 'geoip:telegram']})
    rules = m._profile_rules(edited, 'blocked_only', 'proxy')
    assert any(r.get('domain') == ['geosite:ru-blocked-all', 'geosite:github'] for r in rules)
    assert any(r.get('ip') == ['geoip:telegram'] for r in rules)
    assert p.effective(original, 'blocked_only')['tunnel_lists'] == ['geosite:ru-blocked', 'geoip:ru-blocked', 'geoip:ru-blocked-community']
    assert p.effective(p.undo(edited, 'blocked_only'), 'blocked_only') == p.effective(original, 'blocked_only')


def test_disabled_list_stays_in_profile_but_is_not_compiled():
    original = base()
    edited = p.update(original, 'blocked_only', {'disabled_tunnel_lists': ['geosite:ru-blocked']})
    assert p.effective(edited, 'blocked_only')['tunnel_lists'] == ['geosite:ru-blocked', 'geoip:ru-blocked', 'geoip:ru-blocked-community']
    assert p.effective(edited, 'blocked_only')['disabled_tunnel_lists'] == ['geosite:ru-blocked']
    rules = m._profile_rules(edited, 'blocked_only', 'proxy')
    assert not any('geosite:ru-blocked' in (r.get('domain') or []) for r in rules)
    assert any('geoip:ru-blocked' in (r.get('ip') or []) for r in rules)


def test_disabled_list_must_be_selected():
    with pytest.raises(ValueError):
        p.update(base(), 'blocked_only', {'disabled_tunnel_lists': ['geosite:github']})


@pytest.mark.parametrize('value', ['https://example.com/list', 'geosite:../../file', 'geosite:foo@bar', 'geoip:', 'ext:a.dat:b'])
def test_invalid_list_reference(value):
    with pytest.raises(ValueError):
        p.update(base(), 'blocked_only', {'tunnel_lists': [value]})


def test_custom_rule_order_preview_and_scope():
    original = base(profile='blocked_only')
    rules = [{'kind': 'full', 'value': 'api.example.com', 'route': 'direct'},
             {'kind': 'domain', 'value': 'example.com', 'route': 'tunnel'},
             {'kind': 'ip', 'value': '8.8.8.0/24', 'route': 'tunnel'}]
    edited = p.update(original, 'blocked_only', {'custom_rules': rules})
    with patch.object(m, '_get_active_vpn_outbound', return_value=([], True, None)), patch('socket.getaddrinfo', return_value=[(2,1,6,'',('1.2.3.4',0))]), patch.object(m, '_domain_in_any_geosite', return_value=None), patch.object(m, '_ip_in_geoip', return_value=False):
        for host, outbound in [('api.example.com', 'direct'), ('www.example.com', 'proxy'), ('8.8.8.8', 'proxy')]:
            assert m.route_test(host, edited)['outbound'] == outbound
        assert m.route_test('www.example.com', original)['outbound'] == 'direct'
        edited['custom_rules'] = {'always_direct': ['domain:example.com']}
        assert m.route_test('www.example.com', edited)['matched_rule'] == 'custom:always_direct'
        assert m.route_test('8.8.8.8', edited, profile_id='direct')['outbound'] == 'direct'
        with patch.object(m, '_domain_in_any_geosite', side_effect=lambda d,refs: refs[0] if refs == ['geosite:ru-available-only-inside'] else None):
            assert m.route_test('www.example.com', edited)['outbound'] == 'direct'
    assert p.effective(p.reset(edited, 'blocked_only'), 'blocked_only')['custom_rules'] == []


@pytest.mark.parametrize('rule', [
    {'kind': 'full', 'value': '*.example.com', 'route': 'direct'},
    {'kind': 'domain', 'value': 'https://example.com', 'route': 'tunnel'},
    {'kind': 'ip', 'value': '1.2.3.4/99', 'route': 'direct'},
    {'kind': 'ip', 'value': '1.2.3.4', 'route': 'unknown'},
    {'kind': 'regex', 'value': '.*', 'route': 'tunnel'},
])
def test_invalid_custom_rules(rule):
    with pytest.raises(ValueError):
        p.update(base(), 'blocked_only', {'custom_rules': [rule]})


def test_old_custom_profile_has_no_spurious_modification():
    s = p.clone(base(), 'blocked_only', 'Legacy')
    ident = next(iter(s['custom_profiles']))
    for key in ('config', 'original'):
        s['custom_profiles'][ident][key].pop('custom_rules', None)
    assert p.effective(s, ident)['custom_rules'] == []
    assert not next(r for r in p.catalog(s)['profiles'] if r['id'] == ident)['modified']


def test_preview_reads_nonpreset_categories_after_cache_warmup(tmp_path, monkeypatch):
    path = _dat(tmp_path, [('ru-blocked', ['old.example']), ('ru-blocked-all', ['new.example']), ('github', ['git.example'])])
    monkeypatch.setattr(m, 'GEOSITE_DAT', path)
    monkeypatch.setattr(m, '_geosite_sets', {})
    assert m._domain_in_geosite('old.example', 'ru-blocked')
    assert m._domain_in_geosite('new.example', 'ru-blocked-all')
    assert m._domain_in_geosite('git.example', 'github')
    assert m._domain_in_geosite('old.example', 'ru-blocked')
    name = b'TELEGRAM'
    cidr = b'\x0a\x04\x08\x08\x08\x00\x10\x18'
    entry = b'\x0a' + bytes([len(name)]) + name + b'\x12' + bytes([len(cidr)]) + cidr
    (tmp_path/'geoip.dat').write_bytes(b'\x0a' + bytes([len(entry)]) + entry)
    monkeypatch.setattr(m, 'CFG_DIR', tmp_path)
    monkeypatch.setattr(m, '_geoip_ru_nets', None)
    m._load_geoip('RU')
    assert m._ip_in_geoip('8.8.8.8', ['geoip:telegram'])


def test_missing_new_list_rejected_even_for_inactive_profile(api, monkeypatch, tmp_path):
    client, state, calls = api
    monkeypatch.setattr(m, 'GEOSITE_DAT', _dat(tmp_path, [('github', ['github.com'])]))
    monkeypatch.setattr(m, 'GEOIP_DAT', tmp_path/'geoip.dat')
    before = copy.deepcopy(state)
    r = row(client, 'all')
    result = client.put('/api/profiles/all', json={'revision': r['revision'], 'config': {'tunnel_lists': ['geosite:no-such-list']}})
    assert result.status_code == 400
    assert 'geosite:no-such-list' in result.json()['detail']
    assert state == before and not calls
    result = client.put('/api/profiles/all', json={'revision': r['revision'], 'config': {'tunnel_lists': ['geosite:github']}})
    assert result.status_code == 200
    assert row(client, 'all')['config']['tunnel_lists'] == ['geosite:github']
    assert 'geosite:github' in client.get('/api/profiles').json()['available_lists']
