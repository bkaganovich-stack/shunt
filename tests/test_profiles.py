"""Profile persistence, source policy parity and ordered routing constraints."""
import copy
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
sys.path.insert(0, str(Path(__file__).parents[1] / 'src/web'))
import profiles as p
import main as m


def base(**kw):
    s = copy.deepcopy(m.DEFAULT_SETTINGS)
    s.update(kw)
    return s


def test_save_reset_undo_are_local_and_detached():
    s = base(custom_rules={'always_vpn': ['example.com']}, devices={'x': {'policy': 'all'}})
    original = copy.deepcopy(s)
    changed = p.update(s, 'blocked_only', {'services': ['openai'], 'default_route': 'tunnel'})
    assert s == original
    changed['devices']['x']['ips'] = ['1.2.3.4']
    assert 'ips' not in s['devices']['x']
    reset = p.reset(changed, 'blocked_only')
    restored = p.undo(reset, 'blocked_only')
    assert p.effective(restored, 'blocked_only')['services'] == ['openai']
    assert restored['custom_rules'] == s['custom_rules']
    assert restored['devices'] == changed['devices']
    assert 'blocked_only' not in restored['profile_history']


def test_clone_identity_reset_and_copy_of_copy_keep_family():
    s = p.clone(base(), 'blocked_only', 'My copy')
    ident = next(iter(s['custom_profiles']))
    changed = p.update(s, ident, {'name': 'Renamed', 'services': ['youtube']})
    assert p.effective(p.reset(changed, ident), ident)['name'] == 'My copy'
    twice = p.clone(changed, ident, 'Second')
    second = next(k for k in twice['custom_profiles'] if k != ident)
    assert twice['custom_profiles'][second]['copied_from'] == 'blocked_only'
    assert ident in p.ids(twice)


@pytest.mark.parametrize('config', [
    {'tunnel_lists': ['geosite:antifilter-download-community']}, {'services': ['unknown']},
    {'use_discovered': 1}, {'default_route': 'proxy'}, {'name': 'a' * 81},
    {'extra_tunnel_domains': ['*.example.com']}, {'extra_tunnel_domains': ['127.0.0.1']},
    {'extra_tunnel_domains': ['private.local']}, {'extra_tunnel_domains': ['https://example.com']},
])
def test_invalid_config_is_rejected(config):
    with pytest.raises(ValueError):
        p.update(base(), 'blocked_only', config)


def test_emergency_direct_cannot_change_default():
    with pytest.raises(ValueError):
        p.update(base(), 'direct', {'default_route': 'tunnel'})


def test_priority_and_no_duplicate_antifilter():
    s = p.update(base(profile='blocked_only'), 'blocked_only', {'services': ['openai'], 'extra_tunnel_domains': ['one.example.com']})
    rules = m._profile_rules(s, 'blocked_only', 'proxy')
    assert rules[0]['domain'] == ['geosite:ru-available-only-inside']
    assert next(i for i,r in enumerate(rules) if r.get('_reason') == 'service:openai') < next(i for i,r in enumerate(rules) if r.get('_reason') == 'geoip:ru')
    assert any(r.get('domain') == ['full:one.example.com'] for r in rules)
    assert 'antifilter-download-community' not in str(rules)


def test_shared_compiler_source_preview_and_global_manual_precedence():
    s = p.clone(base(profile='blocked_only', realtime_direct=False), 'all', 'Device VPN')
    ident = next(iter(s['custom_profiles']))
    s['devices'] = {'x': {'ips': ['192.168.1.50'], 'policy': ident}}
    with patch.object(m, '_get_active_vpn_outbound', return_value=([], True, None)), patch.object(m, 'get_arp_table', return_value=[]), patch.object(m, '_ip_in_geoip_ru', return_value=False), patch.object(m, '_ip_in_geoip', return_value=False):
        scoped = m.route_test('8.8.8.8', s, source_ip='192.168.1.50')
        global_result = m.route_test('8.8.8.8', s)
        assert scoped['outbound'] == 'proxy'
        assert global_result['outbound'] == 'direct'
        s['custom_rules'] = {'always_direct': ['8.8.8.8']}
        assert m.route_test('8.8.8.8', s, source_ip='192.168.1.50')['matched_rule'] == 'custom:always_direct'
        assert m.route_test('8.8.8.8', s, profile_id='direct', source_ip='192.168.1.50')['outbound'] == 'direct'


def test_confirmed_domain_overrides_ru_ip_but_ru_only_wins():
    s = p.update(base(profile='blocked_only'), 'blocked_only', {'extra_tunnel_domains': ['one.example.com']})
    with patch.object(m, '_get_active_vpn_outbound', return_value=([], True, None)), patch('socket.getaddrinfo', return_value=[(2,1,6,'',('1.2.3.4',0))]), patch.object(m, '_ip_in_geoip_ru', return_value=True), patch.object(m, '_domain_in_any_geosite', return_value=None):
        assert m.route_test('one.example.com', s)['outbound'] == 'proxy'
        assert m.route_test('child.one.example.com', s)['outbound'] == 'direct'
        with patch.object(m, '_domain_in_any_geosite', side_effect=lambda d, refs: refs[0] if refs == ['geosite:ru-available-only-inside'] else None):
            assert m.route_test('one.example.com', s)['outbound'] == 'direct'


def test_legacy_preferences_are_modified_and_reset_is_profile_local():
    s = base(force_aaplimg_vpn=False, realtime_direct=False)
    rows = {x['id']: x for x in p.catalog(s)['profiles']}
    assert rows['blocked_only']['modified']
    assert not rows['blocked_only']['config']['apple_vpn']
    reset = p.reset(s, 'blocked_only')
    assert p.effective(reset, 'blocked_only')['apple_vpn']
    assert p.effective(reset, 'blocked_only')['realtime_direct']
    assert not p.effective(reset, 'all_except_ru')['apple_vpn']
    assert reset['force_aaplimg_vpn'] is False
    assert p.effective(p.undo(reset, 'blocked_only'), 'blocked_only') == p.effective(s, 'blocked_only')


def test_group_copy_uses_same_compiler_and_device_wins():
    s = p.clone(base(profile='blocked_only'), 'all', 'Group VPN')
    ident = next(iter(s['custom_profiles']))
    s['devices'] = {'x': {'ips': ['192.168.1.50'], 'policy': 'inherit'}}
    s['groups'] = [{'id': 'g', 'name': 'Group', 'devices': ['x'], 'routing_policy': ident}]
    assert not m._ft.validate_group(s['groups'][0], s)
    with patch.object(m, '_get_active_vpn_outbound', return_value=([], True, None)), patch.object(m, 'get_arp_table', return_value=[]), patch.object(m, '_ip_in_geoip_ru', return_value=False), patch.object(m, '_ip_in_geoip', return_value=False):
        assert m.route_test('8.8.8.8', s, source_ip='192.168.1.50')['outbound'] == 'proxy'
        s['devices']['x']['policy'] = 'always_direct'
        assert m.route_test('8.8.8.8', s, source_ip='192.168.1.50')['outbound'] == 'direct'


def test_noop_does_not_erase_last_meaningful_undo():
    original = base(profile='blocked_only')
    changed = p.update(original, 'blocked_only', {'services': []})
    repeated = p.update(changed, 'blocked_only', {'services': []})
    assert repeated == changed
    assert p.effective(p.undo(repeated, 'blocked_only'), 'blocked_only') == p.effective(original, 'blocked_only')
    reset = p.reset(changed, 'blocked_only')
    assert p.reset(reset, 'blocked_only') == reset
