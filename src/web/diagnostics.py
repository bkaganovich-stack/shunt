"""Bounded host diagnostics. Observations are not attribution of censorship.

No page JavaScript, credentials, redirects or remote DNS at the proxy. The
validated public address is pinned on both paths while TLS verifies the hostname.
"""
import concurrent.futures
import ipaddress
import json
import sys
import os
import re
import socket
import subprocess
from urllib.parse import urlsplit


def hostname(target):
    if not isinstance(target, str) or not target.strip() or len(target) > 2048:
        raise ValueError('Укажите домен или HTTPS-адрес')
    raw = target.strip()
    parsed = urlsplit(raw if '://' in raw else 'https://' + raw)
    if parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None:
        raise ValueError('Разрешён только HTTPS без имени пользователя и пароля')
    try:
        if parsed.port not in (None, 443):
            raise ValueError('Разрешён только порт 443')
        host = (parsed.hostname or '').rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        raise ValueError('Некорректный адрес или порт') from None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or '.' not in host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError('Некорректное имя домена')
    else:
        raise ValueError('Для HTTPS-диагностики укажите домен, а не IP-адрес')
    return host


def bounded_resolver(host, port, **kwargs):
    # libc getaddrinfo has no per-call timeout. Run it in a killable child so
    # broken DNS cannot occupy the gateway diagnostic worker indefinitely.
    program = "import json,socket,sys;print(json.dumps(socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)))"
    try:
        result = subprocess.run([sys.executable, '-c', program, host],
                                capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        raise socket.gaierror('DNS lookup timed out or resolver unavailable') from None
    if result.returncode:
        raise socket.gaierror('DNS lookup failed')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise socket.gaierror('Invalid resolver response') from None


def public_addresses(host, resolver=bounded_resolver):
    rows = resolver(host, 443, type=socket.SOCK_STREAM)
    addresses = sorted({r[4][0] for r in rows}, key=lambda ip: (':' in ip, ip))
    if not addresses:
        raise ValueError('DNS не вернул адресов')
    if any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError('Диагностика локальных, служебных и смешанных адресов запрещена')
    return addresses


def request(host, address, *, interface='', socks='', runner=subprocess.run):
    if not interface and not socks:
        return {'state': 'unavailable', 'detail': 'Путь для проверки не настроен'}
    ip = '[' + address + ']' if ':' in address else address
    cmd = ['curl', '-q', '--silent', '--show-error', '--proto', '=https',
           '--connect-timeout', '5', '--max-time', '12', '--max-filesize', '1048576',
           '--output', '/dev/null', '--write-out',
           '%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}',
           '--resolve', f'{host}:443:{ip}', '--noproxy', '']
    if socks:
        # socks5 (not socks5-hostname) uses our pinned, already validated address.
        cmd += ['--socks5', socks]
    else:
        cmd += ['--proxy', '', '--interface', interface]
    cmd += ['https://' + host + '/']
    env = {k: v for k, v in os.environ.items() if k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
    try:
        result = runner(cmd, capture_output=True, text=True, timeout=15, env=env)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {'state': 'failed', 'detail': str(e)[:160], 'address': address}
    parts = result.stdout.strip().split()
    code = int(parts[0]) if parts and parts[0].isdigit() and parts[0] != '000' else None
    # 63 means the bounded body limit was reached; a response was received but
    # this is not a successful page test and must never authorize an exception.
    state = 'ok' if result.returncode == 0 and code and 200 <= code < 300 else 'inconclusive'
    if result.returncode != 0:
        state = 'failed' if code is None else 'inconclusive'
    elif code in (403, 451):
        state = 'refused'
    out = {'state': state, 'http_code': code, 'curl_code': result.returncode,
           'address': address, 'detail': result.stderr.strip()[:160]}
    if len(parts) == 5:
        try:
            out['seconds'] = dict(zip(('connect', 'tls', 'first_byte', 'total'), map(float, parts[1:])))
        except ValueError:
            pass
    return out


def diagnose(target, interface, socks, resolver=bounded_resolver, probe=request):
    host = hostname(target)
    try:
        addresses = public_addresses(host, resolver)
    except socket.gaierror as e:
        return {'host': host, 'addresses': [], 'verdict': 'dns_error',
                'detail': str(e)[:160], 'recommendation': None, 'direct': {}, 'tunnel': {}}
    # One common IP isolates route effects. Report remaining IPs explicitly:
    # a failure here is not evidence that every CDN edge/family is broken.
    address = addresses[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(probe, host, address, interface=interface)
        b = pool.submit(probe, host, address, socks=socks)
        direct, tunnel = a.result(), b.result()
    recommended = direct['state'] in ('failed', 'refused') and tunnel['state'] == 'ok'
    verdict = 'tunnel_works' if recommended else 'direct_works' if direct['state'] == 'ok' else 'inconclusive'
    return {'host': host, 'addresses': addresses, 'tested_address': address,
            'direct': direct, 'tunnel': tunnel, 'verdict': verdict,
            'recommendation': 'tunnel' if recommended else None,
            'scope': 'https_root_one_address',
            'limitations': 'Проверен HTTPS-запрос / к одному IP. Редиректы, авторизация, JavaScript и ресурсы страницы не проверялись. Причина ограничения не установлена.'}
