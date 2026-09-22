"""Profile editor endpoints; mutations preserve every unrelated settings field."""
import asyncio
import copy
import hashlib
import ipaddress
import json
import secrets
import time

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
import profiles as p
import diagnostics as diag
import geosite


class Edit(BaseModel):
    config: dict
    revision: str

class Version(BaseModel):
    revision: str

class CopyProfile(BaseModel):
    name: str = Field(min_length=1, max_length=80)

class Preview(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    config: dict | None = None
    source_ip: str | None = None

class Diagnose(BaseModel):
    target: str = Field(min_length=1, max_length=2048)

class ApplyDiagnosis(BaseModel):
    report_id: str


def revision(settings, ident):
    value = p.effective(settings, ident)
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:20]


def available_lists(m):
    return sorted(kind + ":" + name.lower()
                  for kind, path in (("geosite", m.GEOSITE_DAT), ("geoip", m.GEOIP_DAT))
                  for name in geosite.categories(path))


def validate_added_lists(m, old, new, ident):
    added = set(p.effective(new, ident)["tunnel_lists"]) - set(p.effective(old, ident)["tunnel_lists"])
    missing = sorted(added - set(available_lists(m))) if added else []
    if missing:
        raise HTTPException(400, "В установленных базах нет списков: " + ", ".join(missing) + ". Обновите геобазы или выберите другой список.")


def catalog(settings):
    result = p.catalog(settings)
    for row in result['profiles']:
        row['revision'] = revision(settings, row['id'])
    return result


def used(settings, ident):
    return (settings.get('profile', 'all_except_ru') == ident
            or settings.get('fallback_saved_profile') == ident
            or any(d.get('policy') == ident for d in settings.get('devices', {}).values())
            or any(g.get('routing_policy') == ident for g in settings.get('groups', [])))


def path_revision(m, settings):
    keys = ('egress_active', 'adguard', 'fptn', 'vpn_key', 'vpn_servers', 'active_vpn_id', 'dns')
    state = {k: settings.get(k) for k in keys}
    state['paths'] = m._ft._probe_paths(settings)
    # FPTN server selection is stored outside settings.json.
    try:
        state['fptn_server'] = m.FPTN_SERVER_FILE.read_text()
    except (AttributeError, OSError):
        state['fptn_server'] = None
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()


def persist(m, old, new, ident, reason):
    # Synchronous transaction: no await between read, compilation and persistence.
    # The compiler/apply path validates required lists before writing xray.json.
    validate_added_lists(m, old, new, ident)
    if new == old:
        return {"ok": True, **catalog(new)}
    if used(old, ident) or used(new, ident):
        ok, error = m.apply_config(new, reason, _pre_settings=old)
        if not ok:
            m.save_settings(old)
            raise HTTPException(409, error or 'Не удалось применить профиль')
    m.save_settings(new)
    return {'ok': True, **catalog(new)}


def register(app, m):
    reports = {}
    busy = set()
    last_run = {}

    def same_origin(req):
        origin = req.headers.get('origin')
        if origin and origin != str(req.base_url).rstrip('/'):
            raise HTTPException(403, 'Cross-origin request rejected')
        if req.headers.get('sec-fetch-site') == 'cross-site':
            raise HTTPException(403, 'Cross-site request rejected')

    def get(ident):
        settings = m.load_settings()
        try:
            p.effective(settings, ident)
        except ValueError as e:
            raise HTTPException(404, str(e)) from e
        return settings

    def check_revision(settings, ident, expected):
        if revision(settings, ident) != expected:
            raise HTTPException(409, 'Профиль изменился. Обновите данные и повторите действие')

    @app.get('/api/profiles')
    async def get_profiles(u: str = Depends(m.auth_dep)):
        return {**catalog(m.load_settings()), "available_lists": available_lists(m)}

    @app.put('/api/profiles/{ident}')
    async def edit(ident: str, body: Edit, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        old = get(ident)
        check_revision(old, ident, body.revision)
        try:
            new = p.update(old, ident, body.config)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return persist(m, old, new, ident, 'profile_edit')

    @app.post('/api/profiles/{ident}/reset')
    async def reset(ident: str, body: Version, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        old = get(ident)
        check_revision(old, ident, body.revision)
        try:
            new = p.reset(old, ident)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return persist(m, old, new, ident, 'profile_reset')

    @app.post('/api/profiles/{ident}/undo')
    async def undo(ident: str, body: Version, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        old = get(ident)
        check_revision(old, ident, body.revision)
        try:
            new = p.undo(old, ident)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return persist(m, old, new, ident, 'profile_undo')

    @app.post('/api/profiles/{ident}/copy')
    async def clone(ident: str, body: CopyProfile, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        old = get(ident)
        try:
            new = p.clone(old, ident, body.name)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        new_id = next(iter(set(new.get('custom_profiles', {})) - set(old.get('custom_profiles', {}))))
        m.save_settings(new)
        return {'ok': True, 'created_id': new_id, **catalog(new)}

    @app.post('/api/profiles/{ident}/preview')
    async def preview(ident: str, body: Preview, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        settings = get(ident)
        try:
            if body.source_ip:
                ipaddress.ip_address(body.source_ip)
            if body.config is not None:
                settings = p.update(settings, ident, body.config)
            validate_added_lists(m, get(ident), settings, ident)
            # Hostnames only in this entry point. URL paths are not routing keys.
            host = diag.hostname(body.target)
            result = m.route_test(host, settings, profile_id=ident, source_ip=body.source_ip)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return {'profile_id': ident, 'preview': result, 'applied': False}

    @app.post('/api/profiles/{ident}/diagnose')
    async def diagnose(ident: str, body: Diagnose, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        settings = get(ident)
        now = time.monotonic()
        if busy or now - last_run.get(u, -100) < 5:
            raise HTTPException(429, 'Диагностика уже выполняется или была запущена недавно')
        try:
            host = diag.hostname(body.target)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        busy.add(u)
        last_run[u] = now
        before = revision(settings, ident)
        measured_path = path_revision(m, settings)
        wan, socks = m._ft._probe_paths(settings)
        task = asyncio.create_task(asyncio.to_thread(diag.diagnose, host, wan, socks))
        try:
            result = await asyncio.wait_for(asyncio.shield(task), timeout=35)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        except asyncio.TimeoutError:
            raise HTTPException(504, 'Время диагностики истекло') from None
        finally:
            if task.done():
                busy.discard(u)
            else:
                task.add_done_callback(lambda finished: (busy.discard(u), finished.exception() if not finished.cancelled() else None))
        token = secrets.token_urlsafe(24)
        # Bound lifetime/space. Reports contain no URL paths, credentials or body.
        for key in list(reports):
            if reports[key]['expires'] < now:
                reports.pop(key)
        if len(reports) >= 64:
            reports.pop(next(iter(reports)))
        reports[token] = {'user': u, 'profile': ident, 'revision': before,
                          'expires': now + 900, 'path_revision': measured_path, 'result': copy.deepcopy(result)}
        return {'report_id': token, 'profile_id': ident, **result}

    @app.post('/api/profiles/{ident}/apply-diagnosis')
    async def apply_diagnosis(ident: str, body: ApplyDiagnosis, req: Request, u: str = Depends(m.auth_dep)):
        same_origin(req)
        old = get(ident)
        record = reports.get(body.report_id)
        if not record or record['user'] != u or record['profile'] != ident or record['expires'] < time.monotonic():
            raise HTTPException(409, 'Отчёт истёк. Повторите диагностику')
        check_revision(old, ident, record['revision'])
        if record['path_revision'] != path_revision(m, old):
            raise HTTPException(409, 'Выход или DNS изменились после проверки. Повторите диагностику')
        if record['result'].get('recommendation') != 'tunnel':
            raise HTTPException(400, 'Диагностика не подтвердила рабочий обход')
        cfg = next(r['config'] for r in p.catalog(old)['profiles'] if r['id'] == ident)
        cfg['extra_tunnel_domains'] = sorted(set(cfg['extra_tunnel_domains'] + [record['result']['host']]))
        try:
            new = p.update(old, ident, cfg)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        decision = m.route_test(record['result']['host'], new, profile_id=ident)
        if decision.get('outbound') != 'proxy':
            raise HTTPException(409, 'Правило перекрыто другим правилом или туннель не настроен: ' + str(decision.get('matched_rule', '')))
        result = persist(m, old, new, ident, 'profile_diagnosis')
        reports.pop(body.report_id, None)
        return result
