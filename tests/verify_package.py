"""Verify an uninstalled Shunt .deb, then write checksum and check results beside it."""
from pathlib import Path
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile


def verify(deb):
    root = Path(__file__).resolve().parents[1]
    version = re.search(r'^VERSION = "([^"]+)"', (root / 'src/web/main.py').read_text(), re.M)[1]
    data = tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)])))
    control = tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)])))
    files = {m.name.removeprefix('./'): m for m in data.getmembers() if m.isfile()}
    assert all(m.uid == m.gid == 0 for m in data.getmembers()), 'Non-root archive ownership'
    assert not any('__pycache__' in n or n.endswith(('.pyc', '.DS_Store')) or '/._' in n for n in files), 'Build-host litter'
    sources = list((root / 'src/web/static').rglob('*')) + list((root / 'src/web').glob('*.py'))
    for src in sources:
        if src.is_file():
            target = 'opt/shunt/web/' + str(src.relative_to(root / 'src/web'))
            assert data.extractfile(files[target]).read() == src.read_bytes(), target
    ct = {m.name.removeprefix('./'): m for m in control.getmembers() if m.isfile()}
    meta = control.extractfile(ct['control']).read().decode()
    assert f'Version: {version}\n' in meta and 'Architecture: all\n' in meta, meta
    md5 = control.extractfile(ct['md5sums']).read().decode().splitlines()
    recorded = set()
    for line in md5:
        checksum, name = line.split('  ', 1)
        assert hashlib.md5(data.extractfile(files[name]).read()).hexdigest() == checksum, name
        recorded.add(name)
    conffiles = set(control.extractfile(ct['conffiles']).read().decode().strip().splitlines())
    assert recorded | {n.lstrip('/') for n in conffiles} == set(files), 'Incomplete checksum coverage'
    for name in ['postinst', 'prerm', 'postrm']:
        assert ct[name].mode == 0o755, name
        subprocess.run(['sh', '-n'], input=control.extractfile(ct[name]).read(), check=True)
    for name, member in files.items():
        if name.endswith('.py'):
            compile(data.extractfile(member).read(), name, 'exec')
        if name.startswith(('opt/shunt/scripts/', 'usr/sbin/')):
            assert member.mode in (0o755, 0o750), (name, member.mode)
    checks = dict(version=version, architecture='all', payload_files=len(files), verified_md5=len(md5),
                  root_ownership=True, sources_match=True, maintainer_script_syntax=True,
                  python_syntax=True, no_caches=True, sha256=hashlib.sha256(deb.read_bytes()).hexdigest(),
                  bytes=deb.stat().st_size)
    (deb.parent / 'package-checks.json').write_text(json.dumps(checks, indent=2) + '\n')
    (deb.parent / 'SHA256SUMS').write_text(checks['sha256'] + '  ' + deb.name + '\n')
    print(json.dumps(checks, indent=2))


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
