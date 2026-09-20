"""Browser reloads must not mix UI revisions, including same-version updates."""
import os
import sys
from pathlib import Path
from html.parser import HTMLParser
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/web'))
import main


class Resources(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.urls = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and 'src' in attrs:
            self.urls.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.urls.append(attrs['href'])


def test_same_version_update_changes_only_changed_resource_url(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'STATIC', tmp_path)
    (tmp_path / 'index.html').write_text('<link rel="stylesheet" href="/static/ui.css"><script src="/static/ui.js"></script>')
    (tmp_path / 'ui.css').write_text('body {color:red}')
    script = tmp_path / 'ui.js'
    script.write_text('/* old */')
    client = TestClient(main.app)
    before = client.get('/')
    urls = Resources(before.text).urls
    assert all('?v=' in url for url in urls)
    assert client.get(urls[1]).text == '/* old */'
    assert Resources(client.get('/').text).urls == urls
    stat = script.stat()
    script.write_text('/* new */')
    os.utime(script, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    after = Resources(client.get('/').text).urls
    assert after[0] == urls[0]
    assert after[1] != urls[1]
    assert client.get(after[1]).text == '/* new */'


def test_html_and_unversioned_resources_require_revalidation(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'STATIC', tmp_path)
    (tmp_path / 'index.html').write_text('<h1>Shunt</h1>')
    (tmp_path / 'ui.js').write_text('/* UI */')
    client = TestClient(main.app)
    for url in ('/', '/routing/geo', '/static/ui.js'):
        response = client.get(url)
        assert response.status_code == 200
        assert 'no-cache' in response.headers.get('cache-control', '')
