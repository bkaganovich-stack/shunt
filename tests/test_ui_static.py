"""Contract checks for the unbundled UI served by the existing gateway."""
from html.parser import HTMLParser
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / 'src/web/static'

class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and attrs.get('src'):
            self.paths.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.paths.append(attrs['href'])

def test_gateway_serves_every_runtime_asset_without_external_dependencies():
    assets = Assets()
    assets.feed((STATIC / 'index.html').read_text())
    assert {'/static/ui.css', '/static/ui-model.js', '/static/ui.js'} <= set(assets.paths)
    for asset in assets.paths:
        assert asset.startswith('/static/'), asset
        assert (STATIC / asset.removeprefix('/static/')).is_file(), asset
    html = (STATIC / 'index.html').read_text()
    assert 'href="/favicon.svg"' in html
    assert (STATIC / 'favicon.svg').is_file()

def test_ui_is_initialized_before_authentication_can_show_the_app():
    html = (STATIC / 'index.html').read_text()
    assert html.index('src="/static/ui-model.js"') < html.index('src="/static/ui.js"') < html.index("'/api/auth-check'")



def test_concerns_live_where_the_overview_banner_points():
    # "Обнаружены замечания" links to #diagnostics/path; until 2.32.6 the list
    # and its "Принято" sat on the profile page, where no one looked.
    html = (Path(__file__).resolve().parents[1] / "src/web/static/index.html").read_text()
    path = html[html.index('<div id="page-path"'):html.index('<div id="page-geo"')]
    assert 'id="attention-banner"' in path
    assert html.count('id="attention-banner"') == 1
    ui = (Path(__file__).resolve().parents[1] / "src/web/static/ui.js").read_text()
    assert "link.href='#diagnostics/path'" in ui
