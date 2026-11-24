"""Static checks on the front end.

There is no JS test runner here, and a browser is not available in CI, so these
catch the two failure modes that have actually happened: a variable left
undeclared by an edit, and a DOM id the script reaches for that the template
does not define. Both are silent server-side and fatal in the browser.
"""
import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "threat_detector" / "static"
TEMPLATE = (
    Path(__file__).resolve().parent.parent / "threat_detector" / "templates" / "index.html"
)


def _scripts():
    return {path.name: path.read_text() for path in STATIC.glob("*.js")}


@pytest.mark.parametrize("name", ["app.js", "charts.js"])
def test_script_is_present(name):
    assert (STATIC / name).exists()


def test_every_id_the_script_uses_exists_in_the_template():
    html = TEMPLATE.read_text()
    declared = set(re.findall(r'id="([^"]+)"', html))
    used = set(re.findall(r'\$\("([^"]+)"\)', _scripts()["app.js"]))
    missing = used - declared
    assert not missing, f"app.js reads ids the template does not define: {sorted(missing)}"


def test_no_identifier_is_used_without_being_declared():
    """Specifically: a module-level `let` deleted by an edit elsewhere."""
    source = _scripts()["app.js"]
    for name in ("unitLabel", "TOKEN_KEY", "sleep"):
        assert re.search(rf"\b(?:let|const|var|function)\s+{name}\b", source), (
            f"{name} is used but never declared in app.js"
        )


def test_packet_data_is_never_written_as_markup():
    """Packet fields are attacker-influenced; they must not build HTML."""
    for name, source in _scripts().items():
        stripped = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
        stripped = re.sub(r"//.*", "", stripped)
        assert "innerHTML" not in stripped, f"{name} assigns innerHTML"
        assert "document.write" not in stripped
        assert "eval(" not in stripped


def test_the_csrf_header_is_sent():
    assert "X-Requested-With" in _scripts()["app.js"]


def test_the_token_is_not_kept_in_a_cookie():
    """A cookie rides along on cross-site requests; that is the CSRF property."""
    source = _scripts()["app.js"]
    assert "sessionStorage" in source
    assert "document.cookie" not in source


def test_template_loads_no_third_party_code():
    """The CSP says script-src 'self'; the template has to agree."""
    html = TEMPLATE.read_text()
    assert "http://" not in html and "https://" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), "inline script in template"
