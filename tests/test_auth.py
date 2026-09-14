"""
Tests for the two things that guard a household's gateway: the key its sessions
are signed with, and the password stored on disk.

The first exists because of a landmine rather than a bug report. `SECRET` fell
back to the literal "shunt-default-secret" when /opt/shunt/.secret was missing.
Nothing failed: the gateway came up, the interface worked, and every session
token on it could be forged by anyone who had read the source. The only symptom
was that there was no symptom.

Run:  python -m pytest tests/ -v
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import main as m  # noqa: E402


class TestTheSigningSecret:
    def test_a_missing_file_is_generated_not_substituted(self, tmp_path):
        p = tmp_path / ".secret"
        val = m.load_secret(p)
        assert val != "shunt-default-secret"
        assert len(val) >= 32
        assert p.read_text().strip() == val

    def test_a_generated_key_is_not_readable_by_anyone_else(self, tmp_path):
        p = tmp_path / ".secret"
        m.load_secret(p)
        assert p.stat().st_mode & 0o077 == 0

    def test_two_gateways_do_not_get_the_same_key(self, tmp_path):
        a = m.load_secret(tmp_path / "a")
        b = m.load_secret(tmp_path / "b")
        assert a != b

    def test_an_existing_key_is_kept(self, tmp_path):
        p = tmp_path / ".secret"
        p.write_text("  already-here  \n")
        assert m.load_secret(p) == "already-here"

    def test_a_key_others_can_read_is_repaired(self, tmp_path):
        # Reported to nobody on purpose: the only reader of such a report would
        # be whoever could already read the key.
        p = tmp_path / ".secret"
        p.write_text("abc\n")
        p.chmod(0o644)
        m.load_secret(p)
        assert p.stat().st_mode & 0o077 == 0

    def test_an_unwritable_location_still_yields_a_real_key(self, tmp_path):
        # Sessions then end at the next restart. That is an inconvenience;
        # a shared constant is a way in.
        p = tmp_path / "nope" / "deeper" / ".secret"
        p.parent.parent.mkdir()
        p.parent.mkdir(mode=0o500)
        val = m.load_secret(p)
        assert val and val != "shunt-default-secret"

    def test_an_empty_file_counts_as_missing(self, tmp_path):
        p = tmp_path / ".secret"
        p.write_text("   \n")
        assert m.load_secret(p) not in ("", "shunt-default-secret")


class TestStoringAPassword:
    def test_round_trip(self):
        h = m.hash_password("correct horse")
        assert m.verify_password("correct horse", h)
        assert not m.verify_password("Correct horse", h)

    def test_two_identical_passwords_do_not_share_a_hash(self):
        # Which is what a salt is for: one leaked hash must not identify every
        # gateway using the same password.
        assert m.hash_password("admin") != m.hash_password("admin")

    def test_the_old_format_still_opens_the_door(self, ):
        import hashlib
        legacy = hashlib.sha256(b"admin").hexdigest()
        assert m.verify_password("admin", legacy)
        assert not m.verify_password("wrong", legacy)

    def test_the_old_format_is_recognised_as_old(self):
        import hashlib
        assert m.is_legacy_hash(hashlib.sha256(b"admin").hexdigest())
        assert not m.is_legacy_hash(m.hash_password("admin"))

    def test_rubbish_is_refused_rather_than_crashed_on(self):
        for bad in ("", None, "pbkdf2$", "pbkdf2$notanumber$zz$zz", "short"):
            assert m.verify_password("admin", bad) is False


class TestSessionsEndWhenThePasswordChanges:
    def _settings(self, tmp_path, pwhash):
        p = tmp_path / "settings.json"
        p.write_text(json.dumps({"auth": {"username": "admin",
                                          "password_hash": pwhash}}))
        return p

    def test_a_token_survives_while_the_password_does(self, tmp_path, monkeypatch):
        monkeypatch.setattr(m, "SETTINGS", self._settings(tmp_path, "hash-one"))
        monkeypatch.setattr(m, "_sign_key", (None, None))
        tok = m.make_token("admin")
        assert m.verify_token(tok) == "admin"

    def test_changing_the_password_invalidates_every_token(self, tmp_path, monkeypatch):
        # The reason anybody changes a password in a hurry is to end a session
        # they do not control. A token that outlives the change does not do that.
        p = self._settings(tmp_path, "hash-one")
        monkeypatch.setattr(m, "SETTINGS", p)
        monkeypatch.setattr(m, "_sign_key", (None, None))
        tok = m.make_token("admin")
        assert m.verify_token(tok) == "admin"

        time.sleep(0.01)
        p.write_text(json.dumps({"auth": {"username": "admin",
                                          "password_hash": "hash-two"}}))
        assert m.verify_token(tok) is None

    def test_an_expired_token_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(m, "SETTINGS", self._settings(tmp_path, "h"))
        monkeypatch.setattr(m, "_sign_key", (None, None))
        monkeypatch.setattr(m.time, "time", lambda: 1_000_000)
        tok = m.make_token("admin")
        monkeypatch.setattr(m.time, "time", lambda: 1_000_000 + 86401)
        assert m.verify_token(tok) is None

    def test_a_forged_signature_is_refused(self, tmp_path, monkeypatch):
        import base64
        monkeypatch.setattr(m, "SETTINGS", self._settings(tmp_path, "h"))
        monkeypatch.setattr(m, "_sign_key", (None, None))
        forged = base64.urlsafe_b64encode(
            b"admin:%d:%s" % (int(time.time()) + 60, b"0" * 64)).decode()
        assert m.verify_token(forged) is None

    def test_rubbish_is_not_a_session(self):
        for bad in ("", "....", "!!!!", "YWRtaW4="):
            assert m.verify_token(bad) is None
