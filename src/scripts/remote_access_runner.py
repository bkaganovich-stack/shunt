#!/usr/bin/env python3
"""
Keeps the gateway reachable from outside: one outbound ssh to a server the
owner keeps, with a reverse forward on that server's loopback, proved by an
end-to-end check. Run by shunt-remote-access.service; off unless switched on
on the page. Design and server-side setup: docs/REMOTE_ACCESS.md.

The supervisor runs as root because it reads settings.json and the egress
configuration, both root-only. Every ssh it starts runs as the shunt-ra
account, which owns the key and nothing else. Nothing here routes, touches
iptables or enters a namespace: an egress is used as a SOCKS client, the way
every probe uses it, so the namespaces stay exactly as fail-closed as before.
"""
from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

BASE = Path("/opt/shunt")
sys.path.insert(0, str(BASE / "web"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))

import egresses as eg          # noqa: E402
import remote_access as ra     # noqa: E402

SETTINGS = BASE / "config" / "settings.json"
UP_WAIT = 45          # s for a new session to pass its first check
PROBE_TIMEOUT = 15
STDERR_CAP = 4096


def load_settings(path: Path = SETTINGS) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def local_banner(timeout: float = 5) -> str | None:
    """The gateway's own sshd banner, read on 127.0.0.1:22."""
    try:
        with socket.create_connection(("127.0.0.1", 22), timeout=timeout) as s:
            return s.recv(255).split(b"\n", 1)[0].strip().decode("ascii", "replace")
    except OSError:
        return None


def banner_matches(got: bytes, local: str | None) -> bool:
    """The check passes only on the gateway's own banner. When the local sshd
    cannot be read (it should always be), any SSH banner has to do."""
    first = got.split(b"\n", 1)[0].strip().decode("ascii", "replace")
    if not first.startswith("SSH-"):
        return False
    return local is None or first == local


class Runner:
    """One supervisor. The methods that start processes or sleep are the ones
    a test replaces; the ladder and the status logic run as they are."""

    def __init__(self):
        self.backoff = ra.BACKOFF_MIN
        self.since: float | None = None
        self._code = self._code_stamp()

    # ── side effects (replaced in tests) ─────────────────────────────────────
    def now(self) -> float:
        return time.time()

    def sleep(self, s: float) -> None:
        time.sleep(s)

    def settings(self) -> dict:
        return load_settings()

    def has_key(self) -> bool:
        return ra.KEY.exists() and ra.KEY.with_suffix(".pub").exists()

    def has_host_key(self) -> bool:
        try:
            return ra.KNOWN_HOSTS.read_text().strip() != ""
        except OSError:
            return False

    def write_status(self, st: dict) -> None:
        st = dict(st, updated_at=self.now())
        ra.RUN_DIR.mkdir(parents=True, exist_ok=True)
        tmp = ra.STATUS.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False))
        os.chmod(tmp, 0o644)
        os.replace(tmp, ra.STATUS)

    def _as_account(self) -> dict:
        return {"user": ra.ACCOUNT, "group": ra.ACCOUNT, "extra_groups": [],
                "env": {"HOME": str(ra.HOME), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                "cwd": str(ra.HOME)}

    def prepare(self, cfg: dict, proxy) -> None:
        """A fresh ssh directory and config for this road."""
        import pwd
        ra.SSH_DIR.mkdir(parents=True, exist_ok=True)
        pw = pwd.getpwnam(ra.ACCOUNT)
        os.chown(ra.SSH_DIR, pw.pw_uid, pw.pw_gid)
        os.chmod(ra.SSH_DIR, 0o700)
        try:
            ra.CONTROL.unlink()
        except OSError:
            pass
        ra.SSH_CONFIG.write_text(ra.ssh_config(cfg, proxy))
        os.chmod(ra.SSH_CONFIG, 0o644)

    def spawn_master(self, cfg: dict):
        return subprocess.Popen(ra.master_argv(cfg), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                **self._as_account())

    def probe(self, cfg: dict) -> bool:
        """End to end: server loopback → back down the forward → our sshd."""
        if not ra.CONTROL.exists():
            return False          # never let the probe open a second connection
        local = local_banner()
        p = subprocess.Popen(ra.probe_argv(cfg), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             **self._as_account())
        got = b""
        try:
            deadline = time.monotonic() + PROBE_TIMEOUT
            fd = p.stdout.fileno()
            while b"\n" not in got and len(got) < 255:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                r, _, _ = select.select([fd], [], [], left)
                if not r:
                    break
                chunk = os.read(fd, 255)
                if not chunk:
                    break
                got += chunk
        finally:
            p.kill()
            p.wait()
        return banner_matches(got, local)

    def egress_roads(self, settings: dict, cfg: dict):
        return ra.roads(cfg, eg.candidates(settings), lambda e: eg.socks(settings, e))

    # ── the logic ────────────────────────────────────────────────────────────
    def _code_stamp(self):
        out = []
        for f in (__file__, ra.__file__, getattr(eg, "__file__", "")):
            try:
                out.append(os.stat(f).st_mtime_ns)
            except OSError:
                out.append(None)
        return out

    def session(self, cfg: dict, road: str, proxy) -> tuple[bool, str]:
        """Run one session on one road until it breaks.
        Returns (passed at least one check, reason it ended)."""
        self.write_status({"state": "connecting", "road": road})
        self.prepare(cfg, proxy)
        proc = self.spawn_master(cfg)
        err = bytearray()

        def drain():
            for chunk in iter(lambda: proc.stderr.read(512), b""):
                if len(err) < STDERR_CAP:
                    err.extend(chunk)
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

        def ended() -> tuple[bool, str]:
            reader.join(timeout=2)
            return ra.classify(err.decode("utf-8", "replace"))[0]

        try:
            start = self.now()
            while True:
                if proc.poll() is not None:
                    return False, ended()
                if self.probe(cfg):
                    break
                if self.now() - start > UP_WAIT:
                    return False, "probe"
                self.sleep(3)
            self.since = self.now()
            misses = 0
            while True:
                if proc.poll() is not None:
                    return True, ended()
                if misses == 0:
                    self.write_status({"state": "up", "road": road,
                                       "since": self.since, "checked_at": self.now()})
                self.sleep(ra.PROBE_INTERVAL)
                if proc.poll() is not None:
                    return True, ended()
                if self.probe(cfg):
                    misses = 0
                else:
                    misses += 1
                    if misses >= ra.PROBE_MISSES:
                        return True, "probe"
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def cycle(self) -> float:
        """One walk down the ladder. Returns how long to wait before the next."""
        settings = self.settings()
        cfg = ra.config(settings)
        if not cfg["enabled"]:
            self.write_status({"state": "off"})
            return 60
        miss = ra.missing(cfg, self.has_key(), self.has_host_key())
        if miss:
            self.write_status({"state": "no_config", "missing": miss})
            return 60
        roads = self.egress_roads(settings, cfg)
        tried: list[list[str]] = []
        reason = "no_roads"
        for road, proxy in roads:
            was_up, reason = self.session(cfg, road, proxy)
            if was_up:
                # It worked and then broke: start again from the best road.
                self.backoff = ra.BACKOFF_MIN
                return 5
            tried.append([road, reason])
            if ra.is_fatal(reason):
                break             # the same on every road: key refused, port taken
        wait = self.backoff
        self.backoff = ra.next_backoff(self.backoff)
        self.write_status({"state": "failing", "reason": reason, "tried": tried,
                           "retry_at": self.now() + wait})
        return wait

    def code_changed(self) -> bool:
        return self._code_stamp() != self._code

    def run(self) -> int:
        while True:
            # A package upgrade replaces the code underneath. Restarting the
            # unit from postinst would cut the very ssh the owner may be
            # running the upgrade through; picking up the new code between
            # sessions does not.
            if self.code_changed():
                os.execv(sys.executable, [sys.executable, "-I", *sys.argv])
            self.sleep(self.cycle())


if __name__ == "__main__":
    sys.exit(Runner().run())
