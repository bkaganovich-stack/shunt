#!/usr/bin/env python3
"""
ssh ProxyCommand through an egress's SOCKS5 port.

    socks_connect.py <socks host> <socks port> <target host> <target port>

Used by the remote-access runner (docs/REMOTE_ACCESS.md) so that its ssh can
leave through any egress: the namespaces are not touched, the ssh is simply
one more SOCKS client of the port the host already sees. The target name is
handed to the proxy unresolved, so it is looked up on the far side of the
tunnel, not by the house's resolver.

Standard library only, so the package needs no netcat. Every failure is one
line on stderr starting with "socks:", which the runner reads.
"""
import ipaddress
import os
import select
import socket
import struct
import sys

REPLIES = {
    1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
    4: "host unreachable", 5: "connection refused", 6: "TTL expired",
    7: "command not supported", 8: "address type not supported",
}


class SocksError(Exception):
    pass


def connect_request(host: str, port: int) -> bytes:
    """The CONNECT request for host:port, the name left for the proxy."""
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        name = host.encode("idna")
        if not 0 < len(name) < 256:
            raise SocksError("target name too long")
        addr = b"\x03" + bytes([len(name)]) + name
    return b"\x05\x01\x00" + addr + struct.pack(">H", port)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SocksError("proxy closed the connection")
        buf += chunk
    return buf


def negotiate(sock, host: str, port: int) -> None:
    """No-auth SOCKS5 CONNECT on an open socket; raises SocksError."""
    sock.sendall(b"\x05\x01\x00")
    ver, method = _recv_exact(sock, 2)
    if ver != 5 or method != 0:
        raise SocksError("proxy wants authentication or is not SOCKS5")
    sock.sendall(connect_request(host, port))
    ver, rep, _, atyp = _recv_exact(sock, 4)
    if ver != 5:
        raise SocksError("bad reply from proxy")
    if rep != 0:
        raise SocksError(REPLIES.get(rep, f"error {rep}"))
    if atyp == 1:
        _recv_exact(sock, 4 + 2)
    elif atyp == 4:
        _recv_exact(sock, 16 + 2)
    elif atyp == 3:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    else:
        raise SocksError("bad address type in reply")


def pump(sock, rfd: int = 0, wfd: int = 1) -> None:
    """Copy stdin to the socket and the socket to stdout until either ends."""
    open_in = True
    while True:
        rlist = [sock] + ([rfd] if open_in else [])
        readable, _, _ = select.select(rlist, [], [])
        if sock in readable:
            data = sock.recv(65536)
            if not data:
                return
            os.write(wfd, data)
        if open_in and rfd in readable:
            data = os.read(rfd, 65536)
            if data:
                sock.sendall(data)
            else:
                open_in = False
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    return


def main(argv) -> int:
    if len(argv) != 5:
        print("socks: usage: socks_connect.py proxy_host proxy_port host port", file=sys.stderr)
        return 2
    _, phost, pport, host, port = argv
    try:
        sock = socket.create_connection((phost, int(pport)), timeout=20)
    except OSError as e:
        print(f"socks: proxy {phost}:{pport} does not answer ({e})", file=sys.stderr)
        return 1
    try:
        negotiate(sock, host, int(port))
    except (SocksError, OSError) as e:
        print(f"socks: {host}:{port} through {phost}:{pport}: {e}", file=sys.stderr)
        return 1
    sock.settimeout(None)
    try:
        pump(sock)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
