#!/usr/bin/env python3
# Local DoH proxy. UDP DNS -> RFC8484 POST to Cloudflare DoH over the VPN tunnel
# (the VPN server blocks plain :53; :443 works). Hardened for burst load:
# large recv buffer, keep-alive connection pool, retries with failover.
import socket, socketserver, ssl, http.client, sys, threading, queue
UP  = [("1.1.1.1", "/dns-query"), ("1.0.0.1", "/dns-query")]
CTX = ssl.create_default_context()
LISTEN = [("127.0.0.1", 53), ("127.0.0.1", 5053)]
_pools = {h: queue.Queue(maxsize=64) for h, _ in UP}

def _get_conn(host):
    try: return _pools[host].get_nowait()
    except queue.Empty: return http.client.HTTPSConnection(host, 443, timeout=5, context=CTX)

def _put_conn(host, c):
    try: _pools[host].put_nowait(c)
    except queue.Full:
        try: c.close()
        except Exception: pass

def doh(raw):
    last = None
    for attempt in range(3):
        host, path = UP[attempt % len(UP)]
        try:
            c = _get_conn(host)
            c.request("POST", path, body=raw,
                      headers={"content-type": "application/dns-message",
                               "accept": "application/dns-message",
                               "content-length": str(len(raw))})
            r = c.getresponse(); d = r.read()
            if r.status == 200 and d:
                _put_conn(host, c); return d
            try: c.close()
            except Exception: pass
            last = Exception("status %s" % r.status)
        except Exception as e:
            last = e   # stale/broken conn not returned to pool
    raise last if last else Exception("doh failed")

class H(socketserver.BaseRequestHandler):
    def handle(self):
        raw, sock = self.request[0], self.request[1]
        try: sock.sendto(doh(raw), self.client_address)
        except Exception as e: sys.stderr.write("err %s\n" % e)

class Srv(socketserver.ThreadingUDPServer):
    allow_reuse_address = True; daemon_threads = True
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
        super().server_bind()

def serve(host, port): Srv((host, port), H).serve_forever()

if __name__ == "__main__":
    for host, port in LISTEN[1:]:
        threading.Thread(target=serve, args=(host, port), daemon=True).start()
    serve(*LISTEN[0])
