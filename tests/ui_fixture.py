"""Local-only UI qualification harness. Never imports or runs gateway services."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import json,time,urllib.parse,mimetypes,threading
ROOT=Path(__file__).resolve().parents[1]/'src/web/static'
state={'profile':'blocked_only','fail_status':False,'summary':{'total':178057,'direct':124945,'vpn':53112,'blocked':0},'rules':{'always_direct':[],'always_vpn':[{'rule':'domain:anthropic.com','enabled':True}]}}
# Explicit fixture domain, not a claim that these are the user's private rules.
state['rules']['always_direct']=[{'rule':'domain:fixture-%02d.example'%i,'enabled':True} for i in range(24)]
requests=[]
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def respond(self,data,status=200):
  b=json.dumps(data).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def do_GET(self):
  path=urllib.parse.urlsplit(self.path).path;requests.append(('GET',path))
  if path=='/__fixture/requests':return self.respond(requests[-200:])
  if path=='/__fixture/state':return self.respond(state)
  if not path.startswith('/api/'):
   name='index.html' if path=='/' else path.removeprefix('/static/');p=(ROOT/name).resolve()
   if ROOT not in p.parents or not p.is_file():return self.respond({'error':'not found'},404)
   b=p.read_bytes()
   if name=='index.html':b=b.replace(b'</body>','<div style="position:fixed;bottom:2px;right:8px;z-index:9999;font:10px sans-serif;background:#0f1117;color:#fbbf24;padding:3px 7px">ЛОКАЛЬНЫЙ СТЕНД · ТЕСТОВЫЕ ДАННЫЕ</div></body>'.encode())
   self.send_response(200);self.send_header('Content-Type',mimetypes.guess_type(name)[0] or 'text/plain');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b);return
  if path.endswith('-stream') or path.endswith('/stream'):
   self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
   payload={'rx_bps':8192,'tx_bps':1024} if 'speed' in path else {'cpu':[3,5],'mem':{'total':4000000000,'used':1000000000},'disk':{'total':64000000000,'used':8000000000,'free':56000000000},'net':{'rx_bps':8192,'tx_bps':1024}}
   try:
    for _ in range(300):self.wfile.write(('data: '+json.dumps(payload)+'\n\n').encode());self.wfile.flush();time.sleep(2)
   except (BrokenPipeError,ConnectionResetError):pass
   return
  status={'state':'connected','gateway_ip':'192.168.100.1','profile':state['profile'],'egress':{'kind':'adguard','location':'United States'},'egress_active':'adguard','fptn_enabled':True,'nav':{},'topology':'inline','mgmt_ip':'192.168.100.1','attention':[],'geo_updated':'2026-09-14','vpn':None}
  if path=='/api/status' and state['fail_status']:return self.respond({'error':'fixture unavailable'},503)
  data={
   '/api/auth-check':{'ok':self.headers.get('Cookie')!='fixture=loggedout'},'/api/status':status,'/api/version':{'version':'fixture','xray_core':'fixture'},
   '/api/analytics/summary':state['summary'],'/api/analytics/series':{'series':[]},'/api/custom-rules':state['rules'],
   '/api/discovered':{'rows':[{'domain':'candidate-%02d.example'%i,'enabled':True,'routed':False,'direct':'timeout','tunnel':'ok','last_checked':int(time.time())} for i in range(53)],'routed':0,'schedule':'@hourly','last_run':int(time.time())},
   '/api/network/wan-status':{'topology':'inline','wan':{'iface':'fixture0','link':True,'ip':'100.113.192.178','gateway':'100.113.192.1'}},
   '/api/geo-info':{'geo_updated':'2026-09-14','geosite_size':'12.5 MB','geoip_size':'70.0 MB'},
   '/api/vpn-servers':{'servers':[]},'/api/adguard':{'enabled':True,'connected':True,'location':'United States'},'/api/fptn':{'enabled':True,'service':'active','active':False,'servers':{}},
   '/api/metrics':{'samples':[]},'/api/groups':{'groups':[]},'/api/devices':{'devices':[]},'/api/subscriptions':{'subscriptions':[]},'/api/scheduler':{'tasks':[]},'/api/snapshots':{'snapshots':[]},
   '/api/dns':{'upstream':['1.1.1.1'],'upstream_ru':[],'local_records':[],'cache_size':1000},'/api/dns/probe':{'chain':[],'resolvers':[]},'/api/adblock':{'enabled':True,'custom_rules':[],'allowlist':[],'total_blocked_domains':0},
   '/api/logs':{'logs':'Local fixture: no gateway logs.'},'/api/connections':{'connections':[]},'/api/alerts/log':{'events':[]},
   '/api/network/topology':{'topology':'inline','config':{},'interfaces':[]},'/api/network/interfaces':{'interfaces':[]},'/api/inbound':{'rules':[],'topology':'inline','reachability':{'class':'CGNAT','reachable':False,'why':'Fixture'}},'/api/inbound/listeners':{'listeners':[]},
   '/api/path':{'wan':{'link':{'present':False},'address':{}},'egress':{},'counters':[]},'/api/health/diagnosis':{'steps':[]},'/api/provider':{'assumptions':[]},'/api/updates/history':{'history':[]},'/api/updates/cached':{'components':[]},'/api/updates/gateway/status':{'stage':'idle'},'/api/proxy':{'enabled':False},'/api/alerts/config':{},
  }
  return self.respond(data.get(path,{}))
 def do_POST(self):
  path=urllib.parse.urlsplit(self.path).path;n=int(self.headers.get('Content-Length',0));body=json.loads(self.rfile.read(n) or '{}');requests.append((self.command,path,body))
  if path=='/__fixture/state':state.update(body);return self.respond({'ok':True})
  if path=='/api/login' or path=='/api/logout':
   self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Set-Cookie','fixture='+('loggedout' if path.endswith('logout') else 'loggedin'));self.end_headers();self.wfile.write(b'{"ok":true}');return
  if path=='/api/profile':state['profile']=body['profile']
  if path=='/api/custom-rules':state['rules']=body
  if path=='/api/route-test':return self.respond({'outbound':'proxy','matched_rule':'domain:anthropic.com','note':'Local fixture','resolved_ips':[]})
  return self.respond({'ok':True})
 do_PUT=do_POST
 do_DELETE=do_POST
if __name__ == '__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--port',type=int,default=8766)
 args=parser.parse_args()
 print(f'Local fixture: http://127.0.0.1:{args.port}/ (test data only)',flush=True)
 ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
