const {test}=require('node:test');
const assert=require('node:assert/strict');
const ui=require('../src/web/static/ui-model.js');
test('all previous deep links resolve to one of six groups',()=>{
 const pages='dashboard path inbound vpn profile rules groups subscriptions devices dns adblock proxy geo analytics logs system router scheduler updates alerts settings terminal'.split(' ');
 assert.equal(ui.groups.length,6);
 for(const p of pages)assert.ok(ui.sectionFor(p),p);
 assert.equal(ui.sectionFor('profile').id,'routing');
 assert.equal(ui.resolve('network/dns'),'dns');
 assert.equal(ui.resolve('bad/hash'),'dashboard');
});
test('connection shares do not hide blocked or unclassified traffic',()=>{
 const r=ui.trafficShares({total:100,direct:50,vpn:30,blocked:10});
 assert.equal(r.directPercent,50);assert.equal(r.vpnPercent,30);assert.equal(r.other,10);
 assert.equal(ui.trafficShares({total:0,direct:0,vpn:0,blocked:0}).vpnPercent,0);
 assert.equal(ui.trafficShares({total:null,direct:0,vpn:0,blocked:0}),null);
 assert.equal(ui.trafficShares({total:3,direct:5,vpn:0,blocked:0}),null);
});
test('selected FPTN is not mislabelled as the configured AdGuard exit',()=>{
 const s={egress_active:'fptn',state:'connected',egress:{kind:'adguard',location:'United States'},fptn_enabled:true};
 assert.deepEqual(ui.egress(s),{name:'FPTN',location:'',healthy:true,reserve:false});
 assert.equal(ui.egress({...s,state:'unmeasured'}).healthy,false);
 assert.equal(ui.egress(null).healthy,false);
});
test('discovery respects disabled rules and does not claim a second confirmation',()=>{
 assert.deepEqual(ui.discovery([{routed:true},{routed:true,enabled:false},{routed:false},{routed:false,enabled:false}]),{total:4,routed:1,unrouted:1,disabled:2});
 assert.equal(ui.discovery(null),null);
});

test('WAN projection follows the network/wan-status API shape',()=>{
 assert.deepEqual(ui.wan({topology:'inline',wan:{iface:'enp1s0',link:true,ip:'100.113.192.178',gateway:'100.113.192.1'}}),{address:'100.113.192.178',kind:'CGNAT провайдера'});
 assert.equal(ui.wan({topology:'inline',wan:{ip:'100.128.0.1'}}).kind,'WAN');
 assert.deepEqual(ui.wan({topology:'loop',wan:null}),{address:'—',kind:'Петля (loop)'});
 assert.deepEqual(ui.wan(null),{address:'—',kind:'Не измерено'});
});

test('navigation search covers every route, breadcrumbs, legacy names and translations',()=>{
 for(const group of ui.groups)for(const tab of group.tabs)for(const page of tab.pages)
   assert.ok(ui.navigationEntries().some(e=>e.id===page&&ui.resolve(e.route)===page));
 assert.ok(ui.searchNavigation('сетевой тракт').some(e=>e.route==='diagnostics/path'));
 assert.ok(ui.searchNavigation('система уведом').some(e=>e.id==='alerts'));
 assert.ok(ui.searchNavigation('ручные').some(e=>e.id==='rules'));
 assert.ok(ui.searchNavigation('свои правила').some(e=>e.panel==='rules'));
 assert.ok(ui.searchNavigation('network path',s=>s==='Сетевой тракт'?'Network path':s).some(e=>e.id==='path'));
 assert.deepEqual(ui.searchNavigation('несуществующийраздел'),[]);
 assert.equal(ui.searchNavigation(' <script> ').length,0);
});
test('profile differences separate removal, disabling and rule order and saved list order',()=>{
 const base={name:'Test',default_route:'direct',use_discovered:true,apple_vpn:false,realtime_direct:true,tunnel_lists:['geosite:a','geoip:b'],disabled_tunnel_lists:[],services:['openai'],extra_tunnel_domains:[],custom_rules:[]};
 const current={...base,tunnel_lists:['geosite:a','geoip:c'],disabled_tunnel_lists:['geosite:a'],services:[],custom_rules:[{kind:'full',value:'a.example',route:'tunnel'}]};
 const changes=ui.profileChanges({baseline_config:base,config:current});
 assert.ok(changes.some(c=>c.label==='geosite:a'&&c.after==='Выключено'));
 assert.ok(changes.some(c=>c.label==='geoip:b'&&c.after==='Отсутствует'));
 assert.ok(changes.some(c=>c.label==='geoip:c'&&c.before==='Отсутствует'));
 assert.ok(changes.some(c=>c.field==='custom_rules'));
 assert.ok(ui.profileChanges({baseline_config:base,config:{...base,tunnel_lists:[...base.tunnel_lists].reverse()}}).some(c=>c.label==='Порядок списков'));
 assert.deepEqual(ui.profileChanges({baseline_config:base,config:base}),[]);
 assert.equal(ui.profileChanges({config:base}),null);
 const rules=[{kind:'domain',value:'a.example',route:'tunnel'},{kind:'full',value:'a.example',route:'direct'}];
 assert.ok(ui.profileChanges({baseline_config:{...base,custom_rules:rules},config:{...base,custom_rules:[...rules].reverse()}}).some(c=>c.field==='custom_rules'));
});

test('dynamic WAN notices translate measured events without inventing a server change',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const locale=JSON.parse(fs.readFileSync(require.resolve('../src/web/static/locales/en.json'),'utf8'));
 const source=fs.readFileSync(require.resolve('../src/web/static/index.html'),'utf8');
 const start=source.indexOf('function i18nTranslate(s) {'),end=source.indexOf('/* Available to code',start);
 const context={I18N:{dict:locale.strings,patterns:locale.patterns.map(([rx,rep,groups])=>[new RegExp(rx),rep,groups||null])}};
 vm.createContext(context);vm.runInContext(source.slice(start,end),context);
 const note='Срок DHCP-аренды: 10 мин. Запрос продления через 5 мин после получения адреса. За последние 24 ч зарегистрирована смена WAN-адреса: 2 раза. При смене WAN-адреса возможен разрыв внешних соединений.';
 const translation=context.i18nTranslate(note);
 assert.ok(translation.includes('10 min. Renewal request 5 min'));
 assert.ok(translation.includes('24 h: 2. External'));
 assert.ok(!/[А-Яа-я]/.test(translation));
 const suffix=' Возможен разрыв внешних соединений. Причина смены адреса не установлена.';
 const event='Смена WAN-адреса: 12:00, 1.2.3.4 → 2.3.4.5. Зарегистрировано за 24 ч: 1.';
 assert.ok(!context.i18nTranslate(event+suffix).includes('DHCP server'));
 assert.ok(context.i18nTranslate(event+' DHCP-сервер: 1.1.1.1 → 2.2.2.2.'+suffix).includes('DHCP server: 1.1.1.1 → 2.2.2.2.'));
});
