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
