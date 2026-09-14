/* Pure UI projections. Browser-ready; no package manager or build required. */
(function(root) {
  'use strict';
  const groups = [
    {id:'overview',title:'Обзор',icon:'overview',subtitle:'Ваша сеть. Каждый маршрут на виду.',tabs:[{title:'Обзор',pages:['dashboard']}]},
    {id:'routing',title:'Маршрутизация',icon:'route',subtitle:'Общий принцип, точные исключения и причины выбора пути.',tabs:[{title:'Списки',pages:['geo','subscriptions']},{title:'Ручные правила',pages:['rules']},{title:'Найдено проверкой',pages:['discovered']}]},
    {id:'egress',title:'Выходы',icon:'power',subtitle:'Основной туннель и резервный путь.',tabs:[{title:'Активный выход',pages:['vpn']},{title:'VPN серверы',pages:['servers']},{title:'Proxy',pages:['proxy']}]},
    {id:'network',title:'Домашняя сеть',icon:'network',subtitle:'Устройства, имена и входящие подключения.',tabs:[{title:'Устройства и группы',pages:['devices','groups']},{title:'DNS и защита',pages:['dns','adblock']},{title:'Входящий доступ',pages:['inbound']},{title:'Подключение роутера',pages:['router']}]},
    {id:'diagnostics',title:'Диагностика',icon:'diagnostic',subtitle:'Проверить путь и найти место сбоя.',tabs:[{title:'Сетевой тракт',pages:['path']},{title:'Аналитика',pages:['analytics']},{title:'Логи',pages:['logs']}]},
    {id:'maintenance',title:'Система',icon:'system',subtitle:'Обслуживание шлюза и настройки доступа.',tabs:[{title:'Ресурсы',pages:['system']},{title:'Обновления',pages:['updates']},{title:'Автоматизация',pages:['scheduler','alerts']},{title:'Настройки',pages:['settings','terminal']}]}
  ];
  const aliases={overview:'dashboard',routing:'geo',egress:'vpn',network:'devices',diagnostics:'path',maintenance:'system',profile:'geo'};
  function resolve(route) { const parts=(route||'dashboard').replace(/^#/,'').split('/'); const key=parts.length>1?parts[1]:(aliases[parts[0]]||parts[0]); return groups.some(g=>g.tabs.some(t=>t.pages.includes(key)))?key:'dashboard'; }
  function sectionFor(page) {page=resolve(page);return groups.find(g=>g.tabs.some(t=>t.pages.includes(page)));}
  function count(v) {return typeof v==='number'&&Number.isFinite(v)&&v>=0?v:null;}
  function trafficShares(data) {
    if(!data||['total','direct','vpn','blocked'].some(k=>count(data[k])===null))return null;
    const {total,direct,vpn,blocked}=data;
    if(direct+vpn+blocked>total)return null;
    return {total,direct,vpn,blocked,other:total-direct-vpn-blocked,directPercent:total?direct/total*100:0,vpnPercent:total?vpn/total*100:0};
  }
  function egress(s) {if(!s)return {name:'Не измерено',location:'',healthy:false,reserve:false};const fptn=s.egress_active==='fptn';return {name:fptn?'FPTN':s.egress?.kind==='adguard'?'AdGuard VPN':s.vpn?.protocol||'Не измерено',location:fptn?'':s.egress?.location||s.vpn?.server||'',healthy:s.state==='connected',reserve:!!s.fptn_enabled&&!fptn};}
  function discovery(rows) {if(!Array.isArray(rows))return null;return {total:rows.length,routed:rows.filter(r=>r.routed&&r.enabled!==false).length,unrouted:rows.filter(r=>!r.routed&&r.enabled!==false).length,disabled:rows.filter(r=>r.enabled===false).length};}
  function wan(data) {
    const address=data?.wan?.ip||'';
    if(!address)return {address:'—',kind:data?.topology==='loop'?'Петля (loop)':'Не измерено'};
    const a=address.split('.').map(Number);
    return {address,kind:a[0]===100&&a[1]>=64&&a[1]<=127?'CGNAT провайдера':'WAN'};
  }
  const model={groups,resolve,sectionFor,trafficShares,egress,discovery,wan};
  root.ShuntUIModel=model;
  if(typeof module!=='undefined'&&module.exports)module.exports=model;
})(typeof globalThis!=='undefined'?globalThis:window);
