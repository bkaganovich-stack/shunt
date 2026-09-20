/* Pure UI projections. Browser-ready; no package manager or build required. */
(function(root) {
  'use strict';
  const groups = [
    {id:'overview',title:'Обзор',icon:'overview',subtitle:'Ваша сеть. Каждый маршрут на виду.',tabs:[{title:'Обзор',pages:['dashboard']}]},
    {id:'routing',title:'Маршрутизация',icon:'route',subtitle:'Общий принцип, точные исключения и причины выбора пути.',tabs:[{title:'Списки',pages:['geo','subscriptions']},{title:'Общие правила',pages:['rules']},{title:'Найдено проверкой',pages:['discovered']}]},
    {id:'egress',title:'Выходы',icon:'power',subtitle:'Основной туннель и резервный путь.',tabs:[{title:'Активный выход',pages:['vpn']},{title:'VPN серверы',pages:['servers']},{title:'Proxy',pages:['proxy']}]},
    {id:'network',title:'Домашняя сеть',icon:'network',subtitle:'Устройства, имена и входящие подключения.',tabs:[{title:'Устройства и группы',pages:['devices','groups']},{title:'DNS и защита',pages:['dns','adblock']},{title:'Входящий доступ',pages:['inbound']},{title:'Подключение роутера',pages:['router']}]},
    {id:'diagnostics',title:'Диагностика',icon:'diagnostic',subtitle:'Проверить путь и найти место сбоя.',tabs:[{title:'Сетевой тракт',pages:['path']},{title:'Аналитика',pages:['analytics']},{title:'Логи',pages:['logs']}]},
    {id:'maintenance',title:'Система',icon:'system',subtitle:'Обслуживание шлюза и настройки доступа.',tabs:[{title:'Ресурсы',pages:['system']},{title:'Обновления',pages:['updates']},{title:'Автоматизация',pages:['scheduler','alerts']},{title:'Настройки',pages:['settings','terminal']}]}
  ];
  const aliases={overview:'dashboard',routing:'geo',egress:'vpn',network:'devices',diagnostics:'path',maintenance:'system',profile:'geo'};
  function resolve(route) { const parts=(route||'dashboard').replace(/^#/,'').split('/'); const key=parts.length>1?parts[1]:(aliases[parts[0]]||parts[0]); return groups.some(g=>g.tabs.some(t=>t.pages.includes(key)))?key:'dashboard'; }
  function sectionFor(page) {page=resolve(page);return groups.find(g=>g.tabs.some(t=>t.pages.includes(page)));}
  const pageLabels={dashboard:'Обзор',geo:'Гео-базы',subscriptions:'Подписки',rules:'Общие правила',discovered:'Найдено проверкой',vpn:'Активный выход',servers:'VPN серверы',proxy:'Proxy',devices:'Устройства',groups:'Группы',dns:'DNS',adblock:'Adblock',inbound:'Входящий доступ',router:'Подключение роутера',path:'Сетевой тракт',analytics:'Аналитика',logs:'Логи',system:'Ресурсы',updates:'Обновления',scheduler:'Планировщик',alerts:'Уведомления',settings:'Настройки',terminal:'Терминал'};
  const searchAliases={rules:'ручные правила manual rules global rules',path:'wan dhcp аренда lease сетевой тракт network path',servers:'vpn сервер server',adblock:'реклама блокировка ads',geo:'geosite geoip списки lists',devices:'клиенты clients',system:'cpu память memory диск'};
  function navigationEntries() {
    const entries=groups.flatMap(g=>g.tabs.flatMap(tab=>tab.pages.map(page=>({id:page,route:g.id+'/'+page,labels:[...new Set([g.title,tab.title,pageLabels[page]])],keywords:searchAliases[page]||''}))));
    for(const [panel,title] of [['behavior','Поведение'],['sources','Списки и сервисы'],['rules','Правила профиля'],['check','Проверка']])
      entries.push({id:'profile-'+panel,route:'routing/geo',panel,labels:['Маршрутизация','Редактор профилей',title],keywords:'профиль profile '+(panel==='rules'?'свои правила custom rules':'')});
    return entries;
  }
  function searchNavigation(query,translate=x=>x) {
    const normalize=s=>s.toLocaleLowerCase().replace(/ё/g,'е').trim();
    const words=normalize(query).split(/\s+/).filter(Boolean);
    return navigationEntries().filter(e=>{const haystack=normalize([...e.labels,...e.labels.map(translate),e.keywords,e.id].join(' '));return words.every(w=>haystack.includes(w));});
  }
  function profileChanges(profile) {
    if(!profile?.baseline_config||!profile.config)return null;
    const a=profile.baseline_config,b=profile.config,result=[];
    const add=(field,label,before,after)=>result.push({field,label,before,after});
    const fields={name:'Название',default_route:'Маршрут по умолчанию',use_discovered:'Результаты автоматической проверки',apple_vpn:'Apple CDN через туннель',realtime_direct:'Звонки и realtime напрямую'};
    for(const [field,label] of Object.entries(fields))if(a[field]!==b[field])add(field,label,a[field],b[field]);
    for(const id of new Set([...(a.tunnel_lists||[]),...(b.tunnel_lists||[])])) {
      const state=c=>!c.tunnel_lists.includes(id)?'Отсутствует':c.disabled_tunnel_lists.includes(id)?'Выключено':'Включено';
      if(state(a)!==state(b))add('tunnel_lists',id,state(a),state(b));
    }
    for(const [field,label] of [['services','Сервис'],['extra_tunnel_domains','Точное исключение']])
      for(const value of new Set([...(a[field]||[]),...(b[field]||[])]))if(a[field].includes(value)!==b[field].includes(value))add(field,label+': '+value,a[field].includes(value)?'Включено':'Отсутствует',b[field].includes(value)?'Включено':'Отсутствует');
    for(const [field,label] of [['tunnel_lists','Порядок списков'],['services','Порядок сервисов'],['extra_tunnel_domains','Порядок точных исключений']]) {
      const before=a[field]||[],after=b[field]||[];
      if(before.length===after.length&&before.every(v=>after.includes(v))&&JSON.stringify(before)!==JSON.stringify(after))add(field,label,before.join(', '),after.join(', '));
    }
    const ruleKey=r=>JSON.stringify([r.kind,r.value,r.route]);
    if(JSON.stringify((a.custom_rules||[]).map(ruleKey))!==JSON.stringify((b.custom_rules||[]).map(ruleKey)))
      add('custom_rules','Правила профиля',a.custom_rules||[],b.custom_rules||[]);
    return result;
  }
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
  const model={pageLabels,navigationEntries,searchNavigation,profileChanges,groups,resolve,sectionFor,trafficShares,egress,discovery,wan};
  root.ShuntUIModel=model;
  if(typeof module!=='undefined'&&module.exports)module.exports=model;
})(typeof globalThis!=='undefined'?globalThis:window);
