/* Approved Shunt UI. Presentation only; existing handlers own all writes. */
'use strict';
const UI_OVERVIEW = `<div id="ui-overview-error" class="ui-message" role="status" hidden></div>
<div class="overview-grid">
<article class="card flow-card"><div class="flow-intro"><div><p class="eyebrow muted">Разделение трафика</p><div class="total"><span data-ui="total">—</span></div><p class="small secondary">соединений за сутки</p></div><span class="range">24 часа</span></div>
<svg class="flow-svg desktop-flow" viewBox="0 0 700 260" role="img" aria-labelledby="flow-title flow-description"><title id="flow-title">Разделение соединений</title><desc id="flow-description" data-ui="diagramDescription">Нет данных</desc>
<path d="M49 113H167" stroke="var(--border)" stroke-width="2" fill="none"/>
<path d="M252 120H289C359 120 318 53 394 53H456" fill="none" class="direct-path" data-flow="direct" stroke-width="0" opacity=".09"/>
<path d="M252 132H290C357 132 323 188 394 188H456" fill="none" class="tunnel-path" data-flow="vpn" stroke-width="0" opacity=".2"/>
<path d="M252 120H289C359 120 318 53 394 53H456" fill="none" class="direct-path" stroke-width="2"/>
<path d="M252 132H290C357 132 323 188 394 188H456" fill="none" class="tunnel-path" stroke-width="2" stroke-dasharray="5 5"/>
<circle cx="52" cy="113" r="24" class="node"/><use href="#i-network" x="41" y="102" width="22" height="22" stroke="var(--text)" fill="none" stroke-width="1.5"/>
<text x="52" y="160" text-anchor="middle" class="route-name">Дом</text><text x="52" y="180" text-anchor="middle" class="dim">LAN</text>
<rect x="167" y="81" width="85" height="84" rx="10" class="core"/><use href="#i-shunt" x="193" y="94" width="32" height="32" stroke="var(--accent)" fill="none" stroke-width="1.8"/><text x="209" y="149" text-anchor="middle" class="route-name">shunt</text><text x="209" y="189" text-anchor="middle" class="dim">Решает, куда</text>
<text x="376" y="32" class="dim" data-ui="directPercent">—</text><text x="376" y="221" class="dim accent-text" data-ui="vpnPercent">—</text>
<circle cx="458" cy="53" r="5" fill="var(--text)"/><circle cx="458" cy="188" r="5" fill="var(--accent)"/>
<text x="478" y="35" class="route-name">Напрямую</text><text x="478" y="70" class="count" data-ui="direct">—</text><text x="478" y="91" class="dim">Через провайдера</text>
<text x="478" y="163" class="route-name accent-text">Через туннель</text><text x="478" y="197" class="count accent-text" data-ui="vpn">—</text><text x="478" y="221" class="dim" data-ui="egressFull">—</text>
</svg>
<svg class="flow-svg mobile-flow" viewBox="0 0 320 215" role="img" aria-label="Разделение соединений">
<text x="12" y="33" class="route-name">Дом</text><text x="12" y="51" class="dim">LAN</text><path d="M66 35H128" stroke="var(--border)" stroke-width="2"/>
<rect x="128" y="12" width="64" height="47" rx="10" class="core"/><text x="160" y="41" text-anchor="middle" class="route-name accent-text">shunt</text>
<path d="M153 59V71Q153 92 122 92H92Q71 92 71 111V121" fill="none" stroke="var(--text)" data-flow="direct" stroke-width="0" opacity=".09"/><path d="M168 59V71Q168 92 196 92H224Q245 92 245 111V121" fill="none" stroke="var(--accent)" data-flow="vpn" stroke-width="0" opacity=".2"/>
<path d="M153 59V71Q153 92 122 92H92Q71 92 71 111V121" fill="none" stroke="var(--text)" stroke-width="1.5"/><path d="M168 59V71Q168 92 196 92H224Q245 92 245 111V121" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-dasharray="4 4"/>
<text x="58" y="83" class="dim" data-ui="directPercent">—</text><text x="242" y="83" class="dim accent-text" data-ui="vpnPercent">—</text><circle cx="71" cy="122" r="4" fill="var(--text)"/><circle cx="245" cy="122" r="4" fill="var(--accent)"/>
<text x="71" y="150" text-anchor="middle" class="route-name">Напрямую</text><text x="71" y="179" text-anchor="middle" class="count" data-ui="direct">—</text><text x="71" y="199" text-anchor="middle" class="dim">Провайдер</text><text x="245" y="150" text-anchor="middle" class="route-name accent-text">Туннель</text><text x="245" y="179" text-anchor="middle" class="count accent-text" data-ui="vpn">—</text><text x="245" y="199" text-anchor="middle" class="dim" data-ui="egressFull">—</text></svg>
<div id="ui-traffic-extra" class="small muted" hidden></div><div class="map-caption"><span>Толщина ветвей — доля соединений</span><span>Объём данных не измеряется этой схемой</span></div></article>
<article class="card profile-card"><div class="section-head"><h2>Профиль маршрутов</h2></div><h3 class="profile-title" data-ui="profile">—</h3><p class="profile-description" data-ui="profileDescription">Нет данных</p><div class="egress-row row"><span class="egress-sign"><svg class="icon"><use href="#i-power"/></svg></span><div class="stack"><strong data-ui="egressName">—</strong><small class="muted" data-ui="egressLocation">—</small></div><span class="dot" data-ui-dot style="margin-left:auto;background:var(--muted)"></span></div><p class="standby" data-ui="reserve">—</p><a href="#routing" class="plain">Настроить маршруты <svg class="icon"><use href="#i-route"/></svg></a></article>
</div>
<div class="reasons"><article class="card reasons-card"><div class="section-head"><h2>Почему именно этот путь</h2><span class="section-number">Логика решения</span></div><div class="reason-lines"><div class="reason-item"><div class="reason-line"><span class="line"></span><strong>Напрямую</strong></div><p><span data-ui="directReason">Правила прямого маршрута</span></p><a href="#routing/rules">Посмотреть исключения →</a></div><div class="reason-item"><div class="reason-line"><span class="line tunnel"></span><strong>Через туннель</strong></div><p><span data-ui="vpnReason">Правила туннеля</span></p><a href="#routing/geo">Открыть списки →</a></div></div></article>
<article class="card attention"><div class="section-head"><h2>Найдено проверкой</h2><span class="section-number">Автопроверка</span></div><div class="attention-head"><strong class="attention-num" data-ui="discoveredTotal">—</strong><span class="small muted">записи</span></div><p><span data-ui="discoveredSummary">Нет данных</span></p><a href="#routing/discovered" class="plain">Разобрать найденное <span aria-hidden="true">→</span></a></article></div>
<div class="hardware"><span class="row"><svg class="icon"><use href="#i-network"/></svg><span class="muted">LAN</span><span class="mono" data-ui="lan">—</span></span><span class="row"><span class="muted">WAN</span><span class="mono" data-ui="wan">—</span><span class="badge" data-ui="wanKind">Не измерено</span></span><a href="#diagnostics" class="plain">Сетевой тракт →</a></div>
`;
const UI_SYMBOLS = `<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" aria-hidden="true" style="position:absolute"><defs>
<symbol id="i-shunt" viewBox="0 0 24 24"><path d="M4 7h7l3 5h6M4 17h7l3-5"/><circle cx="19" cy="12" r="2"/></symbol>
<symbol id="i-overview" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/></symbol>
<symbol id="i-route" viewBox="0 0 24 24"><path d="M4 8h5l3 8h8M17 12h3"/><circle cx="20" cy="16" r="1.6"/></symbol>
<symbol id="i-power" viewBox="0 0 24 24"><path d="M12 3v9M7.5 6.5a7 7 0 1 0 9 0"/></symbol>
<symbol id="i-network" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.6 2.4 14.4 0 17M12 3.5c-2.4 2.6-2.4 14.4 0 17"/></symbol>
<symbol id="i-diagnostic" viewBox="0 0 24 24"><path d="M4 16l4-6 4 3 4-7 4 5"/></symbol>
<symbol id="i-system" viewBox="0 0 24 24"><path d="M12 4v3M12 17v3M4 12h3M17 12h3M6.7 6.7l2.1 2.1M15.2 15.2l2.1 2.1M6.7 17.3l2.1-2.1M15.2 8.8l2.1-2.1"/><circle cx="12" cy="12" r="3"/></symbol>
</defs></svg>`;
(function() {
  const M=ShuntUIModel, $=s=>document.querySelector(s), $$=s=>Array.from(document.querySelectorAll(s));
  const ui={page:'dashboard',authenticated:false,profileDirty:false,rulesDirty:false,filter:'all',lastStatus:null,generation:0};
  window.shuntUI=ui;
  const make=(tag,cls,html)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(html)e.innerHTML=html;return e;};
  const icon=name=>`<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const text=(key,value)=>$$(`[data-ui="${key}"]`).forEach(e=>{e.textContent=value??'—';});
  const label={dashboard:'Обзор',geo:'Гео-базы',subscriptions:'Подписки',rules:'Ручные правила',discovered:'Найдено проверкой',vpn:'Активный выход',servers:'VPN серверы',proxy:'Proxy',devices:'Устройства',groups:'Группы',dns:'DNS',adblock:'Adblock',inbound:'Входящий доступ',router:'Подключение роутера',path:'Сетевой тракт',analytics:'Аналитика',logs:'Логи',system:'Ресурсы',updates:'Обновления',scheduler:'Планировщик',alerts:'Уведомления',settings:'Настройки',terminal:'Терминал'};
  const descriptions={blocked_only:'Недоступные сервисы — через VPN. Всё остальное — напрямую.',all_except_ru:'Иностранные сайты — через VPN. Российские IP и домены — напрямую.',all:'Весь трафик через VPN, кроме локальной сети.',direct:'Туннель не используется.'};
  const app=$('#app-screen'), main=app.querySelector('main');main.classList.add('main');
  document.body.insertAdjacentHTML('afterbegin',UI_SYMBOLS);
  // Keep every original control and id; only its presentation location changes.
  const dashboard=$('#page-dashboard');
  const health=make('details','ui-details');health.append(make('summary','','Состояние служб'),dashboard.querySelector('.status-grid'));$('#page-path').append(health);
  const speed=dashboard.querySelector('.card');$('#page-analytics').append(speed);
  const management=make('details','ui-details');management.append(make('summary','','Управление шлюзом'),dashboard.querySelector('.card'));$('#page-settings').append(management);
  dashboard.innerHTML=UI_OVERVIEW;
  const sidebar=make('aside','sidebar');sidebar.id='sidebar';
  sidebar.innerHTML=`<a class="brand" href="#overview/dashboard"><span class="brand-mark">${icon('shunt')}</span><span><span class="brand-name">shunt</span><span class="brand-sub" style="display:block">СВОБОДА МАРШРУТА</span></span></a><p class="nav-caption eyebrow">Домашний шлюз</p><nav class="nav" aria-label="Основная навигация">${M.groups.map((g,i)=>`<a href="#${g.id}/${g.tabs[0].pages[0]}" data-ui-group="${g.id}">${icon(g.icon)}<span>${g.title}</span><span class="nav-index">0${i+1}</span></a>`).join('')}</nav><div class="nav-bottom"><div class="uptime"><span class="small muted">Адрес шлюза</span><strong class="mono" data-ui="lan">—</strong></div><button class="theme-button" onclick="toggleTheme()"><span class="small" id="theme-label">Светлая тема</span>${icon('system')}</button><div class="ui-account"><button class="plain" onclick="toggleLang()" data-i18n-skip><span id="lang-label">English</span></button><button class="plain" onclick="doLogout()">Выйти</button></div><div id="nav-version" class="prototype-label"></div></div>`;
  $('#sidebar').replaceWith(sidebar);
  app.querySelector('.mobile-header')?.remove();
  const mobileTop=make('div','mobile-top');mobileTop.innerHTML=`<a href="#overview/dashboard" class="brand"><span class="brand-mark">${icon('shunt')}</span><span class="brand-name">shunt</span></a><button class="theme-mobile" onclick="toggleTheme()" aria-label="Переключить тему">${icon('system')}</button>`;app.prepend(mobileTop);
  const mobileNav=make('nav','mobile-nav');mobileNav.setAttribute('aria-label','Мобильная навигация');mobileNav.innerHTML=`<a href="#overview/dashboard" data-ui-group="overview">${icon('overview')}<span>Обзор</span></a><a href="#routing/geo" data-ui-group="routing">${icon('route')}<span>Маршруты</span></a><a href="#network/devices" data-ui-group="network">${icon('network')}<span>Сеть</span></a><button onclick="toggleNav()" aria-label="Все разделы">${icon('system')}<span>Ещё</span></button>`;app.append(mobileNav);
  const header=make('header','topbar');header.innerHTML='<div><h1 id="ui-title">Обзор</h1><p class="subtitle" id="ui-subtitle">Ваша сеть. Каждый маршрут на виду.</p></div><div class="top-actions"><span class="badge"><span class="dot" data-ui-dot style="background:var(--muted)"></span><span data-ui="state">Не измерено</span></span></div>';main.prepend(header);
  const tabs=make('div','route-tabs ui-primary-tabs');tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label','Разделы экрана');header.after(tabs);
  const secondary=make('div','ui-secondary-tabs');tabs.after(secondary);
  function dialog(title,id){const d=make('dialog','ui-dialog');d.id=id;d.setAttribute('aria-labelledby',id+'-title');d.innerHTML=`<div class="row between"><h2 id="${id}-title">${title}</h2><button class="close" type="button" aria-label="Закрыть">×</button></div>`;d.querySelector('button').onclick=()=>d.close();document.body.append(d);return d;}
  const profileDialog=dialog('Профиль маршрутов','ui-profile-dialog');
  const profilePage=$('#page-profile');profilePage.classList.remove('page');profilePage.querySelector('h2')?.remove();
  const routeTester=Array.from(profilePage.querySelectorAll('.card')).find(c=>c.querySelector('#rt-input'));
  profileDialog.append(profilePage);
  const routing=make('div','ui-routing-shell');routing.hidden=true;secondary.after(routing);
  const profileBar=make('article','card routing-profile');profileBar.innerHTML=`<div class="profile-label"><p class="eyebrow muted">Профиль маршрутов</p><span class="small" id="ui-profile-state">Сейчас применяется</span></div><div class="profile-select-wrap"><label class="ui-sr-only" for="ui-profile-select">Выберите режим маршрутизации трафика</label><select id="ui-profile-select">${Object.entries(PROFILE_LABELS).map(([v,t])=>`<option value="${v}">${t}</option>`).join('')}</select></div><p class="small muted" data-ui="profileDescription">Нет данных</p><button class="primary" id="ui-profile-apply" hidden>Применить профиль</button><button class="plain" id="ui-profile-more">Подробнее →</button>`;
  routing.append(profileBar);
  const routeGrid=make('div','routing-grid'),routeMain=make('div','ui-route-main'),routeAside=make('aside','ui-route-aside');routeGrid.append(routeMain,routeAside);routing.append(routeGrid);
  routeAside.innerHTML='<article class="card sidebar-card"><h2>Откуда берётся решение</h2><ol class="priority-list"><li><span class="step">1</span><div><h3>Профиль</h3><p>Задаёт общий режим для домашней сети.</p></div></li><li><span class="step">2</span><div><h3>Списки</h3><p>Помогают разделить назначения по маршрутам.</p></div></li><li><span class="step">3</span><div><h3>Ручные правила</h3><p>Переопределяют гео-базы для конкретного домена или IP.</p></div></li></ol><p class="small muted">Схема настройки, не порядок обработки пакета.</p></article>';
  routeTester.classList.add('test-card');routeAside.append(routeTester);
  const discoveredPage=make('section','page');discoveredPage.id='page-discovered';
  const discoveredCard=$('#discovered-meta').closest('.card');discoveredPage.append(discoveredCard);
  const discoveries=make('div','discovery-counts');discoveries.innerHTML='<div><strong data-ui="discoveredTotal">—</strong><span>записей найдено</span></div><div><strong data-ui="discoveredRouted">—</strong><span>переведено в туннель</span></div>';discoveredCard.querySelector('h3').after(discoveries);
  ['geo','rules','subscriptions'].forEach(p=>routeMain.append($('#page-'+p)));routeMain.append(discoveredPage);
  const exitStrip=make('div','route-foot');exitStrip.innerHTML='<span><span>Выход для туннеля</span>: <strong data-ui="egressFull">—</strong><br><span class="muted" data-ui="reserve">—</span></span><a class="plain" href="#egress/vpn">Настроить выходы →</a>';routeMain.append(exitStrip);
  const serverPage=make('section','page');serverPage.id='page-servers';serverPage.innerHTML='<h2>VPN серверы</h2>';
  Array.from($('#page-vpn').children).filter(c=>c.classList.contains('card')&&(c.querySelector('#vpn-servers-list')||c.querySelector('#vpn-add-key'))).forEach(c=>serverPage.append(c));main.append(serverPage);
  // Lists: actual file metadata, never the numbers from the design brief.
  const geoPage=$('#page-geo'),geoDetails=make('details','ui-details');geoDetails.append(make('summary','','Обновление гео-баз'),geoPage.querySelector('.card'));
  const geoTable=make('article','card workspace');geoTable.innerHTML='<div class="table-head"><div><h2>Источники маршрутов</h2><p>Гео-базы текущего профиля</p></div><a class="plain" href="#routing/subscriptions">Подписки →</a></div><table class="data-table"><thead><tr><th>ИСТОЧНИК</th><th>РАЗМЕР</th><th>СОДЕРЖИМОЕ</th></tr></thead><tbody><tr><td class="mono">geosite.dat</td><td data-ui="geoSiteSize">—</td><td>Списки доменов</td></tr><tr><td class="mono">geoip.dat</td><td data-ui="geoIpSize">—</td><td>Списки адресов</td></tr></tbody></table><p class="table-note"><span>Последнее обновление</span>: <span data-ui="geoUpdated">—</span></p>';geoPage.append(geoTable,geoDetails);
  // The old rule editors remain the single source of validation and write semantics.
  const rulePage=$('#page-rules'),ruleDialog=dialog('Добавить правило','ui-rule-dialog');
  Array.from(rulePage.querySelectorAll('.card')).forEach(c=>ruleDialog.append(c));
  ruleDialog.querySelectorAll('.rules-list').forEach(e=>e.hidden=true);
  const ruleEditor=make('article','card workspace');ruleEditor.innerHTML='<div class="table-head"><div><h2>Ручные правила</h2><p>Явные исключения для доменов и IP</p></div><button class="primary" id="ui-rule-add">Добавить правило</button></div><div class="filterbar"><div class="segmented" aria-label="Фильтр правил"><button data-filter="all" aria-pressed="true">Все</button><button data-filter="direct" aria-pressed="false">Напрямую</button><button data-filter="vpn" aria-pressed="false">Туннель</button></div><input id="ui-rule-search" class="search" type="search" placeholder="Домен или IP" aria-label="Найти правило"></div><table class="data-table"><thead><tr><th>ПРАВИЛО</th><th>МАРШРУТ</th><th>СОСТОЯНИЕ</th><th>ДЕЙСТВИЯ</th></tr></thead><tbody id="ui-rule-rows"></tbody></table><p class="table-note" id="ui-rule-note">Нет данных</p></article>';
  const tableScroll=make('div','ui-table-scroll');tableScroll.tabIndex=0;tableScroll.setAttribute('role','region');tableScroll.setAttribute('aria-label','Таблица ручных правил');ruleEditor.querySelector('table').replaceWith(tableScroll);
  const ruleTable=make('table','data-table');ruleTable.innerHTML='<thead><tr><th>ПРАВИЛО</th><th>МАРШРУТ</th><th>СОСТОЯНИЕ</th><th>ДЕЙСТВИЯ</th></tr></thead><tbody id="ui-rule-rows"></tbody>';tableScroll.append(ruleTable);
  rulePage.prepend(ruleEditor);const saveRow=rulePage.querySelector('.btn-row');ruleEditor.after(saveRow);
  $('#ui-rule-add').onclick=()=>ruleDialog.showModal();
  $('#ui-profile-more').onclick=()=>profileDialog.showModal();
  $('#ui-profile-select').onchange=e=>selectProfile(e.target.value);
  $('#ui-profile-apply').onclick=()=>applyProfile();
  $('#ui-rule-search').oninput=()=>ui.renderRules();
  $$('[data-filter]').forEach(b=>b.onclick=()=>{ui.filter=b.dataset.filter;ui.renderRules();});
  // Wire hash navigation, including existing links from the legacy pages.
  window.showPage=function(request,linkEl,replace=false){
    const page=M.resolve(request),group=M.sectionFor(page),old=ui.page;
    if(!document.getElementById('page-'+page))return;
    ui.page=page;
    const hash='#'+group.id+'/'+page;
    if(!replace&&location.hash!==hash)history.pushState(null,'',hash);
    legacyShowPage(page,linkEl);history.replaceState(null,'',hash);
    $('#ui-title').textContent=group.title;$('#ui-subtitle').textContent=group.subtitle;
    document.title='Shunt — '+group.title;
    $$('[data-ui-group]').forEach(a=>{const active=a.dataset.uiGroup===group.id;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
    routing.hidden=group.id!=='routing';tabs.hidden=group.id==='overview';
    if(group.id==='routing')profileBar.after(tabs,secondary);else header.after(tabs,secondary);
    tabs.replaceChildren();
    const selected=group.tabs.find(t=>t.pages.includes(page));
    group.tabs.forEach(t=>{const b=make('button');b.type='button';b.textContent=t.title;b.setAttribute('role','tab');b.setAttribute('aria-selected',t===selected);b.tabIndex=t===selected?0:-1;b.setAttribute('aria-controls','page-'+(t===selected?page:t.pages[0]));b.onclick=()=>showPage(t.pages[0]);b.onkeydown=e=>{if(e.key==='ArrowRight'||e.key==='ArrowLeft'){e.preventDefault();const idx=(group.tabs.indexOf(t)+(e.key==='ArrowRight'?1:-1)+group.tabs.length)%group.tabs.length;showPage(group.tabs[idx].pages[0]);tabs.children[idx].focus();}};tabs.append(b);});
    secondary.replaceChildren();secondary.hidden=selected.pages.length<2;
    selected.pages.forEach(p=>{const b=make('button','plain');b.textContent=label[p];b.classList.toggle('active',p===page);b.setAttribute('aria-current',p===page?'page':'false');b.onclick=()=>showPage(p);secondary.append(b);});
    main.scrollTop=0;
    if(page==='dashboard'&&old!=='dashboard'&&ui.authenticated)ui.refresh();
    if(request==='profile')profileDialog.showModal();
  };
  app.addEventListener('click',e=>{const a=e.target.closest('a[href^="#"]');if(a){e.preventDefault();showPage(a.getAttribute('href').slice(1));}});
  addEventListener('popstate',()=>{if(ui.authenticated)showPage(location.hash.slice(1),null,true);});
  // Source counters and status never depend on whether their detail tab is open.
  ui.profileSelected=p=>{ui.profileDirty=true;$('#ui-profile-select').value=p;$('#ui-profile-apply').hidden=false;$('#ui-profile-state').textContent='Не применено';};
  ui.profileApplied=()=>{ui.profileDirty=false;$('#ui-profile-apply').hidden=true;$('#ui-profile-state').textContent='Сейчас применяется';};
  ui.status=d=>{
    if(!ui.authenticated)return;ui.lastStatus=d;
    const e=M.egress(d);text('state',({connected:'Подключено',connecting:'Подключение…',error:'Ошибка',stopped:'Остановлено',unmeasured:'Не измерено',no_key:'Ключ не задан'})[d.state]||'Не измерено');
    $$('[data-ui-dot]').forEach(n=>n.style.background=e.healthy?'var(--green)':d.state==='error'?'var(--red)':'var(--muted)');
    text('egressName',e.name);text('egressLocation',e.location);text('egressFull',[e.name,e.location].filter(Boolean).join(' · '));text('reserve',e.reserve?'FPTN — резервный выход':d.egress_active==='fptn'?'Используется резервный выход':'Резервный выход не включён');
    text('profile',PROFILE_LABELS[d.profile]||'Не измерено');text('profileDescription',descriptions[d.profile]||'Не измерено');text('lan',d.gateway_ip||'—');
    if(!ui.profileDirty)$('#ui-profile-select').value=d.profile;
    const problem=(d.attention||[]).length||d.in_fallback;const alert=$('#ui-overview-error');alert.hidden=!problem;alert.textContent=d.in_fallback?'Включён резервный профиль. Проверьте сетевой тракт.':problem?'Есть замечания к работе сети. Откройте «Сетевой тракт».':'';
  };
  ui.offline=()=>{text('state','Нет связи со шлюзом');$$('[data-ui-dot]').forEach(n=>n.style.background='var(--muted)');const alert=$('#ui-overview-error');alert.hidden=false;alert.textContent='Нет связи со шлюзом. Показаны последние полученные данные.';};
  ui.geo=r=>{text('geoSiteSize',r.geosite_size||'—');text('geoIpSize',r.geoip_size||'—');text('geoUpdated',r.geo_updated||'Никогда');};
  ui.discovered=r=>{const d=M.discovery(r?.rows);text('discoveredTotal',d?fmtNum(d.total):'—');text('discoveredRouted',d?fmtNum(r.routed??d.routed):'—');text('discoveredSummary',d?`В туннеле: ${fmtNum(r.routed??d.routed)}. Не направлено: ${fmtNum(d.total-(r.routed??d.routed))}.`:'Нет данных');};
  function reasons(r){if(!r){text('directReason','Нет данных');text('vpnReason','Нет данных');return;}const direct=(r.always_direct||[]).filter(v=>ruleOf(v).enabled).length,vpn=(r.always_vpn||[]).filter(v=>ruleOf(v).enabled).length;text('directReason',`Правила прямого маршрута: ${fmtNum(direct)}. Остальное определяется профилем.`);text('vpnReason',`Ручные правила туннеля: ${fmtNum(vpn)}. Списки применяются согласно профилю.`);}
  ui.rulesLoaded=()=>{ui.rulesDirty=false;reasons(_rulesData);ui.renderRules();};
  ui.markRulesDirty=()=>{ui.rulesDirty=true;};
  ui.rulesSaved=()=>{ui.rulesDirty=false;reasons(_rulesData);ui.renderRules();};
  ui.renderRules=()=>{
    const body=$('#ui-rule-rows');if(!body)return;body.replaceChildren();const query=$('#ui-rule-search').value.trim().toLowerCase();
    for(const type of ['direct','vpn']){const rows=_rulesData[type==='direct'?'always_direct':'always_vpn']||[];rows.forEach((raw,index)=>{const r=ruleOf(raw);if((ui.filter!=='all'&&ui.filter!==type)||!r.rule.toLowerCase().includes(query))return;const tr=make('tr');const value=make('td','mono');value.textContent=r.rule;const route=make('td',type==='vpn'?'accent':'');route.textContent=type==='vpn'?'Туннель':'Напрямую';const state=make('td');const toggle=make('button','plain');toggle.textContent=r.enabled?'Включено':'Выключено';toggle.setAttribute('aria-pressed',r.enabled);toggle.onclick=()=>toggleRule(type,index);state.append(toggle);const actions=make('td');const del=make('button','plain');del.textContent='Удалить';del.onclick=()=>removeRule(type,index);actions.append(del);tr.append(value,route,state,actions);body.append(tr);});}
    if(!body.children.length){const tr=make('tr'),td=make('td','empty-state');td.colSpan=4;td.textContent='Нет правил';tr.append(td);body.append(tr);}
    $('#ui-rule-note').textContent=ui.rulesDirty?'Есть несохранённые изменения. Нажмите «Сохранить правила».':'Ручные правила имеют приоритет над гео-базами.';
    $$('[data-filter]').forEach(b=>{b.classList.toggle('active',b.dataset.filter===ui.filter);b.setAttribute('aria-pressed',b.dataset.filter===ui.filter);});
  };
  function renderTraffic(raw){
    const d=M.trafficShares(raw);for(const k of ['total','direct','vpn'])text(k,d?fmtNum(d[k]):'—');
    for(const k of ['direct','vpn']){text(k+'Percent',d?Math.round(d[k+'Percent'])+'%':'—');$$(`[data-flow="${k}"]`).forEach(p=>p.setAttribute('stroke-width',d?Math.max(0,d[k+'Percent']*.4):0));}
    const note=$('#ui-traffic-extra');note.hidden=!!d&&!d.blocked&&!d.other;note.textContent=!d?'Статистика недоступна':`Заблокировано: ${fmtNum(d.blocked)}. Другие маршруты: ${fmtNum(d.other)}.`;
    text('diagramDescription',d?`Всего: ${fmtNum(d.total)}. Напрямую: ${fmtNum(d.direct)}. Туннель: ${fmtNum(d.vpn)}. Заблокировано: ${fmtNum(d.blocked)}.`:'Нет данных');
  }
  function renderWan(r){const w=M.wan(r);text('wan',w.address);text('wanKind',w.kind);}
  let pending=false;
  async function read(path){const r=await api('GET',path);if(!r||!r.ok)throw new Error('Unavailable');return r.json();}
  ui.refresh=async()=>{
    if(!ui.authenticated||document.hidden||ui.page!=='dashboard'||pending)return;
    pending=true;const generation=ui.generation;
    try{const results=await Promise.allSettled([read('/api/analytics/summary?hours=24'),read('/api/discovered'),read('/api/custom-rules'),read('/api/network/wan-status')]);if(generation!==ui.generation||!ui.authenticated)return;const values=results.map(r=>r.status==='fulfilled'?r.value:null);renderTraffic(values[0]);ui.discovered(values[1]);reasons(values[2]);renderWan(values[3]);}finally{pending=false;}
  };
  ui.start=()=>{ui.authenticated=true;clearInterval(ui.timer);ui.timer=setInterval(ui.refresh,30000);showPage(location.hash.slice(1)||'dashboard',null,true);ui.refresh();};
  ui.stop=()=>{ui.authenticated=false;ui.generation++;clearInterval(ui.timer);$$('dialog.ui-dialog[open]').forEach(d=>d.close());};
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)ui.refresh();});
  addEventListener('beforeunload',e=>{if(ui.rulesDirty||ui.profileDirty){e.preventDefault();e.returnValue='';}});
  // Disable the old manual hide/show navigation filter: all six groups are stable.
  window._navShowAll=true;
  ui.renderRules();
  // Login and translated initial content use the same existing localization system.
  if(typeof i18nApply==='function')i18nApply();
})();
