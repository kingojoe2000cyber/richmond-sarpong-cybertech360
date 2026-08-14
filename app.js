const modules = {
  'information-security': {
    title: 'Information Security', icon: '◈', score: 88,
    description: 'Govern information assets, access, classification, retention, encryption and security compliance.',
    templates: [
      'Access Rights & Permissions Matrix','Data Breach Notification Log','Data Classification Register','Data Loss Prevention (DLP) Incident Log','Document Retention & Disposal Tracker','Encryption Key Management Sheet','Incident Reporting & Tracking Sheet','Information Security Policy Compliance Checklist','Security KPI Dashboard'
    ]
  },
  'cloud-security': {
    title: 'Cloud Security', icon: '☁', score: 84,
    description: 'Control cloud access, asset inventory, resilience testing, incident response and secure configurations.',
    templates: ['Cloud Access Control Matrix','Cloud Asset Inventory Tracker','Cloud Backup & Recovery Testing Tracker','Cloud Incident Response Log','Cloud Security Configuration Baseline']
  },
  'security-management': {
    title: 'Security Management', icon: '⌘', score: 91,
    description: 'Manage core security policies, compliance obligations, information handling and lifecycle controls.',
    templates: ['Acceptable Use of Assets','Password Policy','Backup and Recovery Policy','Compliance Management Register','Disposal and Destruction Policy','Information Classification Policy','Information Transfer Policy']
  },
  'network-security': {
    title: 'Network Security', icon: '⌁', score: 81,
    description: 'Monitor network assets, access controls, malicious traffic, patching and security event correlation.',
    templates: ['DDoS Attack Mitigation Plan Tracker','IP Whitelist-Blacklist Tracker','Network Access Control Log','Network Device Inventory','Network Security Risk Mitigation Report','Network Traffic Monitoring Dashboard','Patch Management Schedule for Network Devices','Security Event Correlation Tracker']
  },
  'application-security': {
    title: 'Application Security', icon: '◇', score: 79,
    description: 'Secure software through encryption, threat modeling, authentication controls, testing and vulnerability tracking.',
    templates: ['Application Data Encryption Checklist','Application Risk Assessment Matrix','Application Threat Modeling','Authentication & Authorization Control Sheet','Patch & Update Tracker','Secure Coding Checklist','Secure Mobile App Testing Tracker','Security Misconfiguration Log','Static Code Analysis Log','Web Application Vulnerability Tracker']
  },
  'disaster-recovery': {
    title: 'Disaster Recovery', icon: '↻', score: 86,
    description: 'Maintain recoverability through documented strategy, asset registers, communications and recovery exercises.',
    templates: ['DR Approach Document','DR Asset Register','DR Closure Report','DR Communications Plan','DR Plan Template']
  },
  'incident-management': {
    title: 'Incident Management', icon: '⚠', score: 83,
    description: 'Coordinate incident handling from identification and triage through containment, reporting and closure.',
    templates: ['Incident Management Guide','Incident Management Policy','Incident Management Process','Internal Incident Report','Major Incident Report Template','Structure Damage Incident Report','Workplace Violence Report']
  },
  'problem-management': {
    title: 'Problem Management', icon: '◎', score: 77,
    description: 'Identify root causes, maintain known-error records and prevent recurring technology and security incidents.',
    templates: ['Known Error (KE) Record Template','Major Problem Report Template','Problem Management Process','Problem Record Template']
  }
};

const defaultIncidents = [
  { id: 'INC-0264', title: 'Privileged login from unusual location', severity: 'Critical', status: 'Investigating', owner: 'SOC Team', opened: '14 Aug 2026' },
  { id: 'INC-0261', title: 'Phishing campaign targeting finance users', severity: 'High', status: 'Contained', owner: 'Security Operations', opened: '13 Aug 2026' },
  { id: 'INC-0258', title: 'Outdated TLS configuration detected', severity: 'Medium', status: 'Open', owner: 'Infrastructure', opened: '12 Aug 2026' },
  { id: 'INC-0251', title: 'Cloud storage sharing misconfiguration', severity: 'High', status: 'Resolved', owner: 'Cloud Security', opened: '10 Aug 2026' },
  { id: 'INC-0247', title: 'Endpoint malware alert quarantined', severity: 'Low', status: 'Resolved', owner: 'Endpoint Security', opened: '09 Aug 2026' }
];

let incidents = JSON.parse(localStorage.getItem('cybertech360_incidents') || 'null') || defaultIncidents;
let currentView = 'overview';

const viewContainer = document.getElementById('viewContainer');
const sidebar = document.getElementById('sidebar');
const incidentModal = document.getElementById('incidentModal');
const globalSearch = document.getElementById('globalSearch');

const esc = (value='') => value.replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'');

function setActiveNav(view) {
  document.querySelectorAll('.nav-item').forEach(btn => btn.classList.toggle('active', btn.dataset.view === view));
}

function toast(message) {
  const el = document.getElementById('toast');
  el.textContent = message; el.classList.add('show');
  clearTimeout(window.toastTimer); window.toastTimer = setTimeout(() => el.classList.remove('show'), 2400);
}

function pageHeader(title, subtitle, actions='') {
  return `<div class="page-header"><div><p class="eyebrow">Richmond Sarpong CyberTech 360</p><h1>${title}</h1><p>${subtitle}</p></div><div class="header-actions">${actions}</div></div>`;
}

function metric(label, value, foot, icon, trend='') {
  return `<article class="metric-card"><div class="metric-top"><span>${label}</span><span class="metric-icon">${icon}</span></div><div class="metric-value">${value}</div><div class="metric-foot ${trend.includes('▲') ? 'trend-up' : trend.includes('▼') ? 'trend-down' : ''}">${trend ? trend + ' • ' : ''}${foot}</div></article>`;
}

function activityCard() {
  const items = [
    ['✓','ISO 27001 control review completed','Governance Team','12 min'],
    ['⚠','High-risk vendor assessment requires approval','Third-Party Risk','28 min'],
    ['↻','Disaster recovery tabletop exercise updated','BC/DR Team','1 hr'],
    ['◈','New evidence uploaded for MFA control','Identity & Access','2 hrs'],
    ['⌁','Firewall policy review completed','Network Security','3 hrs']
  ];
  return `<div class="activity-list">${items.map(x=>`<div class="activity"><span class="activity-icon">${x[0]}</span><div><strong>${x[1]}</strong><small>${x[2]}</small></div><time>${x[3]}</time></div>`).join('')}</div>`;
}

function eventChart() {
  const values = [42,55,48,70,65,84,72,91,88,103,96,118];
  const max = 125, w = 720, h = 210, pad = 28;
  const pts = values.map((v,i)=>{
    const x = pad + i*((w-pad*2)/(values.length-1));
    const y = h-pad - (v/max)*(h-pad*2);
    return [x,y];
  });
  const line = pts.map(p=>p.join(',')).join(' ');
  const area = `${pad},${h-pad} ${line} ${w-pad},${h-pad}`;
  const labels = ['03','04','05','06','07','08','09','10','11','12','13','14'];
  return `<div class="chart-wrap"><svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Security events trend">
    <defs><linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#22d3ee" stop-opacity=".28"/><stop offset="100%" stop-color="#22d3ee" stop-opacity="0"/></linearGradient></defs>
    ${[0,1,2,3,4].map(i=>`<line class="grid-line" x1="${pad}" y1="${pad+i*36}" x2="${w-pad}" y2="${pad+i*36}"/>`).join('')}
    <polygon class="chart-area" points="${area}"/><polyline class="chart-line" points="${line}"/>
    ${pts.map((p,i)=>`<circle class="chart-dot" cx="${p[0]}" cy="${p[1]}" r="3"/><text class="axis-label" x="${p[0]}" y="${h-5}" text-anchor="middle">${labels[i]}</text>`).join('')}
  </svg></div>`;
}

function heatmap() {
  const nums = [[0,1,1,2,1],[1,2,3,2,1],[1,3,4,3,2],[2,3,4,5,3],[1,2,3,4,5]];
  let html = `<div class="heatmap"><div></div>${['1','2','3','4','5'].map(x=>`<div class="heatmap-label">${x}</div>`).join('')}`;
  ['5','4','3','2','1'].forEach((label,r)=>{ html += `<div class="heatmap-label">${label}</div>`; nums[r].forEach(n=> html += `<div class="heat-cell risk-${Math.max(1,n)}">${n || ''}</div>`); });
  return html + `</div><div style="display:flex;justify-content:space-between;margin-top:10px;font-size:9px;color:var(--muted)"><span>Likelihood →</span><span>Impact ↑</span></div>`;
}

function incidentRows(list=incidents) {
  return list.map(i => `<tr>
    <td><strong>${esc(i.id)}</strong></td><td>${esc(i.title)}</td>
    <td><span class="severity-pill sev-${i.severity.toLowerCase()}">● ${esc(i.severity)}</span></td>
    <td><span class="status-pill status-${i.status.toLowerCase().replace(/\s+/g,'-')}">${esc(i.status)}</span></td>
    <td>${esc(i.owner)}</td><td>${esc(i.opened)}</td>
  </tr>`).join('');
}

function incidentTable(list=incidents) {
  return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Incident</th><th>Severity</th><th>Status</th><th>Owner</th><th>Opened</th></tr></thead><tbody>${incidentRows(list)}</tbody></table></div>`;
}

function domainCards() {
  return Object.entries(modules).map(([key,m]) => `<article class="domain-card" data-domain="${key}">
    <div class="domain-icon">${m.icon}</div><h3>${m.title}</h3><p>${m.description}</p><div class="domain-meta"><span>${m.templates.length} templates</span><span class="domain-score">${m.score}% mature</span></div>
  </article>`).join('');
}

function overview() {
  viewContainer.innerHTML = `
    ${pageHeader('Security Command Center','A unified view of cybersecurity governance, risk, compliance and operational resilience.',`<button class="btn secondary" id="exportBtn">Export CSV</button><button class="btn primary" id="addIncidentBtn">+ New Incident</button>`)}
    <section class="metrics-grid">
      ${metric('Security posture','87/100','Strong posture','◈','▲ 4.2%')}
      ${metric('Open incidents',String(incidents.filter(i=>i.status!=='Resolved').length),'Across all domains','⚠','▼ 12%')}
      ${metric('Critical risks','4','2 overdue treatments','◆')}
      ${metric('Compliance','82%','4 frameworks tracked','✓','▲ 3.1%')}
      ${metric('Assets monitored','1,248','Cloud + on-prem','⌁','▲ 38')}
      ${metric('Mean time to detect','18m','Target < 30m','⌕','▲ 8m faster')}
    </section>

    <section class="dashboard-grid">
      <article class="card card-span-2"><div class="card-header"><div><h3>Security events trend</h3><p>Detected security events • last 12 days</p></div><button class="link-btn">Live telemetry</button></div>${eventChart()}</article>
      <article class="card"><div class="card-header"><div><h3>Risk distribution</h3><p>83 active risks by residual severity</p></div></div><div class="donut-layout"><div class="donut"></div><div class="legend"><div class="legend-row"><span class="dot red"></span><span>Critical</span><strong>9</strong></div><div class="legend-row"><span class="dot orange"></span><span>High</span><strong>17</strong></div><div class="legend-row"><span class="dot yellow"></span><span>Medium</span><strong>26</strong></div><div class="legend-row"><span class="dot green"></span><span>Low</span><strong>31</strong></div></div></div></article>
      <article class="card"><div class="card-header"><div><h3>Framework compliance</h3><p>Current control implementation progress</p></div></div><div class="progress-list">
        ${[['ISO/IEC 27001',88],['NIST CSF 2.0',84],['CIS Controls',79],['COBIT 2019',76]].map(x=>`<div class="progress-row"><div class="progress-meta"><strong>${x[0]}</strong><span>${x[1]}%</span></div><div class="progress-bar"><div class="progress-fill" style="width:${x[1]}%"></div></div></div>`).join('')}
      </div></article>
      <article class="card"><div class="card-header"><div><h3>Enterprise risk heat map</h3><p>Residual risk concentration</p></div></div>${heatmap()}</article>
      <article class="card"><div class="card-header"><div><h3>Control activity</h3><p>Latest governance and security updates</p></div><button class="link-btn">View all</button></div>${activityCard()}</article>
      <article class="card card-span-3"><div class="card-header"><div><h3>Recent security incidents</h3><p>Operational incidents requiring monitoring or action</p></div><button class="link-btn" data-view-jump="incident-management">Open incident register →</button></div>${incidentTable(incidents.slice(0,5))}</article>
    </section>

    <div class="section-title"><div><h2>Cybersecurity Domains</h2><p>Manage the template and control library derived from your cybersecurity catalogue.</p></div></div>
    <section class="domain-grid">${domainCards()}</section>

    <div class="section-title"><div><h2>Quick Actions</h2><p>Common tasks for day-to-day security governance.</p></div></div>
    <section class="quick-grid">
      <button class="quick-action" id="qaIncident"><span class="quick-icon">⚠</span><span><strong>Create incident</strong><small>Log and assign a security incident</small></span></button>
      <button class="quick-action" data-domain-jump="information-security"><span class="quick-icon">◈</span><span><strong>Control review</strong><small>Review information security controls</small></span></button>
      <button class="quick-action" data-domain-jump="disaster-recovery"><span class="quick-icon">↻</span><span><strong>DR exercise</strong><small>Review recovery plans and testing</small></span></button>
      <button class="quick-action" id="qaExport"><span class="quick-icon">⇩</span><span><strong>Export incidents</strong><small>Download the current register as CSV</small></span></button>
    </section>`;

  document.getElementById('addIncidentBtn').onclick = openIncidentModal;
  document.getElementById('qaIncident').onclick = openIncidentModal;
  document.getElementById('exportBtn').onclick = exportIncidents;
  document.getElementById('qaExport').onclick = exportIncidents;
  document.querySelectorAll('[data-domain]').forEach(c => c.onclick = () => navigate(c.dataset.domain));
  document.querySelectorAll('[data-domain-jump]').forEach(c => c.onclick = () => navigate(c.dataset.domainJump));
  document.querySelectorAll('[data-view-jump]').forEach(c => c.onclick = () => navigate(c.dataset.viewJump));
}

function moduleView(key) {
  const m = modules[key];
  const actions = key === 'incident-management' ? `<button class="btn primary" id="addIncidentBtn">+ New Incident</button>` : `<button class="btn secondary" id="runAssessmentBtn">Run Assessment</button><button class="btn primary" id="newEvidenceBtn">+ Add Evidence</button>`;
  const incidentBlock = key === 'incident-management' ? `<article class="card" style="margin-top:16px"><div class="card-header"><div><h3>Incident register</h3><p>${incidents.length} incidents currently recorded in this browser</p></div><button class="btn secondary" id="exportBtn">Export CSV</button></div>${incidentTable(incidents)}</article>` : '';
  viewContainer.innerHTML = `
    ${pageHeader(m.title,m.description,actions)}
    <section class="module-hero">
      <article class="card"><div class="card-header"><div><h3>${m.title} maturity</h3><p>Control effectiveness based on sample dashboard data</p></div></div><div class="module-score"><div class="score-ring" style="--score:${m.score}" data-score="${m.score}"></div><div><h2 style="margin:0 0 7px">${m.score >= 85 ? 'Strong' : m.score >= 80 ? 'Managed' : 'Developing'}</h2><p style="color:var(--muted);font-size:11px;line-height:1.6;margin:0">${m.templates.length} governance templates are available in this domain. Review evidence, owners, due dates and control performance regularly.</p></div></div></article>
      <article class="card"><div class="card-header"><div><h3>Domain indicators</h3><p>Current operational snapshot</p></div></div><div class="progress-list">
        <div class="progress-row"><div class="progress-meta"><strong>Controls implemented</strong><span>${Math.min(98,m.score+3)}%</span></div><div class="progress-bar"><div class="progress-fill" style="width:${Math.min(98,m.score+3)}%"></div></div></div>
        <div class="progress-row"><div class="progress-meta"><strong>Evidence freshness</strong><span>${Math.max(70,m.score-4)}%</span></div><div class="progress-bar"><div class="progress-fill" style="width:${Math.max(70,m.score-4)}%"></div></div></div>
        <div class="progress-row"><div class="progress-meta"><strong>Actions closed on time</strong><span>${Math.max(66,m.score-9)}%</span></div><div class="progress-bar"><div class="progress-fill" style="width:${Math.max(66,m.score-9)}%"></div></div></div>
      </div></article>
    </section>
    <article class="card"><div class="card-header"><div><h3>Templates & Documents</h3><p>Operational documents based on the cybersecurity catalogue you supplied.</p></div><span style="font-size:10px;color:var(--muted)">${m.templates.length} items</span></div><div class="module-list">
      ${m.templates.map((t,idx)=>`<div class="template-item" data-template="${slug(t)}"><span class="template-icon">▤</span><div><strong>${t}</strong><small>Template • Owner: ${idx%2 ? 'Security Operations' : 'GRC Office'} • Review: Quarterly</small></div><div class="template-actions"><button class="mini-btn" data-template-open="${esc(t)}">Open</button></div></div>`).join('')}
    </div></article>${incidentBlock}`;

  const addBtn = document.getElementById('addIncidentBtn'); if(addBtn) addBtn.onclick = openIncidentModal;
  const exportBtn = document.getElementById('exportBtn'); if(exportBtn) exportBtn.onclick = exportIncidents;
  const assessmentBtn = document.getElementById('runAssessmentBtn'); if(assessmentBtn) assessmentBtn.onclick = ()=>toast(`${m.title} assessment workspace prepared.`);
  const evidenceBtn = document.getElementById('newEvidenceBtn'); if(evidenceBtn) evidenceBtn.onclick = ()=>toast(`Evidence action opened for ${m.title}.`);
  document.querySelectorAll('[data-template-open]').forEach(b=> b.onclick = ()=>toast(`${b.dataset.templateOpen}: document workspace is ready for integration.`));
}

function reportsView() {
  const reports = [
    ['Executive Security Posture','Board-ready overview of risk, compliance, incidents and resilience.'],
    ['Risk & Treatment Report','Enterprise risk register summary with action status and residual risk.'],
    ['Compliance Status Report','Framework-by-framework control implementation and evidence gaps.'],
    ['Incident Trend Report','Incident volume, severity, response time and closure performance.'],
    ['Cloud Security Report','Cloud controls, misconfiguration trends, access and backup health.'],
    ['Business Resilience Report','DR readiness, exercises, recovery objectives and open actions.']
  ];
  viewContainer.innerHTML = `${pageHeader('Reports & Analytics','Generate decision-ready cybersecurity reports for management, audit and operations.',`<button class="btn primary" id="generateReportBtn">Generate Executive Report</button>`)}<section class="report-grid">${reports.map((r,i)=>`<article class="report-card"><span class="template-icon">${['▤','◆','✓','⚠','☁','↻'][i]}</span><h3>${r[0]}</h3><p>${r[1]}</p><button class="mini-btn" data-report="${r[0]}">Prepare report →</button></article>`).join('')}</section>`;
  document.getElementById('generateReportBtn').onclick=()=>toast('Executive report generation workflow prepared.');
  document.querySelectorAll('[data-report]').forEach(b=>b.onclick=()=>toast(`${b.dataset.report} prepared for export integration.`));
}

function settingsView() {
  viewContainer.innerHTML = `${pageHeader('Settings','Configure dashboard behavior, alerts, governance defaults and data preferences.')}
  <section class="settings-grid"><article class="card"><div class="card-header"><div><h3>Security preferences</h3><p>Local demo settings for this GitHub-ready dashboard</p></div></div>
    ${[['Critical incident alerts','Receive notifications for critical severity events',true],['Evidence expiry alerts','Flag evidence that requires refresh',true],['Weekly executive summary','Prepare a weekly governance digest',false],['Auto-save local changes','Persist demo incident data in the browser',true]].map(x=>`<div class="setting-row"><div><strong>${x[0]}</strong><small>${x[1]}</small></div><button class="switch ${x[2]?'on':''}" aria-label="Toggle ${x[0]}"></button></div>`).join('')}
  </article><article class="card"><div class="card-header"><div><h3>Organization profile</h3><p>Branding and governance context</p></div></div>
    <div class="setting-row"><div><strong>Organization</strong><small>Richmond Sarpong CyberTech 360</small></div></div>
    <div class="setting-row"><div><strong>Primary frameworks</strong><small>ISO 27001 • NIST CSF • CIS • COBIT</small></div></div>
    <div class="setting-row"><div><strong>Environment</strong><small>Demo / GitHub Pages</small></div></div>
    <div class="setting-row"><div><strong>Data storage</strong><small>Browser localStorage for demo records</small></div></div>
  </article></section>`;
  document.querySelectorAll('.switch').forEach(s=>s.onclick=()=>{s.classList.toggle('on');toast('Setting updated locally.');});
}

function navigate(view) {
  currentView = view; setActiveNav(view); sidebar.classList.remove('open');
  if (view === 'overview') overview();
  else if (modules[view]) moduleView(view);
  else if (view === 'reports') reportsView();
  else if (view === 'settings') settingsView();
  else viewContainer.innerHTML = `<div class="empty-state"><h3>Module coming soon</h3><p>This section is ready for expansion.</p></div>`;
  window.scrollTo({top:0,behavior:'smooth'});
}

function openIncidentModal() { incidentModal.classList.add('show'); incidentModal.setAttribute('aria-hidden','false'); setTimeout(()=>incidentModal.querySelector('input')?.focus(),50); }
function closeIncidentModal() { incidentModal.classList.remove('show'); incidentModal.setAttribute('aria-hidden','true'); }

document.querySelectorAll('[data-close-modal]').forEach(el => el.addEventListener('click', closeIncidentModal));
document.getElementById('incidentForm').addEventListener('submit', e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const next = String(267 + incidents.length).padStart(4,'0');
  const record = { id:`INC-${next}`, title:fd.get('title'), owner:fd.get('owner'), severity:fd.get('severity'), status:fd.get('status'), opened:new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) };
  incidents.unshift(record); localStorage.setItem('cybertech360_incidents', JSON.stringify(incidents));
  e.target.reset(); closeIncidentModal(); toast(`Incident ${record.id} created.`); navigate(currentView);
});

function exportIncidents() {
  const header = ['ID','Title','Severity','Status','Owner','Opened'];
  const csv = [header, ...incidents.map(i=>[i.id,i.title,i.severity,i.status,i.owner,i.opened])]
    .map(row=>row.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8'}); const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'cybertech360-incidents.csv'; a.click(); URL.revokeObjectURL(url); toast('Incident register exported as CSV.');
}

document.querySelectorAll('.nav-item').forEach(btn => btn.addEventListener('click',()=>navigate(btn.dataset.view)));
document.getElementById('menuBtn').onclick = () => sidebar.classList.toggle('open');
document.getElementById('themeToggle').onclick = () => { document.body.classList.toggle('light'); localStorage.setItem('cybertech360_theme', document.body.classList.contains('light')?'light':'dark'); };
if(localStorage.getItem('cybertech360_theme')==='light') document.body.classList.add('light');

globalSearch.addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  if (!q) return;
  const moduleMatch = Object.entries(modules).find(([k,m])=>m.title.toLowerCase().includes(q) || m.templates.some(t=>t.toLowerCase().includes(q)));
  if (moduleMatch && e.inputType === 'insertLineBreak') navigate(moduleMatch[0]);
});
globalSearch.addEventListener('keydown',e=>{
  if(e.key==='Enter'){
    const q=e.target.value.trim().toLowerCase();
    const moduleMatch=Object.entries(modules).find(([k,m])=>m.title.toLowerCase().includes(q)||m.templates.some(t=>t.toLowerCase().includes(q)));
    if(moduleMatch){navigate(moduleMatch[0]);toast(`Opened ${moduleMatch[1].title}.`);} else toast('No matching module or template found.');
  }
});
document.addEventListener('keydown', e => { if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();globalSearch.focus();} if(e.key==='Escape')closeIncidentModal(); });

navigate('overview');
