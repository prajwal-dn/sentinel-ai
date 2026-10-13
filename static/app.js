'use strict';
/* Sentinel AI UI. Every dynamic value is escaped by the `html` tagged template; there are no inline handlers (CSP). */
class Raw { constructor(s) { this.s = s; } }
const raw = s => new Raw(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rend = v => v instanceof Raw ? v.s : Array.isArray(v) ? v.map(rend).join('') : esc(v);
const html = (s, ...v) => raw(s.reduce((a, t, i) => a + t + (i < v.length ? rend(v[i]) : ''), ''));
const q = s => document.querySelector(s), qa = s => [...document.querySelectorAll(s)];

const S = { status: null, datasets: [], invs: [], view: 'overview', arg: null, lastIngest: null, busy: false, error: null };
const NAV = {
  overview: 'Overview',
  ingest: 'Ingest',
  events: 'Events',
  investigations: 'Cases',
  mitre: 'MITRE ATT&CK',
  connectors: 'Connectors',
  settings: 'Settings',
};

const token = () => sessionStorage.getItem('sentinel_token') || '';
async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (token()) headers.Authorization = 'Bearer ' + token();
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  const ct = r.headers.get('content-type') || '';
  const body = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok && !(opts.allowStatus || []).includes(r.status)) {
    const msg = typeof body === 'string' ? body : (typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail || body));
    const e = new Error(msg); e.status = r.status; throw e;
  }
  return body;
}
const announce = m => { q('#live').textContent = m; };
const alertBox = (kind, msg) => html`<div class="alert ${kind}" role="${kind === 'bad' ? 'alert' : 'status'}">${msg}</div>`;
const sev = s => html`<span class="sev sev-${s}">${String(s).toUpperCase()}</span>`;
const pill = (t, k = 'muted') => html`<span class="pill ${k}">${t}</span>`;
const tm = s => s ? s.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : 'unknown';
const evs = ids => (ids || []).slice(0, 12).map(i => html`<button class="ev" data-act="event" data-id="${i}" title="Open evidence">${i}</button>`);

async function refresh() {
  const [status, ds, inv] = await Promise.all([api('/api/status'), api('/api/datasets'), api('/api/investigations')]);
  S.status = status; S.datasets = ds.datasets; S.invs = inv.investigations;
  const c = status.connectors[0];
  const b = q('#modebadge');
  b.className = 'pill ' + (c.live ? 'ok' : 'muted');
  b.textContent = c.live ? 'LIVE: WAZUH CONNECTED' : 'NO LIVE FEED / FILE ANALYSIS';
}

/* ------------------------------------------------------------------ views */
function head(k, t, d, extra = '') { return html`<div class="head"><div><div class="kicker">${k}</div><h1>${t}</h1><p>${d}</p></div><div>${extra}</div></div>`; }

function overview() {
  const st = S.status, c = st.connectors[0];
  const stats = html`<div class="grid stats">
    <div class="card stat"><small>DATASETS</small><b>${S.datasets.length}</b><small>UPLOADED / CONNECTED</small></div>
    <div class="card stat"><small>EVENTS STORED</small><b>${st.counts.events}</b><small>NORMALISED FROM YOUR LOGS</small></div>
    <div class="card stat"><small>INVESTIGATIONS</small><b>${S.invs.length}</b><small>${S.invs.filter(i => i.agent_status === 'COMPLETED').length} WITH AI RESULT</small></div>
    <div class="card stat"><small>AI AGENT</small><b class="${st.llm.configured ? 'green' : 'amber'}">${st.llm.configured ? 'READY' : 'OFF'}</b><small>${st.llm.status}</small></div></div>`;
  if (!S.datasets.length) {
    return html`${head('COMMAND CENTER', 'Security overview', 'Sentinel AI investigates real security logs. Nothing is pre-loaded.')}${stats}
      <div class="empty gap"><h2>No logs yet</h2><p>Upload an auth.log, syslog, JSON/JSONL, Wazuh alert export or Windows event XML to start an investigation.</p>
      <button class="btn" data-act="nav" data-v="ingest">Upload logs</button></div>`;
  }
  const rows = S.invs.length ? html`<table class="table"><tr><th>CASE</th><th>SEVERITY (RULES)</th><th>FINDINGS</th><th>HOSTS</th><th>AI</th></tr>
    ${S.invs.map(i => html`<tr><td><button class="btn ghost sm" data-act="open" data-id="${i.id}">${i.id}</button><br><span class="sp">${i.title}</span></td><td>${sev(i.severity)}</td><td>${i.findings}</td><td>${i.hosts.join(', ')}</td><td>${i.agent_status}${i.ai_assessment ? ' / ' + i.ai_assessment : ''}</td></tr>`)}</table>`
    : alertBox('info', 'Datasets are loaded but no analysis has produced cases yet (or no suspicious patterns were detected). Open Ingest logs and press Analyze.');
  return html`${head('COMMAND CENTER', 'Security overview', 'State of your uploaded data and investigations.')}${stats}
    <div class="card gap"><div class="title">INVESTIGATIONS</div><div class="box scroll">${rows}</div></div>`;
}

function ingest() {
  const li = S.lastIngest;
  let result = '';
  if (li) {
    const s = li.summary, kind = s.status === 'SUCCESS' ? 'ok' : s.status === 'PARTIAL' ? 'warn' : 'bad';
    result = html`<div class="card gap box"><div class="title">INGESTION RESULT</div>
      ${alertBox(kind, s.status === 'FAILED' ? (s.message || 'Nothing could be ingested.') : `${s.status}: ${s.accepted} accepted, ${s.rejected} rejected, ${s.unsupported} unsupported of ${s.records_total} records (${s.detected_format}).`)}
      <dl class="kv gap"><dt>FILE</dt><dd>${s.filename}</dd><dt>SHA-256</dt><dd class="mono">${s.sha256}</dd><dt>NEW EVENTS STORED</dt><dd>${s.new_events_stored} (duplicates skipped: ${s.duplicates_skipped})</dd>
      <dt>UNCLASSIFIED</dt><dd>${s.accepted_but_unclassified} accepted events could not be classified; they are stored but do not drive detections.</dd>
      <dt>NO TIMESTAMP</dt><dd>${s.accepted_without_timestamp}</dd></dl>
      ${(s.caveats || []).map(c => alertBox('warn', c))}
      ${[...s.rejected_samples.map(r => ['Rejected', r]), ...s.unsupported_samples.map(r => ['Unsupported', r])].slice(0, 10).map(([k, r]) => html`<p class="sp">${k} / record ${r.position}: ${r.reason} <span class="mono">${r.excerpt}</span></p>`)}
      ${li.dataset_id ? html`<button class="btn" data-act="analyze" data-id="${li.dataset_id}">Analyze dataset</button>` : ''}</div>`;
  }
  const opts = S.datasets.map(d => html`<option value="${d.id}">${d.name} (${d.event_count} events)</option>`);
  const dsRows = S.datasets.length ? html`<table class="table"><tr><th>DATASET</th><th>SOURCE</th><th>EVENTS</th><th>RANGE</th><th></th></tr>${S.datasets.map(d => html`<tr>
    <td>${d.name}<br><span class="sp mono">${d.id}</span></td><td>${d.source_kind === 'FILE_UPLOAD' ? pill('FILE UPLOAD / NOT LIVE', 'muted') : pill(d.source_kind, 'info')}</td><td>${d.event_count}</td>
    <td class="sp">${tm(d.first_event)}<br>${tm(d.last_event)}</td><td><button class="btn sm" data-act="analyze" data-id="${d.id}">Analyze</button>
    <button class="btn ghost sm" data-act="events" data-id="${d.id}">Events</button> <button class="btn danger sm" data-act="delete" data-id="${d.id}">Delete</button></td></tr>`)}</table>`
    : html`<p class="sp">No datasets yet.</p>`;
  const fmts = Object.entries(S.status.supported_formats).map(([k, v]) => html`<li><b>${k}</b> - ${v}</li>`);
  return html`${head('INGESTION', 'Ingest logs', 'Upload real security logs. Files are parsed, validated and normalised; unparseable records are reported, never silently dropped.')}
    <div class="card box"><div class="dz" id="dz"><p>Drop a log file here or choose one (max ${S.status.limits.max_upload_mb} MB)</p>
    <input type="file" id="file" aria-label="Log file" accept=".log,.txt,.json,.jsonl,.ndjson,.xml,.out,.syslog"></div>
    <div class="gap"><span class="field"><label for="dsname">Dataset name (optional)</label><input id="dsname" maxlength="120"></span>
    <span class="field"><label for="dsid">Add to existing dataset</label><select id="dsid"><option value="">New dataset</option>${opts}</select></span>
    <span class="field"><label for="year">Year for syslog lines (no year in file)</label><input id="year" type="number" min="1990" max="2100" value="${new Date().getFullYear()}"></span></div>
    <button class="btn" id="upload" data-act="upload" ${S.busy ? 'disabled' : ''}>${S.busy ? 'Uploading...' : 'Upload & parse'}</button></div>
    ${result}
    <div class="card gap"><div class="title">DATASETS</div><div class="box scroll">${dsRows}</div></div>
    <div class="card gap box"><div class="title">SUPPORTED FORMATS</div><ul class="sp">${fmts}</ul><p class="sp">Binary .evtx is not supported: export to XML or JSON first.</p></div>`;
}

async function eventsView() {
  if (!S.datasets.length) return html`${head('EVENTS', 'Events', 'Search normalised events.')}<div class="empty"><h2>No events</h2><p>Upload logs first.</p></div>`;
  const id = S.arg && S.datasets.find(d => d.id === S.arg) ? S.arg : S.datasets[0].id;
  const f = S.filters || {};
  const params = new URLSearchParams(Object.entries(f).filter(([, v]) => v)); params.set('limit', '200');
  const r = await api(`/api/datasets/${encodeURIComponent(id)}/events?` + params);
  const filt = k => html`<span class="field"><label for="f_${k}">${k}</label><input id="f_${k}" value="${f[k] || ''}" data-filter="${k}"></span>`;
  return html`${head('EVENTS', 'Events', 'Normalised events with source evidence. Missing fields stay empty; never inferred.')}
    <div class="card box"><span class="field"><label for="dssel">Dataset</label><select id="dssel">${S.datasets.map(d => html`<option value="${d.id}" ${d.id === id ? 'selected' : ''}>${d.name}</option>`)}</select></span>
    ${['text', 'host', 'username', 'src_ip', 'action', 'outcome'].map(filt)}<button class="btn sm" data-act="filter">Apply</button></div>
    <div class="card gap"><div class="title">${r.total} MATCHING / SHOWING ${r.count}</div><div class="box scroll"><table class="table"><tr><th>TIME (UTC)</th><th>ID</th><th>HOST</th><th>USER</th><th>SRC</th><th>ACTION</th><th>OUTCOME</th><th>MESSAGE</th></tr>
    ${r.events.map(e => html`<tr><td>${tm(e.timestamp)}</td><td><button class="ev" data-act="event" data-id="${e.event_id}" data-ds="${id}">${e.event_id}</button></td><td>${e.host}</td><td>${e.username}</td><td>${e.src_ip}</td><td>${e.action}</td><td>${e.outcome}</td><td class="mono">${(e.message || '').slice(0, 140)}</td></tr>`)}</table></div></div>`;
}

function investigations() {
  if (!S.invs.length) return html`${head('CASES', 'Investigations', 'Cases are produced by analysing a dataset.')}<div class="empty"><h2>No investigations</h2><p>${S.datasets.length ? 'Analyze a dataset from Ingest logs. If nothing suspicious matches the configured rules, no case is created.' : 'Upload logs first.'}</p><button class="btn" data-act="nav" data-v="ingest">Go to ingestion</button></div>`;
  return html`${head('CASES', 'Investigations', 'Severity shown is from transparent rules. AI confidence is separate and only present after an agent run.')}
  <div class="card"><div class="box scroll"><table class="table"><tr><th>CASE</th><th>SEVERITY (RULES)</th><th>FINDINGS</th><th>WINDOW</th><th>AI INVESTIGATION</th></tr>
  ${S.invs.map(i => html`<tr><td><button class="btn ghost sm" data-act="open" data-id="${i.id}">${i.id}</button><br>${i.title}</td><td>${sev(i.severity)}${i.attack_chain ? pill('CHAIN', 'bad') : ''}</td><td>${i.findings}</td><td class="sp">${tm(i.first_seen)}<br>${tm(i.last_seen)}</td><td>${i.agent_status}${i.ai_assessment ? ' / ' + i.ai_assessment : ''}</td></tr>`)}</table></div></div>`;
}

async function incident() {
  const v = await api('/api/investigations/' + encodeURIComponent(S.arg));
  const a = v.agent || { status: 'NOT_RUN' }, res = a.result;
  const llm = S.status.llm;
  const hdr = html`<div class="card case box"><div class="row">${sev(v.severity)} ${pill('RULE-BASED SEVERITY', 'muted')} ${v.case.attack_chain ? pill('ATTACK CHAIN', 'bad') : ''} ${pill(v.source.kind === 'FILE_UPLOAD' ? 'FILE UPLOAD / NOT LIVE TELEMETRY' : v.source.kind, 'muted')}</div>
    <h2>${v.title}</h2><p class="note">${v.severity_basis.join(' ')}</p>
    <dl class="kv gap"><dt>CASE</dt><dd class="mono">${v.id}</dd><dt>HOSTS</dt><dd>${v.case.hosts.join(', ') || 'unknown'}</dd><dt>ACCOUNTS</dt><dd>${v.case.users.join(', ') || 'unknown'}</dd><dt>IPS</dt><dd>${v.case.ips.join(', ') || 'unknown'}</dd><dt>WINDOW</dt><dd>${tm(v.case.first_seen)} to ${tm(v.case.last_seen)}</dd></dl>
    <div class="row gap"><a class="btn ghost" href="/api/investigations/${encodeURIComponent(v.id)}/report" data-act="report" data-id="${v.id}">Download report</a></div></div>`;
  const links = v.case.correlation_links.length ? html`<ul class="sp">${v.case.correlation_links.map(l => html`<li>${l.findings.join(' <-> ')}: ${l.reason}</li>`)}</ul>` : html`<p class="sp">Single finding; no correlation links.</p>`;
  const findings = v.findings.map(f => html`<div class="item"><b>${f.finding_id} / ${f.title}</b> ${sev(f.severity)} ${pill('evidence: ' + f.evidence_strength)} ${pill(f.origin)}
    <p>${f.description}</p><p><b>Severity basis:</b> ${f.severity_basis}</p><p><b>Explanation:</b> ${f.explanation}</p><p class="amber"><b>Uncertainty:</b> ${f.uncertainty}</p>
    <p>Evidence (${f.evidence_total}): ${evs(f.evidence_ids)}</p></div>`);
  const timeline = html`<div class="timeline">${v.timeline.slice(0, 120).map(t => html`<div class="tl"><b>${tm(t.timestamp)} / ${t.stage} <button class="ev" data-act="event" data-id="${t.event_id}">${t.event_id}</button></b><p>${t.summary}</p></div>`)}</div>`;
  const iocs = html`<table class="table"><tr><th>TYPE</th><th>VALUE</th><th>CONTEXT</th><th>ENRICHMENT</th></tr>${v.iocs.slice(0, 60).map(i => html`<tr><td>${i.type}${i.scope ? ' / ' + i.scope : ''}</td><td class="mono">${i.value}</td><td class="sp">${i.roles.slice(0, 2).join('; ')}<br>${evs(i.evidence_ids.slice(0, 3))}</td><td>${pill(i.enrichment.status, i.enrichment.status === 'MATCH' ? 'bad' : 'muted')} <span class="sp">${i.enrichment.detail || ''}</span></td></tr>`)}</table>
    <p class="sp">Extracted locally from cited events; not a verdict on maliciousness. ${S.status.threat_intel.message}</p>
    <button class="btn ghost sm" data-act="enrich" data-id="${v.id}">Run enrichment</button>`;
  const mitre = (list, origin) => list.map(m => html`<div class="mitre"><b>${m.technique_id} ${m.name}</b> ${pill(m.status, m.status === 'OBSERVED' ? 'ok' : 'warn')} ${pill(origin, 'muted')}<br><small>${m.tactic || 'tactic unverified'}</small><p class="sp">${m.basis || (m.bases || [])[0]}</p><p>${evs(m.evidence_ids.slice(0, 5))}</p></div>`);
  const mitreAll = (v.mitre.length || (v.mitre_ai || []).length) ? html`${mitre(v.mitre, 'RULE')}${mitre(v.mitre_ai || [], 'AI HYPOTHESIS')}` : html`<p class="sp">No technique mapping is supported by the evidence.</p>`;
  let ai;
  const trace = (a.trace || []).map(s => html`<div class="step ${s.status === 'OK' || s.status === 'ACCEPTED' ? '' : 'err'}"><b>${s.step}. ${s.type}${s.tool ? ' -> ' + s.tool : ''}</b> ${pill(s.status)}<br>
    ${s.rationale ? html`<small>why: ${s.rationale}</small><br>` : ''}${s.arguments && Object.keys(s.arguments).length ? html`<small class="mono">args: ${JSON.stringify(s.arguments)}</small><br>` : ''}<small>${s.result_summary || s.detail || s.error || ''}</small></div>`);
  if (a.status === 'NOT_RUN' || a.status === 'NOT_CONFIGURED') {
    ai = html`${alertBox(llm.configured ? 'info' : 'warn', llm.configured ? 'AI investigation has not been run for this case. Rule-based findings are shown above.' : llm.message)}
      <button class="btn gap" data-act="agent" data-id="${v.id}" ${llm.configured ? '' : 'disabled'}>Run AI investigation</button>`;
  } else if (res) {
    ai = html`${alertBox(res.assessment === 'LIKELY_MALICIOUS' ? 'bad' : 'info', html`<b>${res.assessment}</b> / model confidence <b>${res.confidence.level}</b> - ${res.confidence.rationale}`)}
      <p>${res.summary}</p>
      <h3>Hypotheses</h3>${res.hypotheses.map(h => html`<div class="item"><b>${h.title}</b> ${pill(h.status, h.status === 'SUPPORTED' ? 'ok' : 'muted')}<p>${h.description}</p><p>${evs(h.evidence_ids.slice(0, 6))}</p></div>`)}
      <h3>Alternative explanations</h3><ul>${res.alternative_explanations.map(x => html`<li>${x}</li>`)}</ul>
      <h3>Missing information</h3><ul>${res.missing_information.map(x => html`<li>${x}</li>`)}</ul>
      ${a.validation_warnings.length ? alertBox('warn', 'Validation: ' + a.validation_warnings.join('; ')) : ''}
      <h3>Investigation trace (${a.provider} / ${a.model} / ${a.steps_used}/${a.max_steps} steps)</h3>${trace}`;
  } else {
    ai = html`${alertBox('bad', `AI investigation ${a.status}: ${a.error || 'no result produced'}. Rule-based findings are unaffected.`)}${trace}
      <button class="btn gap" data-act="agent" data-id="${v.id}" ${llm.configured ? '' : 'disabled'}>Retry AI investigation</button>`;
  }
  const recs = v.recommendations.map(r => { const d = r.latest_decision; return html`<div class="item"><b class="${r.disruptive ? 'amber' : ''}">${r.disruptive ? 'DISRUPTIVE / ' : ''}${r.action}</b> ${pill(r.origin)}
    <p>${r.rationale}${r.risk ? ' Risk: ' + r.risk : ''}</p>
    ${d ? alertBox('info', `${d.decision} by ${d.actor} at ${d.decided_at}. Execution: ${d.execution_status} - ${d.execution_detail}`) : ''}
    ${r.requires_approval ? html`<button class="btn sm" data-act="decide" data-id="${v.id}" data-rec="${r.recommendation_id}" data-d="APPROVED">Approve (record only)</button> <button class="btn danger sm" data-act="decide" data-id="${v.id}" data-rec="${r.recommendation_id}" data-d="REJECTED">Reject</button>` : html`<span class="sp">No approval needed (non-disruptive).</span>`}</div>`; });
  const src = v.source.uploads.map(u => html`<li>${u.filename} / ${u.detected_format} / accepted ${u.summary.accepted}, rejected ${u.summary.rejected}, unsupported ${u.summary.unsupported}</li>`);
  return html`${head('INCIDENT', v.id, 'Evidence-linked investigation. Click any event ID to see the source record.')}${hdr}
    <div class="grid invest gap"><div class="stack">
      <div class="card box"><h3>FINDINGS (RULE-BASED)</h3>${findings}<h3>CORRELATION REASONING</h3>${links}</div>
      <div class="card box"><h3>AI INVESTIGATION</h3>${ai}</div>
      <div class="card box"><h3>ATTACK TIMELINE</h3>${timeline}</div>
      <div class="card box"><h3>RECOMMENDED ACTIONS / NOT EXECUTED</h3>${recs}</div></div>
    <div class="stack"><div class="card box"><h3>MITRE ATT&amp;CK</h3>${mitreAll}</div><div class="card box scroll"><h3>INDICATORS</h3>${iocs}</div>
      <div class="card box"><h3>SOURCE</h3><ul class="sp">${src}</ul><p class="sp">Dataset events: ${v.scope.dataset_events}; evidence events: ${v.scope.evidence_events}.</p></div></div></div>`;
}

async function mitreView() {
  const m = await api('/api/mitre');
  if (!m.groups.length) return html`${head('ATT&CK', 'MITRE ATT&CK', 'Technique mappings supported by evidence.')}<div class="empty"><h2>No mappings</h2><p>Mappings appear only when analysed evidence supports them.</p></div>`;
  return html`${head('ATT&CK', 'MITRE ATT&CK', 'OBSERVED = behaviour present in logs. SUSPECTED = inferred from a pattern. Neither proves malicious intent.')}
    <div class="grid matrix">${m.groups.map(g => html`<div class="card"><div class="title">${g.tactic.toUpperCase()}</div>${g.techniques.map(t => html`<div class="tech"><b>${t.technique_id} ${t.name}</b><br>${pill(t.status, t.status === 'OBSERVED' ? 'ok' : 'warn')} ${pill(t.origin === 'RULE' ? 'RULE' : 'AI HYPOTHESIS')}<p>${t.basis || (t.bases || [])[0]}</p><p>${t.investigations.join(', ')}</p></div>`)}</div>`)}</div>`;
}

function connectors() {
  const c = S.status.connectors[0];
  const kind = c.live ? 'ok' : c.status === 'ERROR' ? 'bad' : 'warn';
  return html`${head('INTEGRATIONS', 'Connectors', 'Live status is shown only when events are genuinely arriving.')}
    <div class="card box"><div class="row"><h2>${c.name}</h2>${pill(c.status, kind)}${c.live ? pill('LIVE', 'ok') : pill('NOT LIVE', 'muted')}</div>
    ${alertBox(kind, c.message)}
    <dl class="kv gap"><dt>LAST SUCCESS</dt><dd>${c.last_success || 'never'}</dd><dt>NEWEST EVENT</dt><dd>${c.last_event || 'none received'}</dd><dt>EVENTS STORED</dt><dd>${c.events_stored_total ?? 0}</dd>
    <dt>LIVE WINDOW</dt><dd>${c.live_window_seconds}s</dd><dt>LAST ERROR</dt><dd>${c.last_error ? c.last_error.kind + ' - ' + c.last_error.detail : 'none'}</dd></dl>
    ${(c.warnings || []).map(w => alertBox('warn', w))}
    <div class="row gap"><button class="btn ghost" data-act="wtest">Test connection</button><button class="btn" data-act="wpoll">Poll now</button>${c.dataset_id ? html`<button class="btn ghost" data-act="events" data-id="${c.dataset_id}">View events</button>` : ''}</div>
    <p class="sp">Configure with environment variables on the server (never in the browser): SENTINEL_WAZUH_INDEXER_URL, SENTINEL_WAZUH_USER, SENTINEL_WAZUH_PASSWORD. File uploads are never treated as live telemetry.</p></div>`;
}

async function settings() {
  const st = S.status, au = await api('/api/audit?limit=30');
  return html`${head('CONFIGURATION', 'Status & settings', 'What is configured, and what is not.')}
    <div class="grid stats"><div class="card stat"><small>API AUTH</small><b class="${st.auth === 'ENABLED' ? 'green' : 'amber'}">${st.auth}</b><small>SENTINEL_API_TOKEN</small></div>
    <div class="card stat"><small>LLM</small><b class="${st.llm.configured ? 'green' : 'amber'}">${st.llm.status}</b><small>${st.llm.provider || 'none'} ${st.llm.model || ''}</small></div>
    <div class="card stat"><small>THREAT INTEL</small><b class="amber">${st.threat_intel.status}</b><small>${st.threat_intel.provider || 'none'}</small></div>
    <div class="card stat"><small>AGENT LIMITS</small><b>${st.agent.max_steps}</b><small>MAX STEPS / ${st.agent.deadline_seconds}s</small></div></div>
    <div class="card gap box"><p class="sp">${st.llm.message}</p><p class="sp">${st.threat_intel.message}</p>
    <span class="field"><label for="tok">API token (kept in this browser tab only)</label><input id="tok" type="password" autocomplete="off" value="${token()}"></span><button class="btn sm" data-act="savetoken">Save token</button></div>
    <div class="card gap"><div class="title">AUDIT LOG (latest)</div><div class="box scroll"><table class="table"><tr><th>TIME</th><th>ACTOR</th><th>ACTION</th><th>TARGET</th></tr>${au.entries.map(e => html`<tr><td>${e.ts}</td><td>${e.actor}</td><td>${e.action}</td><td>${e.target}</td></tr>`)}</table></div></div>`;
}

/* ------------------------------------------------------------------ routing & actions */
const VIEWS = { overview, ingest, events: eventsView, investigations, incident, mitre: mitreView, connectors, settings };
async function render() {
  const name = S.view;
  q('#crumb').textContent = (name === 'incident' ? 'INVESTIGATION' : name).toUpperCase();
  qa('#nav button').forEach(b => b.classList.toggle('on', b.dataset.v === (name === 'incident' ? 'investigations' : name)));
  const c = q('#content');
  try { const out = await VIEWS[name](); c.innerHTML = out.s; }
  catch (e) {
    if (e.status === 401) { c.innerHTML = html`${alertBox('bad', 'Authentication required. Enter the API token under Status & settings.')}<button class="btn gap" data-act="nav" data-v="settings">Open settings</button>`.s; }
    else c.innerHTML = alertBox('bad', 'Could not load this view: ' + e.message).s;
  }
  bindDrop();
}
async function go(view, arg = null) {
  S.view = view; S.arg = arg;
  if (location.hash !== '#/' + view + (arg ? '/' + arg : '')) history.pushState(null, '', '#/' + view + (arg ? '/' + arg : ''));
  try { await refresh(); } catch (e) { if (e.status !== 401) { q('#content').innerHTML = alertBox('bad', 'Backend unavailable: ' + e.message).s; return; } if (view !== 'settings') S.view = 'settings'; }
  await render();
}
function bindDrop() {
  const dz = q('#dz'); if (!dz) return;
  ['dragenter', 'dragover'].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.remove('over'); }));
  dz.addEventListener('drop', e => { if (e.dataTransfer.files.length) q('#file').files = e.dataTransfer.files; });
}
async function showEvent(id, ds) {
  const d = q('#drawer');
  try {
    const dsid = ds || (S.view === 'incident' ? (await api('/api/investigations/' + encodeURIComponent(S.arg))).dataset_id : S.arg || (S.datasets[0] || {}).id);
    const e = await api(`/api/datasets/${encodeURIComponent(dsid)}/events/${encodeURIComponent(id)}`);
    d.innerHTML = html`<button class="btn ghost sm" data-act="closedrawer">Close</button><h2>${e.event_id}</h2>
      <dl class="kv">${['timestamp', 'host', 'source_type', 'username', 'target_user', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'process', 'command', 'file_path', 'category', 'action', 'outcome', 'source_file', 'line_no', 'parser']
        .filter(k => e[k] !== null && e[k] !== undefined).map(k => html`<dt>${k}</dt><dd class="mono">${e[k]}</dd>`)}</dl>
      ${e.notes && e.notes.length ? alertBox('warn', 'Notes: ' + e.notes.join(', ')) : ''}<h3>Original record (untrusted)</h3><pre>${e.raw}</pre>`.s;
  } catch (err) { d.innerHTML = html`<button class="btn ghost sm" data-act="closedrawer">Close</button>${alertBox('bad', 'Could not load event: ' + err.message)}`.s; }
  d.classList.remove('hide'); d.querySelector('button').focus();
}
async function act(btn) {
  const a = btn.dataset.act, id = btn.dataset.id;
  const run = async (label, fn) => { btn.disabled = true; announce(label + '...'); try { await fn(); } catch (e) { announce('Error: ' + e.message); q('#content').insertAdjacentHTML('afterbegin', alertBox('bad', label + ' failed: ' + e.message).s); } finally { btn.disabled = false; } };
  switch (a) {
    case 'nav': return go(btn.dataset.v);
    case 'open': return go('incident', id);
    case 'events': S.filters = {}; return go('events', id);
    case 'event': return showEvent(id, btn.dataset.ds);
    case 'closedrawer': return q('#drawer').classList.add('hide');
    case 'upload': {
      const f = q('#file').files[0]; if (!f) return announce('Choose a file first');
      S.busy = true; btn.disabled = true; btn.textContent = 'Uploading...';
      const fd = new FormData(); fd.append('file', f);
      if (q('#dsname').value) fd.append('dataset_name', q('#dsname').value);
      if (q('#dsid').value) fd.append('dataset_id', q('#dsid').value);
      if (q('#year').value) fd.append('default_year', q('#year').value);
      try { S.lastIngest = await api('/api/ingest', { method: 'POST', body: fd, allowStatus: [422] }); announce('Ingestion ' + S.lastIngest.summary.status); }
      catch (e) { S.lastIngest = { dataset_id: null, summary: { status: 'FAILED', message: e.message, filename: f.name, sha256: '', records_total: 0, accepted: 0, rejected: 0, unsupported: 0, new_events_stored: 0, duplicates_skipped: 0, accepted_but_unclassified: 0, accepted_without_timestamp: 0, detected_format: 'unknown', caveats: [], rejected_samples: [], unsupported_samples: [] } }; }
      S.busy = false; await refresh(); return render();
    }
    case 'analyze': return run('Analyzing', async () => { const r = await api(`/api/datasets/${encodeURIComponent(id)}/analyze`, { method: 'POST' }); S.invs = r.investigations; announce(r.message); S.view = 'investigations'; await go('investigations'); if (!r.count) q('#content').insertAdjacentHTML('afterbegin', alertBox('info', r.message).s); });
    case 'delete': if (!confirm('Delete this dataset, its events, investigations and decisions? This cannot be undone.')) return; return run('Deleting', async () => { await api('/api/datasets/' + encodeURIComponent(id), { method: 'DELETE' }); S.lastIngest = null; await go('ingest'); });
    case 'agent': return run('AI investigation', async () => { await api(`/api/investigations/${encodeURIComponent(id)}/agent`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); await render(); });
    case 'enrich': return run('Enrichment', async () => { await api(`/api/investigations/${encodeURIComponent(id)}/enrich`, { method: 'POST' }); await render(); });
    case 'decide': {
      const approve = btn.dataset.d === 'APPROVED';
      if (!confirm((approve ? 'Record APPROVAL' : 'Record REJECTION') + ' for this recommendation?\nSentinel AI will NOT execute anything; this only records your decision.')) return;
      return run('Recording decision', async () => { await api(`/api/investigations/${encodeURIComponent(id)}/recommendations/${encodeURIComponent(btn.dataset.rec)}/decision`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: btn.dataset.d }) }); await render(); });
    }
    case 'filter': { S.filters = {}; qa('[data-filter]').forEach(i => { S.filters[i.dataset.filter] = i.value.trim(); }); S.arg = q('#dssel').value; return render(); }
    case 'wtest': return run('Testing connection', async () => { const r = await api('/api/connectors/wazuh/test', { method: 'POST' }); announce(r.detail); await go('connectors'); });
    case 'wpoll': return run('Polling', async () => { const r = await api('/api/connectors/wazuh/poll', { method: 'POST' }); announce(r.detail); await go('connectors'); });
    case 'savetoken': sessionStorage.setItem('sentinel_token', q('#tok').value); return go('settings');
    case 'report': return;   // plain link download; token-protected deployments use fetch below
  }
}
document.addEventListener('click', async e => {
  const b = e.target.closest('[data-act]'); if (!b) return;
  if (b.dataset.act === 'report' && token()) {
    e.preventDefault();
    const r = await fetch(b.getAttribute('href'), { headers: { Authorization: 'Bearer ' + token() } });
    if (!r.ok) return announce('Report download failed');
    const url = URL.createObjectURL(await r.blob()), a = document.createElement('a'); a.href = url; a.download = b.dataset.id + '-report.md'; a.click(); URL.revokeObjectURL(url); return;
  }
  if (b.dataset.act !== 'report') e.preventDefault();
  act(b);
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') q('#drawer').classList.add('hide'); });
q('#nav').innerHTML = Object.entries(NAV).map(([k, v]) => `<button data-act="nav" data-v="${k}">${v}</button>`).join('');
function fromHash() { const m = location.hash.match(/^#\/([a-z]+)(?:\/(.+))?$/); return m && VIEWS[m[1]] ? [m[1], m[2] ? decodeURIComponent(m[2]) : null] : ['overview', null]; }
window.addEventListener('popstate', () => { const [v, a] = fromHash(); S.view = v; S.arg = a; refresh().then(render).catch(() => render()); });
const [v0, a0] = fromHash(); go(v0, a0);
