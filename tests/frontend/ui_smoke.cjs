// End-to-end UI smoke test: real server + real static assets in jsdom. Usage: node ui_smoke.cjs <baseUrl>
const { JSDOM } = require(process.env.JSDOM_PATH || 'jsdom');
const base = process.argv[2];
const assert = (c, m) => { if (!c) { console.error('FAIL: ' + m); process.exit(1); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function open(path = '/') {
  const html = await (await fetch(base + '/')).text();
  const dom = new JSDOM(html, { url: base + path, runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window;
  w.fetch = (u, o) => fetch(new URL(u, base), o);
  w.confirm = () => true;
  w.eval(await (await fetch(base + '/assets/app.js')).text());
  await sleep(400);
  return w;
}
async function waitFor(w, fn, label) { for (let i = 0; i < 40; i++) { if (fn()) return; await sleep(100); } assert(false, 'timeout: ' + label); }
const text = w => w.document.querySelector('#content').textContent;

(async () => {
  // 1. empty state: no demo, no fake numbers, guides to upload
  let w = await open();
  await waitFor(w, () => text(w).includes('No logs yet'), 'empty state');
  assert(!/demo/i.test(w.document.body.textContent), 'no demo wording in UI');
  assert(w.document.querySelector('#modebadge').textContent.includes('NO LIVE FEED'), 'badge says not live');
  assert(/Upload logs/.test(text(w)), 'upload CTA present');
  w.document.querySelector('[data-v="investigations"]').click();
  await waitFor(w, () => text(w).includes('No investigations'), 'empty investigations');
  w.document.querySelector('[data-v="mitre"]').click();
  await waitFor(w, () => text(w).includes('No mappings'), 'empty mitre');
  w.document.querySelector('[data-v="connectors"]').click();
  await waitFor(w, () => text(w).includes('NOT_CONFIGURED'), 'connector not configured');
  assert(text(w).includes('NOT LIVE'), 'connector not labelled live');

  // 2. upload a hostile log through the API, analyze, then render
  const lines = [];
  for (let i = 1; i <= 7; i++) lines.push(`Feb 18 08:41:0${i} h1 sshd[1]: Failed password for <img/src=x/onerror=window.PWNED=1> from 203.0.113.9 port 40${i} ssh2`);
  lines.push('Feb 18 08:42:00 h1 sshd[1]: Accepted password for bob from 203.0.113.9 port 4100 ssh2');
  const fd = new FormData(); fd.append('file', new Blob([lines.join('\n')]), 'auth.log'); fd.append('default_year', '2025');
  const up = await (await fetch(base + '/api/ingest', { method: 'POST', body: fd })).json();
  assert(up.summary.status === 'SUCCESS', 'upload ok');
  const an = await (await fetch(base + `/api/datasets/${up.dataset_id}/analyze`, { method: 'POST' })).json();
  assert(an.count === 1, 'one case');
  w = await open('/#/investigations');
  await waitFor(w, () => text(w).includes(an.investigations[0].id), 'case listed');
  w.document.querySelector('[data-act="open"]').click();
  await waitFor(w, () => text(w).includes('FINDINGS (RULE-BASED)'), 'incident view');
  assert(text(w).includes('NOT LIVE TELEMETRY'), 'file source labelled');
  assert(text(w).includes('AI investigation has not been run') || text(w).includes('No LLM provider'), 'AI not run is explicit');
  assert(!w.document.querySelector('#content img'), 'XSS: injected <img> must not exist in DOM');
  assert(!w.PWNED, 'XSS: handler must not run');
  const evBtn = w.document.querySelector('button.ev[data-act="event"]');
  assert(evBtn, 'evidence buttons rendered');
  evBtn.click();
  await waitFor(w, () => !w.document.querySelector('#drawer').classList.contains('hide') && w.document.querySelector('#drawer pre'), 'evidence drawer');
  assert(w.document.querySelector('#drawer pre').textContent.includes('sshd'), 'raw record shown');
  assert(!w.document.querySelector('#drawer img'), 'XSS: drawer safe');
  // AI button disabled without provider
  const agentBtn = w.document.querySelector('[data-act="agent"]');
  assert(agentBtn && agentBtn.disabled, 'run-AI disabled when no provider');
  // approval flow records only
  const dec = w.document.querySelector('[data-act="decide"][data-d="APPROVED"]');
  assert(dec, 'approval button');
  dec.click();
  await waitFor(w, () => text(w).includes('NOT_EXECUTED'), 'decision recorded, not executed');

  // 3. backend failure surfaces an error, not fake data
  const bad = new (require(process.env.JSDOM_PATH || 'jsdom').JSDOM)(await (await fetch(base + '/')).text(), { url: base + '/', runScripts: 'outside-only', pretendToBeVisual: true });
  bad.window.fetch = () => Promise.reject(new Error('network down'));
  bad.window.eval(await (await fetch(base + '/assets/app.js')).text());
  await sleep(400);
  assert(bad.window.document.querySelector('#content').textContent.includes('Backend unavailable'), 'backend failure shown');
  console.log('UI SMOKE OK');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
