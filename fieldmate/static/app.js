'use strict';

const $ = (s, root = document) => root.querySelector(s);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const html = escapeHtml;
const paths = {
  overview:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  evidence:'<path d="M5 3h10l4 4v14H5z"/><path d="M14 3v5h5M8 12h8M8 16h6"/>',
  coverage:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 3v3m0 12v3M3 12h3m12 0h3"/>',
  findings:'<path d="M5 21V3m0 1c5-4 9 4 14 0v10c-5 4-9-4-14 0"/>',
  projects:'<path d="M3 6h7l2 3h9v11H3zM3 6V4h7l2 2h7v3"/>',
  settings:'<path d="m10 3-.6 2.2-2 .9-2-.7L3 9l1.7 1.7v2.6L3 15l2.4 3.6 2-.7 2 .9L10 21h4l.6-2.2 2-.9 2 .7L21 15l-1.7-1.7v-2.6L21 9l-2.4-3.6-2 .7-2-.9L14 3z"/><circle cx="12" cy="12" r="3"/>',
  terminal:'<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 8 4 4-4 4m7 0h4"/>',
  service:'<rect x="3" y="3" width="18" height="7" rx="1"/><rect x="3" y="14" width="18" height="7" rx="1"/><path d="M7 6.5h.01M7 17.5h.01M15 6.5h3m-3 11h3"/>',
  http:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  screenshot:'<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  note:'<path d="m15 3 6 6-12 12H3v-6zM12 6l6 6"/>',
  upload:'<path d="M12 16V3m-5 5 5-5 5 5M4 15v6h16v-6"/>',
  arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
  spark:'<path d="m12 2 2.4 7.6L22 12l-7.6 2.4L12 22l-2.4-7.6L2 12l7.6-2.4z"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  link:'<path d="m9 15 6-6m-7 3-2 2a4 4 0 0 0 6 6l2-2m-2-12 2-2a4 4 0 0 1 6 6l-2 2"/>',
  download:'<path d="M12 3v13m-5-5 5 5 5-5M4 17v4h16v-4"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  eye:'<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.evidence}</svg>`;
const state = {token:sessionStorage.getItem('fieldmate-token') || '', engagements:[], settings:{}, eid:localStorage.getItem('fieldmate-engagement') || '', view:'overview', snapshot:null, filter:'open', models:[], search:'', kind:'all', capture:null, suggestionLimit:5};
let toastTimer, imageBlob, pollBusy = false;
const fragmentToken = new URLSearchParams(location.hash.slice(1)).get('token');
if (fragmentToken) { state.token = fragmentToken; sessionStorage.setItem('fieldmate-token', fragmentToken); history.replaceState(null, '', location.pathname); }

function toast(message) {
  $('#toast').textContent = message; $('#toast').classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => $('#toast').classList.remove('show'), 5500);
}
async function api(path, data, raw = false) {
  const response = await fetch('/api/' + path, {method:data === undefined ? 'GET' : 'POST', headers:{'Authorization':'Bearer ' + state.token, ...(data === undefined ? {} : {'Content-Type':'application/json'})}, ...(data === undefined ? {} : {body:JSON.stringify(data)})});
  if (!response.ok) { let value; try { value = await response.json(); } catch { value = {}; } throw new Error(value.error || `Request failed (${response.status})`); }
  return raw ? response : response.json();
}
const endpoint = action => `engagements/${state.eid}${action ? '/' + action : ''}`;
const date = value => new Date(value).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
const shortId = value => String(value).slice(0, 8);
const badge = value => `<span class="state-badge ${html(value)}">${html(String(value).replaceAll('_',' '))}</span>`;
const btn = (action, label, name, style='') => `<button type="button" class="btn ${style}" data-action="${action}">${name ? icon(name) : ''}${label}</button>`;

async function bootstrap() {
  try {
    const value = await api('bootstrap'); state.engagements = value.engagements; state.settings = value.settings;
    if (!state.engagements.some(e => e.id === state.eid)) state.eid = state.engagements[0]?.id || '';
    if (state.eid) await refresh(false); else state.snapshot = null;
    render();
  } catch (error) { authDialog(error.message); }
}
async function refresh(draw = true) {
  if (!state.eid) return;
  const eid = state.eid;
  const value = await api(`engagements/${eid}`);
  if (state.eid !== eid) return;
  state.snapshot = value;
  if (draw) render();
}
function renderNav() {
  $('#nav').innerHTML = [['overview','Overview'],['evidence','Evidence'],['projects','Project review'],['coverage','Coverage'],['findings','Findings'],['settings','Connections']].map(([id,label]) => `<button data-view="${id}" class="${state.view === id ? 'active' : ''}" title="${label}">${icon(id)}<span>${label}</span>${id === 'findings' && state.snapshot?.findings.length ? `<span class="nav-count">${state.snapshot.findings.length}</span>` : ''}</button>`).join('');
  $('#settings-button').innerHTML = icon('settings');
  $('#engagement-select').innerHTML = state.engagements.length ? state.engagements.map(e => `<option value="${html(e.id)}" ${e.id === state.eid ? 'selected' : ''}>${html(e.name)}</option>`).join('') : '<option>No engagements yet</option>';
  $('#breadcrumb-name').textContent = state.snapshot?.engagement.name || 'Getting started';
  $('#connection-label').textContent = state.settings.model || 'Connect your model';
  $('#connection-detail').textContent = state.settings.base_url || 'Unsloth Studio · local network';
}
function render() {
  renderNav();
  if (state.view === 'settings') $('#main').innerHTML = settingsPage();
  else if (!state.snapshot) $('#main').innerHTML = welcome();
  else $('#main').innerHTML = ({overview:overviewPage,evidence:evidencePage,projects:projectsPage,coverage:coveragePage,findings:findingsPage}[state.view] || overviewPage)();
  $('#footer-status').textContent = state.capture ? `Capturing ${state.capture.target} · every 20 seconds` : 'Stored on this device';
}
function heading(eyebrow, title, subtitle, actions='') {
  return `<div class="page-heading"><div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1><p class="subtitle">${subtitle}</p></div><div class="heading-actions">${actions}</div></div>`;
}
function welcome() {
  return `<p class="eyebrow">YOUR NEXT FINDING STARTS HERE</p><section class="welcome"><div><h1>Your work.<br>A second <em>set of eyes.</em></h1><p>A quiet partner for your network and web application pentests. Connect the evidence, notice the gaps, and keep your next move in focus.</p><div class="heading-actions">${btn('new','Create an engagement','plus','primary')}${btn('demo','Explore a practice lab','arrow')}</div></div><div class="welcome-art"><div class="orbit"><img src="/icon.svg" alt="Fieldmate"><span class="orbit-label one">↳ evidence connected</span><span class="orbit-label two">✳ a useful next step</span></div></div></section><div class="welcome-bottom"><article>${icon('terminal')}<h3>Follow your workflow</h3><p>Capture terminal output and import tool exports without changing how you test.</p></article><article>${icon('coverage')}<h3>Keep the full picture</h3><p>Track services, operations, identities, test results, and supporting evidence.</p></article><article>${icon('spark')}<h3>Bring your own intelligence</h3><p>Use your Unsloth Studio model over your local network. You choose what to share.</p></article></div>`;
}
function openSuggestions() {
  return state.snapshot.suggestions.filter(s => state.filter === 'all' || (state.filter === 'open' ? ['open','useful'].includes(s.state) : s.state === state.filter));
}
function evidenceLinks(ids) {
  return ids.slice(0, 5).map(id => `<button class="evidence-link" data-action="evidence-detail" data-id="${html(id)}">${icon('link')} ${html(shortId(id))}</button>`).join('');
}
function suggestionCard(s) {
  return `<article class="suggestion"><div class="card-top"><span class="tag ${html(s.priority)}">● ${html(s.priority)} priority</span><span class="tag">${html(s.kind === 'coverage' ? 'Coverage gap' : s.kind === 'evidence' ? 'Evidence quality' : 'Hypothesis')}</span><span class="card-source">${s.origin === 'model' ? '✳ Model review' : '◉ Coverage rules'}</span></div><h3>${html(s.title)}</h3><p class="observation">${html(s.observation)}</p><div class="next-step"><strong>Suggested next step</strong>${html(s.next_step)}</div>${s.rationale ? `<p class="rationale">${html(s.rationale)}</p>` : ''}<div class="evidence-links">${evidenceLinks(s.evidence)}${s.state !== 'open' ? badge(s.state) : ''}</div><div class="card-footer"><button data-action="feedback" data-id="${html(s.id)}" data-value="useful">${icon('check')} Useful</button><button data-action="feedback" data-id="${html(s.id)}" data-value="tested">${icon('coverage')} Already tested</button><button data-action="feedback" data-id="${html(s.id)}" data-value="snoozed">${icon('clock')} Snooze</button><button data-action="feedback" data-id="${html(s.id)}" data-value="dismissed">${icon('close')} Dismiss</button><button data-action="draft" data-id="${html(s.id)}">Draft finding ${icon('arrow')}</button></div></article>`;
}
function overviewPage() {
  const s = state.snapshot;
  const services = s.coverage.filter(c => c.check_name === 'service-review').length;
  const operations = new Set(s.coverage.filter(c => c.check_name === 'authorization').map(c => c.subject)).size;
  const recorded = s.coverage.filter(c => !['unobserved','suggested'].includes(c.state)).length;
  const active = s.suggestions.filter(c => ['open','useful'].includes(c.state)).length;
  const latest = s.analyses[0];
  return heading('ENGAGEMENT OVERVIEW', 'A little more <em>perspective.</em>', 'Your evidence, open questions, and the next useful move.', `${btn('capture',state.capture ? 'Stop watching' : 'Watch screen','screenshot',state.capture ? 'capture-on' : '')}${btn('import','Import evidence','upload')}${btn('review','Review evidence','spark','primary')}`) +
    `<section class="stats" aria-label="Engagement statistics"><div class="stat"><div class="stat-head">Evidence captured ${icon('evidence')}</div><div class="stat-number">${s.total_events}</div><small>${s.scope_counts.in_scope} in scope · ${s.scope_counts.unattributed} unattributed</small></div><div class="stat"><div class="stat-head">Attack surface ${icon('service')}</div><div class="stat-number">${services + operations}</div><small>${services} services · ${operations} web operations</small></div><div class="stat"><div class="stat-head">Checks recorded ${icon('coverage')}</div><div class="stat-number">${recorded}<span class="stat-fraction">/ ${s.coverage.length}</span></div><small>From captured evidence only</small></div><div class="stat accent"><div class="stat-head">Worth a closer look ${icon('eye')}</div><div class="stat-number">${active}</div><small>Open suggestions · awaiting your review</small></div></section>` +
    `${state.capture ? `<div class="notice">${icon('screenshot')} Screen capture is active for <strong>${html(state.capture.target)}</strong>. Screenshots are stored as images; text redaction cannot remove secrets inside them.</div>` : ''}` +
    `<div class="overview-grid"><section><div class="section-bar"><h2>Your next moves <span>${openSuggestions().length} suggestions</span></h2><div class="segment"><button data-action="filter" data-value="open" class="${state.filter === 'open' ? 'active' : ''}">Open</button><button data-action="filter" data-value="all" class="${state.filter === 'all' ? 'active' : ''}">All activity</button></div></div>${openSuggestions().length ? openSuggestions().slice(0,state.suggestionLimit).map(suggestionCard).join('') : empty('Nothing competing for your attention.','Import evidence to surface coverage gaps. Connect Unsloth Studio for model-assisted review.','import','Import evidence','upload')}${openSuggestions().length > state.suggestionLimit ? btn('more-suggestions','Show more suggestions','arrow','wide') : ''}<form class="prompt-box" id="question-form"><label class="sr-only" for="review-question">Ask about your evidence</label><input id="review-question" name="question" placeholder="What should I look at next? Ask about this engagement…" maxlength="4000"><button class="btn primary" type="submit" aria-label="Ask the model">${icon('arrow')}</button></form>${latest ? `<p class="review-status ${latest.status === 'failed' ? 'failed' : ''}">${latest.status === 'running' ? '✳ Reviewing evidence with your model…' : html(latest.message)} <span class="muted">${date(latest.created)}</span></p>` : ''}</section><aside class="context-column"><section class="panel"><div class="panel-head"><h2>Engagement context</h2>${icon('coverage')}</div><div class="scope-name">${html(s.engagement.name)}</div><div class="scope-detail">Defined scope · ${s.engagement.scope.length} entries</div><div class="spaced-top">${s.engagement.scope.slice(0,6).map(t => `<div class="scope-item">${html(t)}</div>`).join('')}</div><div class="context-label">Observed identities</div><div class="identity-list">${s.identities.length ? s.identities.map(i => `<span class="identity">${html(i)}</span>`).join('') : '<span class="scope-detail">Label captured traffic to track account roles.</span>'}</div><div class="scope-foot">${s.scope_counts.out_of_scope} out-of-scope events excluded from review</div></section><section class="panel"><div class="panel-head"><h2>Latest evidence</h2><button class="text-btn" data-view="evidence">View all ↗</button></div>${s.events.slice(0,5).map(e => `<div class="timeline-item"><div class="timeline-icon">${icon(e.kind)}</div><div class="timeline-body"><button data-action="evidence-detail" data-id="${html(e.id)}">${html(e.content.slice(0,80) || e.kind)}</button><small>${html(e.source)} · ${date(e.created)}</small></div></div>`).join('') || '<p class="scope-detail">Your timeline begins with your first capture.</p>'}</section><div class="review-box"><strong>Keep the evidence close.</strong><p>Save an observation or a business rule while it is fresh. Context makes the next suggestion better.</p>${btn('note','Add a field note','note','soft')}</div></aside></div>`;
}
function empty(title, description, action, label, name='plus') {
  return `<div class="empty-state"><span class="empty-icon">${icon(name)}</span><h2>${title}</h2><p>${description}</p>${action ? btn(action,label,name,'primary') : ''}</div>`;
}
function evidencePage() {
  const s = state.snapshot;
  const filtered = s.events.filter(e => (state.kind === 'all' || e.kind === state.kind) && `${e.content} ${e.target} ${e.identity} ${e.source}`.toLowerCase().includes(state.search.toLowerCase()));
  return heading('EVIDENCE LIBRARY','Every observation, <em>connected.</em>', `${s.total_events} events stored. The latest 150 are shown here.`, `${btn('note','Add note','note')}${btn('import','Import evidence','upload','primary')}`) +
    `<div class="toolbar"><label class="search"><span class="sr-only">Search recent evidence</span><input id="evidence-search" value="${html(state.search)}" placeholder="Search targets, output, identities…"></label><label><span class="sr-only">Evidence type</span><select id="evidence-kind">${['all','terminal','command','service','http','note','screenshot'].map(k => `<option ${k === state.kind ? 'selected' : ''}>${k}</option>`).join('')}</select></label><span class="hint">${filtered.length} recent events</span></div>${filtered.length ? `<div class="table-wrap"><table><thead><tr><th>Observation</th><th>Identity / target</th><th>Scope</th><th>Captured</th><th></th></tr></thead><tbody>${filtered.map(e => `<tr><td><span class="primary-text">${icon(e.kind)} ${html(e.kind)}</span><small>${html(e.content.slice(0,95))}</small></td><td><code>${html(e.target || 'Unattributed')}</code><small>${html(e.identity)}</small></td><td>${badge(e.scope_state)}</td><td>${date(e.created)}<small>${html(e.source)}</small></td><td><button class="icon-button" data-action="evidence-detail" data-id="${html(e.id)}" aria-label="Open evidence">${icon('arrow')}</button></td></tr>`).join('')}</tbody></table></div>` : empty('A clear place to start.','Import Nmap XML, Burp XML, HAR, JSONL, or a terminal transcript.','import','Import evidence','upload')}`;
}
function coveragePage() {
  const rows = state.snapshot.coverage;
  return heading('TEST COVERAGE','Know where <em>you stand.</em>','Track what was observed, what you tried, and what still needs evidence.',btn('test','Record a check','plus','primary')) +
    `<div class="notice">${icon('eye')} “Unobserved” means no test result was recorded here. It does not mean a test never happened. “Confirmed” records your assessment of a check, not an automatically confirmed finding.</div>${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Subject / check</th><th>Identity</th><th>State</th><th>Notes</th><th></th></tr></thead><tbody>${rows.map((r,i) => `<tr><td><code class="primary-text">${html(r.subject)}</code><small>${html(r.check_name)}</small></td><td>${html(r.identity)}</td><td>${badge(r.state)}</td><td>${html((r.notes || 'No result recorded').slice(0,130))}</td><td><button class="btn small" data-action="test" data-index="${i}">Record result</button></td></tr>`).join('')}</tbody></table></div>` : empty('Make your coverage visible.','Imported services and web operations appear here. You can also record any manual check.','test','Record a check','coverage')}`;
}
function findingsPage() {
  const rows = state.snapshot.findings;
  return heading('FINDINGS WORKBENCH','Make the evidence <em>count.</em>','Turn a hypothesis into a reproducible, defensible finding.', `${btn('export','Export report','download')}${btn('finding','New finding','plus','primary')}`) +
    `${rows.length ? `<div class="finding-grid">${rows.map(f => `<article class="panel finding"><div class="split-header">${badge(f.status)}<span class="tag ${html(f.severity)}">${html(f.severity)}</span></div><h3>${html(f.title)}</h3><p>${html((f.impact || 'Impact has not been recorded yet.').slice(0,350))}</p><div class="evidence-links">${evidenceLinks(f.evidence)}</div><button class="btn small" data-action="finding" data-id="${html(f.id)}">Open finding ${icon('arrow')}</button></article>`).join('')}</div>` : empty('Good findings begin with a question.','Draft a finding from a suggestion or start your own. Confirmation requires reproduction steps, impact, and in-scope evidence.','finding','Draft a finding','findings')}`;
}
function settingsPage() {
  const s = state.settings;
  return heading('CONNECTIONS & CAPTURE','Your model. <em>Your network.</em>','Connect Unsloth Studio and bring your workflow into the picture.') +
    `<div class="settings-grid"><section class="panel settings-form"><div class="panel-head"><h2>Unsloth Studio</h2><span class="tag">LAN inference</span></div><form id="settings-form"><label class="field"><span>API base URL</span><input name="base_url" type="url" value="${html(s.base_url)}" placeholder="http://192.168.1.50:8888/v1"><small>Use the network address shown by Unsloth Studio. /v1 is added automatically.</small></label><label class="field"><span>API key</span><input name="api_key" type="password" autocomplete="new-password" placeholder="${s.has_api_key ? 'Key saved · leave blank to keep it' : 'sk-unsloth-…'}"><small>Stored in the private local data directory. Never returned by the API.</small></label>${s.has_api_key ? '<label class="checkbox"><input type="checkbox" name="clear_key"><span>Remove saved API key</span></label>' : ''}<label class="field"><span>Model ID</span><input name="model" list="model-list" value="${html(s.model)}" placeholder="Discover models, or paste the exact model ID"><datalist id="model-list">${state.models.map(m => `<option value="${html(m.id)}">${m.loaded === true ? 'Loaded' : ''}</option>`).join('')}</datalist><small>Load your chosen local model in Unsloth before reviewing evidence.</small></label><div class="heading-actions"><button class="btn primary" type="submit">${icon('check')} Save connection</button><button class="btn" type="button" data-action="models">${icon('link')} Test & discover models</button></div><div id="connection-result"></div><div class="divider"></div><label class="checkbox"><input name="vision" type="checkbox" ${s.vision ? 'checked' : ''}><span><strong>Send screenshots to a vision-capable model</strong><small>Only selected, in-scope screenshots are included. Images can contain unredacted secrets.</small></span></label><label class="checkbox"><input name="auto_analyze" type="checkbox" ${s.auto_analyze ? 'checked' : ''}><span><strong>Review new evidence in the background</strong><small>Uses this connection when in-scope evidence changes. No cloud fallback.</small></span></label><label class="checkbox"><input name="structured" type="checkbox" ${s.structured ? 'checked' : ''}><span><strong>Request JSON output mode</strong><small>Enable if your loaded model and server support response_format.</small></span></label><div class="field-row"><label class="field"><span>Background interval (seconds)</span><input name="interval" type="number" min="20" max="600" value="${s.interval || 45}" required></label><label class="field"><span>Response token budget</span><input name="max_tokens" type="number" min="256" max="8000" value="${s.max_tokens || 2400}" required></label></div><div class="field-row"><label class="field"><span>Evidence context (characters)</span><input name="context_chars" type="number" min="4000" max="80000" value="${s.context_chars || 24000}" required></label><label class="field"><span>Inference timeout (seconds)</span><input name="timeout" type="number" min="10" max="300" value="${s.timeout || 120}" required></label></div><button class="btn soft" type="submit">Save preferences</button></form></section><aside><section class="panel"><p class="eyebrow">CONNECT THE WORKFLOW</p><h2>A few ways to bring evidence in.</h2><div class="integration-step"><span class="step-number">1</span><div><strong>Terminal companion</strong><p>Run from the Fieldmate project directory. An interactive shell records output; Bash also records command completion.</p></div></div><pre class="code-block">python3 -m fieldmate capture \
  --engagement ${html(state.eid || 'ENGAGEMENT_ID')} \
  --target TARGET \
  --identity tester</pre><div class="integration-step"><span class="step-number">2</span><div><strong>Watch an evidence folder</strong><p>Nmap XML, Burp XML, HAR, JSONL, and growing text logs.</p></div></div><pre class="code-block">python3 -m fieldmate watch ./evidence \
  --engagement ${html(state.eid || 'ENGAGEMENT_ID')} \
  --target TARGET</pre><div class="integration-step"><span class="step-number">3</span><div><strong>Connect Burp Suite</strong><p>The included Montoya extension forwards in-scope HTTP traffic asynchronously. Configure it with your local Fieldmate token, engagement ID, and identity label.</p></div></div><div class="integration-step"><span class="step-number">4</span><div><strong>Watch a selected screen or window</strong><p>Use Watch screen on Overview. Your browser asks what to share. Changed frames are sampled every 20 seconds; stop sharing at any time.</p></div></div></section><section class="panel"><h2>Connection boundaries</h2><p class="note-text">The dashboard binds to this machine only. Inference accepts loopback and private LAN addresses. Evidence is sent only when you review it or enable background review. The app requests no model tools and never runs suggested commands.</p><p class="note-text">Use a local model in Unsloth Studio and disable its server-side tools. Fieldmate cannot inspect whether the server routes a model to another provider.</p></section></aside></div>`;
}
function dialog(title, body) {
  if (imageBlob) { URL.revokeObjectURL(imageBlob); imageBlob = null; }
  $('#dialog-content').innerHTML = `<div class="dialog-head"><h2>${title}</h2><button class="icon-button" data-action="close" aria-label="Close dialog">${icon('close')}</button></div><div class="dialog-body">${body}</div>`;
  if (!$('#dialog').open) $('#dialog').showModal();
}
function closeDialog() { $('#dialog').close(); if (imageBlob) { URL.revokeObjectURL(imageBlob); imageBlob = null; } }
const actions = label => `<div class="dialog-actions">${btn('close','Cancel')}<button class="btn primary" type="submit">${label}</button></div>`;
const targetIdentity = (target='', identity='unlabeled', required=false) => `<div class="field-row"><label class="field"><span>Target ${required ? '' : '(for text evidence)'}</span><input name="target" value="${html(target)}" placeholder="Host, IP, or URL" ${required ? 'required' : ''}><small>Must match engagement scope to be reviewed.</small></label><label class="field"><span>Identity label</span><input name="identity" value="${html(identity)}" maxlength="100" placeholder="customer-a, administrator…" required></label></div>`;
function authDialog(message='') {
  dialog('Open your local workspace', `<p class="hint">Paste the access token from your private <code>.fieldmate/token</code> file, or launch with <code>python3 -m fieldmate open</code>.</p><form id="auth-form"><label class="field"><span>Local access token</span><input name="token" type="password" autocomplete="off" required></label><div id="auth-error" class="hint">${html(message)}</div><div class="dialog-actions"><button class="btn primary" type="submit">Open workspace ${icon('arrow')}</button></div></form>`);
}
function newDialog() {
  dialog('A new engagement', `<form id="new-form"><label class="field"><span>Engagement name</span><input name="name" placeholder="Client · internal network & portal" maxlength="160" required></label><label class="field"><span>In-scope targets · one per line</span><textarea name="scope" placeholder="192.168.56.0/24&#10;portal.example.test&#10;*.example.test" required></textarea><small>Use hostnames, IPs, CIDRs, or wildcard subdomains. A wildcard excludes the parent domain.</small></label><label class="field"><span>Context & business rules</span><textarea name="notes" placeholder="Goals, expected roles, known exclusions, and what matters to this engagement…"></textarea></label>${actions('Create engagement')}</form>`);
}
function importDialog() {
  dialog('Bring the evidence in', `<form id="import-form"><div class="file-drop"><input id="import-file" type="file" accept=".burp,.xml,.har,.jsonl,.ndjson,.log,.txt" required aria-label="Evidence file"><p>.burp project archive · Nmap XML · Burp traffic/issues XML · HAR · JSONL · terminal logs<br>Text exports: 20 MB. Native .burp archives: 10 GiB, followed by companion extraction.</p></div><label class="field"><span>Format</span><select name="format">${[['auto','Detect automatically'],['nmap','Nmap XML'],['burp','Burp XML'],['har','HAR'],['jsonl','Event JSONL'],['terminal','Terminal transcript']].map(([v,l]) => `<option value="${v}">${l}</option>`).join('')}</select></label>${targetIdentity()}<p class="hint">Text secrets are redacted before storage. Native .burp archives are stored unchanged locally and are never sent to the model or opened automatically.</p>${actions('Import evidence')}</form>`);
}
function noteDialog() {
  dialog('A note from the field', `<form id="note-form"><label class="field"><span>Observation or business rule</span><textarea name="content" required maxlength="10000" placeholder="What did you notice? What should your partner remember?"></textarea></label>${targetIdentity('', 'tester', true)}${actions('Save note')}</form>`);
}
function testDialog(index) {
  const row = index === undefined ? {} : state.snapshot.coverage[Number(index)] || {};
  dialog('Record a check', `<form id="test-form"><label class="field"><span>Subject</span><input name="subject" value="${html(row.subject || '')}" placeholder="Host:port/protocol or METHOD https://host/path" required></label><div class="field-row"><label class="field"><span>Check category</span><input name="check_name" value="${html(row.check_name || '')}" placeholder="authorization, service-review…" required></label><label class="field"><span>Identity</span><input name="identity" value="${html(row.identity || 'unlabeled')}" required></label></div><label class="field"><span>Result state</span><select name="state">${['attempted','inconclusive','confirmed','dismissed','unobserved'].map(t => `<option ${row.state === t ? 'selected' : ''}>${t}</option>`).join('')}</select></label><label class="field"><span>What did you test, and what happened?</span><textarea name="notes">${html(row.notes || '')}</textarea></label><label class="field"><span>Supporting evidence IDs · comma separated</span><input name="evidence" value="${html((row.evidence || []).join(', '))}"><small>Use full IDs from the Evidence detail view.</small></label>${actions('Save result')}</form>`);
}
function findingDialog(id, suggestion) {
  const f = state.snapshot.findings.find(f => f.id === id) || {title:suggestion?.title || '', evidence:suggestion?.evidence || [], reproduction:'', impact:'', status:'draft', severity:'unrated'};
  dialog(f.id ? 'Review the finding' : 'Draft a finding', `<form id="finding-form">${f.id ? `<input name="id" type="hidden" value="${html(f.id)}">` : ''}<label class="field"><span>Finding title</span><input name="title" value="${html(f.title)}" maxlength="200" required></label><div class="field-row"><label class="field"><span>Status · your assessment</span><select name="status">${['draft','confirmed','dismissed'].map(t => `<option ${f.status === t ? 'selected' : ''}>${t}</option>`).join('')}</select></label><label class="field"><span>Severity · your assessment</span><select name="severity">${['unrated','info','low','medium','high','critical'].map(t => `<option ${f.severity === t ? 'selected' : ''}>${t}</option>`).join('')}</select></label></div><label class="field"><span>Reproduction steps</span><textarea name="reproduction" placeholder="Include prerequisites, identity, steps, and observed vs expected results.">${html(f.reproduction)}</textarea></label><label class="field"><span>Demonstrated impact</span><textarea name="impact" placeholder="Explain the impact supported by your evidence.">${html(f.impact)}</textarea></label><label class="field"><span>Supporting evidence IDs · comma separated</span><input name="evidence" value="${html(f.evidence.join(', '))}"></label><p class="hint">Confirmed findings require reproduction steps, impact, and in-scope evidence. AI suggestions remain hypotheses until you validate them.</p>${actions('Save finding')}</form>`);
}
async function evidenceDialog(id) {
  const e = await api(endpoint('events/' + id));
  state.editEvent = e;
  dialog('Evidence detail', `<div class="pill-row">${badge(e.kind)}${badge(e.scope_state)}<span class="pill">${html(e.identity)}</span><button class="text-btn" data-action="attribute">Change identity</button></div><label class="field"><span>Evidence ID</span><input readonly value="${html(e.id)}" aria-label="Evidence ID"></label><p class="hint">${html(e.target || 'Unattributed')} · ${html(e.source)} · ${new Date(e.created).toLocaleString()}</p>${e.kind === 'screenshot' ? '<img class="evidence-image" id="evidence-image" alt="Captured screen evidence">' : ''}<pre class="evidence-content">${html(e.content)}</pre><details><summary class="hint">Structured evidence</summary><pre class="evidence-meta">${html(JSON.stringify(e.metadata,null,2))}</pre></details>`);
  if (e.kind === 'http' && e.scope_state === 'in_scope') $('.dialog-body').insertAdjacentHTML('beforeend',`<div class="dialog-actions"><button type="button" class="btn primary" data-action="repeater-baseline" data-id="${html(e.id)}">${icon('evidence')} Repeater request text</button></div>`);
  if (e.kind === 'screenshot') {
    const response = await api(endpoint('image/' + id), undefined, true);
    const blob = await response.blob();
    if ($('#evidence-image')) { imageBlob = URL.createObjectURL(blob); $('#evidence-image').src = imageBlob; }
  }
}
async function saveSettings(form) {
  const data = Object.fromEntries(new FormData(form));
  for (const k of ['interval','context_chars','max_tokens','timeout']) data[k] = Number(data[k]);
  for (const k of ['vision','auto_analyze','structured']) data[k] = form.elements[k].checked;
  if (!data.api_key && !data.clear_key) delete data.api_key;
  if (data.clear_key) data.api_key = '';
  state.settings = await api('settings', data);
  form.elements.api_key.value = '';
  renderNav();
}
function captureDialog() {
  if (state.capture) { stopCapture(); return; }
  dialog('Share a window with your partner', `<form id="capture-form"><p class="note-text">Choose the pentest window or screen in your browser’s sharing prompt. Fieldmate saves changed frames every 20 seconds, resized to 1440 pixels wide. Start with a specific window to keep unrelated content out.</p>${targetIdentity('', 'tester', true)}<div class="notice">Screenshots are stored locally without image redaction. When vision is enabled, selected screenshots are sent to your configured Unsloth server during review.</div>${actions('Choose window & start')}</form>`);
}
async function startCapture(data) {
  if (!navigator.mediaDevices?.getDisplayMedia) throw new Error('Screen capture requires a supported browser on localhost.');
  const eid = state.eid;
  const stream = await navigator.mediaDevices.getDisplayMedia({video:{frameRate:1},audio:false});
  const video = document.createElement('video'); video.muted = true; video.playsInline = true; video.srcObject = stream;
  state.capture = {stream,video,eid,target:data.target,identity:data.identity,timer:null,previous:null};
  stream.getVideoTracks()[0].addEventListener('ended', stopCapture, {once:true});
  try { await video.play(); } catch (error) { stopCapture(); throw error; }
  closeDialog(); render(); toast('Screen capture started. You can stop sharing at any time.');
  await captureFrame();
}
async function captureFrame() {
  const capture = state.capture;
  if (!capture) return;
  try {
    if (!capture.video.videoWidth || !capture.video.videoHeight) { capture.timer = setTimeout(captureFrame, 1000); return; }
    const tiny = document.createElement('canvas'); tiny.width = 32; tiny.height = 18;
    const tinyContext = tiny.getContext('2d', {willReadFrequently:true}); tinyContext.drawImage(capture.video,0,0,32,18);
    const pixels = tinyContext.getImageData(0,0,32,18).data;
    const changed = !capture.previous || pixels.reduce((sum,p,i) => sum + Math.abs(p - capture.previous[i]),0) / pixels.length > 2;
    if (changed) {
      const canvas = document.createElement('canvas'); canvas.width = Math.min(1440,capture.video.videoWidth); canvas.height = Math.round(capture.video.videoHeight * canvas.width / capture.video.videoWidth);
      canvas.getContext('2d').drawImage(capture.video,0,0,canvas.width,canvas.height);
      const encoded = canvas.toDataURL('image/jpeg',0.65).split(',')[1];
      await api(`engagements/${capture.eid}/screenshot`, {image_base64:encoded,target:capture.target,identity:capture.identity,content:'Selected screen · ' + new Date().toISOString()});
      capture.previous = pixels;
    }
    if (state.capture === capture) capture.timer = setTimeout(captureFrame,20000);
  } catch (error) { toast('Screen capture stopped: ' + error.message); stopCapture(); }
}
function stopCapture() {
  const capture = state.capture; state.capture = null;
  if (!capture) return;
  clearTimeout(capture.timer); capture.stream.getTracks().forEach(t => t.stop()); capture.video.srcObject = null;
  render();
}

document.addEventListener('click', async event => {
  const target = event.target.closest('[data-action],[data-view]');
  if (!target) return;
  const view = target.dataset.view;
  if (view) { state.view = view; state.search = ''; render(); return; }
  const action = target.dataset.action;
  try {
    if (action === 'close') closeDialog();
    else if (action === 'new') newDialog();
    else if (action === 'settings') { state.view = 'settings'; render(); }
    else if (action === 'demo') {
      target.disabled = true; const e = await api('demo', {}); state.eid = e.id; localStorage.setItem('fieldmate-engagement',e.id); await bootstrap(); toast('Practice lab loaded. All observations are synthetic.');
    }
    else if (action === 'import') importDialog();
    else if (action === 'note') noteDialog();
    else if (action === 'test') testDialog(target.dataset.index);
    else if (action === 'finding') findingDialog(target.dataset.id);
    else if (action === 'draft') findingDialog(undefined,state.snapshot.suggestions.find(s => s.id === target.dataset.id));
    else if (action === 'evidence-detail') await evidenceDialog(target.dataset.id);
    else if (action === 'attribute') {
      const e = state.editEvent;
      dialog('Label the identity', `<form id="attribution-form"><input type="hidden" name="id" value="${html(e.id)}"><label class="field"><span>Identity label</span><input name="identity" value="${html(e.identity)}" maxlength="100" required></label><label class="checkbox"><input type="checkbox" name="same_source"><span>Apply to all ${html(e.kind)} evidence from ${html(e.source)}</span></label><p class="hint">Evidence IDs stay the same. Existing recorded test results keep their original identity labels; edit them in Coverage if needed.</p>${actions('Save identity')}</form>`);
    }
    else if (action === 'filter') { state.filter = target.dataset.value; render(); }
    else if (action === 'more-suggestions') { state.suggestionLimit += 10; render(); }
    else if (action === 'feedback') { await api(endpoint('feedback'),{id:target.dataset.id,state:target.dataset.value}); await refresh(); toast('Feedback saved.'); }
    else if (action === 'review') { await api(endpoint('review'),{}); await refresh(); toast('Evidence review started.'); }
    else if (action === 'capture') captureDialog();
    else if (action === 'project-upload') projectUploadDialog();
    else if (action === 'project-link') {
      const p = await api(endpoint('projects'),{filename:'Opened Burp project'}); await refresh(); projectSetup(p.id);
    }
    else if (action === 'project-setup') projectSetup(target.dataset.id);
    else if (action === 'project-export') projectExportDialog(target.dataset.id);
    else if (action === 'project-review') { await api(endpoint(`projects/${target.dataset.id}/review`),{}); await refresh(); toast('Project review started. No test requests will be sent.'); }
    else if (action === 'project-cancel') { const result=await api(endpoint('review-cancel'),{id:target.dataset.id});toast(result.message); }
    else if (action === 'project-archive') {
      await downloadArchive(target.dataset.id);
    }
    else if (action === 'more-assessments') { state.reviewLimit=(state.reviewLimit||20)+20;render(); }
    else if (action === 'review-detail') reviewDetail(target.dataset.id);
    else if (action === 'review-decision') reviewDecision(target.dataset.id);
    else if (action === 'repeater-baseline') {
      const value=await api(endpoint('repeater/'+target.dataset.id));requestDialog([{...value,title:'Captured baseline request',purpose:'Use as a control before changing one variable.',expected:'Compare with the original recorded response and relevant account permissions.'}]);
    }
    else if (action === 'review-repeater') {
      const item=state.snapshot.assessments.find(a=>a.id===target.dataset.id);requestDialog(item.manual_tests);
    }
    else if (action === 'request-copy') {
      const value=state.manualTemplates[Number(target.dataset.index)];const content=target.dataset.baseline==='true'?value.baseline_request:value.request;
      try{await navigator.clipboard.writeText(content);toast('Request text copied. Fieldmate has not sent it.');}catch{toast('Clipboard unavailable. Select the request text and copy it manually.');}
    }
    else if (action === 'request-download') { const value=state.manualTemplates[Number(target.dataset.index)];downloadText(new Blob([value.request],{type:'text/plain'}),'repeater-request.txt'); }
    else if (action === 'models') {
      target.disabled = true;
      try {
        await saveSettings($('#settings-form'));
        const result = await api('models',{}); state.models = result.models;
        $('#model-list').innerHTML = result.models.map(m => `<option value="${html(m.id)}">${m.loaded === true ? 'Loaded' : ''}</option>`).join('');
        const loaded = result.models.find(m => m.loaded === true);
        if (!$('#settings-form').elements.model.value && (loaded || result.models.length === 1)) $('#settings-form').elements.model.value = (loaded || result.models[0]).id;
        $('#connection-result').innerHTML = `<div class="connection-result">Connected. ${result.models.length} model(s) available.${result.models.length ? ' Select a model ID above and save.' : ' Load a model in Unsloth Studio.'}</div>`;
      } catch (error) { $('#connection-result').innerHTML = `<div class="connection-result error">${html(error.message)}</div>`; }
      finally { target.disabled = false; }
    }
    else if (action === 'export') {
      const response = await api(endpoint('report'),undefined,true); const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'fieldmate-report.md'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
    }
  } catch (error) { toast(error.message); target.disabled = false; }
});
document.addEventListener('submit', async event => {
  const form = event.target;
  const formId = form.getAttribute('id');
  if (!formId) return;
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  const button = $('button[type="submit"]',form); if (button) button.disabled = true;
  $('.dialog-error',form)?.remove();
  try {
    if (formId === 'auth-form') {
      state.token = data.token.trim(); await api('bootstrap'); sessionStorage.setItem('fieldmate-token',state.token); closeDialog(); await bootstrap(); return;
    }
    if (formId === 'new-form') {
      const e = await api('engagements', data); stopCapture(); state.eid = e.id; localStorage.setItem('fieldmate-engagement',e.id); state.view = 'overview'; closeDialog(); await bootstrap(); return;
    }
    if (formId === 'settings-form') { await saveSettings(form); toast('Connection and preferences saved.'); return; }
    if (formId === 'question-form') { await api(endpoint('review'),{question:data.question}); form.reset(); await refresh(); return; }
    if (formId === 'capture-form') { await startCapture(data); return; }
    if (formId === 'project-upload-form') {
      const file=$('#project-file').files[0];if(!file)throw new Error('Choose a .burp file.');const p=await uploadProject(file);closeDialog();state.view='projects';await refresh();projectSetup(p.id);return;
    }
    if (formId === 'project-export-form') {
      const file=$('#project-export-file').files[0];if(!file||file.size>20000000)throw new Error('Choose a traffic/issues export under 20 MB.');
      await api(endpoint(`projects/${data.project_id}/export`),{filename:file.name,content:await file.text(),identity:data.identity,format:'auto'});closeDialog();await refresh();toast('Saved project evidence imported. Ready for model review.');return;
    }
    if (formId === 'review-decision-form') { await api(endpoint('assessment-disposition'),data);closeDialog();await refresh();toast('Your decision was recorded; no requests were sent.');return; }
    if (formId === 'import-form') {
      const file = $('#import-file').files[0]; if (!file) throw new Error('Choose a file first.');
      if(file.name.toLowerCase().endsWith('.burp')) {const p=await uploadProject(file);closeDialog();state.view='projects';await refresh();projectSetup(p.id);return;}
      if (file.size > 20000000) throw new Error('Split files larger than 20 MB before importing.');
      const result = await api(endpoint('import'),{...data,filename:file.name,content:await file.text()}); toast(`${result.inserted} events imported · ${result.duplicates} duplicates skipped.`);
    }
    else if (formId === 'note-form') await api(endpoint('events'),{events:[{kind:'note',source:'field-note',content:data.content,target:data.target,identity:data.identity}]});
    else if (formId === 'test-form' || formId === 'finding-form') {
      data.evidence = data.evidence.split(',').map(s => s.trim()).filter(Boolean);
      await api(endpoint(formId === 'test-form' ? 'tests' : 'findings'),data); toast('Saved.');
    }
    else if (formId === 'attribution-form') await api(endpoint('attribution'),{id:data.id,identity:data.identity,same_source:form.elements.same_source.checked});
    closeDialog(); await refresh();
  } catch (error) {
    if ($('#dialog').open) { const warning = document.createElement('div'); warning.className = 'dialog-error'; warning.setAttribute('role','alert'); warning.textContent = error.message; form.prepend(warning); }
    else toast(error.message);
  } finally { if (button?.isConnected) button.disabled = false; }
});
$('#engagement-select').addEventListener('change',async event => {
  stopCapture(); state.eid = event.target.value; localStorage.setItem('fieldmate-engagement',state.eid); state.search = ''; state.kind = 'all';
  try { await refresh(); } catch (error) { toast(error.message); }
});
document.addEventListener('change',event => {
  if (event.target.id === 'evidence-kind') { state.kind = event.target.value; render(); }
});
document.addEventListener('input',event => {
  if (event.target.id === 'evidence-search') {
    state.search = event.target.value; const position = event.target.selectionStart; render(); const input = $('#evidence-search'); input.focus(); input.setSelectionRange(position,position);
  }
});
$('#dialog').addEventListener('close',() => { if (imageBlob) { URL.revokeObjectURL(imageBlob); imageBlob = null; } });
window.addEventListener('beforeunload',() => { if (state.capture) state.capture.stream.getTracks().forEach(t => t.stop()); });
setInterval(async () => {
  if (pollBusy || !state.eid || !state.token || $('#dialog').open || state.view === 'settings' || ['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)) return;
  pollBusy = true;
  try { await refresh(); } catch (error) { $('#footer-status').textContent = 'Dashboard disconnected · retrying…'; }
  finally { pollBusy = false; }
},4000);
const assessmentNames={possible_finding:'Possible missed finding',needs_validation:'Needs validation',likely_false_positive:'Likely false positive',insufficient_evidence:'Insufficient evidence'};
function projectsPage(){
  const s=state.snapshot,projects=s.projects||[],items=s.assessments||[],run=s.review_runs?.[0];
  return heading('SKEPTICAL PROJECT REVIEW','A second look at <em>the evidence.</em>','Review stored traffic and scanner claims. Every follow-up request stays text for you to test manually.',`${btn('project-link','Link opened project','link')}${btn('project-upload','Upload .burp project','upload','primary')}`)+
    `<div class="notice">${icon('eye')} Fieldmate never opens or executes project files, sends Repeater requests, starts scans, or runs suggested tests. Native .burp uploads need saved-data extraction from the Burp companion; uploading alone does not review their contents.</div>`+
    `${run?`<section class="panel"><div class="split-header"><h2>Latest review ${badge(run.status)}</h2>${run.status==='running'?`<button class="btn small" data-action="project-cancel" data-id="${html(run.id)}">Stop review</button>`:''}</div><p class="note-text">${html(run.message)}</p><span class="hint">${run.reviewed_events}/${run.total_events} events · ${run.completed_batches}/${run.total_batches} batches · ${run.failed_batches} failed</span></section>`:''}`+
    `<div class="project-grid">${projects.map(p=>`<article class="panel project-card"><div class="split-header"><h2>${icon('projects')} ${html(p.filename)}</h2>${badge(p.status)}</div><p class="note-text">${html(p.message)}</p><div class="pill-row"><span class="pill">${p.counts.http||0} saved HTTP messages</span><span class="pill">${p.counts.scanner_issue||0} scanner issues</span><span class="pill">${p.in_scope_events} in scope</span>${p.has_archive?`<span class="pill">${(p.bytes/1024/1024).toFixed(1)} MiB retained locally</span>`:''}</div><div class="heading-actions"><button class="btn small" data-action="project-setup" data-id="${html(p.id)}">Import setup</button><button class="btn small" data-action="project-export" data-id="${html(p.id)}">Add XML / HAR / JSONL</button><button class="btn small primary" data-action="project-review" data-id="${html(p.id)}" ${!['ready','import_failed'].includes(p.status)||!p.in_scope_events||run?.status==='running'?'disabled':''}>${icon('spark')} Review project</button></div></article>`).join('')}</div>`+
    `${!projects.length?empty('Bring your project into focus.','Upload a native .burp archive, then use the companion in Burp to import saved messages and issues. You can also link an opened project or attach an existing XML/HAR export.','project-upload','Upload .burp project','projects'):''}`+
    `<div class="section-bar spaced-top"><h2>Review assessments <span>${items.length} retained across reviews</span></h2><span class="hint">AI opinions · your decision is recorded separately</span></div>${items.length?items.slice(0,state.reviewLimit||20).map(a=>`<article class="suggestion"><div class="card-top"><span class="tag ${a.assessment==='likely_false_positive'?'low':'medium'}">${html(assessmentNames[a.assessment])}</span><span class="card-source">Model assessment · ${html(a.disposition.replaceAll('_',' '))}</span></div><h3>${html(a.title)}</h3><p class="observation">${html(a.explanation)}</p><div class="next-step"><strong>False-positive checks</strong>${a.false_positive_checks.slice(0,2).map(html).join('<br>')}</div><div class="evidence-links"><span class="hint">Supporting:</span>${evidenceLinks(a.evidence)}${a.counter_evidence.length?`<span class="hint">Counter-evidence:</span>${evidenceLinks(a.counter_evidence)}`:''}</div><div class="card-footer"><button data-action="review-detail" data-id="${html(a.id)}">${icon('evidence')} Review reasoning</button>${a.manual_tests.length?`<button data-action="review-repeater" data-id="${html(a.id)}">${icon('terminal')} Repeater request text (${a.manual_tests.length})</button>`:''}<button data-action="review-decision" data-id="${html(a.id)}">Record my decision ${icon('arrow')}</button></div></article>`).join(''):'<p class="note-text">Once saved evidence is imported, Review project will look for missed leads and challenge scanner claims. Nothing is automatically confirmed or ruled out.</p>'}${items.length>(state.reviewLimit||20)?btn('more-assessments','Show more assessments','arrow','wide'):''}`;
}
async function uploadProject(file){
  if(!file.name.toLowerCase().endsWith('.burp')||!file.size||file.size>10*1024**3)throw new Error('Choose a .burp archive between 1 byte and 10 GiB.');
  const response=await fetch('/api/'+endpoint('projects'),{method:'POST',headers:{Authorization:'Bearer '+state.token,'Content-Type':'application/octet-stream','X-Filename':encodeURIComponent(file.name)},body:file});
  const value=await response.json();if(!response.ok)throw new Error(value.error||'Project upload failed');return value;
}
function projectUploadDialog(){
  dialog('Upload a Burp project',`<form id="project-upload-form"><div class="file-drop"><input id="project-file" type="file" accept=".burp" required aria-label="Burp project archive"><p>Native .burp archive · up to 10 GiB · streamed to private local storage</p></div><p class="note-text">The original archive is retained unchanged locally. It is never sent to the model or opened automatically. After upload, open a copy in Burp with automated tasks paused and import saved evidence using the companion.</p>${actions('Upload project archive')}</form>`);
}
function projectSetup(id){
  const p=state.snapshot.projects.find(p=>p.id===id);if(!p)return;
  dialog('Import saved project evidence',`<p class="note-text">${html(p.filename)} is ${html(p.status.replaceAll('_',' '))}. Uploading an archive does not decode its traffic.</p><ol class="setup-steps"><li>Open or import a copy of this project in Burp. Pause automated tasks.</li><li>Load the updated <strong>fieldmate-burp.jar</strong> extension and open its Fieldmate tab.</li><li>Apply your local Fieldmate URL, token, and engagement ID. Paste the project import ID below.</li><li>Click <strong>Import opened project (saved data only)</strong>. The companion reads Proxy history, site map, and scanner issues without sending target requests.</li><li>Return here and choose <strong>Review project</strong>. Repeater-only tabs not exposed by Burp’s project API may be absent.</li></ol><label class="field"><span>Engagement ID</span><input readonly value="${html(state.eid)}"></label><label class="field"><span>Project import ID</span><input readonly value="${html(p.id)}" aria-label="Project import ID"></label><p class="hint">Use your Fieldmate token from .fieldmate/token, not the Unsloth API key. Exported traffic/issues XML, HAR, or event JSONL can also be attached to this project.</p><div class="heading-actions">${p.has_archive?`<button class="btn" data-action="project-archive" data-id="${html(p.id)}">Download stored copy</button>`:''}<button class="btn" data-action="project-export" data-id="${html(p.id)}">Attach a readable export</button></div>`);
}
function projectExportDialog(id){
  dialog('Attach saved project data',`<form id="project-export-form"><input type="hidden" name="project_id" value="${html(id)}"><div class="file-drop"><input id="project-export-file" type="file" accept=".xml,.har,.jsonl,.ndjson" required aria-label="Project evidence export"><p>Burp traffic XML · scanner issues XML · HAR · event JSONL · 20 MB per file</p></div><label class="field"><span>Identity label for this export</span><input name="identity" value="unlabeled" maxlength="100" required></label><p class="hint">Import separate exports for different known account identities. This imports saved data only and does not run tests.</p>${actions('Import saved evidence')}</form>`);
}
function reviewDetail(id){
  const a=state.snapshot.assessments.find(a=>a.id===id);if(!a)return;
  dialog('Assess the evidence',`<div class="pill-row"><span class="pill">${html(assessmentNames[a.assessment])}</span>${badge(a.disposition)}</div><h3>${html(a.title)}</h3><p class="note-text">${html(a.explanation)}</p><h4>Supporting evidence</h4><div class="evidence-links">${evidenceLinks(a.evidence)}</div><h4>Counter-evidence</h4><div class="evidence-links">${evidenceLinks(a.counter_evidence)||'<span class="hint">No counter-evidence was identified in the supplied excerpts. That does not establish a vulnerability.</span>'}</div><h4>Checks before deciding</h4><ul class="setup-steps">${a.false_positive_checks.map(c=>`<li>${html(c)}</li>`).join('')}</ul><div class="notice">“Likely false positive” is an advisory assessment. Only your recorded decision can mark this review item ruled out. Existing findings are never changed automatically.</div>${a.manual_tests.length?`<button class="btn primary" data-action="review-repeater" data-id="${html(a.id)}">View Repeater request text</button>`:'<p class="hint">No captured HTTP request was available for a grounded manual test.</p>'}`);
}
function reviewDecision(id){
  const a=state.snapshot.assessments.find(a=>a.id===id);if(!a)return;
  dialog('Record your decision',`<form id="review-decision-form"><input type="hidden" name="id" value="${html(id)}"><p class="note-text">${html(a.title)}</p><label class="field"><span>Tester disposition</span><select name="disposition">${[['open','Open'],['needs_more_evidence','Needs more evidence'],['validated','Manually validated'],['ruled_out','Manually ruled out']].map(([v,l])=>`<option value="${v}" ${a.disposition===v?'selected':''}>${l}</option>`).join('')}</select></label><p class="hint">This records your assessment. It does not execute tests or confirm/dismiss an existing finding. Record detailed results in Coverage and Findings.</p>${actions('Record decision')}</form>`);
}
function requestDialog(tests){
  state.manualTemplates=tests;
  dialog('Burp Repeater · manual request text',`<div class="notice">${icon('eye')} Copy or download only. Fieldmate has not sent these requests and has no Send or Execute action.</div>${tests.map((t,i)=>`<section class="repeater-test"><h3>${html(t.title)}</h3><p class="note-text">${html(t.purpose)}</p><p class="hint">Destination: <strong>${t.destination.tls?'HTTPS':'HTTP'} ${html(t.destination.host)}:${t.destination.port}</strong> · Evidence ${html(shortId(t.evidence_id))}</p>${t.baseline_request&&t.baseline_request!==t.request?`<details><summary>Baseline control request</summary><textarea class="request-text" readonly aria-label="Baseline control request">${html(t.baseline_request)}</textarea><button class="btn small" data-action="request-copy" data-index="${i}" data-baseline="true">Copy baseline</button></details>`:''}<label class="field"><span>${t.modified?'Candidate request':'Captured baseline request'}</span><textarea class="request-text" readonly aria-label="Repeater request text">${html(t.request)}</textarea></label><div class="heading-actions"><button class="btn primary" data-action="request-copy" data-index="${i}">${icon('evidence')} Copy request text</button><button class="btn" data-action="request-download" data-index="${i}">${icon('download')} Download .txt</button></div><h4>What to compare manually</h4><p class="note-text">${html(t.expected)}</p><ul class="setup-steps">${t.warnings.map(w=>`<li>${html(w)}</li>`).join('')}</ul></section>`).join('')}`);
}
function downloadText(blob,filename){
  const url=URL.createObjectURL(blob),anchor=document.createElement('a');anchor.href=url;anchor.download=filename;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1500);
}
async function downloadArchive(id){
  const project=state.snapshot.projects.find(p=>p.id===id);
  // Obtain a user-selected destination before the first await loses activation.
  if(typeof window.showSaveFilePicker==='function'){
    let handle;
    try{handle=await window.showSaveFilePicker({suggestedName:id+'.burp'});}
    catch(error){if(error.name==='AbortError')return;throw error;}
    const response=await api(endpoint(`projects/${id}/archive`),undefined,true);
    const writable=await handle.createWritable();
    try{await response.body.pipeTo(writable);}
    catch(error){try{await writable.abort();}catch{}throw error;}
    toast('Stored archive saved.');return;
  }
  if(!project||project.bytes>100*1024**2)throw new Error('For archives over 100 MiB, use Chrome/Chromium with file-save support or copy the archive from your private Fieldmate data directory.');
  const response=await api(endpoint(`projects/${id}/archive`),undefined,true);
  downloadText(await response.blob(),id+'.burp');
}
if (state.token) bootstrap(); else { render(); authDialog(); }
