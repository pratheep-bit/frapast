'use strict';

/* =========================================================================
   CONFIG
   Centralized so behavior (timeouts, thresholds, endpoints) is defined
   once instead of scattered as magic numbers through the code.
   ========================================================================= */
const CONFIG = Object.freeze({
  ENDPOINTS: {
    findings: '/api/findings',
    stats: '/api/stats',
    prove: '/api/prove',
    stream: '/api/stream',
  },
  // Severity band lower bounds (score >= bound). Centralized so the
  // header badges, table badges, and filter dropdown can never drift
  // out of sync with each other, unlike the original implementation
  // where the same three numbers were duplicated inline.
  SEVERITY_THRESHOLDS: { CRITICAL: 60, HIGH: 40, MEDIUM: 20 },
  PAGE_SIZE_DEFAULT: 25,
  MAX_LOG_ITEMS: 500,
  // If no SSE message arrives for this long during an active run, treat
  // the run as stalled rather than leaving the UI spinning forever.
  WATCHDOG_TIMEOUT_MS: 45000,
  RECONNECT_MAX_ATTEMPTS: 5,
  RECONNECT_BASE_DELAY_MS: 1000,
  TOAST_DURATION_MS: 5000,
});

/* =========================================================================
   UTILITIES
   ========================================================================= */

/** Escape a value for safe insertion into innerHTML (text or attribute
 *  context). The original dashboard interpolated rule IDs, file paths,
 *  and function names straight into innerHTML with no escaping at all —
 *  since those strings originate from scanned source code, a crafted
 *  file name or symbol containing `<`/`"` could break out of markup.
 *  Every dynamic value rendered below goes through this first. */
function escapeHtml(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return s.replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function debounce(fn, waitMs) {
  let timer = null;
  return function debounced(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(null, args), waitMs);
  };
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

/** Collapse every status spelling the backend might send ('passed',
 *  'failed', 'proven', 'refuted', missing, ...) into exactly one of four
 *  canonical values, applied once at ingestion. The original code kept
 *  two different fields (`status` and `proof_status`) that could disagree
 *  with each other — e.g. after a failed proof, `proof_status` became
 *  'failed' but `status` was never updated, so the "Refuted" filter
 *  silently matched nothing. Normalizing to one field removes that class
 *  of bug entirely. */
function normalizeStatus(raw) {
  const s = String(raw || 'candidate').toLowerCase();
  if (s === 'proven' || s === 'passed' || s === 'pass') return 'proven';
  if (s === 'refuted' || s === 'failed' || s === 'fail') return 'refuted';
  if (s === 'skipped' || s === 'skip') return 'skipped';
  return 'candidate';
}

/** Stable identity for a finding used to key the in-memory map and to
 *  correlate incoming SSE progress events back to a row. Preferring a
 *  server-issued id avoids the original bug where two different findings
 *  that shared the same rule_id + function (e.g. the same rule firing
 *  twice in one function, on different lines) were indistinguishable and
 *  a progress event for one could silently update the other. */
function computeKey(f) {
  if (f && f.id !== undefined && f.id !== null && f.id !== '') return `id:${f.id}`;
  return `loc:${(f && f.file) || ''}::${(f && f.line) || ''}::${(f && f.rule_id) || ''}::${(f && f.function) || ''}`;
}

function normalizeFinding(raw) {
  raw = raw || {};
  const scoreRaw = raw.severity && typeof raw.severity === 'object' ? raw.severity.score : undefined;
  return {
    key: computeKey(raw),
    id: raw.id ?? null,
    rule_id: raw.rule_id ?? '',
    file: raw.file ?? '',
    line: raw.line ?? '',
    function: raw.function ?? '',
    // Track presence explicitly instead of `score || 0`, which the
    // original code used — that collapses a genuine score of 0 and a
    // missing score into the same falsy value, hiding real data.
    score: Number.isFinite(scoreRaw) ? scoreRaw : null,
    status: normalizeStatus(raw.status ?? raw.proof_status),
    evidence: raw.evidence ?? '',
    description: raw.description ?? '',
    remediation: raw.remediation ?? '',
  };
}

function sevLabel(score) {
  if (!Number.isFinite(score)) return 'LOW';
  const t = CONFIG.SEVERITY_THRESHOLDS;
  if (score >= t.CRITICAL) return 'CRITICAL';
  if (score >= t.HIGH) return 'HIGH';
  if (score >= t.MEDIUM) return 'MEDIUM';
  return 'LOW';
}

function sevClass(label) {
  return {
    CRITICAL: 'badge-sev-critical',
    HIGH: 'badge-sev-high',
    MEDIUM: 'badge-sev-medium',
    LOW: 'badge-sev-low',
  }[label] || 'badge-sev-low';
}

function statusBadgeHtml(status) {
  const map = {
    proven: ['badge-status-proven', 'PROVEN'],
    refuted: ['badge-status-refuted', 'REFUTED'],
    skipped: ['badge-status-skipped', 'SKIPPED'],
    candidate: ['badge-status-candidate', 'CANDIDATE'],
  };
  const [cls, label] = map[status] || map.candidate;
  return `<span class="badge ${cls}">${label}</span>`;
}

function shortenPath(file, segments = 2) {
  return (file || '').split('/').slice(-segments).join('/');
}

function shortenFn(fn) {
  return (fn || '').split('.').pop();
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadTextFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* =========================================================================
   STATE
   Single source of truth. Findings live in a Map keyed by computeKey()
   so lookups during live streaming are O(1) instead of the original
   `Array.prototype.findIndex` scan on every progress event.
   ========================================================================= */
const state = {
  findings: new Map(),
  repo: '',
  loadError: null,

  filters: { query: '', status: '', severity: '' },
  sort: { key: 'severity', dir: 'desc' },

  page: 1,
  pageSize: CONFIG.PAGE_SIZE_DEFAULT,

  selected: new Set(),
  expandedKeys: new Set(),

  run: {
    active: false,
    total: 0,
    completed: 0,
    logCount: 0,
    watchdogTimer: null,
    reconnectTimer: null,
    reconnectAttempts: 0,
    sse: null,
    startedAt: null,
  },
};

/* =========================================================================
   DOM SHORTHAND
   ========================================================================= */
const $ = (id) => document.getElementById(id);

const els = {}; // populated in init() once the DOM is ready

/* =========================================================================
   DATA LOADING
   ========================================================================= */
async function loadFindings() {
  renderTableSkeleton();
  try {
    const res = await fetch(CONFIG.ENDPOINTS.findings);
    if (!res.ok) throw new Error(`Server returned ${res.status} ${res.statusText}`);
    const data = await res.json();
    if (data && typeof data.repo === 'string' && data.repo) {
      state.repo = data.repo;
    }
    const list = Array.isArray(data && data.candidates) ? data.candidates : [];
    state.findings.clear();
    for (const raw of list) {
      const f = normalizeFinding(raw);
      if (state.findings.has(f.key)) {
        console.warn('[frapast] duplicate finding key, later entry wins:', f.key);
      }
      state.findings.set(f.key, f);
    }
    state.loadError = null;
    state.page = 1;
    refresh();
    updateHeaderBadges();
    updateCandidateRemaining();
    updateQuickButtonAvailability();
  } catch (err) {
    state.loadError = err;
    renderTableError(err);
    showToast(`Couldn't load findings: ${err.message}`, 'error');
  }
}

async function loadStats() {
  try {
    const res = await fetch(CONFIG.ENDPOINTS.stats);
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const s = await res.json();
    if (s && typeof s.repo === 'string' && s.repo) {
      state.repo = s.repo;
    }
  } catch (err) {
    console.warn('[frapast] failed to load stats:', err.message);
  }
}

/* =========================================================================
   DERIVED DATA / FILTER-SORT-PAGINATE PIPELINE
   ========================================================================= */
function countByStatus(status) {
  let n = 0;
  for (const f of state.findings.values()) if (f.status === status) n++;
  return n;
}

function compareFindings(a, b) {
  const dir = state.sort.dir === 'asc' ? 1 : -1;
  switch (state.sort.key) {
    case 'severity': {
      const sa = a.score ?? -1, sb = b.score ?? -1;
      return (sa - sb) * dir;
    }
    case 'rule_id': return a.rule_id.localeCompare(b.rule_id) * dir;
    case 'file': return `${a.file}:${String(a.line).padStart(10, '0')}`
      .localeCompare(`${b.file}:${String(b.line).padStart(10, '0')}`) * dir;
    case 'function': return a.function.localeCompare(b.function) * dir;
    case 'status': return a.status.localeCompare(b.status) * dir;
    default: return 0;
  }
}

function getFilteredSorted() {
  const q = state.filters.query.trim().toLowerCase();
  let list = Array.from(state.findings.values());

  if (q) {
    list = list.filter((f) =>
      `${f.rule_id} ${f.file} ${f.function} ${f.evidence}`.toLowerCase().includes(q)
    );
  }
  if (state.filters.status) {
    list = list.filter((f) => f.status === state.filters.status);
  }
  if (state.filters.severity) {
    list = list.filter((f) => sevLabel(f.score) === state.filters.severity);
  }

  list.sort(compareFindings);
  return list;
}

function getPageSlice(list) {
  const totalPages = Math.max(1, Math.ceil(list.length / state.pageSize));
  state.page = clamp(state.page, 1, totalPages);
  const start = (state.page - 1) * state.pageSize;
  return { slice: list.slice(start, start + state.pageSize), totalPages, start };
}

/* =========================================================================
   RENDERING — TABLE
   ========================================================================= */
function renderTableSkeleton() {
  const rows = Array.from({ length: 8 }, () => `
    <tr class="skeleton-row">
      <td></td>
      <td class="skeleton-block" style="width:20px;"></td>
      <td><div class="skeleton-block" style="width:120px;"></div></td>
      <td><div class="skeleton-block" style="width:70px;"></div></td>
      <td><div class="skeleton-block" style="width:160px;"></div></td>
      <td><div class="skeleton-block" style="width:100px;"></div></td>
      <td><div class="skeleton-block" style="width:80px;"></div></td>
      <td></td>
    </tr>`).join('');
  els.findingsTbody.innerHTML = rows;
  els.resultsSummary.textContent = 'Loading findings…';
}

function renderTableError(err) {
  els.findingsTbody.innerHTML = `
    <tr><td colspan="8">
      <div class="error-state">
        <div class="empty-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--red-text);"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
        <p>Couldn't load security candidates. ${escapeHtml(err.message)}</p>
        <button class="retry-btn" id="tableRetryBtn">Try again</button>
      </div>
    </td></tr>`;
  const btn = $('tableRetryBtn');
  if (btn) btn.addEventListener('click', loadFindings);
  els.resultsSummary.textContent = 'Failed to load findings.';
}

async function fetchSnippetLines(f) {
  if (f.snippetLoaded) return;
  f.snippetLoading = true;
  f.snippetError = null;
  try {
    const fileParam = encodeURIComponent(f.file || '');
    const lineParam = parseInt(f.line, 10) || 1;
    const res = await fetch(`/api/snippet?file=${fileParam}&line=${lineParam}&before=2&after=3`);
    const data = await res.json();
    if (res.ok && Array.isArray(data.lines) && data.lines.length > 0) {
      f.snippetLines = data.lines;
    } else {
      f.snippetError = (data && data.error) || 'Server returned no lines for this file.';
    }
  } catch (e) {
    f.snippetError = 'Could not reach the scanner server to load this file.';
  } finally {
    f.snippetLoading = false;
    f.snippetLoaded = true;
    renderTable();
  }
}

function toggleRowExpansion(key) {
  if (state.expandedKeys.has(key)) {
    state.expandedKeys.delete(key);
  } else {
    state.expandedKeys.add(key);
    const f = state.findings.get(key);
    if (f && !f.snippetLoaded && !f.snippetLoading) {
      fetchSnippetLines(f);
    }
  }
  renderTable();
}

function renderTable() {
  const totalCount = state.findings.size;
  const filtered = getFilteredSorted();
  const { slice, totalPages, start } = getPageSlice(filtered);

  if (totalCount === 0 && !state.loadError) {
    els.findingsTbody.innerHTML = `<tr><td colspan="9"><div class="empty"><div class="empty-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--green-text);"><polyline points="20 6 9 17 4 12"/></svg></div><p>No security candidates were found in this scan.</p></div></td></tr>`;
  } else if (filtered.length === 0) {
    els.findingsTbody.innerHTML = `<tr><td colspan="9"><div class="empty"><div class="empty-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-light);"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></div><p>No findings match the current filters. Try clearing them.</p></div></td></tr>`;
  } else {
    let rowsHtml = '';
    slice.forEach((f, i) => {
      const isExpanded = state.expandedKeys.has(f.key);
      rowsHtml += renderRow(f, start + i + 1, isExpanded);
      if (isExpanded) {
        rowsHtml += `<tr class="code-dropdown-row" data-parent-key="${escapeHtml(f.key)}"><td colspan="9">${renderInlineCodeSnippetHtml(f)}</td></tr>`;
      }
    });
    els.findingsTbody.innerHTML = rowsHtml;
  }

  renderResultsSummary(totalCount, filtered.length, start, slice.length);
  renderPagination(totalPages);
  updateSelectAllCheckboxState(slice);
}

function renderRow(f, rowNumber, isExpanded) {
  const label = sevLabel(f.score);
  const scoreText = Number.isFinite(f.score) ? f.score.toFixed(0) : '—';
  const file = shortenPath(f.file);
  const fn = shortenFn(f.function);
  const titleLoc = escapeHtml(`${f.file || ''}:${f.line ?? ''}`);
  const selected = state.selected.has(f.key);

  return `<tr data-key="${escapeHtml(f.key)}" class="${selected ? 'row-selected' : ''} ${isExpanded ? 'row-expanded' : ''}" style="cursor: pointer;">
      <td class="col-check">
        <input type="checkbox" class="row-check" data-key="${escapeHtml(f.key)}" ${selected ? 'checked' : ''} aria-label="Select finding ${escapeHtml(f.rule_id)}">
      </td>
      <td class="col-expand">
        <button class="expand-toggle-btn ${isExpanded ? 'expanded' : ''}" data-expand-key="${escapeHtml(f.key)}" aria-label="Toggle code snippet dropdown">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </button>
      </td>
      <td class="col-num">${rowNumber}</td>
      <td class="col-rule">${escapeHtml(f.rule_id)}</td>
      <td><span class="badge ${sevClass(label)}">${label}${scoreText !== '—' ? ' ' + escapeHtml(scoreText) : ''}</span></td>
      <td class="col-file" title="${titleLoc}">${escapeHtml(file)}:${escapeHtml(f.line ?? '')}</td>
      <td class="col-fn" title="${escapeHtml(f.function)}">${escapeHtml(fn)}</td>
      <td>${statusBadgeHtml(f.status)}</td>
      <td class="col-actions">
        <button class="icon-btn" data-view-key="${escapeHtml(f.key)}" aria-label="View details for ${escapeHtml(f.rule_id)}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
      </td>
    </tr>`;
}

function renderInlineCodeSnippetHtml(f) {
  const targetLine = parseInt(f.line, 10) || 1;
  let lineRowsHtml = '';

  if (f.snippetLoading) {
    lineRowsHtml = `<div class="code-line-row context-line" style="padding: 12px; font-style: italic;"><span class="line-code" style="color: #64748b;">Loading exact source code lines from disk…</span></div>`;
  } else if (Array.isArray(f.snippetLines) && f.snippetLines.length > 0) {
    lineRowsHtml = f.snippetLines.map((l) => {
      const isErr = l.is_error;
      const rowCls = isErr ? 'code-line-row error-line' : 'code-line-row context-line';
      const tag = isErr ? `<span class="error-marker-tag">VULNERABILITY LINE ${l.num}</span>` : '';
      return `<div class="${rowCls}">
            <span class="line-num">${l.num}</span>
            <span class="line-code">${escapeHtml(l.code)}</span>
            ${tag}
          </div>`;
    }).join('');
  } else {
    const reason = f.snippetError || 'Real source lines are unavailable for this finding.';
    lineRowsHtml = `<div class="code-line-row context-line" style="padding: 12px; color: #b91c1c; font-style: italic;">
          <span class="line-code">⚠ ${escapeHtml(reason)}</span>
        </div>`;
  }

  return `
      <div class="code-expansion-container">
        <div class="code-expansion-header">
          <div class="code-expansion-file">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            ${escapeHtml(f.file)}:${targetLine} (${escapeHtml(f.rule_id)})
          </div>
          <div class="code-expansion-meta">
            Exact file source code (2 lines before & 3 lines after error line ${targetLine})
          </div>
        </div>
        <div class="code-expansion-block">
          ${lineRowsHtml}
        </div>
      </div>`;
}

function renderResultsSummary(totalCount, filteredCount, start, sliceLen) {
  if (totalCount === 0) { els.resultsSummary.textContent = ''; return; }
  const from = sliceLen === 0 ? 0 : start + 1;
  const to = start + sliceLen;
  const filterNote = filteredCount === totalCount ? '' : ` (filtered from ${totalCount})`;
  els.resultsSummary.textContent = `Showing ${from}–${to} of ${filteredCount}${filterNote}`;
}

function renderPagination(totalPages) {
  els.pageInfo.textContent = `Page ${state.page} of ${totalPages}`;
  els.pageFirstBtn.disabled = state.page <= 1;
  els.pagePrevBtn.disabled = state.page <= 1;
  els.pageNextBtn.disabled = state.page >= totalPages;
  els.pageLastBtn.disabled = state.page >= totalPages;
}

function updateSortHeaders() {
  document.querySelectorAll('th.sortable').forEach((th) => {
    const key = th.dataset.sortKey;
    const active = key === state.sort.key;
    th.dataset.active = active ? 'true' : 'false';
    const arrow = th.querySelector('.sort-arrow');
    if (arrow) arrow.textContent = state.sort.dir === 'asc' ? '▲' : '▼';
  });
}

/* =========================================================================
   RENDERING — HEADER BADGES
   ========================================================================= */
function updateHeaderBadges() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of state.findings.values()) counts[sevLabel(f.score)]++;
  els.badgeTotal.textContent = `${state.findings.size} Findings`;
  els.badgeCritical.textContent = `${counts.CRITICAL} Critical`;
  els.badgeHigh.textContent = `${counts.HIGH} High`;
  els.badgeMedium.textContent = `${counts.MEDIUM} Medium`;
  els.badgeLow.textContent = `${counts.LOW} Low`;
}

function updateCandidateRemaining() {
  const n = countByStatus('candidate');
  els.candidateRemaining.textContent = `${n} remaining`;
}

/* =========================================================================
   FILTERS
   ========================================================================= */
const onFilterInput = debounce(() => {
  state.filters.query = els.filterInput.value;
  state.page = 1;
  renderTable();
}, 200);

function onFilterStatusChange() {
  state.filters.status = els.filterStatus.value;
  state.page = 1;
  renderTable();
}

function onFilterSevChange() {
  state.filters.severity = els.filterSev.value;
  state.page = 1;
  renderTable();
}

function onSortHeaderClick(e) {
  const th = e.target.closest('th.sortable');
  if (!th) return;
  const key = th.dataset.sortKey;
  if (state.sort.key === key) {
    state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.sort.key = key;
    state.sort.dir = key === 'severity' ? 'desc' : 'asc';
  }
  updateSortHeaders();
  renderTable();
}

/* =========================================================================
   PAGINATION EVENTS
   ========================================================================= */
function goToPage(delta) {
  state.page += delta;
  renderTable();
}
function goToFirstPage() { state.page = 1; renderTable(); }
function goToLastPage() { state.page = Number.MAX_SAFE_INTEGER; renderTable(); }

function onPageSizeChange() {
  state.pageSize = parseInt(els.pageSizeSelect.value, 10) || CONFIG.PAGE_SIZE_DEFAULT;
  state.page = 1;
  renderTable();
}

/* =========================================================================
   ROW SELECTION
   Lets the user target specific findings for proving instead of only
   "the first N by severity", which is the only mode the original UI
   supported despite showing a full table of individually distinguishable
   rows.
   ========================================================================= */
function toggleSelection(key, checked) {
  if (checked) state.selected.add(key); else state.selected.delete(key);
  renderSelectionBar();
  const row = els.findingsTbody.querySelector(`tr[data-key="${cssEscapeAttr(key)}"]`);
  if (row) row.classList.toggle('row-selected', checked);
  updateSelectAllCheckboxState(getPageSlice(getFilteredSorted()).slice);
}

function cssEscapeAttr(value) {
  // Minimal escaping for use inside a CSS attribute selector string.
  return String(value).replace(/["\\]/g, '\\$&');
}

function clearSelection() {
  state.selected.clear();
  renderSelectionBar();
  renderTable();
}

function renderSelectionBar() {
  const n = state.selected.size;
  els.selectionBar.classList.toggle('visible', n > 0);
  els.selectionCount.textContent = `${n} selected`;
  updateProveButtonLabel();
}

function updateSelectAllCheckboxState(visibleSlice) {
  if (!visibleSlice || visibleSlice.length === 0) {
    els.selectAllCheckbox.checked = false;
    els.selectAllCheckbox.indeterminate = false;
    return;
  }
  const selectedOnPage = visibleSlice.filter((f) => state.selected.has(f.key)).length;
  els.selectAllCheckbox.checked = selectedOnPage === visibleSlice.length;
  els.selectAllCheckbox.indeterminate = selectedOnPage > 0 && selectedOnPage < visibleSlice.length;
}

function onSelectAllToggle() {
  const visible = getPageSlice(getFilteredSorted()).slice;
  const shouldSelect = !els.selectAllCheckbox.checked ? false : true;
  visible.forEach((f) => {
    if (shouldSelect) state.selected.add(f.key); else state.selected.delete(f.key);
  });
  renderSelectionBar();
  renderTable();
}

/* Event delegation for per-row controls, since rows are re-rendered on
   every table update — attaching listeners once on the tbody avoids
   re-binding hundreds of handlers and keeps dynamic HTML free of
   inline onclick attributes built from untrusted string data. */
function onTableBodyClick(e) {
  const viewBtn = e.target.closest('[data-view-key]');
  if (viewBtn) { openDrawer(viewBtn.dataset.viewKey); return; }

  const checkbox = e.target.closest('input.row-check');
  if (checkbox) { toggleSelection(checkbox.dataset.key, checkbox.checked); return; }

  const expandBtn = e.target.closest('[data-expand-key]');
  if (expandBtn) { toggleRowExpansion(expandBtn.dataset.expandKey); return; }

  const row = e.target.closest('tr[data-key]');
  if (row && !e.target.closest('.code-dropdown-row')) {
    toggleRowExpansion(row.dataset.key);
    return;
  }
}

/* =========================================================================
   COUNT INPUT / QUICK SELECT
   ========================================================================= */
function setCount(rawCount, btnEl) {
  document.querySelectorAll('.quick-btn').forEach((b) => b.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');

  const candidateCount = countByStatus('candidate');
  const value = rawCount === 'all' ? Math.max(candidateCount, 1) : rawCount;
  els.countInput.value = value;
  clearCountError();
}

function updateQuickButtonAvailability() {
  const hasCandidates = countByStatus('candidate') > 0;
  document.querySelectorAll('.quick-btn').forEach((b) => { b.disabled = !hasCandidates; });
  els.proveBtn.disabled = !hasCandidates || state.run.active;
}

/** Validate the manual count field. Fixes several bugs in the original:
 *  `parseInt(input) || 10` silently replaced an intentional 0 with 10,
 *  negative numbers were accepted outright, and there was no upper
 *  bound check against how many candidates actually remain. */
function validateCount(raw) {
  const n = Math.floor(Number(raw));
  const candidateCount = countByStatus('candidate');
  if (raw === '' || raw === null || Number.isNaN(n)) {
    return { valid: false, message: 'Enter a number.' };
  }
  if (!Number.isFinite(n) || n < 1) {
    return { valid: false, message: 'Enter a whole number of at least 1.' };
  }
  if (candidateCount === 0) {
    return { valid: false, message: 'No unproven candidates remain.' };
  }
  if (n > candidateCount) {
    return {
      valid: false,
      message: `Only ${candidateCount} candidate${candidateCount === 1 ? '' : 's'} remain — lower the count.`,
    };
  }
  return { valid: true, value: n };
}

function showCountError(message) {
  els.countError.textContent = message;
  els.countInput.classList.add('input-error');
}
function clearCountError() {
  els.countError.textContent = '';
  els.countInput.classList.remove('input-error');
}

function updateProveButtonLabel() {
  if (state.run.active) return;
  els.proveBtn.textContent = state.selected.size > 0
    ? `Prove ${state.selected.size} Selected`
    : 'Start Proof Engine';
}

/* =========================================================================
   PROOF ENGINE — RUN LIFECYCLE
   ========================================================================= */
function setConnectionStatus(mode) {
  const labels = { idle: 'Idle', connected: 'Live', reconnecting: 'Reconnecting…', offline: 'Offline' };
  els.connStatus.dataset.state = mode;
  els.connStatusLabel.textContent = labels[mode] || mode;
}

async function startProving() {
  if (state.run.active) return;

  let payload;
  if (state.selected.size > 0) {
    const ids = [];
    const locators = [];
    for (const key of state.selected) {
      const f = state.findings.get(key);
      if (!f) continue;
      if (f.id !== null && f.id !== undefined) ids.push(f.id);
      else locators.push({ file: f.file, line: f.line, rule_id: f.rule_id, function: f.function });
    }
    // Every selected key resolved to nothing (e.g. a rescan replaced the
    // findings out from under a stale selection). Fail fast here rather
    // than sending an empty selection payload — the earlier version of
    // the code had no check like this, and combined with a backend bug
    // that ignored empty finding_ids arrays, this silently proved an
    // unrelated default set of candidates instead of telling the user
    // their selection was gone.
    if (ids.length === 0 && locators.length === 0) {
      showToast('Your selection is no longer valid — clear it and reselect.', 'warning');
      return;
    }
    payload = { finding_ids: ids };
    if (locators.length) payload.finding_locators = locators;
  } else {
    const check = validateCount(els.countInput.value);
    if (!check.valid) { showCountError(check.message); return; }
    clearCountError();
    payload = { count: check.value };
  }

  beginRunUI(payload);

  openStream();

  try {
    const res = await fetch(CONFIG.ENDPOINTS.prove, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Server returned ${res.status} ${res.statusText}`);
  } catch (err) {
    // The original code never checked this request's outcome at all, so
    // a failed POST left the "Running…" button spinning forever because
    // nothing but an SSE 'done' event could ever reset it.
    failRun(`Couldn't start the proof engine: ${err.message}`);
  }
}

function beginRunUI() {
  state.run.active = true;
  state.run.completed = 0;
  state.run.logCount = 0;
  state.run.startedAt = Date.now();
  state.run.reconnectAttempts = 0;

  els.proveBtn.disabled = true;
  els.proveBtn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Running Proof Engine…';
  els.progressWrap.style.display = 'flex';
  els.progressBar.style.width = '0%';
  els.progressBar.classList.remove('progress-stalled');
  els.progressText.textContent = 'Initializing…';
  els.progressWarning.classList.remove('visible');
  els.statsCard.style.display = 'none';
  els.streamList.innerHTML = '';
  els.streamCount.textContent = '';
  document.querySelectorAll('.quick-btn').forEach((b) => { b.disabled = true; });
}

function endRunUI() {
  state.run.active = false;
  els.proveBtn.disabled = false;
  updateProveButtonLabel();
  updateQuickButtonAvailability();
}

function resetWatchdog() {
  clearTimeout(state.run.watchdogTimer);
  if (!state.run.active) return;
  els.progressWarning.classList.remove('visible');
  els.progressBar.classList.remove('progress-stalled');
  state.run.watchdogTimer = setTimeout(() => {
    // Don't kill the run outright on the first silence — surface a
    // visible warning, since a slow rule can legitimately take a while.
    els.progressWarning.classList.add('visible');
    els.progressBar.classList.add('progress-stalled');
    state.run.watchdogTimer = setTimeout(() => {
      failRun('No response from the proof engine for a while — the run may have stalled.');
    }, CONFIG.WATCHDOG_TIMEOUT_MS);
  }, CONFIG.WATCHDOG_TIMEOUT_MS);
}

function clearWatchdog() {
  clearTimeout(state.run.watchdogTimer);
  state.run.watchdogTimer = null;
}

function openStream() {
  closeStream();
  setConnectionStatus('reconnecting');

  let es;
  try {
    es = new EventSource(CONFIG.ENDPOINTS.stream);
  } catch (err) {
    failRun(`Couldn't open the live stream: ${err.message}`);
    return;
  }
  state.run.sse = es;

  es.onopen = () => {
    state.run.reconnectAttempts = 0;
    setConnectionStatus('connected');
    resetWatchdog();
  };

  es.onmessage = (ev) => {
    resetWatchdog();
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (err) {
      console.warn('[frapast] malformed SSE payload, ignoring:', ev.data);
      return;
    }
    if (msg.type === 'progress') handleProgress(msg);
    else if (msg.type === 'done') handleDone(msg);
    else if (msg.type === 'error') handleStreamAppError(msg);
    else if (msg.type === 'scan_start' || msg.type === 'scan_progress' || msg.type === 'scan_done' || msg.type === 'scan_error') handleScanSseEvent(msg);
  };

  // The original handler just closed the stream on any error and left
  // everything else (the disabled button, the spinner, the run state)
  // exactly as it was — a dropped connection meant the UI was stuck
  // until the page was reloaded. This retries with backoff and only
  // gives up, visibly, after repeated failures.
  es.onerror = () => {
    if (!state.run.active) {
      // Not in a proof run — quietly attempt reconnect for scan event monitoring
      setConnectionStatus('idle');
      attemptReconnect();
      return;
    }
    setConnectionStatus('reconnecting');
    attemptReconnect();
  };
}

function attemptReconnect() {
  if (state.run.reconnectAttempts >= CONFIG.RECONNECT_MAX_ATTEMPTS) {
    failRun('Lost connection to the proof engine and could not reconnect.');
    return;
  }
  state.run.reconnectAttempts += 1;
  const delay = CONFIG.RECONNECT_BASE_DELAY_MS * Math.pow(2, state.run.reconnectAttempts - 1);
  showToast(`Connection interrupted — retrying (${state.run.reconnectAttempts}/${CONFIG.RECONNECT_MAX_ATTEMPTS})…`, 'warning');
  clearTimeout(state.run.reconnectTimer);
  state.run.reconnectTimer = setTimeout(() => {
    if (state.run.active) openStream();
  }, delay);
}

function closeStream() {
  clearTimeout(state.run.reconnectTimer);
  if (state.run.sse) {
    state.run.sse.close();
    state.run.sse = null;
  }
}

function failRun(message) {
  clearWatchdog();
  closeStream();
  setConnectionStatus('offline');
  endRunUI();
  els.progressText.textContent = message;
  els.progressWarning.classList.remove('visible');
  showToast(message, 'error');
}

/** Locate the finding a progress event refers to. Tries the server id
 *  first, then falls back to the same composite locator used at load
 *  time. The original code used
 *    `c.id === d.finding_id || (c.rule_id === d.rule_id && c.function === d.function)`
 *  which — missing file/line — could update the wrong row whenever the
 *  same rule fired more than once in the same function. */
function resolveFindingKey(d) {
  if (d.finding_id !== undefined && d.finding_id !== null) {
    const byId = `id:${d.finding_id}`;
    if (state.findings.has(byId)) return byId;
  }
  const byLoc = computeKey({ file: d.file, line: d.line, rule_id: d.rule_id, function: d.function });
  if (state.findings.has(byLoc)) return byLoc;
  return null;
}

function handleProgress(d) {
  state.run.total = Number(d.total) || state.run.total;
  state.run.completed = Number(d.index) || state.run.completed;

  const pct = state.run.total > 0 ? Math.round((state.run.completed / state.run.total) * 100) : 0;
  els.progressBar.style.width = `${pct}%`;
  els.progressText.textContent = `${state.run.completed} / ${state.run.total} — ${d.rule_id || ''} in ${d.function || ''}`;

  const status = normalizeStatus(d.status === 'passed' ? 'proven' : d.status === 'failed' ? 'refuted' : d.status);
  const key = resolveFindingKey(d);

  if (key) {
    const f = state.findings.get(key);
    f.status = status;
    patchRowIfVisible(key);
  } else {
    console.warn('[frapast] progress event did not match any known finding:', d);
  }

  pushStreamLogItem(d, status, !key);
  updateHeaderBadges();
  updateCandidateRemaining();
}

/** Live-patch a single row's status badge in place, instead of the
 *  original behavior of silently mutating the data array and leaving
 *  the visible table stale until the run finished (or the user
 *  happened to re-filter). */
function patchRowIfVisible(key) {
  const row = els.findingsTbody.querySelector(`tr[data-key="${cssEscapeAttr(key)}"]`);
  if (!row) return;
  const f = state.findings.get(key);
  const statusCell = row.children[6];
  if (statusCell) statusCell.innerHTML = statusBadgeHtml(f.status);
}

function pushStreamLogItem(d, status, unmatched) {
  const clsMap = { proven: 'badge-status-proven', refuted: 'badge-status-refuted', skipped: 'badge-status-skipped' };
  const labelMap = { proven: 'PROVEN', refuted: 'REFUTED', skipped: 'SKIPPED' };
  const cls = clsMap[status] || 'badge-status-candidate';
  const label = labelMap[status] || status.toUpperCase();
  const file = shortenPath(d.file);

  const item = document.createElement('div');
  item.className = `stream-item${unmatched ? ' unmatched' : ''}`;
  item.innerHTML = `
    <div class="stream-idx">${escapeHtml(d.index ?? '?')}</div>
    <div class="stream-info">
      <div class="stream-rule">${escapeHtml(d.rule_id)}</div>
      <div class="stream-loc">${escapeHtml(file)}:${escapeHtml(d.line ?? '')} — ${escapeHtml(shortenFn(d.function))}</div>
    </div>
    <span class="badge ${cls}">${label}</span>`;
  els.streamList.prepend(item);

  state.run.logCount++;
  // Unbounded DOM growth was one of the original's quieter bugs — a
  // long run (hundreds/thousands of findings) would keep every log
  // entry in the DOM forever. Cap it and note the truncation.
  while (els.streamList.children.length > CONFIG.MAX_LOG_ITEMS) {
    els.streamList.removeChild(els.streamList.lastChild);
  }
  els.streamCount.textContent = state.run.logCount > CONFIG.MAX_LOG_ITEMS
    ? `showing last ${CONFIG.MAX_LOG_ITEMS} of ${state.run.logCount}`
    : `${state.run.logCount} logged`;
}

function handleStreamAppError(d) {
  showToast(d.message || 'The proof engine reported an error.', 'error');
}

function handleDone(d) {
  clearWatchdog();
  closeStream();
  setConnectionStatus('idle');
  endRunUI();

  els.progressBar.style.width = '100%';
  els.progressBar.classList.remove('progress-stalled');
  els.progressText.textContent = 'Verification complete.';
  els.progressWarning.classList.remove('visible');

  const s = d.summary || {};
  const proven = Number(s.proven) || 0;
  const refuted = Number(s.refuted) || 0;
  const skipped = Number(s.skipped) || 0;
  const total = Number(s.total) || proven + refuted + skipped;

  els.statsCard.style.display = 'block';
  els.statProven.textContent = proven;
  els.statRefuted.textContent = refuted;
  els.statSkipped.textContent = skipped;
  els.statTotal.textContent = total;

  clearSelectionSilently();
  renderTable();
  updateHeaderBadges();
  updateCandidateRemaining();
  updateQuickButtonAvailability();

  showToast(`Verification complete — ${proven} proven, ${refuted} refuted, ${skipped} skipped.`, 'success');
}

function clearSelectionSilently() {
  state.selected.clear();
  els.selectionBar.classList.remove('visible');
}

/* =========================================================================
   CENTRAL REFRESH
   ========================================================================= */
function refresh() {
  updateSortHeaders();
  renderTable();
}

/* =========================================================================
   TOASTS
   ========================================================================= */
function showToast(message, type = 'info', duration = CONFIG.TOAST_DURATION_MS) {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.innerHTML = `<span class="toast-msg">${escapeHtml(message)}</span><button class="toast-close" aria-label="Dismiss notification">&times;</button>`;
  el.querySelector('.toast-close').addEventListener('click', () => removeToast(el));
  els.toastContainer.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  if (duration) setTimeout(() => removeToast(el), duration);
}

function removeToast(el) {
  el.classList.remove('show');
  setTimeout(() => el.remove(), 250);
}

/* =========================================================================
   DETAIL DRAWER
   ========================================================================= */
function openDrawer(key) {
  const f = state.findings.get(key);
  if (!f) return;

  const label = sevLabel(f.score);
  const scoreText = Number.isFinite(f.score) ? f.score.toFixed(0) : 'unscored';

  $('drawerRuleId').textContent = f.rule_id || '(unnamed rule)';
  $('drawerLoc').textContent = `${f.file || 'unknown file'}:${f.line ?? '?'}`;
  $('drawerBadges').innerHTML = `<span class="badge ${sevClass(label)}">${label} · ${escapeHtml(scoreText)}</span> &nbsp; ${statusBadgeHtml(f.status)}`;
  $('drawerFunction').textContent = f.function || '—';

  toggleDrawerField('drawerDescriptionWrap', 'drawerDescription', f.description);
  toggleDrawerField('drawerEvidenceWrap', 'drawerEvidence', f.evidence, true);
  toggleDrawerField('drawerRemediationWrap', 'drawerRemediation', f.remediation);

  els.drawer.classList.add('open');
  els.drawer.setAttribute('aria-hidden', 'false');
  els.drawerBackdrop.classList.add('open');
  els.drawerCloseBtn.focus();
}

function toggleDrawerField(wrapId, valueId, value, isCode) {
  const wrap = $(wrapId);
  const target = $(valueId);
  if (value) {
    wrap.style.display = 'block';
    if (isCode) target.textContent = value; // <pre> — no HTML escaping needed via textContent
    else target.textContent = value;
  } else {
    wrap.style.display = 'none';
  }
}

function closeDrawer() {
  els.drawer.classList.remove('open');
  els.drawer.setAttribute('aria-hidden', 'true');
  els.drawerBackdrop.classList.remove('open');
}

/* =========================================================================
   EXPORT
   ========================================================================= */
function exportVisibleAsCsv() {
  const rows = getFilteredSorted();
  if (rows.length === 0) {
    showToast('Nothing to export with the current filters.', 'warning');
    return;
  }
  const header = ['rule_id', 'severity_score', 'severity_label', 'status', 'file', 'line', 'function'];
  const lines = [header.join(',')];
  for (const f of rows) {
    lines.push([
      f.rule_id, f.score ?? '', sevLabel(f.score), f.status, f.file, f.line, f.function,
    ].map(csvEscape).join(','));
  }
  downloadTextFile(lines.join('\n'), 'frapast-findings.csv', 'text/csv;charset=utf-8');
  showToast(`Exported ${rows.length} finding${rows.length === 1 ? '' : 's'} to CSV.`, 'success');
}

/* =========================================================================
   KEYBOARD SHORTCUTS
   ========================================================================= */
function onGlobalKeydown(e) {
  const tag = (document.activeElement && document.activeElement.tagName) || '';
  const inField = tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA';

  if (e.key === '/' && !inField) {
    e.preventDefault();
    els.filterInput.focus();
    return;
  }
  if (e.key === 'Escape') {
    if (els.drawer.classList.contains('open')) closeDrawer();
    closeReportModal();
    closeFolderModal();
  }
}

/* =========================================================================
   SCAN TRIGGER
   ========================================================================= */
function setScanStatus(text) {
  if (!els.scanStatus) return;
  if (!text) {
    els.scanStatus.style.display = 'none';
    els.scanStatus.textContent = '';
  } else {
    els.scanStatus.style.display = 'inline-flex';
    els.scanStatus.textContent = text;
  }
}

function triggerScan() {
  const repoPath = els.scanPathInput.value.trim();
  if (!repoPath) {
    showToast('Please enter a folder path to scan.', 'warning');
    els.scanPathInput.focus();
    return;
  }
  els.scanBtn.disabled = true;
  setScanStatus('Scanning…');
  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_path: repoPath }),
  })
    .then((r) => r.json())
    .then((d) => {
      if (d.error) {
        showToast(`Scan error: ${d.error}`, 'error');
        setScanStatus('Error');
      } else if (d.status === 'already_running') {
        showToast('A scan is already running.', 'warning');
        setScanStatus('Running…');
      } else {
        showToast(`Scanning ${repoPath}…`, 'info');
      }
    })
    .catch((err) => {
      showToast(`Network error: ${err.message}`, 'error');
      setScanStatus('Error');
      els.scanBtn.disabled = false;
    });
}

// React to SSE scan_done / scan_progress events
function handleScanSseEvent(evt) {
  if (evt.type === 'scan_start') {
    setScanStatus('Indexing…');
  } else if (evt.type === 'scan_progress') {
    setScanStatus(`${evt.count} candidates found`);
    els.scanBtn.disabled = false;
    loadFindings();
    loadStats();
  } else if (evt.type === 'scan_done') {
    setScanStatus(`Scan complete`);
    els.scanBtn.disabled = false;
    loadFindings();
    loadStats();
  } else if (evt.type === 'scan_error') {
    setScanStatus(evt.error);
    els.scanBtn.disabled = false;
  }
}

/* =========================================================================
   BENCH SETTINGS
   ========================================================================= */
function toggleBenchSettings() {
  const open = els.benchSettingsBody.classList.toggle('open');
  els.benchChevron.classList.toggle('open', open);
}

function loadBenchConfig() {
  fetch('/api/bench/config')
    .then((r) => r.json())
    .then((d) => {
      if (d.bench_url) els.benchUrlInput.value = d.bench_url;
      if (d.bench_user) els.benchUserInput.value = d.bench_user;
      if (d.bench_site) els.benchSiteInput.value = d.bench_site;
    })
    .catch(() => { }); // silent — optional prefill
}

function saveBenchConfig() {
  const payload = {
    bench_url: els.benchUrlInput.value.trim(),
    bench_port: els.benchPortInput.value.trim(),
    bench_user: els.benchUserInput.value.trim(),
    bench_password: els.benchPasswordInput.value,
    bench_site: els.benchSiteInput.value.trim(),
  };
  els.benchSaveBtn.disabled = true;
  els.benchSaveBtn.textContent = 'Saving…';
  fetch('/api/bench/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then((r) => r.json())
    .then(() => {
      showToast('Bench config saved. Testing connection…', 'info');
      return fetch('/api/bench/check');
    })
    .then((r) => r.json())
    .then((d) => renderBenchDiag(d))
    .catch((err) => {
      showToast(`Error: ${err.message}`, 'error');
    })
    .finally(() => {
      els.benchSaveBtn.disabled = false;
      els.benchSaveBtn.textContent = 'Save & Test Connection';
    });
}

function renderBenchDiag(d) {
  els.benchDiag.style.display = '';

  const reach = d.reachable;
  const auth = d.authenticated;
  const site = d.site_valid !== undefined ? d.site_valid : true;

  // URL row
  els.diagUrl.textContent = d.url || '—';
  _setDiagBadge(els.diagReachBadge, reach, 'REACHABLE', 'UNREACHABLE');

  // Site row
  els.diagSite.textContent = d.site || '—';
  _setDiagBadge(els.diagSiteBadge, site, 'VALID', 'NOT FOUND');

  // Auth row
  els.diagUser.textContent = d.user || '—';
  _setDiagBadge(els.diagAuthBadge, auth, 'OK', 'FAILED');

  // Overall badge in card header
  const overall = reach && auth && site;
  const badge = els.benchStatusBadge;
  badge.className = 'bench-status-badge ' + (overall ? 'ready' : auth === null ? 'warn' : 'error');
  badge.textContent = overall ? 'Ready' : 'Issue';

  // Issues list
  const issues = [];
  if (!reach) issues.push(`Bench URL is unreachable. Is "bench start" running on ${d.url || 'the configured port'}?`);
  if (reach && !auth) issues.push('Authentication failed. Check your username and password.');
  if (reach && !site) issues.push(`Site "${d.site}" not found. Check your site name.`);

  if (issues.length) {
    els.diagIssues.innerHTML = issues.map((i) => `<div><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>${escapeHtml(i)}</div>`).join('');
    els.diagIssues.style.display = '';
  } else {
    els.diagIssues.style.display = 'none';
  }
}

function _setDiagBadge(el, ok, okLabel, failLabel) {
  if (ok === null || ok === undefined) {
    el.textContent = '—';
    el.className = 'bench-diag-badge neutral';
  } else if (ok) {
    el.textContent = okLabel;
    el.className = 'bench-diag-badge ok';
  } else {
    el.textContent = failLabel;
    el.className = 'bench-diag-badge fail';
  }
}

/* =========================================================================
   DOWNLOAD HELPER
   ========================================================================= */
function downloadFile(url, filename) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/* =========================================================================
   REPORT MODAL
   ========================================================================= */
let rawReportMarkdown = '';

function renderReportMarkdownToHtml(markdownText) {
  rawReportMarkdown = markdownText || '';
  if (!markdownText) return '<div class="report-p">No report data available.</div>';

  const lines = markdownText.split('\n');
  let html = '<div class="report-styled-container">';
  let inTable = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) {
      if (inTable) {
        html += '</tbody></table>';
        inTable = false;
      }
      continue;
    }

    if (line.startsWith('# ')) {
      html += `<h1 class="report-h1">${escapeHtml(line.slice(2))}</h1>`;
    } else if (line.startsWith('## ')) {
      html += `<h2 class="report-h2">${escapeHtml(line.slice(3))}</h2>`;
    } else if (line.startsWith('|')) {
      const cells = line.split('|').map((c) => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
      if (line.includes('---')) continue;
      if (!inTable) {
        html += '<table class="report-styled-table"><thead><tr>';
        cells.forEach((c) => { html += `<th>${escapeHtml(c)}</th>`; });
        html += '</tr></thead><tbody>';
        inTable = true;
      } else {
        html += '<tr>';
        cells.forEach((c) => {
          let content = escapeHtml(c);
          const lower = c.toLowerCase();
          if (['candidate', 'proven', 'false_positive', 'patched', 'refuted'].includes(lower)) {
            content = `<span class="report-badge status-${lower}">${content}</span>`;
          }
          html += `<td>${content}</td>`;
        });
        html += '</tr>';
      }
    } else {
      if (inTable) {
        html += '</tbody></table>';
        inTable = false;
      }
      html += `<p class="report-p">${escapeHtml(line)}</p>`;
    }
  }

  if (inTable) {
    html += '</tbody></table>';
  }
  html += '</div>';
  return html;
}

function openReportModal() {
  els.reportModalOverlay.style.display = 'flex';
  els.reportModalContent.innerHTML = '<div class="report-p">Loading report data…</div>';
  fetch('/api/report')
    .then((r) => r.json())
    .then((d) => {
      if (d.error) {
        els.reportModalContent.innerHTML = `<div class="report-p" style="color:var(--red-text);">Error: ${escapeHtml(d.error)}</div>`;
      } else {
        els.reportModalContent.innerHTML = renderReportMarkdownToHtml(d.report);
      }
    })
    .catch((err) => {
      els.reportModalContent.innerHTML = `<div class="report-p" style="color:var(--red-text);">Network error: ${escapeHtml(err.message)}</div>`;
    });
}

function closeReportModal() {
  if (els.reportModalOverlay) els.reportModalOverlay.style.display = 'none';
}

/* =========================================================================
   FOLDER CHOOSER & BROWSER
   ========================================================================= */
let currentBrowsePath = '';
let parentBrowsePath = '';
let selectedBrowsePath = '';

function openFolderModal(targetPath) {
  els.folderModalOverlay.style.display = 'flex';
  loadFolderBrowser(targetPath || '/Users');
}

function closeFolderModal() {
  if (els.folderModalOverlay) els.folderModalOverlay.style.display = 'none';
}

function loadFolderBrowser(targetPath) {
  els.folderCurrentPath.textContent = 'Loading…';
  els.folderList.innerHTML = '<div class="empty"><p>Loading directories…</p></div>';

  fetch(`/api/browse?path=${encodeURIComponent(targetPath || '')}`)
    .then((r) => {
      if (!r.ok) throw new Error(`Server endpoint /api/browse returned HTTP ${r.status}. Please restart frapast to pick up the backend changes.`);
      return r.json();
    })
    .then((d) => {
      if (d.error) {
        els.folderCurrentPath.textContent = d.current_path || 'Error loading directory';
        els.folderList.innerHTML = `<div class="empty"><p>Error: ${escapeHtml(d.error)}</p></div>`;
        return;
      }

      currentBrowsePath = d.current_path || '';
      parentBrowsePath = d.parent_path || '';
      selectedBrowsePath = currentBrowsePath;

      els.folderCurrentPath.textContent = currentBrowsePath;
      els.folderSelectedLabel.textContent = `Selected: ${currentBrowsePath}`;

      // Quick locations chips
      if (d.quick_locations && d.quick_locations.length) {
        els.folderQuickLocations.innerHTML = d.quick_locations.map((loc) =>
          `<span class="folder-chip" data-path="${escapeHtml(loc.path)}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:4px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>${escapeHtml(loc.name)}</span>`
        ).join('');
      } else {
        els.folderQuickLocations.innerHTML = '';
      }

      // Subdirectories list
      if (d.subdirs && d.subdirs.length) {
        els.folderList.innerHTML = d.subdirs.map((dir) => `
              <div class="folder-item" data-path="${escapeHtml(dir.path)}">
                <div class="folder-item-left">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--primary);flex-shrink:0;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                  <span class="folder-item-name">${escapeHtml(dir.name)}</span>
                  ${dir.is_app ? '<span class="folder-app-badge">App</span>' : ''}
                </div>
                <button class="folder-open-btn" data-open-path="${escapeHtml(dir.path)}" title="Open subdirectories">Open &rsaquo;</button>
              </div>
            `).join('');
      } else {
        els.folderList.innerHTML = '<div class="empty"><p>No subdirectories here.</p></div>';
      }
    })
    .catch((err) => {
      els.folderCurrentPath.textContent = 'Error loading directory';
      els.folderList.innerHTML = `<div class="empty"><p>Error: ${escapeHtml(err.message)}</p></div>`;
    });
}

function confirmFolderSelection() {
  if (selectedBrowsePath) {
    els.scanPathInput.value = selectedBrowsePath;
    closeFolderModal();
    triggerScan();
  }
}

/* =========================================================================
   INIT
   =========================================================================*/
function cacheEls() {
  [
    'connStatus', 'connStatusLabel',
    'badgeTotal', 'badgeCritical', 'badgeHigh', 'badgeMedium', 'badgeLow',
    'filterInput', 'filterStatus', 'filterSev',
    'selectionBar', 'selectionCount', 'selectionClearBtn',
    'resultsSummary', 'findingsTbody', 'selectAllCheckbox',
    'pageFirstBtn', 'pagePrevBtn', 'pageNextBtn', 'pageLastBtn', 'pageInfo', 'pageSizeSelect',
    'quickBtns', 'countInput', 'countError', 'candidateRemaining', 'proveBtn',
    'progressWrap', 'progressBar', 'progressText', 'progressWarning',
    'statsCard', 'statProven', 'statRefuted', 'statSkipped', 'statTotal',
    'streamList', 'streamCount',
    'toastContainer', 'drawer', 'drawerBackdrop', 'drawerCloseBtn', 'drawerCloseBtn2',
    'exportCsvBtn', 'refreshBtn',
    // New elements
    'scanPathInput', 'scanBtn', 'scanStatus',
    'benchSettingsToggle', 'benchSettingsBody', 'benchChevron', 'benchStatusBadge',
    'benchUrlInput', 'benchPortInput', 'benchSiteInput', 'benchUserInput', 'benchPasswordInput',
    'benchSaveBtn',
    'benchDiag', 'diagUrl', 'diagReachBadge', 'diagSite', 'diagSiteBadge', 'diagUser', 'diagAuthBadge', 'diagIssues',
    'reportBtn', 'exportJsonBtn', 'exportSarifBtn',
    'reportModalOverlay', 'reportModalClose', 'reportModalContent',
    'browseBtn', 'folderModalOverlay', 'folderModalClose', 'folderModalCancel', 'folderModalSelectBtn',
    'folderQuickLocations', 'folderUpBtn', 'folderCurrentPath', 'folderList', 'folderSelectedLabel',
    'nativePickerBtn', 'nativeFolderInput',
  ].forEach((id) => { els[id] = $(id); });
}

function wireEvents() {
  els.filterInput.addEventListener('input', onFilterInput);
  els.filterStatus.addEventListener('change', onFilterStatusChange);
  els.filterSev.addEventListener('change', onFilterSevChange);

  els.selectionClearBtn.addEventListener('click', clearSelection);
  els.selectAllCheckbox.addEventListener('change', onSelectAllToggle);
  els.findingsTbody.addEventListener('click', onTableBodyClick);

  document.querySelectorAll('th.sortable').forEach((th) => th.addEventListener('click', onSortHeaderClick));

  els.pageFirstBtn.addEventListener('click', goToFirstPage);
  els.pagePrevBtn.addEventListener('click', () => goToPage(-1));
  els.pageNextBtn.addEventListener('click', () => goToPage(1));
  els.pageLastBtn.addEventListener('click', goToLastPage);
  els.pageSizeSelect.addEventListener('change', onPageSizeChange);

  els.quickBtns.addEventListener('click', (e) => {
    const btn = e.target.closest('.quick-btn');
    if (!btn || btn.disabled) return;
    const raw = btn.dataset.count;
    setCount(raw === 'all' ? 'all' : parseInt(raw, 10), btn);
  });
  els.countInput.addEventListener('input', () => {
    document.querySelectorAll('.quick-btn').forEach((b) => b.classList.remove('active'));
    clearCountError();
  });

  els.proveBtn.addEventListener('click', startProving);

  els.drawerCloseBtn.addEventListener('click', closeDrawer);
  els.drawerCloseBtn2.addEventListener('click', closeDrawer);
  els.drawerBackdrop.addEventListener('click', closeDrawer);

  els.exportCsvBtn.addEventListener('click', exportVisibleAsCsv);
  els.refreshBtn.addEventListener('click', () => { if (!state.run.active) loadFindings(); });

  // --- Scan bar & Folder Chooser ---
  els.scanBtn.addEventListener('click', triggerScan);
  els.scanPathInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') triggerScan(); });
  els.browseBtn.addEventListener('click', () => openFolderModal());

  els.folderModalClose.addEventListener('click', closeFolderModal);
  els.folderModalCancel.addEventListener('click', closeFolderModal);
  els.folderModalOverlay.addEventListener('click', (e) => { if (e.target === els.folderModalOverlay) closeFolderModal(); });
  els.folderModalSelectBtn.addEventListener('click', confirmFolderSelection);

  els.nativePickerBtn.addEventListener('click', () => {
    if (els.nativeFolderInput) els.nativeFolderInput.click();
  });

  els.nativeFolderInput.addEventListener('change', (e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const relPath = files[0].webkitRelativePath || '';
      const topFolder = relPath.split('/')[0];
      if (topFolder) {
        // Check if user's current directory or parent directory matches topFolder name
        if (currentBrowsePath && currentBrowsePath.endsWith(topFolder)) {
          loadFolderBrowser(currentBrowsePath);
        } else {
          showToast(`Selected "${topFolder}" via System Finder`, 'info');
        }
      }
    }
  });

  els.folderUpBtn.addEventListener('click', () => {
    if (parentBrowsePath) loadFolderBrowser(parentBrowsePath);
  });

  els.folderQuickLocations.addEventListener('click', (e) => {
    const chip = e.target.closest('.folder-chip');
    if (chip && chip.dataset.path) loadFolderBrowser(chip.dataset.path);
  });

  els.folderList.addEventListener('click', (e) => {
    const openBtn = e.target.closest('.folder-open-btn');
    if (openBtn && openBtn.dataset.openPath) {
      loadFolderBrowser(openBtn.dataset.openPath);
      return;
    }
    const item = e.target.closest('.folder-item');
    if (item && item.dataset.path) {
      els.folderList.querySelectorAll('.folder-item').forEach((i) => i.classList.remove('selected'));
      item.classList.add('selected');
      selectedBrowsePath = item.dataset.path;
      els.folderSelectedLabel.textContent = `Selected: ${selectedBrowsePath}`;
    }
  });

  els.folderList.addEventListener('dblclick', (e) => {
    const item = e.target.closest('.folder-item');
    if (item && item.dataset.path) loadFolderBrowser(item.dataset.path);
  });

  // --- Bench settings toggle ---
  els.benchSettingsToggle.addEventListener('click', toggleBenchSettings);

  // --- Bench save & test ---
  els.benchSaveBtn.addEventListener('click', saveBenchConfig);

  // Port shortcut: fill benchUrlInput when port changes
  els.benchPortInput.addEventListener('input', () => {
    const p = els.benchPortInput.value.trim();
    if (p) els.benchUrlInput.value = `http://localhost:${p}`;
  });

  // --- Report modal ---
  els.reportBtn.addEventListener('click', openReportModal);
  els.reportModalClose.addEventListener('click', closeReportModal);
  const reportModalClose2 = $('reportModalClose2');
  if (reportModalClose2) reportModalClose2.addEventListener('click', closeReportModal);
  const reportCopyBtn = $('reportCopyBtn');
  if (reportCopyBtn) {
    reportCopyBtn.addEventListener('click', () => {
      if (!rawReportMarkdown) return;
      navigator.clipboard.writeText(rawReportMarkdown).then(() => {
        showToast('Track-record markdown report copied to clipboard!', 'success');
      });
    });
  }
  els.reportModalOverlay.addEventListener('click', (e) => { if (e.target === els.reportModalOverlay) closeReportModal(); });

  // --- Export JSON / SARIF ---
  els.exportJsonBtn.addEventListener('click', () => downloadFile('/api/export/json', 'frapast-findings.json'));
  els.exportSarifBtn.addEventListener('click', () => downloadFile('/api/export/sarif', 'frapast-findings.sarif'));

  document.addEventListener('keydown', onGlobalKeydown);
}

function boot() {
  cacheEls();
  wireEvents();
  updateSortHeaders();
  loadFindings();
  loadStats();
  loadBenchConfig();
  // Open the persistent SSE stream so scan events arrive even outside proof runs
  openStream();
  // Auto-open directory chooser modal on launch so user can choose folder by themselves
  setTimeout(() => {
    openFolderModal();
  }, 300);
}

document.addEventListener('DOMContentLoaded', boot);