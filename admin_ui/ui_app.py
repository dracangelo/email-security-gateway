"""
Admin UI & Dashboard Web Application Template.
Renders a modern, accessible (WCAG 2.1 AA), localized (i18n), and timezone-aware Single Page Application
for Security Operations Center (SOC) analysis and quarantine management.
"""
from __future__ import annotations

import json
from .i18n import get_all_translations


def render_admin_dashboard_html() -> str:
    translations_json = json.dumps(get_all_translations())

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Auth Gateway — Enterprise Security Operations Center</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-color: #0f172a;
      --card-bg: rgba(30, 41, 59, 0.75);
      --card-border: rgba(255, 255, 255, 0.12);
      --accent-blue: #38bdf8;
      --accent-purple: #818cf8;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-yellow: #f59e0b;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --focus-ring: #38bdf8;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
    body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }

    /* Accessibility Skip Link */
    .skip-link {
      position: absolute; top: -40px; left: 0; background: var(--accent-blue); color: #0f172a; padding: 8px 16px;
      font-weight: 700; z-index: 1000; text-decoration: none; border-radius: 0 0 6px 0; transition: top 0.2s;
    }
    .skip-link:focus { top: 0; outline: 3px solid #ffffff; }

    /* Focus Visible Styling for WCAG AA */
    :focus-visible {
      outline: 2px solid var(--focus-ring);
      outline-offset: 2px;
    }

    header {
      background: rgba(15, 23, 42, 0.95);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border);
      padding: 0.85rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky; top: 0; z-index: 100;
      flex-wrap: wrap; gap: 1rem;
    }
    .brand {
      font-size: 1.25rem; font-weight: 700;
      background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      display: flex; align-items: center; gap: 0.5rem;
    }

    nav { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .nav-btn {
      background: transparent; border: none; color: var(--text-muted); padding: 0.5rem 0.9rem;
      font-weight: 500; cursor: pointer; border-radius: 6px; transition: all 0.2s; font-size: 0.9rem;
    }
    .nav-btn:hover, .nav-btn[aria-selected="true"] { color: var(--text-main); background: rgba(255, 255, 255, 0.08); }
    .nav-btn[aria-selected="true"] { border-bottom: 2px solid var(--accent-blue); }

    .header-controls {
      display: flex; align-items: center; gap: 0.75rem;
    }
    .select-dropdown {
      background: rgba(30, 41, 59, 0.9);
      border: 1px solid var(--card-border);
      color: var(--text-main);
      padding: 0.45rem 0.75rem;
      border-radius: 6px;
      font-size: 0.85rem;
      outline: none;
      cursor: pointer;
    }

    main { padding: 2rem; flex: 1; max-width: 1400px; margin: 0 auto; width: 100%; }

    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.25s ease-in-out; }

    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

    /* Dashboard Metrics Cards */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .metric-card {
      background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; backdrop-filter: blur(8px);
    }
    .metric-title { font-size: 0.875rem; color: var(--text-muted); margin-bottom: 0.5rem; }
    .metric-val { font-size: 2.2rem; font-weight: 700; color: var(--text-main); }
    .metric-sub { font-size: 0.75rem; color: var(--accent-green); margin-top: 0.25rem; }

    /* Controls Bar */
    .controls-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; gap: 1rem; flex-wrap: wrap; }
    .search-input {
      background: rgba(15, 23, 42, 0.8); border: 1px solid var(--card-border); border-radius: 6px; color: var(--text-main); padding: 0.6rem 1rem; width: 320px; outline: none;
    }
    .btn {
      padding: 0.6rem 1.2rem; border-radius: 6px; border: none; font-weight: 600; cursor: pointer; transition: all 0.2s;
    }
    .btn-primary { background: var(--accent-blue); color: #0f172a; }
    .btn-primary:hover { opacity: 0.9; }
    .btn-danger { background: var(--accent-red); color: #fff; }
    .btn-success { background: var(--accent-green); color: #0f172a; }

    /* Table Styles */
    .table-container { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; overflow: hidden; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
    th, td { padding: 1rem; border-bottom: 1px solid var(--card-border); }
    th { background: rgba(15, 23, 42, 0.65); color: var(--text-muted); font-weight: 600; }
    tr:hover { background: rgba(255, 255, 255, 0.03); }

    .badge { padding: 0.25rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
    .badge-high { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.4); }

    /* Modal */
    .modal { display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.8); backdrop-filter: blur(8px); z-index: 1000; align-items: center; justify-content: center; }
    .modal.active { display: flex; }
    .modal-box { background: var(--bg-color); border: 1px solid var(--card-border); border-radius: 12px; width: 90%; max-width: 800px; max-height: 85vh; display: flex; flex-direction: column; overflow: hidden; }
    .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center; }
    .modal-body { padding: 1.5rem; overflow-y: auto; flex: 1; background: #ffffff; color: #1e293b; border-radius: 0 0 12px 12px; }
  </style>
</head>
<body>
  <a href="#main-content" class="skip-link">Skip to main content</a>

  <header role="banner">
    <div class="brand">
      <span aria-hidden="true">🛡️</span>
      <span data-i18n="brand">Email Auth Gateway SOC</span>
    </div>

    <nav role="tablist" aria-label="SOC Navigation Tabs">
      <button id="nav-dashboard" role="tab" aria-selected="true" aria-controls="tab-dashboard" class="nav-btn active" onclick="switchTab('dashboard')" data-i18n="tab_dashboard">Dashboard</button>
      <button id="nav-quarantine" role="tab" aria-selected="false" aria-controls="tab-quarantine" class="nav-btn" onclick="switchTab('quarantine')" data-i18n="tab_quarantine">Quarantine Queue</button>
      <button id="nav-audit" role="tab" aria-selected="false" aria-controls="tab-audit" class="nav-btn" onclick="switchTab('audit')" data-i18n="tab_audit">Audit Logs</button>
      <button id="nav-alerts" role="tab" aria-selected="false" aria-controls="tab-alerts" class="nav-btn" onclick="switchTab('alerts')" data-i18n="tab_alerts">High-Risk Alerts</button>
      <button id="nav-policy" role="tab" aria-selected="false" aria-controls="tab-policy" class="nav-btn" onclick="switchTab('policy')" data-i18n="tab_policy">Policy Config</button>
    </nav>

    <div class="header-controls">
      <!-- Language Selector -->
      <label for="lang-select" class="sr-only" style="display:none;" data-i18n="lang_selector_label">Language</label>
      <select id="lang-select" class="select-dropdown" aria-label="Select Interface Language" onchange="changeLanguage(this.value)">
        <option value="en">🌐 English (EN)</option>
        <option value="es">🌐 Español (ES)</option>
        <option value="de">🌐 Deutsch (DE)</option>
        <option value="fr">🌐 Français (FR)</option>
        <option value="ja">🌐 日本語 (JA)</option>
        <option value="zh">🌐 中文 (ZH)</option>
        <option value="pt">🌐 Português (PT)</option>
      </select>

      <!-- Timezone Selector -->
      <label for="tz-select" class="sr-only" style="display:none;" data-i18n="tz_selector_label">Timezone</label>
      <select id="tz-select" class="select-dropdown" aria-label="Select Display Timezone" onchange="changeTimezone(this.value)">
        <option value="UTC">🕒 UTC</option>
        <option value="America/New_York">🕒 US Eastern (NY)</option>
        <option value="America/Chicago">🕒 US Central</option>
        <option value="America/Los_Angeles">🕒 US Pacific (LA)</option>
        <option value="Europe/London">🕒 Europe/London</option>
        <option value="Europe/Berlin">🕒 Europe/Berlin</option>
        <option value="Asia/Tokyo">🕒 Asia/Tokyo (JST)</option>
        <option value="Asia/Shanghai">🕒 Asia/Shanghai (CST)</option>
        <option value="LOCAL">🕒 Local Browser</option>
      </select>
    </div>
  </header>

  <main id="main-content" role="main">
    <!-- 1. Dashboard Tab -->
    <div id="tab-dashboard" role="tabpanel" aria-labelledby="nav-dashboard" class="tab-content active">
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-title" data-i18n="metric_total_24h">Total Processed (24h)</div>
          <div class="metric-val" id="metric-total">1,248</div>
          <div class="metric-sub" data-i18n="metric_total_sub">+12% vs yesterday</div>
        </div>
        <div class="metric-card">
          <div class="metric-title" data-i18n="metric_pending">Pending Quarantine</div>
          <div class="metric-val" id="metric-pending" style="color: var(--accent-yellow)">14</div>
          <div class="metric-sub" data-i18n="metric_pending_sub">Requires analyst review</div>
        </div>
        <div class="metric-card">
          <div class="metric-title" data-i18n="metric_fp">False Positive Rate</div>
          <div class="metric-val" id="metric-fp">0.82%</div>
          <div class="metric-sub" data-i18n="metric_fp_sub">Derived from release actions</div>
        </div>
        <div class="metric-card">
          <div class="metric-title" data-i18n="metric_alerts">High-Risk Threat Detections</div>
          <div class="metric-val" id="metric-alerts" style="color: var(--accent-red)">32</div>
          <div class="metric-sub" data-i18n="metric_alerts_sub">Phishing / BEC / Malware</div>
        </div>
      </div>
    </div>

    <!-- 2. Quarantine Queue Tab -->
    <div id="tab-quarantine" role="tabpanel" aria-labelledby="nav-quarantine" class="tab-content">
      <div class="controls-bar">
        <input type="text" id="quarantine-search" class="search-input" data-i18n-placeholder="search_quarantine_placeholder" placeholder="Search by sender, subject, score..." oninput="filterQuarantine()">
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-success" onclick="bulkAction('release')" data-i18n="release_selected">Release Selected</button>
          <button class="btn btn-danger" onclick="bulkAction('reject')" data-i18n="reject_selected">Reject Selected</button>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="select-all" aria-label="Select all items" onclick="toggleSelectAll(this)"></th>
              <th data-i18n="th_id">Quarantine ID</th>
              <th data-i18n="th_sender">Sender</th>
              <th data-i18n="th_recipient">Recipient(s)</th>
              <th data-i18n="th_score">Risk Score</th>
              <th data-i18n="th_action">Action</th>
              <th data-i18n="th_actions">Actions</th>
            </tr>
          </thead>
          <tbody id="quarantine-table-body">
            <!-- Dynamically Populated -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- 3. Audit Logs Tab -->
    <div id="tab-audit" role="tabpanel" aria-labelledby="nav-audit" class="tab-content">
      <div class="controls-bar">
        <input type="text" class="search-input" data-i18n-placeholder="search_audit_placeholder" placeholder="Search audit trail..." id="audit-search">
        <button class="btn btn-primary" onclick="searchAudit()" data-i18n="search_audit_btn">Search Audit Logs</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th data-i18n="th_timestamp">Timestamp</th>
              <th data-i18n="th_actor">Actor</th>
              <th data-i18n="th_event_type">Event Type</th>
              <th data-i18n="th_details">Details</th>
            </tr>
          </thead>
          <tbody id="audit-table-body">
            <tr><td colspan="4" style="text-align: center; color: var(--text-muted);" data-i18n="audit_empty_hint">Enter query to search audit logs.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 4. High Risk Alerts Tab -->
    <div id="tab-alerts" role="tabpanel" aria-labelledby="nav-alerts" class="tab-content">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th data-i18n="th_timestamp">Timestamp</th>
              <th data-i18n="th_sender">Sender</th>
              <th data-i18n="th_subject">Subject</th>
              <th data-i18n="th_score">Score</th>
              <th data-i18n="th_threat_reasons">Threat Reasons</th>
            </tr>
          </thead>
          <tbody id="alerts-table-body">
            <!-- Dynamically Populated -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- 5. Policy Configurator Tab -->
    <div id="tab-policy" role="tabpanel" aria-labelledby="nav-policy" class="tab-content">
      <div class="table-container" style="padding: 2rem;">
        <h3 style="margin-bottom: 1rem;" data-i18n="policy_title">Dynamic Policy & Threshold Configurator</h3>
        <p style="color: var(--text-muted); margin-bottom: 1.5rem;" data-i18n="policy_desc">Adjust dynamic threat scoring thresholds without requiring system restarts.</p>
        <div style="display: grid; gap: 1rem; max-width: 400px;">
          <label><span data-i18n="policy_warn_label">Warn Threshold Score:</span> <input type="number" id="policy-warn-input" value="45" class="search-input" style="width: 100%; margin-top: 0.4rem;"></label>
          <label><span data-i18n="policy_quarantine_label">Quarantine Threshold Score:</span> <input type="number" id="policy-quar-input" value="75" class="search-input" style="width: 100%; margin-top: 0.4rem;"></label>
          <button class="btn btn-primary" style="margin-top: 1rem;" data-i18n="btn_save_policy">Save Policy Configuration</button>
        </div>
      </div>
    </div>
  </main>

  <!-- Email Preview Modal -->
  <div id="preview-modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-box">
      <div class="modal-header">
        <h3 id="modal-title" data-i18n="modal_preview_title">Sanitized Safe Email Preview</h3>
        <button class="btn btn-danger" onclick="closeModal()" data-i18n="btn_close">Close</button>
      </div>
      <div id="modal-content" class="modal-body" data-i18n="modal_loading">
        Loading sanitized preview...
      </div>
    </div>
  </div>

  <script>
    const TRANSLATIONS = __TRANSLATIONS_JSON__;
    let currentLang = localStorage.getItem('admin_ui_lang') || 'en';
    let currentTz = localStorage.getItem('admin_ui_tz') || 'UTC';

    function init() {
      if (TRANSLATIONS[currentLang]) {
        document.getElementById('lang-select').value = currentLang;
      }
      document.getElementById('tz-select').value = currentTz;
      applyLanguage(currentLang);
    }

    function changeLanguage(lang) {
      currentLang = lang;
      localStorage.setItem('admin_ui_lang', lang);
      applyLanguage(lang);
    }

    function changeTimezone(tz) {
      currentTz = tz;
      localStorage.setItem('admin_ui_tz', tz);
      if (document.getElementById('tab-quarantine').classList.contains('active')) {
        loadQuarantineItems();
      }
    }

    function t(key) {
      const bundle = TRANSLATIONS[currentLang] || TRANSLATIONS['en'];
      return bundle[key] || (TRANSLATIONS['en'][key] || key);
    }

    function applyLanguage(lang) {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = t(key);
      });
      document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        el.placeholder = t(key);
      });
      document.documentElement.lang = lang;
    }

    function formatTimestamp(epochSec) {
      if (!epochSec) return '-';
      const d = new Date(epochSec * 1000);
      const tzOption = currentTz === 'LOCAL' ? undefined : currentTz;
      try {
        return new Intl.DateTimeFormat(currentLang, {
          timeZone: tzOption,
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }).format(d);
      } catch (e) {
        return d.toISOString();
      }
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(t => {
        t.classList.remove('active');
      });
      document.querySelectorAll('.nav-btn').forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });

      const targetTab = document.getElementById('tab-' + tabId);
      const targetNav = document.getElementById('nav-' + tabId);

      if (targetTab) targetTab.classList.add('active');
      if (targetNav) {
        targetNav.classList.add('active');
        targetNav.setAttribute('aria-selected', 'true');
      }

      if (tabId === 'quarantine') loadQuarantineItems();
    }

    // Keyboard navigation across tabs (ArrowLeft, ArrowRight)
    const navBar = document.querySelector('nav[role="tablist"]');
    if (navBar) {
      navBar.addEventListener('keydown', (e) => {
        const tabs = Array.from(document.querySelectorAll('.nav-btn'));
        const activeIdx = tabs.findIndex(tab => tab.classList.contains('active'));
        if (e.key === 'ArrowRight') {
          const next = tabs[(activeIdx + 1) % tabs.length];
          next.click();
          next.focus();
        } else if (e.key === 'ArrowLeft') {
          const prev = tabs[(activeIdx - 1 + tabs.length) % tabs.length];
          prev.click();
          prev.focus();
        }
      });
    }

    // Modal Escape Key Listener
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeModal();
    });

    async function loadQuarantineItems() {
      try {
        const res = await fetch('/admin/quarantine');
        const data = await res.json();
        const tbody = document.getElementById('quarantine-table-body');
        tbody.innerHTML = '';

        (data.pending || []).forEach(item => {
          const tr = document.createElement('tr');
          const badgeClass = item.total_score >= 70 ? 'badge-high' : 'badge-medium';
          tr.innerHTML = `
            <td><input type="checkbox" class="item-checkbox" value="${item.quarantine_id}" aria-label="Select item ${item.quarantine_id}"></td>
            <td><code>${item.quarantine_id.substring(0, 8)}...</code></td>
            <td>${item.envelope_from}</td>
            <td>${(item.envelope_to || []).join(', ')}</td>
            <td><span class="badge ${badgeClass}">${item.total_score}</span></td>
            <td>${item.action}</td>
            <td>
              <button class="btn btn-primary" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="previewEmail('${item.quarantine_id}')">${t('btn_preview')}</button>
              <button class="btn btn-success" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="singleAction('${item.quarantine_id}', 'release')">${t('btn_release')}</button>
              <button class="btn btn-danger" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="singleAction('${item.quarantine_id}', 'reject')">${t('btn_reject')}</button>
            </td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.error('Failed to load quarantine queue', err);
      }
    }

    async function previewEmail(id) {
      const modal = document.getElementById('preview-modal');
      modal.classList.add('active');
      document.getElementById('modal-content').innerHTML = t('modal_loading');
      try {
        const res = await fetch(`/admin/ui/api/preview/${id}`);
        const data = await res.json();
        document.getElementById('modal-content').innerHTML = data.html || data.text || 'No preview available';
      } catch (err) {
        document.getElementById('modal-content').innerHTML = 'Error loading safe preview.';
      }
    }

    function closeModal() {
      document.getElementById('preview-modal').classList.remove('active');
    }

    function toggleSelectAll(master) {
      document.querySelectorAll('.item-checkbox').forEach(cb => cb.checked = master.checked);
    }

    async function singleAction(id, action) {
      await fetch(`/admin/quarantine/${id}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: 'SOC UI action' })
      });
      loadQuarantineItems();
    }

    async function bulkAction(action) {
      const selected = Array.from(document.querySelectorAll('.item-checkbox:checked')).map(cb => cb.value);
      if (selected.length === 0) return alert('Select items to perform bulk action.');
      await fetch('/admin/ui/api/bulk-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action, quarantine_ids: selected, note: 'Bulk SOC UI action' })
      });
      loadQuarantineItems();
    }

    function filterQuarantine() {
      const q = document.getElementById('quarantine-search').value.toLowerCase();
      document.querySelectorAll('#quarantine-table-body tr').forEach(tr => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    }

    document.addEventListener('DOMContentLoaded', init);
    init();
  </script>
</body>
</html>"""

    return html_template.replace("__TRANSLATIONS_JSON__", translations_json)
