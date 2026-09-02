"""
Admin UI & Dashboard Web Application Template.
Renders a modern, responsive Single Page Application (SPA) for SOC analysis and quarantine management.
"""
from __future__ import annotations


def render_admin_dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Auth Gateway — Enterprise Security Operations Center</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-color: #0f172a;
      --card-bg: rgba(30, 41, 59, 0.7);
      --card-border: rgba(255, 255, 255, 0.1);
      --accent-blue: #38bdf8;
      --accent-purple: #818cf8;
      --accent-green: #34d399;
      --accent-red: #f87171;
      --accent-yellow: #fbbf24;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
    body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }

    header {
      background: rgba(15, 23, 42, 0.9);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky; top: 0; z-index: 100;
    }
    .brand { font-size: 1.25rem; font-weight: 700; background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

    nav { display: flex; gap: 1rem; }
    .nav-btn {
      background: transparent; border: none; color: var(--text-muted); padding: 0.5rem 1rem; font-weight: 500; cursor: pointer; border-radius: 6px; transition: all 0.2s;
    }
    .nav-btn:hover, .nav-btn.active { color: var(--text-main); background: rgba(255, 255, 255, 0.05); }
    .nav-btn.active { border-bottom: 2px solid var(--accent-blue); }

    main { padding: 2rem; flex: 1; max-width: 1400px; margin: 0 auto; width: 100%; }

    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.3s ease-in-out; }

    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

    /* Dashboard Metrics Cards */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .metric-card {
      background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; backdrop-filter: blur(8px);
    }
    .metric-title { font-size: 0.875rem; color: var(--text-muted); margin-bottom: 0.5rem; }
    .metric-val { font-size: 2rem; font-weight: 700; color: var(--text-main); }
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
    th { background: rgba(15, 23, 42, 0.5); color: var(--text-muted); font-weight: 600; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }

    .badge { padding: 0.25rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
    .badge-high { background: rgba(248, 113, 113, 0.2); color: var(--accent-red); }
    .badge-medium { background: rgba(251, 191, 36, 0.2); color: var(--accent-yellow); }
    .badge-low { background: rgba(52, 211, 153, 0.2); color: var(--accent-green); }

    /* Modal */
    .modal { display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); backdrop-filter: blur(8px); z-index: 1000; align-items: center; justify-content: center; }
    .modal.active { display: flex; }
    .modal-box { background: var(--bg-color); border: 1px solid var(--card-border); border-radius: 12px; width: 90%; max-width: 800px; max-height: 85vh; display: flex; flex-direction: column; overflow: hidden; }
    .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center; }
    .modal-body { padding: 1.5rem; overflow-y: auto; flex: 1; background: #ffffff; color: #1e293b; border-radius: 0 0 12px 12px; }
  </style>
</head>
<body>

  <header>
    <div class="brand">🛡️ Email Auth Gateway SOC</div>
    <nav>
      <button class="nav-btn active" onclick="switchTab('dashboard')">Dashboard</button>
      <button class="nav-btn" onclick="switchTab('quarantine')">Quarantine Queue</button>
      <button class="nav-btn" onclick="switchTab('audit')">Audit Logs</button>
      <button class="nav-btn" onclick="switchTab('alerts')">High-Risk Alerts</button>
      <button class="nav-btn" onclick="switchTab('policy')">Policy Config</button>
    </nav>
  </header>

  <main>
    <!-- 1. Dashboard Tab -->
    <div id="tab-dashboard" class="tab-content active">
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-title">Total Processed (24h)</div>
          <div class="metric-val" id="metric-total">1,248</div>
          <div class="metric-sub">+12% vs yesterday</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Pending Quarantine</div>
          <div class="metric-val" id="metric-pending" style="color: var(--accent-yellow)">14</div>
          <div class="metric-sub">Requires analyst review</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">False Positive Rate</div>
          <div class="metric-val" id="metric-fp">0.82%</div>
          <div class="metric-sub">Derived from release actions</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">High-Risk Threat Detections</div>
          <div class="metric-val" id="metric-alerts" style="color: var(--accent-red)">32</div>
          <div class="metric-sub">Phishing / BEC / Malware</div>
        </div>
      </div>
    </div>

    <!-- 2. Quarantine Queue Tab -->
    <div id="tab-quarantine" class="tab-content">
      <div class="controls-bar">
        <input type="text" id="quarantine-search" class="search-input" placeholder="Search by sender, subject, score..." oninput="filterQuarantine()">
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-success" onclick="bulkAction('release')">Release Selected</button>
          <button class="btn btn-danger" onclick="bulkAction('reject')">Reject Selected</button>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="select-all" onclick="toggleSelectAll(this)"></th>
              <th>Quarantine ID</th>
              <th>Sender</th>
              <th>Recipient(s)</th>
              <th>Risk Score</th>
              <th>Action</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="quarantine-table-body">
            <!-- Dynamically Populated -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- 3. Audit Logs Tab -->
    <div id="tab-audit" class="tab-content">
      <div class="controls-bar">
        <input type="text" class="search-input" placeholder="Search audit trail..." id="audit-search">
        <button class="btn btn-primary" onclick="searchAudit()">Search Audit Logs</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Timestamp</th><th>Actor</th><th>Event Type</th><th>Details</th></tr>
          </thead>
          <tbody id="audit-table-body">
            <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Enter query to search audit logs.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 4. High Risk Alerts Tab -->
    <div id="tab-alerts" class="tab-content">
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Timestamp</th><th>Sender</th><th>Subject</th><th>Score</th><th>Threat Reasons</th></tr>
          </thead>
          <tbody id="alerts-table-body">
            <!-- Dynamically Populated -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- 5. Policy Configurator Tab -->
    <div id="tab-policy" class="tab-content">
      <div class="table-container" style="padding: 2rem;">
        <h3 style="margin-bottom: 1rem;">Dynamic Policy & Threshold Configurator</h3>
        <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Adjust dynamic threat scoring thresholds without requiring system restarts.</p>
        <div style="display: grid; gap: 1rem; max-width: 400px;">
          <label>Warn Threshold Score: <input type="number" value="45" class="search-input" style="width: 100%; margin-top: 0.4rem;"></label>
          <label>Quarantine Threshold Score: <input type="number" value="75" class="search-input" style="width: 100%; margin-top: 0.4rem;"></label>
          <button class="btn btn-primary" style="margin-top: 1rem;">Save Policy Configuration</button>
        </div>
      </div>
    </div>
  </main>

  <!-- Email Preview Modal -->
  <div id="preview-modal" class="modal">
    <div class="modal-box">
      <div class="modal-header">
        <h3 id="modal-title">Sanitized Safe Email Preview</h3>
        <button class="btn btn-danger" onclick="closeModal()">Close</button>
      </div>
      <div id="modal-content" class="modal-body">
        Loading sanitized preview...
      </div>
    </div>
  </div>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-' + tabId).classList.add('active');
      event.target.classList.add('active');

      if (tabId === 'quarantine') loadQuarantineItems();
    }

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
            <td><input type="checkbox" class="item-checkbox" value="${item.quarantine_id}"></td>
            <td><code>${item.quarantine_id.substring(0, 8)}...</code></td>
            <td>${item.envelope_from}</td>
            <td>${(item.envelope_to || []).join(', ')}</td>
            <td><span class="badge ${badgeClass}">${item.total_score}</span></td>
            <td>${item.action}</td>
            <td>
              <button class="btn btn-primary" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="previewEmail('${item.quarantine_id}')">Preview</button>
              <button class="btn btn-success" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="singleAction('${item.quarantine_id}', 'release')">Release</button>
              <button class="btn btn-danger" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="singleAction('${item.quarantine_id}', 'reject')">Reject</button>
            </td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.error('Failed to load quarantine queue', err);
      }
    }

    async function previewEmail(id) {
      document.getElementById('preview-modal').classList.add('active');
      document.getElementById('modal-content').innerHTML = 'Loading safe preview...';
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
      await fetch(`/admin/quarantine/${id}/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ note: 'SOC UI action' }) });
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
  </script>
</body>
</html>"""
