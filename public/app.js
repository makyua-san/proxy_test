const logBody = document.getElementById('logBody');
const logContainer = document.getElementById('logContainer');
const whitelistItems = document.getElementById('whitelistItems');
const addForm = document.getElementById('addForm');
const domainInput = document.getElementById('domainInput');
const autoScrollCheckbox = document.getElementById('autoScroll');
const clearLogBtn = document.getElementById('clearLog');
const connStatus = document.getElementById('connStatus');
const statTotal = document.getElementById('statTotal');
const statAllowed = document.getElementById('statAllowed');
const statBlocked = document.getElementById('statBlocked');
const statMonitored = document.getElementById('statMonitored');
const detailPanel = document.getElementById('detailPanel');
const detailContent = document.getElementById('detailContent');
const closeDetailBtn = document.getElementById('closeDetail');
const monitorListItems = document.getElementById('monitorListItems');
const monitorAddForm = document.getElementById('monitorAddForm');
const monitorDomainInput = document.getElementById('monitorDomainInput');
const filterMonitored = document.getElementById('filterMonitored');

let stats = { total: 0, allowed: 0, blocked: 0, monitored: 0 };
let selectedRow = null;

// --- Whitelist ---
async function loadWhitelist() {
  const res = await fetch('/api/whitelist');
  const data = await res.json();
  renderWhitelist(data.domains);
}

function renderWhitelist(domains) {
  whitelistItems.innerHTML = '';
  domains.forEach(domain => {
    const li = document.createElement('li');
    li.innerHTML = `<span>${escapeHtml(domain)}</span><button class="remove-btn" title="Remove">&times;</button>`;
    li.querySelector('.remove-btn').addEventListener('click', () => removeDomain(domain));
    whitelistItems.appendChild(li);
  });
}

addForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim();
  if (!domain) return;

  const res = await fetch('/api/whitelist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  const data = await res.json();
  if (data.ok) {
    renderWhitelist(data.domains);
    domainInput.value = '';
  }
});

async function removeDomain(domain) {
  const res = await fetch('/api/whitelist', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  const data = await res.json();
  if (data.ok) {
    renderWhitelist(data.domains);
  }
}

// --- Logs ---
function addLogRow(entry) {
  const tr = document.createElement('tr');
  tr.className = entry.status;
  if (entry.monitored) tr.classList.add('monitored');
  tr.dataset.logId = entry.id;
  const time = new Date(entry.timestamp).toLocaleTimeString();
  tr.innerHTML = `
    <td>${time}</td>
    <td class="monitor-badge">${entry.monitored ? '&#9679;' : ''}</td>
    <td>${escapeHtml(entry.method)}</td>
    <td>${escapeHtml(entry.host)}</td>
    <td>${entry.port}</td>
    <td>${entry.status === 'allowed' ? 'ALLOWED' : 'BLOCKED'}</td>
    <td>${entry.matchedRule ? escapeHtml(entry.matchedRule) : '-'}</td>
  `;

  tr.addEventListener('click', () => showDetail(entry.id, tr));
  logBody.appendChild(tr);

  stats.total++;
  if (entry.status === 'allowed') stats.allowed++;
  else stats.blocked++;
  if (entry.monitored) stats.monitored++;
  updateStats();

  if (filterMonitored.checked && !entry.monitored) {
    tr.style.display = 'none';
  }

  if (autoScrollCheckbox.checked) {
    logContainer.scrollTop = logContainer.scrollHeight;
  }
}

function updateStats() {
  statTotal.textContent = stats.total;
  statAllowed.textContent = stats.allowed;
  statBlocked.textContent = stats.blocked;
  statMonitored.textContent = stats.monitored;
}

async function loadInitialLogs() {
  const res = await fetch('/api/logs?limit=200');
  const data = await res.json();
  // data.logs is newest first, reverse to insert oldest first
  data.logs.reverse().forEach(entry => addLogRow(entry));
}

clearLogBtn.addEventListener('click', async () => {
  await fetch('/api/logs/clear', { method: 'POST' });
  logBody.innerHTML = '';
  stats = { total: 0, allowed: 0, blocked: 0, monitored: 0 };
  updateStats();
  closeDetail();
});

// --- Detail Panel ---
async function showDetail(logId, row) {
  // Highlight selected row
  if (selectedRow) selectedRow.classList.remove('selected');
  row.classList.add('selected');
  selectedRow = row;

  detailContent.innerHTML = '<div class="detail-note">Loading...</div>';
  detailPanel.classList.add('open');

  try {
    const res = await fetch(`/api/logs/detail?id=${logId}`);
    if (!res.ok) {
      detailContent.innerHTML = '<div class="detail-note">Detail not available</div>';
      return;
    }
    const detail = await res.json();
    renderDetail(detail);
  } catch {
    detailContent.innerHTML = '<div class="detail-note">Failed to load detail</div>';
  }
}

function renderDetail(detail) {
  let html = '';

  // CONNECT tunnel notice
  if (detail.type === 'connect') {
    html += `
      <div class="detail-section">
        <h3>Connection Info</h3>
        <dl class="detail-meta">
          <dt>Method</dt><dd>CONNECT</dd>
          <dt>Target</dt><dd>${escapeHtml(detail.request.url)}</dd>
        </dl>
        <div class="detail-note">${escapeHtml(detail.note)}</div>
      </div>`;

    if (detail.request.headers && Object.keys(detail.request.headers).length > 0) {
      html += `
        <div class="detail-section">
          <h3>Proxy Headers</h3>
          ${renderHeaders(detail.request.headers)}
        </div>`;
    }

    detailContent.innerHTML = html;
    return;
  }

  // HTTP request detail
  const req = detail.request;
  html += `
    <div class="detail-section">
      <h3>Request</h3>
      <dl class="detail-meta">
        <dt>Method</dt><dd>${escapeHtml(req.method)}</dd>
        <dt>URL</dt><dd>${escapeHtml(req.url)}</dd>
        <dt>HTTP</dt><dd>${escapeHtml(req.httpVersion || '')}</dd>
      </dl>
      ${renderHeaders(req.headers)}
      ${req.body ? renderBody('Request Body', req.body, req.bodyTruncated) : ''}
    </div>`;

  // Response
  const resp = detail.response;
  if (resp) {
    html += `
      <div class="detail-section">
        <h3>Response</h3>
        <dl class="detail-meta">
          <dt>Status</dt><dd>${resp.statusCode} ${escapeHtml(resp.statusMessage || '')}</dd>
        </dl>
        ${resp.headers ? renderHeaders(resp.headers) : ''}
        ${resp.body ? renderBody('Response Body', resp.body, resp.bodyTruncated) : ''}
      </div>`;
  }

  detailContent.innerHTML = html;
}

function renderHeaders(headers) {
  if (!headers || Object.keys(headers).length === 0) return '';
  let html = '<table class="detail-headers"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
  for (const [key, value] of Object.entries(headers)) {
    const val = Array.isArray(value) ? value.join(', ') : String(value);
    html += `<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(val)}</td></tr>`;
  }
  html += '</tbody></table>';
  return html;
}

function renderBody(label, body, truncated) {
  const cls = truncated ? 'detail-body-block truncated' : 'detail-body-block';
  // Try to format JSON
  let display = body;
  try {
    const parsed = JSON.parse(body);
    display = JSON.stringify(parsed, null, 2);
  } catch { /* not JSON, display as-is */ }
  return `<p style="color:#888;font-size:11px;margin:8px 0 4px">${escapeHtml(label)}</p><pre class="${cls}">${escapeHtml(display)}</pre>`;
}

function closeDetail() {
  detailPanel.classList.remove('open');
  if (selectedRow) {
    selectedRow.classList.remove('selected');
    selectedRow = null;
  }
}

closeDetailBtn.addEventListener('click', closeDetail);

// --- Monitor List ---
async function loadMonitorList() {
  const res = await fetch('/api/monitorlist');
  const data = await res.json();
  renderMonitorList(data.domains);
}

function renderMonitorList(domains) {
  monitorListItems.innerHTML = '';
  domains.forEach(domain => {
    const li = document.createElement('li');
    li.innerHTML = `<span>${escapeHtml(domain)}</span><button class="remove-btn" title="Remove">&times;</button>`;
    li.querySelector('.remove-btn').addEventListener('click', () => removeMonitorDomain(domain));
    monitorListItems.appendChild(li);
  });
}

monitorAddForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = monitorDomainInput.value.trim();
  if (!domain) return;

  const res = await fetch('/api/monitorlist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  const data = await res.json();
  if (data.ok) {
    renderMonitorList(data.domains);
    monitorDomainInput.value = '';
  }
});

async function removeMonitorDomain(domain) {
  const res = await fetch('/api/monitorlist', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  const data = await res.json();
  if (data.ok) {
    renderMonitorList(data.domains);
  }
}

// --- Monitor Filter ---
filterMonitored.addEventListener('change', () => {
  const rows = logBody.querySelectorAll('tr');
  rows.forEach(row => {
    if (filterMonitored.checked && !row.classList.contains('monitored')) {
      row.style.display = 'none';
    } else {
      row.style.display = '';
    }
  });
});

// --- WebSocket ---
function connectWebSocket() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${location.host}/ws`);

  ws.onopen = () => {
    connStatus.textContent = 'Connected';
    connStatus.className = 'connection-status connected';
  };

  ws.onmessage = (event) => {
    const entry = JSON.parse(event.data);
    addLogRow(entry);
  };

  ws.onclose = () => {
    connStatus.textContent = 'Disconnected';
    connStatus.className = 'connection-status disconnected';
    // Reconnect after 2 seconds
    setTimeout(connectWebSocket, 2000);
  };

  ws.onerror = () => {
    ws.close();
  };
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// --- Init ---
loadWhitelist();
loadMonitorList();
loadInitialLogs();
connectWebSocket();
