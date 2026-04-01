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

let stats = { total: 0, allowed: 0, blocked: 0 };

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
  const time = new Date(entry.timestamp).toLocaleTimeString();
  tr.innerHTML = `
    <td>${time}</td>
    <td>${escapeHtml(entry.method)}</td>
    <td>${escapeHtml(entry.host)}</td>
    <td>${entry.port}</td>
    <td>${entry.status === 'allowed' ? 'ALLOWED' : 'BLOCKED'}</td>
    <td>${entry.matchedRule ? escapeHtml(entry.matchedRule) : '-'}</td>
  `;
  logBody.appendChild(tr);

  stats.total++;
  if (entry.status === 'allowed') stats.allowed++;
  else stats.blocked++;
  updateStats();

  if (autoScrollCheckbox.checked) {
    logContainer.scrollTop = logContainer.scrollHeight;
  }
}

function updateStats() {
  statTotal.textContent = stats.total;
  statAllowed.textContent = stats.allowed;
  statBlocked.textContent = stats.blocked;
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
  stats = { total: 0, allowed: 0, blocked: 0 };
  updateStats();
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
loadInitialLogs();
connectWebSocket();
