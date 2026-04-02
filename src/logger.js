const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const LOG_PATH = path.join(DATA_DIR, 'logs.jsonl');
const DETAILS_DIR = path.join(DATA_DIR, 'details');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(DETAILS_DIR, { recursive: true });

const emitter = new EventEmitter();

function createEntry({ method, host, port, sourceIp, status, matchedRule }) {
  return {
    id: crypto.randomBytes(4).toString('hex'),
    timestamp: new Date().toISOString(),
    method,
    host,
    port: port || 0,
    sourceIp: sourceIp || '127.0.0.1',
    status,
    matchedRule: matchedRule || null
  };
}

function append(entry) {
  const line = JSON.stringify(entry) + '\n';
  fs.appendFileSync(LOG_PATH, line, 'utf8');
  emitter.emit('log', entry);
}

function log(params) {
  const entry = createEntry(params);
  append(entry);
  return entry;
}

function saveDetail(id, detail) {
  if (!/^[a-f0-9]+$/.test(id)) return;
  const filePath = path.join(DETAILS_DIR, `${id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(detail, null, 2), 'utf8');
}

function getDetail(id) {
  if (!/^[a-f0-9]+$/.test(id)) return null;
  const filePath = path.join(DETAILS_DIR, `${id}.json`);
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function readLogs(limit = 100, offset = 0) {
  try {
    const raw = fs.readFileSync(LOG_PATH, 'utf8');
    const lines = raw.trim().split('\n').filter(Boolean);
    const all = lines.map(l => JSON.parse(l));
    // newest first
    all.reverse();
    const total = all.length;
    const paged = all.slice(offset, offset + limit);
    return { logs: paged, total };
  } catch {
    return { logs: [], total: 0 };
  }
}

function clear() {
  fs.writeFileSync(LOG_PATH, '', 'utf8');
  // Clear details directory
  try {
    const files = fs.readdirSync(DETAILS_DIR);
    for (const file of files) {
      fs.unlinkSync(path.join(DETAILS_DIR, file));
    }
  } catch { /* ignore */ }
}

module.exports = { log, saveDetail, getDetail, readLogs, clear, emitter };
