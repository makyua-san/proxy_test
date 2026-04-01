const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const crypto = require('crypto');

const LOG_PATH = path.join(__dirname, '..', 'data', 'logs.jsonl');
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
}

module.exports = { log, readLogs, clear, emitter };
