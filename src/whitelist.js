const fs = require('fs');
const path = require('path');

const DATA_PATH = path.join(__dirname, '..', 'data', 'whitelist.json');

let domains = [];

function load() {
  try {
    const raw = fs.readFileSync(DATA_PATH, 'utf8');
    const data = JSON.parse(raw);
    domains = data.domains || [];
  } catch {
    domains = [];
    save();
  }
}

function save() {
  const data = { domains, updatedAt: new Date().toISOString() };
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function matchDomain(hostname, pattern) {
  if (pattern === hostname) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // ".example.com"
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }
  return false;
}

function isWhitelisted(hostname) {
  for (const pattern of domains) {
    if (matchDomain(hostname, pattern)) return pattern;
  }
  return null;
}

function add(domain) {
  domain = domain.toLowerCase().trim();
  if (!domain || domains.includes(domain)) return domains;
  domains.push(domain);
  save();
  return domains;
}

function remove(domain) {
  domain = domain.toLowerCase().trim();
  domains = domains.filter(d => d !== domain);
  save();
  return domains;
}

function list() {
  return [...domains];
}

load();

module.exports = { isWhitelisted, add, remove, list, load };
