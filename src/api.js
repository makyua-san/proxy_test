const fs = require('fs');
const path = require('path');
const whitelist = require('./whitelist');
const logger = require('./logger');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function handleRequest(req, res) {
  const parsed = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsed.pathname;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // API routes
  if (pathname === '/api/logs' && req.method === 'GET') {
    const limit = parseInt(parsed.searchParams.get('limit'), 10) || 100;
    const offset = parseInt(parsed.searchParams.get('offset'), 10) || 0;
    const result = logger.readLogs(limit, offset);
    jsonResponse(res, 200, result);
    return;
  }

  if (pathname === '/api/logs/detail' && req.method === 'GET') {
    const id = parsed.searchParams.get('id');
    if (!id) {
      jsonResponse(res, 400, { error: 'id is required' });
      return;
    }
    const detail = logger.getDetail(id);
    if (!detail) {
      jsonResponse(res, 404, { error: 'Detail not found' });
      return;
    }
    jsonResponse(res, 200, detail);
    return;
  }

  if (pathname === '/api/logs/clear' && req.method === 'POST') {
    logger.clear();
    jsonResponse(res, 200, { ok: true });
    return;
  }

  if (pathname === '/api/whitelist' && req.method === 'GET') {
    jsonResponse(res, 200, { domains: whitelist.list() });
    return;
  }

  if (pathname === '/api/whitelist' && req.method === 'POST') {
    readBody(req, (body) => {
      try {
        const { domain } = JSON.parse(body);
        if (!domain) {
          jsonResponse(res, 400, { error: 'domain is required' });
          return;
        }
        const domains = whitelist.add(domain);
        jsonResponse(res, 200, { ok: true, domains });
      } catch {
        jsonResponse(res, 400, { error: 'Invalid JSON' });
      }
    });
    return;
  }

  if (pathname === '/api/whitelist' && req.method === 'DELETE') {
    readBody(req, (body) => {
      try {
        const { domain } = JSON.parse(body);
        if (!domain) {
          jsonResponse(res, 400, { error: 'domain is required' });
          return;
        }
        const domains = whitelist.remove(domain);
        jsonResponse(res, 200, { ok: true, domains });
      } catch {
        jsonResponse(res, 400, { error: 'Invalid JSON' });
      }
    });
    return;
  }

  // Static file serving
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(PUBLIC_DIR, filePath);

  // Prevent directory traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

function jsonResponse(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readBody(req, callback) {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => callback(body));
}

module.exports = { handleRequest };
