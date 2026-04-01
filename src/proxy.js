const http = require('http');
const net = require('net');
const whitelist = require('./whitelist');
const logger = require('./logger');

const BYPASS_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

function isLocalhost(hostname) {
  return BYPASS_HOSTS.has(hostname);
}

function createProxyServer() {
  const server = http.createServer();

  // HTTP forward proxy (plain HTTP requests)
  server.on('request', (clientReq, clientRes) => {
    let parsed;
    try {
      parsed = new URL(clientReq.url);
    } catch {
      clientRes.writeHead(400, { 'Content-Type': 'text/plain' });
      clientRes.end('Bad Request');
      return;
    }

    const hostname = (parsed.hostname || '').toLowerCase();
    const port = parseInt(parsed.port, 10) || 80;
    const sourceIp = clientReq.socket.remoteAddress || '127.0.0.1';

    // Bypass localhost traffic (UI server etc.)
    if (isLocalhost(hostname)) {
      const options = {
        hostname,
        port,
        path: parsed.pathname + parsed.search,
        method: clientReq.method,
        headers: clientReq.headers
      };
      const proxyReq = http.request(options, (proxyRes) => {
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(clientRes, { end: true });
      });
      proxyReq.on('error', (err) => {
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end(`Proxy error: ${err.message}`);
      });
      clientReq.pipe(proxyReq, { end: true });
      return;
    }

    const matchedRule = whitelist.isWhitelisted(hostname);

    logger.log({
      method: clientReq.method,
      host: hostname,
      port,
      sourceIp,
      status: matchedRule ? 'allowed' : 'blocked',
      matchedRule
    });

    if (!matchedRule) {
      clientRes.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
      clientRes.end(`<!DOCTYPE html><html><body>
        <h1>403 Blocked by Proxy</h1>
        <p>Domain <strong>${escapeHtml(hostname)}</strong> is not in the whitelist.</p>
      </body></html>`);
      return;
    }

    // Forward the request to the upstream server
    const options = {
      hostname: parsed.hostname,
      port,
      path: parsed.pathname + parsed.search,
      method: clientReq.method,
      headers: clientReq.headers
    };

    const proxyReq = http.request(options, (proxyRes) => {
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes, { end: true });
    });

    proxyReq.on('error', (err) => {
      clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
      clientRes.end(`Proxy error: ${err.message}`);
    });

    clientReq.pipe(proxyReq, { end: true });
  });

  // HTTPS CONNECT tunnel
  server.on('connect', (req, clientSocket, head) => {
    const [hostname, portStr] = req.url.split(':');
    const host = hostname.toLowerCase();
    const port = parseInt(portStr, 10) || 443;
    const sourceIp = clientSocket.remoteAddress || '127.0.0.1';

    // Bypass localhost traffic
    if (isLocalhost(host)) {
      const serverSocket = net.connect(port, host, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.write(head);
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
      });
      serverSocket.on('error', () => {
        clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        clientSocket.end();
      });
      clientSocket.on('error', () => serverSocket.destroy());
      return;
    }

    const matchedRule = whitelist.isWhitelisted(host);

    logger.log({
      method: 'CONNECT',
      host,
      port,
      sourceIp,
      status: matchedRule ? 'allowed' : 'blocked',
      matchedRule
    });

    if (!matchedRule) {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.end();
      return;
    }

    // Establish TCP tunnel to upstream
    const serverSocket = net.connect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', () => {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      clientSocket.end();
    });

    clientSocket.on('error', () => {
      serverSocket.destroy();
    });
  });

  return server;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

module.exports = { createProxyServer };
