const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const whitelist = require('./whitelist');
const monitorlist = require('./monitorlist');
const logger = require('./logger');
const certs = require('./certs');

const BYPASS_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

const REQ_BODY_LIMIT = 10 * 1024;   // 10KB
const RES_BODY_LIMIT = 50 * 1024;   // 50KB

const TEXT_MIME_PATTERNS = [
  /^text\//,
  /^application\/json/,
  /^application\/xml/,
  /^application\/javascript/,
  /^application\/x-www-form-urlencoded/,
  /^application\/xhtml\+xml/,
  /^application\/svg\+xml/,
];

function isTextMime(contentType) {
  if (!contentType) return false;
  const mime = contentType.split(';')[0].trim().toLowerCase();
  return TEXT_MIME_PATTERNS.some(p => p.test(mime));
}

function isLocalhost(hostname) {
  return BYPASS_HOSTS.has(hostname);
}

function collectBody(stream, limit, callback) {
  const chunks = [];
  let size = 0;
  let truncated = false;

  stream.on('data', (chunk) => {
    if (truncated) return;
    size += chunk.length;
    if (size > limit) {
      truncated = true;
      chunks.push(chunk.slice(0, limit - (size - chunk.length)));
    } else {
      chunks.push(chunk);
    }
  });

  stream.on('end', () => {
    callback(Buffer.concat(chunks).toString('utf8'), truncated, size);
  });

  stream.on('error', () => {
    callback('', false, 0);
  });
}

// --- MITM HTTP server for decrypting monitored HTTPS traffic ---
const mitmHttpServer = http.createServer((clientReq, clientRes) => {
  const meta = clientReq.socket._mitmMeta;
  if (!meta) {
    clientRes.writeHead(500);
    clientRes.end('Internal error');
    return;
  }

  const { host, port, sourceIp, matchedRule, monitoredRule } = meta;
  const fullUrl = `https://${host}${clientReq.url}`;

  collectBody(clientReq, REQ_BODY_LIMIT, (reqBody, reqTruncated, reqTotalSize) => {
    const entry = logger.log({
      method: clientReq.method,
      host,
      port,
      sourceIp,
      status: 'allowed',
      matchedRule,
      monitored: true,
      monitoredRule
    });

    const detail = {
      id: entry.id,
      type: 'https-monitored',
      request: {
        method: clientReq.method,
        url: fullUrl,
        httpVersion: clientReq.httpVersion,
        headers: clientReq.headers,
        body: reqBody || null,
        bodyTruncated: reqTruncated,
        bodyTotalSize: reqTotalSize
      },
      response: null
    };

    const fwdHeaders = { ...clientReq.headers };
    delete fwdHeaders['proxy-connection'];
    delete fwdHeaders['accept-encoding'];

    const proxyReq = https.request({
      hostname: host,
      port,
      path: clientReq.url,
      method: clientReq.method,
      headers: fwdHeaders
    }, (proxyRes) => {
      const resContentType = proxyRes.headers['content-type'] || '';
      const captureBody = isTextMime(resContentType);

      if (captureBody) {
        collectBody(proxyRes, RES_BODY_LIMIT, (resBody, resTruncated, resTotalSize) => {
          detail.response = {
            statusCode: proxyRes.statusCode,
            statusMessage: proxyRes.statusMessage,
            headers: proxyRes.headers,
            body: resBody,
            bodyTruncated: resTruncated,
            bodyTotalSize: resTotalSize
          };
          logger.saveDetail(entry.id, detail);

          clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
          clientRes.end(resBody);
        });
      } else {
        const contentLength = parseInt(proxyRes.headers['content-length'], 10) || 0;
        detail.response = {
          statusCode: proxyRes.statusCode,
          statusMessage: proxyRes.statusMessage,
          headers: proxyRes.headers,
          body: `(binary content, ${contentLength} bytes)`,
          bodyTruncated: false,
          bodyTotalSize: contentLength
        };
        logger.saveDetail(entry.id, detail);

        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(clientRes, { end: true });
      }
    });

    proxyReq.on('error', (err) => {
      detail.response = { statusCode: 502, statusMessage: err.message, headers: {}, body: null };
      logger.saveDetail(entry.id, detail);
      clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
      clientRes.end(`Proxy error: ${err.message}`);
    });

    if (reqBody) proxyReq.end(reqBody);
    else proxyReq.end();
  });
});
mitmHttpServer.timeout = 0;

function handleMitm(clientSocket, head, host, port, sourceIp, matchedRule, monitoredRule) {
  const hostCert = certs.getHostCert(host);

  if (head && head.length > 0) {
    clientSocket.unshift(head);
  }

  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: hostCert.key,
    cert: hostCert.cert,
    ALPNProtocols: ['http/1.1']
  });

  tlsSocket.on('error', () => {
    tlsSocket.destroy();
  });

  tlsSocket._mitmMeta = { host, port, sourceIp, matchedRule, monitoredRule };
  mitmHttpServer.emit('connection', tlsSocket);
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
    const monitoredRule = monitorlist.isMonitored(hostname);
    const entry = logger.log({
      method: clientReq.method,
      host: hostname,
      port,
      sourceIp,
      status: matchedRule ? 'allowed' : 'blocked',
      matchedRule,
      monitored: !!monitoredRule,
      monitoredRule
    });

    // Collect request body for detail capture
    collectBody(clientReq, REQ_BODY_LIMIT, (reqBody, reqTruncated, reqTotalSize) => {
      const detail = {
        id: entry.id,
        type: 'http',
        request: {
          method: clientReq.method,
          url: clientReq.url,
          httpVersion: clientReq.httpVersion,
          headers: clientReq.headers,
          body: reqBody || null,
          bodyTruncated: reqTruncated,
          bodyTotalSize: reqTotalSize
        },
        response: null
      };

      if (!matchedRule) {
        // Blocked - save detail with request info only
        detail.response = { statusCode: 403, statusMessage: 'Blocked by Proxy', headers: {}, body: null };
        logger.saveDetail(entry.id, detail);

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
        // Capture response headers
        const resContentType = proxyRes.headers['content-type'] || '';
        const captureBody = isTextMime(resContentType);

        if (captureBody) {
          // Collect response body, then pipe to client
          collectBody(proxyRes, RES_BODY_LIMIT, (resBody, resTruncated, resTotalSize) => {
            detail.response = {
              statusCode: proxyRes.statusCode,
              statusMessage: proxyRes.statusMessage,
              headers: proxyRes.headers,
              body: resBody,
              bodyTruncated: resTruncated,
              bodyTotalSize: resTotalSize
            };
            logger.saveDetail(entry.id, detail);

            // Send response to client
            clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
            clientRes.end(resBody);
          });
        } else {
          // Binary/non-text: pipe directly, don't capture body
          const contentLength = parseInt(proxyRes.headers['content-length'], 10) || 0;
          detail.response = {
            statusCode: proxyRes.statusCode,
            statusMessage: proxyRes.statusMessage,
            headers: proxyRes.headers,
            body: `(binary content, ${contentLength} bytes)`,
            bodyTruncated: false,
            bodyTotalSize: contentLength
          };
          logger.saveDetail(entry.id, detail);

          clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(clientRes, { end: true });
        }
      });

      proxyReq.on('error', (err) => {
        detail.response = { statusCode: 502, statusMessage: err.message, headers: {}, body: null };
        logger.saveDetail(entry.id, detail);
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end(`Proxy error: ${err.message}`);
      });

      // Re-send the collected request body to upstream
      if (reqBody) {
        proxyReq.end(reqBody);
      } else {
        proxyReq.end();
      }
    });
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
    const monitoredRule = monitorlist.isMonitored(host);
    const entry = logger.log({
      method: 'CONNECT',
      host,
      port,
      sourceIp,
      status: matchedRule ? 'allowed' : 'blocked',
      matchedRule,
      monitored: !!monitoredRule,
      monitoredRule
    });

    // Save CONNECT detail
    logger.saveDetail(entry.id, {
      id: entry.id,
      type: 'connect',
      request: {
        method: 'CONNECT',
        url: req.url,
        headers: req.headers || {}
      },
      response: null,
      note: monitoredRule
        ? 'HTTPS tunnel with MITM active - individual requests are logged separately'
        : 'HTTPS tunnel - encrypted content not visible'
    });

    if (!matchedRule) {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.end();
      return;
    }

    // MITM for monitored domains - decrypt and log individual requests
    if (monitoredRule) {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      handleMitm(clientSocket, head, host, port, sourceIp, matchedRule, monitoredRule);
      return;
    }

    // Establish TCP tunnel to upstream (non-monitored)
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
