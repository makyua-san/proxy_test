const http = require('http');
const { createProxyServer } = require('./src/proxy');
const { handleRequest } = require('./src/api');
const { createWebSocketServer } = require('./src/websocket');

const PROXY_PORT = parseInt(process.env.PROXY_PORT, 10) || 8080;
const UI_PORT = parseInt(process.env.UI_PORT, 10) || 3000;

// Start proxy server
const proxyServer = createProxyServer();
proxyServer.listen(PROXY_PORT, () => {
  console.log(`[Proxy] Listening on port ${PROXY_PORT}`);
  console.log(`[Proxy] Configure browser proxy to http://localhost:${PROXY_PORT}`);
});

// Start web UI server
const uiServer = http.createServer(handleRequest);
createWebSocketServer(uiServer);
uiServer.listen(UI_PORT, () => {
  console.log(`[UI] Monitoring dashboard at http://localhost:${UI_PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  proxyServer.close();
  uiServer.close();
  process.exit(0);
});
