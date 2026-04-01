const { WebSocketServer, WebSocket } = require('ws');
const logger = require('./logger');

function createWebSocketServer(httpServer) {
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', (req, socket, head) => {
    if (req.url === '/ws') {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    } else {
      socket.destroy();
    }
  });

  // Broadcast new log entries to all connected clients
  logger.emitter.on('log', (entry) => {
    const msg = JSON.stringify(entry);
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(msg);
      }
    }
  });

  return wss;
}

module.exports = { createWebSocketServer };
