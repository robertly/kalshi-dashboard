const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const url = require("url");
const tls = require("tls");

const PORT = process.env.PORT || 3456;

// ═══════════════════════════════════════════════
//  MODE DETECTION
//  ENV vars set → auto-connect, no login form
//  No env vars  → login form (local mode)
//  KALSHI_PASSWORD=x → require password to unlock write access
//  KALSHI_READ_ONLY=1 → permanently read-only
// ═══════════════════════════════════════════════
let ENV_KEY_ID = process.env.KALSHI_KEY_ID || "";
let ENV_PRIVATE_KEY = process.env.KALSHI_PRIVATE_KEY || "";
const ENV_DEMO = process.env.KALSHI_DEMO === "1" || process.env.KALSHI_DEMO === "true";
const HARD_READ_ONLY = process.env.KALSHI_READ_ONLY === "1" || process.env.KALSHI_READ_ONLY === "true";
const PASSWORD = process.env.KALSHI_PASSWORD || "";

// Support file path for private key
if (ENV_PRIVATE_KEY && !ENV_PRIVATE_KEY.includes("-----BEGIN") && fs.existsSync(ENV_PRIVATE_KEY)) {
  ENV_PRIVATE_KEY = fs.readFileSync(ENV_PRIVATE_KEY, "utf8");
}

// Fix escaped newlines from env vars (Railway, Heroku, etc.)
ENV_PRIVATE_KEY = ENV_PRIVATE_KEY.replace(/\\n/g, "\n");

// Some platforms double-escape
ENV_PRIVATE_KEY = ENV_PRIVATE_KEY.replace(/\\\\n/g, "\n");

// Remove carriage returns
ENV_PRIVATE_KEY = ENV_PRIVATE_KEY.replace(/\r/g, "");

// Trim whitespace
ENV_PRIVATE_KEY = ENV_PRIVATE_KEY.trim();

// If it's base64-encoded PEM (some platforms), try decoding
if (!ENV_PRIVATE_KEY.includes("-----BEGIN") && ENV_PRIVATE_KEY.length > 100) {
  try {
    const decoded = Buffer.from(ENV_PRIVATE_KEY, "base64").toString("utf8");
    if (decoded.includes("-----BEGIN")) ENV_PRIVATE_KEY = decoded;
  } catch(e) {}
}

// Reconstruct PEM if newlines got fully stripped (all on one line)
if (ENV_PRIVATE_KEY.includes("-----BEGIN") && ENV_PRIVATE_KEY.indexOf("\n") === -1) {
  // It's all on one line — split the base64 body into 64-char lines
  const match = ENV_PRIVATE_KEY.match(/(-----BEGIN [^-]+-----)(.*)(-----END [^-]+-----)/);
  if (match) {
    const body = match[2].replace(/\s/g, "");
    const lines = body.match(/.{1,64}/g) || [];
    ENV_PRIVATE_KEY = match[1] + "\n" + lines.join("\n") + "\n" + match[3];
  }
}

const ENV_MODE = !!(ENV_KEY_ID && ENV_PRIVATE_KEY && ENV_PRIVATE_KEY.includes("-----BEGIN"));

if (ENV_MODE) {
  // Debug: show key format info (no sensitive data)
  const firstLine = ENV_PRIVATE_KEY.split("\n")[0];
  const lineCount = ENV_PRIVATE_KEY.split("\n").length;
  console.log(`  Key format: ${firstLine}`);
  console.log(`  Key lines: ${lineCount}`);
  console.log(`  Key length: ${ENV_PRIVATE_KEY.length} chars`);

  try {
    const s = crypto.createSign("RSA-SHA256"); s.update("test"); s.end();
    s.sign({ key: ENV_PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, "base64");
    console.log("  Key validation: ✓ OK");
  } catch (e) {
    console.error("  ✗ KALSHI_PRIVATE_KEY invalid:", e.message);
    console.error("  First 80 chars:", ENV_PRIVATE_KEY.substring(0, 80));
    console.error("  Last 80 chars:", ENV_PRIVATE_KEY.substring(ENV_PRIVATE_KEY.length - 80));
    process.exit(1);
  }
}

// ─── Session store ───
const sessions = {};
const authedWriteTokens = new Set(); // password-authenticated write tokens
let envSessionId = null;

if (ENV_MODE) {
  envSessionId = "env-" + crypto.randomBytes(8).toString("hex");
  sessions[envSessionId] = {
    apiKeyId: ENV_KEY_ID, privateKeyPem: ENV_PRIVATE_KEY,
    useDemoEnv: ENV_DEMO, createdAt: Date.now(),
  };
}

// ─── Helpers ───
const MIME = {
  ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
  ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
};

function httpsRequest(options, postData) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error("timeout")); });
    if (postData) req.write(postData);
    req.end();
  });
}

function signRequest(privateKeyPem, timestamp, method, pathStr) {
  const msg = timestamp + method.toUpperCase() + pathStr;
  const s = crypto.createSign("RSA-SHA256"); s.update(msg); s.end();
  return s.sign({ key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, "base64");
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 10e6) reject(new Error("Too large")); });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function sendJson(res, code, data) {
  const b = JSON.stringify(data);
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(b) });
  res.end(b);
}

function serveStatic(res, filePath) {
  const pub = path.join(__dirname, "..", "public");
  let resolved = path.join(pub, filePath);
  if (!resolved.startsWith(pub)) { res.writeHead(403); res.end("Forbidden"); return; }
  if (!fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) resolved = path.join(pub, "index.html");
  const mime = MIME[path.extname(resolved)] || "application/octet-stream";
  fs.readFile(resolved, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, { "Content-Type": mime }); res.end(data);
  });
}

function cleanSessions() {
  const now = Date.now();
  for (const [id, s] of Object.entries(sessions)) {
    if (id !== envSessionId && now - s.createdAt > 7200000) delete sessions[id];
  }
}

function canWrite(req) {
  if (HARD_READ_ONLY) return false;
  if (!PASSWORD) return true; // no password set = full access
  const writeToken = req.headers["x-write-token"];
  return writeToken && authedWriteTokens.has(writeToken);
}

// ═══════════════════════════════════════════════
//  HTTP SERVER
// ═══════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method = req.method.toUpperCase();

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Session-Id, X-Write-Token");
  if (method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  try {
    // ═══ GET /api/config — tells the frontend what mode we're in ═══
    if (pathname === "/api/config" && method === "GET") {
      return sendJson(res, 200, {
        envMode: ENV_MODE,
        envSessionId: ENV_MODE ? envSessionId : null,
        envDemo: ENV_DEMO,
        readOnly: HARD_READ_ONLY,
        passwordRequired: !!PASSWORD && !HARD_READ_ONLY,
      });
    }

    // ═══ POST /api/auth-write — authenticate for write access ═══
    if (pathname === "/api/auth-write" && method === "POST") {
      if (HARD_READ_ONLY) return sendJson(res, 403, { error: "Read-only mode" });
      if (!PASSWORD) return sendJson(res, 400, { error: "No password configured" });
      const raw = await readBody(req);
      const { password } = JSON.parse(raw);
      if (password !== PASSWORD) return sendJson(res, 401, { error: "Wrong password" });
      const token = crypto.randomBytes(24).toString("hex");
      authedWriteTokens.add(token);
      // Expire after 8 hours
      setTimeout(() => authedWriteTokens.delete(token), 8 * 3600 * 1000);
      return sendJson(res, 200, { writeToken: token });
    }

    // ═══ POST /api/connect (LOCAL mode only) ═══
    if (pathname === "/api/connect" && method === "POST") {
      if (ENV_MODE) return sendJson(res, 400, { error: "Server is in env mode, connect not needed" });
      const raw = await readBody(req);
      const { apiKeyId, privateKeyPem, useDemoEnv } = JSON.parse(raw);
      if (!apiKeyId || !privateKeyPem) return sendJson(res, 400, { error: "Missing credentials" });

      try {
        const s = crypto.createSign("RSA-SHA256"); s.update("test"); s.end();
        s.sign({ key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, "base64");
      } catch (e) { return sendJson(res, 400, { error: "Invalid key: " + e.message }); }

      const host = useDemoEnv ? "demo-api.kalshi.co" : "api.elections.kalshi.com";
      const apiPath = "/trade-api/v2/portfolio/balance";
      const ts = Date.now().toString();
      const sig = signRequest(privateKeyPem, ts, "GET", apiPath);
      const result = await httpsRequest({
        hostname: host, port: 443, path: apiPath, method: "GET",
        headers: { "KALSHI-ACCESS-KEY": apiKeyId, "KALSHI-ACCESS-SIGNATURE": sig, "KALSHI-ACCESS-TIMESTAMP": ts },
      });
      console.log("[connect]", host, "status:", result.status);
      if (result.status !== 200) return sendJson(res, result.status, { error: "Kalshi " + result.status, details: result.body });

      const sessionId = crypto.randomBytes(16).toString("hex");
      sessions[sessionId] = { apiKeyId, privateKeyPem, useDemoEnv, createdAt: Date.now() };
      cleanSessions();
      return sendJson(res, 200, { sessionId, balance: result.body });
    }

    // ═══ POST /api/disconnect ═══
    if (pathname === "/api/disconnect" && method === "POST") {
      const sid = req.headers["x-session-id"];
      if (sid && sid !== envSessionId && sessions[sid]) {
        if (sessions[sid].ws) try { sessions[sid].ws.close(); } catch(e) {}
        delete sessions[sid];
      }
      return sendJson(res, 200, { ok: true });
    }

    // ═══ SSE stream: GET /api/stream ═══
    if (pathname === "/api/stream" && method === "GET") {
      const sid = parsed.query["session"];
      const session = sessions[sid];
      if (!session) return sendJson(res, 401, { error: "Not authenticated" });

      res.writeHead(200, {
        "Content-Type": "text/event-stream", "Cache-Control": "no-cache",
        "Connection": "keep-alive", "Access-Control-Allow-Origin": "*",
      });
      res.write("data: {\"type\":\"connected\"}\n\n");
      if (!session.sseClients) session.sseClients = [];
      session.sseClients.push(res);
      if (!session.ws || session.wsReadyState === "closed") startKalshiWebSocket(sid, session);
      req.on("close", () => {
        if (session.sseClients) session.sseClients = session.sseClients.filter(c => c !== res);
      });
      return;
    }

    // ═══ Proxy /api/kalshi/* ═══
    if (pathname.startsWith("/api/kalshi/")) {
      const sid = req.headers["x-session-id"];
      const session = sessions[sid];
      if (!session) return sendJson(res, 401, { error: "Not authenticated" });

      // Block writes if read-only or not authed for write
      const isWrite = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
      if (isWrite && !canWrite(req)) {
        return sendJson(res, 403, { error: "Write access denied. Authenticate with password first." });
      }

      const { apiKeyId, privateKeyPem, useDemoEnv } = session;
      const host = useDemoEnv ? "demo-api.kalshi.co" : "api.elections.kalshi.com";
      const kalshiPath = req.url.replace("/api/kalshi", "/trade-api/v2");
      const pathOnly = kalshiPath.split("?")[0];
      const ts = Date.now().toString();
      const sig = signRequest(privateKeyPem, ts, method, pathOnly);
      const headers = {
        "KALSHI-ACCESS-KEY": apiKeyId, "KALSHI-ACCESS-SIGNATURE": sig,
        "KALSHI-ACCESS-TIMESTAMP": ts, "Content-Type": "application/json",
      };
      let postData = null;
      if (isWrite) postData = await readBody(req);
      const result = await httpsRequest({ hostname: host, port: 443, path: kalshiPath, method, headers }, postData);
      return sendJson(res, result.status, result.body);
    }

    serveStatic(res, pathname);
  } catch (e) {
    console.error("Server error:", e);
    sendJson(res, 500, { error: e.message });
  }
});

// ═══════════════════════════════════════════════
//  KALSHI WEBSOCKET
// ═══════════════════════════════════════════════
function startKalshiWebSocket(sessionId, session) {
  const { apiKeyId, privateKeyPem, useDemoEnv } = session;
  const wsHost = useDemoEnv ? "demo-api.kalshi.co" : "api.elections.kalshi.com";
  const wsPath = "/trade-api/ws/v2";
  const ts = Date.now().toString();
  const sig = signRequest(privateKeyPem, ts, "GET", wsPath);

  const hdrs = [
    `GET ${wsPath} HTTP/1.1`, `Host: ${wsHost}`, `Upgrade: websocket`, `Connection: Upgrade`,
    `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString("base64")}`, `Sec-WebSocket-Version: 13`,
    `KALSHI-ACCESS-KEY: ${apiKeyId}`, `KALSHI-ACCESS-SIGNATURE: ${sig}`, `KALSHI-ACCESS-TIMESTAMP: ${ts}`,
    ``, ``
  ].join("\r\n");

  const socket = tls.connect(443, wsHost, { servername: wsHost }, () => {
    console.log(`[ws] TLS connected to ${wsHost}`);
    socket.write(hdrs);
  });

  let upgraded = false, headerBuf = "", frameBuf = Buffer.alloc(0);

  function sendWsFrame(data) {
    const payload = Buffer.from(data, "utf8");
    const mask = crypto.randomBytes(4);
    let header;
    if (payload.length < 126) {
      header = Buffer.alloc(6); header[0] = 0x81; header[1] = 0x80 | payload.length; mask.copy(header, 2);
    } else if (payload.length < 65536) {
      header = Buffer.alloc(8); header[0] = 0x81; header[1] = 0x80 | 126;
      header.writeUInt16BE(payload.length, 2); mask.copy(header, 4);
    } else {
      header = Buffer.alloc(14); header[0] = 0x81; header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2); mask.copy(header, 10);
    }
    const masked = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
    socket.write(Buffer.concat([header, masked]));
  }

  function parseFrames() {
    while (frameBuf.length >= 2) {
      const opcode = frameBuf[0] & 0x0f;
      const masked = (frameBuf[1] & 0x80) !== 0;
      let payloadLen = frameBuf[1] & 0x7f, offset = 2;
      if (payloadLen === 126) { if (frameBuf.length < 4) return; payloadLen = frameBuf.readUInt16BE(2); offset = 4; }
      else if (payloadLen === 127) { if (frameBuf.length < 10) return; payloadLen = Number(frameBuf.readBigUInt64BE(2)); offset = 10; }
      if (masked) offset += 4;
      if (frameBuf.length < offset + payloadLen) return;
      let payload = frameBuf.slice(offset, offset + payloadLen);
      if (masked) { const mk = frameBuf.slice(offset - 4, offset); for (let i = 0; i < payload.length; i++) payload[i] ^= mk[i % 4]; }
      frameBuf = frameBuf.slice(offset + payloadLen);
      if (opcode === 0x01) broadcastSSE(sessionId, JSON.parse(payload.toString("utf8")));
      else if (opcode === 0x09) {
        const pong = Buffer.alloc(6); pong[0] = 0x8a; pong[1] = 0x80;
        const pm = crypto.randomBytes(4); pm.copy(pong, 2); socket.write(pong);
      } else if (opcode === 0x08) socket.end();
    }
  }

  socket.on("data", (chunk) => {
    if (!upgraded) {
      headerBuf += chunk.toString("utf8");
      const idx = headerBuf.indexOf("\r\n\r\n");
      if (idx !== -1) {
        if (headerBuf.split("\r\n")[0].includes("101")) {
          upgraded = true; session.wsReadyState = "open";
          console.log("[ws] WebSocket upgraded");
          const rest = headerBuf.substring(idx + 4);
          if (rest.length) { frameBuf = Buffer.concat([frameBuf, Buffer.from(rest, "binary")]); parseFrames(); }
          sendWsFrame(JSON.stringify({ id: 1, cmd: "subscribe", params: { channels: ["ticker"] } }));
          sendWsFrame(JSON.stringify({ id: 2, cmd: "subscribe", params: { channels: ["fill"] } }));
          console.log("[ws] Subscribed to ticker + fill");
        } else { console.error("[ws] Upgrade failed:", headerBuf.split("\r\n")[0]); session.wsReadyState = "closed"; socket.end(); }
      }
    } else { frameBuf = Buffer.concat([frameBuf, chunk]); parseFrames(); }
  });

  socket.on("error", (err) => { console.error("[ws] Error:", err.message); session.wsReadyState = "closed"; });
  socket.on("close", () => {
    console.log("[ws] Closed"); session.wsReadyState = "closed"; session.ws = null;
    broadcastSSE(sessionId, { type: "ws_disconnected" });
    setTimeout(() => {
      if (sessions[sessionId] && session.sseClients?.length > 0) { console.log("[ws] Reconnecting..."); startKalshiWebSocket(sessionId, sessions[sessionId]); }
    }, 5000);
    if (session.pingInterval) clearInterval(session.pingInterval);
  });

  session.ws = socket; session.sendWsFrame = sendWsFrame;
  session.pingInterval = setInterval(() => {
    if (session.wsReadyState === "open") {
      const p = Buffer.alloc(6); p[0] = 0x89; p[1] = 0x80;
      crypto.randomBytes(4).copy(p, 2); try { socket.write(p); } catch(e) {}
    }
  }, 30000);
}

function broadcastSSE(sessionId, data) {
  const session = sessions[sessionId];
  if (!session?.sseClients) return;
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  session.sseClients.forEach(c => { try { c.write(msg); } catch(e) {} });
}

// ═══════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════
server.listen(PORT, () => {
  console.log("");
  console.log("  ╔══════════════════════════════════════════════╗");
  console.log("  ║   Kalshi Command Dashboard                   ║");
  console.log("  ║   → http://localhost:" + PORT + "                    ║");
  console.log("  ║                                              ║");
  if (ENV_MODE) {
    console.log("  ║   Mode: ENV (auto-connect)                   ║");
    console.log("  ║   Key:  " + ENV_KEY_ID.substring(0, 8) + "...                          ║");
    console.log("  ║   Env:  " + (ENV_DEMO ? "DEMO" : "LIVE") + "                               ║");
  } else {
    console.log("  ║   Mode: LOCAL (login form)                   ║");
  }
  if (HARD_READ_ONLY) console.log("  ║   Access: READ-ONLY                         ║");
  else if (PASSWORD) console.log("  ║   Access: Password-protected writes           ║");
  else console.log("  ║   Access: Full (no password)                 ║");
  console.log("  ║                                              ║");
  console.log("  ╚══════════════════════════════════════════════╝");
  console.log("");
});
