
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

loadEnv();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "diggou</>";
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_ME_SESSION_SECRET";
const DATA_SECRET = process.env.DATA_SECRET || "CHANGE_ME_DATA_SECRET";
const DATA_FILE = path.join(__dirname, "data", "messages.json");

app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());
app.use(express.static(__dirname));

function loadEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  for (const raw of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const idx = line.indexOf("=");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1);
    if (!process.env[key]) process.env[key] = value;
  }
}

function readMessages() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return [];
  }
}

function writeMessages(messages) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(messages, null, 2), "utf8");
}

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}
function unb64(s) {
  return Buffer.from(s, "base64");
}

function keyFromSecret(secret, salt) {
  return crypto.scryptSync(secret, salt, 32);
}

function encryptText(plainText) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = keyFromSecret(DATA_SECRET, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: "AES-256-GCM",
    salt: b64(salt),
    iv: b64(iv),
    tag: b64(tag),
    data: b64(encrypted)
  };
}

function decryptText(payload) {
  const key = keyFromSecret(DATA_SECRET, unb64(payload.salt));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, unb64(payload.iv));
  decipher.setAuthTag(unb64(payload.tag));
  const plain = Buffer.concat([
    decipher.update(unb64(payload.data)),
    decipher.final()
  ]);
  return plain.toString("utf8");
}

function hashAnswer(answer, salt = crypto.randomBytes(16)) {
  const normalized = String(answer || "").trim().toLowerCase();
  const hash = crypto.scryptSync(normalized, salt, 32);
  return { salt: b64(salt), hash: b64(hash) };
}

function answerMatches(answer, record) {
  const normalized = String(answer || "").trim().toLowerCase();
  const salt = unb64(record.answerSalt);
  const derived = crypto.scryptSync(normalized, salt, 32);
  const expected = unb64(record.answerHash);
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

function makeSessionToken() {
  const expires = Date.now() + 1000 * 60 * 60 * 8;
  const body = `${expires}.${crypto.randomBytes(18).toString("hex")}`;
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("hex");
  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [expires, nonce, sig] = parts;
  const body = `${expires}.${nonce}`;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("hex");
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  } catch {
    return false;
  }
  return Date.now() < Number(expires);
}

function requireAdmin(req, res, next) {
  if (!verifySession(req.cookies.owner_session)) {
    return res.status(401).json({ error: "Não autorizado." });
  }
  next();
}

app.get("/", (req, res) => res.redirect("/access.html"));
app.get("/access", (req, res) => res.sendFile(path.join(__dirname, "access.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));

app.post("/api/admin/login", (req, res) => {
  const password = String(req.body?.password || "");
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  let ok = false;
  if (a.length === b.length) {
    try { ok = crypto.timingSafeEqual(a, b); } catch {}
  }
  if (!ok) return res.status(401).json({ error: "Senha incorreta." });

  res.cookie("owner_session", makeSessionToken(), {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  });
  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("owner_session");
  res.json({ ok: true });
});

app.get("/api/admin/me", (req, res) => {
  res.json({ authenticated: verifySession(req.cookies.owner_session) });
});

app.get("/api/admin/messages", requireAdmin, (req, res) => {
  const items = readMessages().map(m => ({
    id: m.id,
    title: m.title,
    clue: m.clue,
    createdAt: m.createdAt,
    updatedAt: m.updatedAt,
    message: decryptText(m.encrypted)
  }));
  res.json(items);
});

app.post("/api/admin/messages", requireAdmin, (req, res) => {
  const title = String(req.body?.title || "").trim();
  const clue = String(req.body?.clue || "").trim();
  const message = String(req.body?.message || "").trim();
  const answer = String(req.body?.answer || "").trim();

  if (!title || !message || !answer) {
    return res.status(400).json({ error: "Título, mensagem e resposta são obrigatórios." });
  }

  const answerData = hashAnswer(answer);
  const now = new Date().toISOString();
  const item = {
    id: crypto.randomUUID(),
    title,
    clue,
    encrypted: encryptText(message),
    answerSalt: answerData.salt,
    answerHash: answerData.hash,
    createdAt: now,
    updatedAt: now
  };

  const messages = readMessages();
  messages.unshift(item);
  writeMessages(messages);
  res.json({ ok: true, id: item.id });
});

app.put("/api/admin/messages/:id", requireAdmin, (req, res) => {
  const messages = readMessages();
  const idx = messages.findIndex(m => m.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Mensagem não encontrada." });

  const current = messages[idx];
  const title = String(req.body?.title ?? current.title).trim();
  const clue = String(req.body?.clue ?? current.clue).trim();
  const message = String(req.body?.message ?? decryptText(current.encrypted)).trim();
  const answer = String(req.body?.answer || "").trim();

  current.title = title;
  current.clue = clue;
  current.encrypted = encryptText(message);
  current.updatedAt = new Date().toISOString();

  if (answer) {
    const answerData = hashAnswer(answer);
    current.answerSalt = answerData.salt;
    current.answerHash = answerData.hash;
  }

  messages[idx] = current;
  writeMessages(messages);
  res.json({ ok: true });
});

app.delete("/api/admin/messages/:id", requireAdmin, (req, res) => {
  const messages = readMessages();
  const next = messages.filter(m => m.id !== req.params.id);
  if (next.length === messages.length) return res.status(404).json({ error: "Mensagem não encontrada." });
  writeMessages(next);
  res.json({ ok: true });
});

app.get("/api/public/messages", (req, res) => {
  const items = readMessages().map(m => ({
    id: m.id,
    title: m.title,
    clue: m.clue,
    createdAt: m.createdAt
  }));
  res.json(items);
});

app.post("/api/public/unlock/:id", (req, res) => {
  const item = readMessages().find(m => m.id === req.params.id);
  if (!item) return res.status(404).json({ error: "Arquivo não encontrado." });

  const answer = String(req.body?.answer || "");
  if (!answerMatches(answer, item)) {
    return res.status(403).json({ error: "ACCESS DENIED" });
  }

  res.json({
    ok: true,
    title: item.title,
    message: decryptText(item.encrypted)
  });
});

app.listen(PORT, () => {
  console.log(`Painel secreto rodando em http://localhost:${PORT}`);
  console.log(`Visitante: http://localhost:${PORT}/access`);
  console.log(`Admin:     http://localhost:${PORT}/admin`);
  if (ADMIN_PASSWORD === "diggou</>") {
    console.log("AVISO: altere a senha padrão no arquivo .env antes de publicar.");
  }
});
