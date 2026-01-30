 import db from "./db/database.js";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import crypto from "crypto";
import fetch from "node-fetch"; // ✅ REQUIRED

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// --------------------
// Fix __dirname for ES modules
// --------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --------------------
// Middleware
// --------------------
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// --------------------
// Serve frontend
// --------------------
app.use(express.static(path.join(__dirname, "public")));

// --------------------
// Signature verification
// --------------------
function verifySignature(secret, rawBody, receivedSignature) {
  if (!receivedSignature) return false;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(receivedSignature)
  );
}

// --------------------
// Health check
// --------------------
app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "Hero HookTrace" });
});

// --------------------
// REPLAY EVENT ✅
// --------------------
 app.post("/webhook/:endpointKey", express.json(), (req, res) => {
  const { endpointKey } = req.params;

  const event = {
    id: crypto.randomUUID(),
    endpointKey,
    method: req.method,
    headers: JSON.stringify(req.headers),
    body: JSON.stringify(req.body),
    created_at: new Date().toISOString()
  };

  saveEvent(event);

  res.json({ received: true });
});

// --------------------
// Receive webhook events (RAW BODY ONLY)
// --------------------
app.all(
  "/webhook/:endpointKey",
  express.raw({ type: "*/*" }),
  (req, res) => {
    const { endpointKey } = req.params;

    const endpoint = db
      .prepare("SELECT * FROM endpoints WHERE id = ?")
      .get(endpointKey);

    if (!endpoint) {
      return res.status(404).json({ error: "Endpoint not found" });
    }

    const signature = req.headers["x-hooktrace-signature"];

    const isValid = verifySignature(
      endpoint.secret,
      req.body.toString("utf8"),
      signature
    );

    if (!isValid) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    db.prepare(`
      INSERT INTO events (
        id,
        endpoint_id,
        method,
        headers,
        body,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      crypto.randomUUID(),
      endpointKey,
      req.method,
      JSON.stringify(req.headers),
      req.body.toString("utf8"),
      new Date().toISOString()
    );

    res.json({ received: true, secured: true });
  }
);

// --------------------
// Fetch events
// --------------------
app.get("/events/:endpointKey", (req, res) => {
  const { endpointKey } = req.params;

  const endpoint = db
    .prepare("SELECT id FROM endpoints WHERE id = ?")
    .get(endpointKey);

  if (!endpoint) {
    return res.status(404).json({ error: "Endpoint not found" });
  }

  const events = db.prepare(`
    SELECT id, method, headers, body, created_at
    FROM events
    WHERE endpoint_id = ?
    ORDER BY created_at DESC
    LIMIT 50
  `).all(endpointKey);

  res.json({ endpointKey, count: events.length, events });
});

// --------------------
// Start server
// --------------------
app.listen(PORT, () => {
  console.log("Hero HookTrace running on port " + PORT);
});
