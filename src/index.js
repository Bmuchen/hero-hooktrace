 import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import crypto from "crypto";

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
app.use(
  express.json({
    limit: "2mb",
    verify: (req, res, buf) => {
      req.rawBody = buf.toString("utf8");
    }
  })
);

app.use(express.urlencoded({ extended: true }));

// --------------------
// Serve frontend
// --------------------
app.use(express.static(path.join(__dirname, "public")));

// --------------------
// In-memory storage (SAFE)
// --------------------
const endpoints = Object.create(null);
// endpointKey -> events[]
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
// Create webhook endpoint
// --------------------
 app.post("/endpoints", (req, res) => {
  const endpointKey = crypto.randomBytes(8).toString("hex");
  const secret = crypto.randomBytes(24).toString("hex");

  endpoints[endpointKey] = {
    secret: secret,
    events: []
  };

  res.json({
    endpointKey,
    secret,
    webhookUrl: `http://localhost:${PORT}/webhook/${endpointKey}`
  });
});


// --------------------
// Receive webhook events
// --------------------
 app.all("/webhook/:endpointKey", (req, res) => {
  const { endpointKey } = req.params;
  const endpoint = endpoints[endpointKey];

  if (!endpoint) {
    return res.status(404).json({ error: "Endpoint not found" });
  }

   const signature = req.headers["x-hooktrace-signature"];

const isValid = verifySignature(
  endpoint.secret,
  req.rawBody || "",
  signature
);

if (!isValid) {
  return res.status(401).json({ error: "Invalid signature" });
}


  const event = {
    id: crypto.randomUUID(),
    time: new Date().toISOString(),
    method: req.method,
    headers: req.headers,
    body: req.body
  };

  endpoint.events.unshift(event);

  res.json({ received: true, secured: true });
});
// --------------------
// Fetch events
// --------------------
app.get("/events/:endpointKey", (req, res) => {
  const { endpointKey } = req.params;

  if (!endpoints[endpointKey]) {
    return res.status(404).json({ error: "Endpoint not found" });
  }

  res.json(endpoints[endpointKey]);
});

// --------------------
// Start server
// --------------------
 app.listen(PORT, () => {
  console.log("Hero HookTrace running on http://localhost:" + PORT);
});