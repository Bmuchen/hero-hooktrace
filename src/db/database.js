import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

// Fix __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create / open SQLite database
const db = new Database(path.join(__dirname, "hooktrace.db"));

// Create tables if they don't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    method TEXT,
    headers TEXT,
    body TEXT,
    created_at TEXT NOT NULL
  );
`);

export default db;
