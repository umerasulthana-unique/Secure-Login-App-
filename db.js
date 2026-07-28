const path = require('path');
const Database = require('better-sqlite3');

// better-sqlite3 is synchronous and safe for a small app like this.
// All queries in this file use parameterized statements ("?" placeholders)
// instead of string concatenation, which is what actually prevents SQL injection.
const db = new Database(path.join(__dirname, 'app.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Prepared statements are compiled once and reused -- every value passed in
// is bound as a parameter, never interpolated into the SQL string.
const statements = {
  insertUser: db.prepare(
    `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`
  ),
  getUserByUsername: db.prepare(`SELECT * FROM users WHERE username = ?`),
  getUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  getUserById: db.prepare(`SELECT * FROM users WHERE id = ?`),
  setTotpSecret: db.prepare(
    `UPDATE users SET totp_secret = ? WHERE id = ?`
  ),
  enableTotp: db.prepare(
    `UPDATE users SET totp_enabled = 1 WHERE id = ?`
  ),
  disableTotp: db.prepare(
    `UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?`
  ),
  recordFailedAttempt: db.prepare(
    `UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?`
  ),
  resetFailedAttempts: db.prepare(
    `UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?`
  ),
  lockAccount: db.prepare(
    `UPDATE users SET locked_until = ? WHERE id = ?`
  ),
};

module.exports = { db, statements };
