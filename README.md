# Secure Login System

A self-contained Node.js/Express web app demonstrating a secure username/password
login flow with optional TOTP-based two-factor authentication.

## Features

- **Password hashing** with bcrypt (cost factor 12) — plaintext passwords are
  never stored.
- **SQL injection protection** — every database query uses parameterized
  statements (`better-sqlite3` prepared statements with `?` placeholders),
  never string concatenation.
- **Input validation** on registration and login via `express-validator`
  (username charset/length, valid email, password complexity, confirm-password match).
- **Session management** — `express-session` with a SQLite-backed store,
  `httpOnly` + `sameSite=strict` cookies, session regeneration on login/2FA
  success (mitigates session fixation), and a logout route that destroys the
  session server-side.
- **Account lockout** — 5 failed logins locks the account for 15 minutes,
  slowing down credential-stuffing/brute-force attempts.
- **Rate limiting** on auth endpoints (`express-rate-limit`).
- **Security headers** via `helmet`.
- **Optional 2FA** — TOTP (Google Authenticator-compatible) with QR-code
  enrollment via `speakeasy` + `qrcode`.

## Setup

```bash
cd secure-login-app
npm install
cp .env.example .env
# Edit .env and set a real SESSION_SECRET, e.g.:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

npm start
```

Visit `http://localhost:3000`.

## How it works

1. **Register** at `/register`. Passwords must be 10+ characters with upper,
   lower, and numeric characters. The password is hashed with bcrypt before
   it's written to the database — the raw password is never stored or logged.
2. **Log in** at `/login`. On success, the session is regenerated (a fresh
   session ID is issued) before marking it authenticated, which protects
   against session fixation attacks.
3. **Enable 2FA** from the dashboard. Scan the QR code with an authenticator
   app, then confirm with a generated code before 2FA is actually turned on
   for the account — this avoids locking a user out with a secret they never
   actually captured.
4. Once 2FA is enabled, subsequent logins require a valid 6-digit code in
   addition to the password; a "pending" login state in the session cannot
   reach any protected route on its own.
5. **Log out** via the button on the dashboard, which calls
   `POST /logout` and destroys the session server-side.

## Security notes / production hardening checklist

This app is a solid educational/starter baseline, not a finished product.
Before deploying it for real users, also consider:

- Serve over HTTPS only, and set `NODE_ENV=production` so cookies get the
  `secure` flag.
- Add CSRF tokens on state-changing forms (e.g. `csurf` or a
  double-submit-cookie pattern) — `sameSite=strict` cookies mitigate a lot of
  CSRF risk already, but defense in depth is worthwhile for a production app.
- Add email verification and a password-reset flow (with signed, expiring
  tokens sent by email — never send the password itself).
- Consider a managed session store (Redis, etc.) instead of SQLite if you
  expect to run multiple app instances.
- Add structured logging/alerting for repeated failed logins.
- Rotate `SESSION_SECRET` requires invalidating existing sessions; plan for
  that in your deployment process.
- Review and tighten the `helmet` Content-Security-Policy for your actual
  frontend needs.

## Project structure

```
secure-login-app/
├── server.js            # App entry point, security middleware, session config
├── db/
│   └── db.js             # SQLite schema + parameterized prepared statements
├── middleware/
│   └── auth.js           # requireAuth / redirectIfAuthenticated guards
├── routes/
│   └── auth.js           # register, login, logout, 2FA setup/verify routes
├── views/                 # EJS templates
└── public/
    └── style.css
```
