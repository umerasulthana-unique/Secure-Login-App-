const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const { statements } = require('../db/db');
const { requireAuth, redirectIfAuthenticated } = require('../middleware/auth');

const router = express.Router();

const BCRYPT_COST_FACTOR = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Slows down brute-force attempts against the login and register endpoints.
// This is a second layer of defense on top of the per-account lockout below.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many attempts from this IP. Please try again later.',
});

// ---------- Validation rules ----------
// express-validator both validates shape/format and, just as importantly,
// rejects unexpected input before it ever reaches a database query.

const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username may only contain letters, numbers, and underscores'),
  body('email').trim().isEmail().withMessage('A valid email is required').normalizeEmail(),
  body('password')
    .isLength({ min: 10 })
    .withMessage('Password must be at least 10 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain an uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain a lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain a number'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return true;
  }),
];

const loginValidation = [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required'),
];

// ---------- Registration ----------

router.get('/register', redirectIfAuthenticated, (req, res) => {
  res.render('register', { errors: [], oldInput: {} });
});

router.post('/register', authLimiter, redirectIfAuthenticated, registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('register', {
      errors: errors.array(),
      oldInput: { username: req.body.username, email: req.body.email },
    });
  }

  const { username, email, password } = req.body;

  try {
    // Parameterized SELECTs -- values are bound, never concatenated into SQL.
    const existingUsername = statements.getUserByUsername.get(username);
    const existingEmail = statements.getUserByEmail.get(email);

    if (existingUsername || existingEmail) {
      return res.status(400).render('register', {
        errors: [{ msg: 'Username or email is already registered' }],
        oldInput: { username, email },
      });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST_FACTOR);
    statements.insertUser.run(username, email, passwordHash);

    res.redirect('/login?registered=1');
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).render('register', {
      errors: [{ msg: 'Something went wrong. Please try again.' }],
      oldInput: { username, email },
    });
  }
});

// ---------- Login ----------

router.get('/login', redirectIfAuthenticated, (req, res) => {
  res.render('login', { errors: [], oldInput: {}, registered: req.query.registered === '1' });
});

router.post('/login', authLimiter, redirectIfAuthenticated, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('login', {
      errors: errors.array(),
      oldInput: { username: req.body.username },
      registered: false,
    });
  }

  const { username, password } = req.body;
  const genericError = 'Invalid username or password';

  try {
    const user = statements.getUserByUsername.get(username);

    if (!user) {
      // Same generic message as a wrong password -- don't reveal whether
      // the username exists.
      return res.status(400).render('login', {
        errors: [{ msg: genericError }],
        oldInput: { username },
        registered: false,
      });
    }

    if (user.locked_until && user.locked_until > Date.now()) {
      const minutesLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
      return res.status(423).render('login', {
        errors: [{ msg: `Account temporarily locked. Try again in ${minutesLeft} minute(s).` }],
        oldInput: { username },
        registered: false,
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      statements.recordFailedAttempt.run(user.id);
      const updated = statements.getUserById.get(user.id);
      if (updated.failed_attempts >= MAX_FAILED_ATTEMPTS) {
        statements.lockAccount.run(Date.now() + LOCKOUT_MINUTES * 60 * 1000, user.id);
      }
      return res.status(400).render('login', {
        errors: [{ msg: genericError }],
        oldInput: { username },
        registered: false,
      });
    }

    statements.resetFailedAttempts.run(user.id);

    if (user.totp_enabled) {
      // Password was correct, but 2FA is enabled: hold a *pending* login in
      // the session and require a valid TOTP code before granting a full
      // session. This intermediate state cannot access protected routes.
      req.session.pendingUserId = user.id;
      return res.redirect('/login/2fa');
    }

    // Regenerate the session ID on privilege change to prevent session fixation.
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regenerate error:', err.message);
        return res.status(500).render('login', {
          errors: [{ msg: 'Something went wrong. Please try again.' }],
          oldInput: { username },
          registered: false,
        });
      }
      req.session.userId = user.id;
      req.session.username = user.username;
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).render('login', {
      errors: [{ msg: 'Something went wrong. Please try again.' }],
      oldInput: { username },
      registered: false,
    });
  }
});

// ---------- Login-time 2FA challenge ----------

router.get('/login/2fa', (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect('/login');
  }
  res.render('login-2fa', { error: null });
});

router.post('/login/2fa', authLimiter, (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect('/login');
  }

  const user = statements.getUserById.get(req.session.pendingUserId);
  const token = (req.body.token || '').trim();

  const verified = user && user.totp_secret && speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token,
    window: 1, // allows the code from slightly before/after "now" for clock drift
  });

  if (!verified) {
    return res.status(400).render('login-2fa', { error: 'Invalid or expired code' });
  }

  const pendingUserId = req.session.pendingUserId;
  req.session.regenerate((err) => {
    if (err) {
      console.error('Session regenerate error:', err.message);
      return res.status(500).render('login-2fa', { error: 'Something went wrong. Please try again.' });
    }
    req.session.userId = pendingUserId;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });
});

// ---------- Logout ----------

router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err.message);
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// ---------- Two-factor authentication setup (from the dashboard) ----------

router.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = statements.getUserById.get(req.session.userId);

  if (user.totp_enabled) {
    return res.redirect('/dashboard');
  }

  const secret = speakeasy.generateSecret({
    name: `SecureLoginApp (${user.username})`,
  });

  // Stash the secret temporarily; it's only committed to totp_enabled=1
  // once the user proves they can generate a valid code with it.
  statements.setTotpSecret.run(secret.base32, user.id);

  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
  res.render('2fa-setup', { qrDataUrl, secret: secret.base32, error: null });
});

router.post('/2fa/setup', requireAuth, (req, res) => {
  const user = statements.getUserById.get(req.session.userId);
  const token = (req.body.token || '').trim();

  const verified = user.totp_secret && speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!verified) {
    return res.status(400).render('2fa-setup', {
      error: 'Invalid code. Please scan the QR code again and try the current code.',
      secret: user.totp_secret,
      qrDataUrl: null,
    });
  }

  statements.enableTotp.run(user.id);
  res.redirect('/dashboard');
});

router.post('/2fa/disable', requireAuth, (req, res) => {
  statements.disableTotp.run(req.session.userId);
  res.redirect('/dashboard');
});

module.exports = router;
