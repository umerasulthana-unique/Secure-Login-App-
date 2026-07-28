require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');

const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');
const { statements } = require('./db/db');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set. Copy .env.example to .env and set a real secret.');
  process.exit(1);
}

// Sets a range of protective HTTP headers (CSP, X-Frame-Options, etc.)
app.use(helmet());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'db') }),
    name: 'connect.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // not readable from client-side JS -- mitigates cookie theft via XSS
      secure: isProduction, // only sent over HTTPS in production
      sameSite: 'strict', // mitigates CSRF by not sending the cookie on cross-site requests
      maxAge: 1000 * 60 * 60 * 2, // 2 hour idle session lifetime
    },
  })
);

app.use('/', authRoutes);

app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/dashboard' : '/login');
});

app.get('/dashboard', requireAuth, (req, res) => {
  const user = statements.getUserById.get(req.session.userId);
  res.render('dashboard', { user });
});

// Fallback error handler -- avoids leaking stack traces to the client.
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong.');
});

app.listen(PORT, () => {
  console.log(`Secure login app running at http://localhost:${PORT}`);
});
