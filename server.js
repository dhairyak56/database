const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// Initialize Express App
const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/causeconnect', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function () {
  console.log('Connected to MongoDB');
});

// Load User Model
const User = require('./models/User');
const Event = require('./models/Event');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Passport Config
passport.use(new LocalStrategy({ usernameField: 'email' },
    async (email, password, done) => {
        const user = await User.findOne({ email });
        if (!user) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        if (!bcrypt.compareSync(password, user.password)) {
            return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user);
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'views', 'signup.html')));
app.get('/dashboard', ensureAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
app.get('/notification', ensureAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'views', 'notification.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'views', 'about.html')));
app.get('/events', (req, res) => res.sendFile(path.join(__dirname, 'views', 'events.html')));
app.get('/post_event', ensureAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'views', 'post_event.html')));
app.get('/faqs', (req, res) => res.sendFile(path.join(__dirname, 'views', 'faqs.html')));

app.post('/login', [
  body('email').isEmail().withMessage('Enter a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password cannot be empty'),
], (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', errors.array().map(err => err.msg).join(' '));
    return res.redirect('/login');
  }

  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })(req, res, next);
});

app.post('/signup', [
  body('email').isEmail().withMessage('Enter a valid email').normalizeEmail(),
  body('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', errors.array().map(err => err.msg).join(' '));
    return res.redirect('/signup');
  }

  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash('error', 'Email is already registered');
      return res.redirect('/signup');
    }
    const user = new User({ email, password });
    await user.save();
    req.flash('success', 'You are now registered and can log in');
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.redirect('/signup');
  }
});

app.post('/post_event', ensureAuthenticated, [
  body('name').notEmpty().withMessage('Event name is required'),
  body('organization').notEmpty().withMessage('Organization name is required'),
  body('location').notEmpty().withMessage('Location is required'),
  body('time').isISO8601().toDate().withMessage('Time must be a valid date'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', errors.array().map(err => err.msg).join(' '));
    return res.redirect('/post_event');
  }

  const { name, organization, location, time } = req.body;
  try {
    const event = new Event({ name, organization, location, time });
    await event.save();
    res.redirect('/events');
  } catch (err) {
    console.error(err);
    res.redirect('/post_event');
  }
});

// Middleware to ensure user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
