require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' })); // state blobs can be large

// ── MongoDB connection ──────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`LifeOS backend running on port ${PORT}`));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected ✅'))
  .catch(err => console.error('MongoDB connection failed ❌', err.message));

// ── User schema: stores the entire frontend STATE blob per user ─────────────
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true, lowercase: true },
  mobile:    { type: String, default: '' },
  password:  { type: String, default: '' },
  authProvider: { type: String, default: 'email' }, // 'email' | 'google'
  picture:   { type: String, default: '' },
  state:     { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// ── Auth middleware ─────────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'lifeos_secret_key');
    next();
  } catch {
    res.status(401).json({ error: 'Token expired or invalid — please log in again' });
  }
}

function makeToken(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET || 'lifeos_secret_key', { expiresIn: '90d' });
}

// ── Routes ──────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (_, res) => res.json({ ok: true }));

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email and password are required' });

    if (await User.findOne({ email: email.toLowerCase() }))
      return res.status(400).json({ error: 'An account with this email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user   = await User.create({ name, email, mobile, password: hashed });
    const token  = makeToken(user._id);

    res.json({
      token,
      state: {},
      user: { name: user.name, email: user.email, mobile: user.mobile, joinDate: user.createdAt }
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user)
      return res.status(401).json({ error: 'No account found with this email' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res.status(401).json({ error: 'Incorrect password' });

    const token = makeToken(user._id);
    res.json({
      token,
      state: user.state || {},
      user: { name: user.name, email: user.email, mobile: user.mobile, joinDate: user.createdAt }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get current user + state
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      user:  { name: user.name, email: user.email, mobile: user.mobile, joinDate: user.createdAt },
      state: user.state || {}
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Sync state (save entire STATE blob)
app.post('/api/sync', auth, async (req, res) => {
  try {
    const { state } = req.body;
    if (!state) return res.status(400).json({ error: 'No state provided' });
    await User.findByIdAndUpdate(req.user.id, { state }, { new: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Sync failed' });
  }
});

// Google Sign-In (find-or-create by email)
app.post('/api/google-auth', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'No Google credential provided' });

    // Verify the ID token via Google's tokeninfo endpoint (no extra deps needed)
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '33547416778-vg3i2e2shoaiptoouhpo2ns0iojecok9.apps.googleusercontent.com';
    const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
    const payload = await gRes.json();
    if (!gRes.ok || payload.aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ error: 'Invalid Google token' });
    }

    const { name, email, picture } = payload;
    let user = await User.findOne({ email: email.toLowerCase() });

    if (user) {
      // Update picture if changed, ensure authProvider recorded
      if (picture && user.picture !== picture) { user.picture = picture; await user.save(); }
      const token = makeToken(user._id);
      const userObj = { name: user.name, email: user.email, picture: user.picture, mobile: user.mobile, joinDate: user.createdAt, authProvider: user.authProvider };
      return res.json({ token, user: userObj, state: user.state || {} });
    }

    // New Google user — create without password
    user = await User.create({ name, email, mobile: '', password: '', authProvider: 'google', picture });
    const token = makeToken(user._id);
    const userObj = { name: user.name, email: user.email, picture, joinDate: user.createdAt, authProvider: 'google' };
    res.json({ token, user: userObj, state: {} });
  } catch (e) {
    console.error('Google auth error:', e);
    res.status(500).json({ error: 'Google sign-in failed: ' + e.message });
  }
});

// Reset password (verified by mobile + email)
app.post('/api/reset-password', async (req, res) => {
  try {
    const { mobile, email, newPassword } = req.body;
    if (!mobile || !email || !newPassword)
      return res.status(400).json({ error: 'Mobile, email and new password are required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user)
      return res.status(404).json({ error: 'No account found with this email' });
    if (user.mobile !== mobile)
      return res.status(400).json({ error: 'Mobile number does not match our records' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password reset successfully! You can now log in with your new password.' });
  } catch (e) {
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

// Admin — user stats (protected by ADMIN_KEY env variable)
app.get('/api/admin/users', async (req, res) => {
  const ADMIN_KEY = process.env.ADMIN_KEY || 'lifeos-admin-2024';
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' });

  try {
    const users = await User.find({}, 'name email mobile authProvider createdAt').sort({ createdAt: -1 });
    res.json({
      total: users.length,
      email_users: users.filter(u => u.authProvider !== 'google').length,
      google_users: users.filter(u => u.authProvider === 'google').length,
      users: users.map(u => ({
        id: u._id,
        name: u.name,
        email: u.email,
        mobile: u.mobile,
        auth_provider: u.authProvider || 'email',
        joined: u.createdAt
      }))
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

