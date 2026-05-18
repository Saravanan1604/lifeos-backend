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
  password:  { type: String, required: true },
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

