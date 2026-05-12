const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
// Increase limit because user state can get large over time
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'lifeos_super_secret_key_123';

// 1. Initialize SQLite Database
const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database opening error: ', err);
    } else {
        console.log('Connected to SQLite database.');
        
        // Create Users Table (We store the entire frontend STATE object as a JSON string)
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT UNIQUE,
                password TEXT,
                state_data TEXT
            )
        `);
    }
});

// Middleware to protect routes
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: "No token provided" });
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Unauthorized / Token expired" });
        req.userId = decoded.id;
        next();
    });
};

// 2. Register Route
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: "Name, email and password required" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Initial state for new user
        const initialState = JSON.stringify({
            user: { name, email, joinDate: new Date().toISOString() },
            settings: { theme: 'dark', currency: '₹', name }
        });
        
        db.run(`INSERT INTO users (name, email, password, state_data) VALUES (?, ?, ?, ?)`, 
            [name, email, hashedPassword, initialState], 
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: "Email already exists" });
                    }
                    return res.status(500).json({ error: "Database error: " + err.message });
                }
                
                // Auto-login after register
                const token = jwt.sign({ id: this.lastID, email }, SECRET_KEY);
                res.json({ 
                    message: "User registered successfully", 
                    token, 
                    state: JSON.parse(initialState) 
                });
            });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// 3. Login Route
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: "User not found. Please register." });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: "Invalid password" });

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY);
        const stateData = user.state_data ? JSON.parse(user.state_data) : {};
        
        res.json({ 
            message: "Login successful", 
            token, 
            state: stateData 
        });
    });
});

// 4. Reset Password Route (Requires exact Name and Email match for security)
app.post('/api/reset-password', (req, res) => {
    const { name, email, newPassword } = req.body;
    if (!name || !email || !newPassword) return res.status(400).json({ error: "Name, email and new password required" });
    
    db.get(`SELECT * FROM users WHERE email = ? COLLATE NOCASE AND name = ? COLLATE NOCASE`, [email, name], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: "Account with that Name and Email not found." });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, user.id], function(err) {
            if (err) return res.status(500).json({ error: "Failed to reset: " + err.message });
            res.json({ message: "Password reset successful! You can now login." });
        });
    });
});

// 5. Sync Route (Save Data to Cloud)
app.post('/api/sync', verifyToken, (req, res) => {
    const { state } = req.body;
    if (!state) return res.status(400).json({ error: "No state data provided" });
    
    const stateString = JSON.stringify(state);

    db.run(`UPDATE users SET state_data = ? WHERE id = ?`, [stateString, req.userId], function(err) {
        if (err) return res.status(500).json({ error: "Failed to sync: " + err.message });
        res.json({ message: "State successfully synced to cloud", timestamp: new Date() });
    });
});

app.listen(PORT, () => {
    console.log(`LifeOS Backend running on http://localhost:${PORT}`);
});
