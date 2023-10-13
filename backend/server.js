const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 5000;
const SECRET_KEY = "your_secret_key"; // Please replace this with a strong secret key for production.

const db = new sqlite3.Database('./mydatabase.sqlite');

// Create the users table if it doesn't exist.
db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)", (err) => {
    if (err) {
        console.error("Error creating users table:", err);
    } else {
        console.log("Users table created or already exists.");
    }
});

app.use(cors());
app.use(bodyParser.json());

// Registration Endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        db.get("SELECT username FROM users WHERE username = ?", [username], (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (row) {
                return res.status(400).json({ message: 'Username already exists' });
            }

            // Insert the new user
            db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Database error' });
                }
                return res.status(201).json({ message: 'User registered successfully', success: true });
            });
        });
    } else {
        return res.status(400).json({ message: 'Username and password are required' });
    }
});

// Login Endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username && password) {
        db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const isPasswordCorrect = await bcrypt.compare(password, user.password);

            if (isPasswordCorrect) {
                const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
                return res.status(200).json({ message: 'Login successful', token, success: true });
            } else {
                return res.status(403).json({ message: 'Incorrect password' });
            }
        });
    } else {
        return res.status(400).json({ message: 'Username and password are required' });
    }
});

app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});

// Handle app termination gracefully
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Closed the database connection.');
    });
    process.exit(0);
});
