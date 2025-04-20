require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });
const PORT = process.env.PORT || 5000;
const saltRounds = 10;
const ADMIN_USERNAME = 'joshua';
const ADMIN_PASSWORD = 'admin';
const FREE_SHARE_LIMIT = 500;
const DB_PATH = path.join(__dirname, 'db', 'users.sqlite');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const ADMIN_PFP_PATH = 'admin/admin.jpg';
const OTP_EXPIRY_MS = 10 * 60 * 1000;

const SUBSCRIPTION_PLANS = {
    '1_week': { durationMs: 7 * 24 * 60 * 60 * 1000, amount: 30 },
    '3_weeks': { durationMs: 3 * 7 * 24 * 60 * 60 * 1000, amount: 100 },
    '3_months': { durationMs: 3 * 30 * 24 * 60 * 60 * 1000, amount: 300 },
    '1_year': { durationMs: 365 * 24 * 60 * 60 * 1000, amount: 500 }
};

if (!fs.existsSync(UPLOADS_DIR)){
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
const adminDir = path.join(__dirname, 'public', 'admin');
if (!fs.existsSync(adminDir)) {
     fs.mkdirSync(adminDir, { recursive: true });
     console.log(`Created directory: ${adminDir}. Place admin.jpg here.`);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, UPLOADS_DIR);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const mimetype = allowedTypes.test(file.mimetype);
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb('Error: File upload only supports the following filetypes - ' + allowedTypes);
    }
});
const pfpUpload = upload.single('newPfp');

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                userId TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                phoneNumber TEXT UNIQUE,
                pfpPath TEXT,
                accessToken TEXT,
                isPremium INTEGER DEFAULT 0,
                subscriptionExpiresAt DATETIME,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => { if (err) console.error('Error creating/altering users table:', err.message); });

            db.run(`CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                sess TEXT NOT NULL,
                expire INTEGER NOT NULL
            )`, (err) => { if (err) console.error('Error creating sessions table:', err.message); });

            db.run(`CREATE TABLE IF NOT EXISTS subscription_requests (
                requestId INTEGER PRIMARY KEY AUTOINCREMENT,
                userId TEXT NOT NULL,
                planType TEXT NOT NULL,
                amountExpected INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                requestedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                approvedAt DATETIME,
                expiresAt DATETIME,
                approvedByAdminId TEXT,
                FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE,
                FOREIGN KEY (approvedByAdminId) REFERENCES users(userId) ON DELETE SET NULL
            )`, (err) => { if (err) console.error('Error creating subscription_requests table:', err.message); });


            db.get('SELECT 1 FROM users WHERE username = ?', [ADMIN_USERNAME], async (err, row) => {
                if (err) { console.error('Error checking for admin user:', err.message); return; }
                if (!row) {
                    try {
                        const hashedAdminPassword = await bcrypt.hash(ADMIN_PASSWORD, saltRounds);
                        const adminUserId = uuidv4();
                        db.run('INSERT INTO users (userId, username, password, isPremium) VALUES (?, ?, ?, ?)',
                           [adminUserId, ADMIN_USERNAME, hashedAdminPassword, 1],
                           (err) => {
                                if (err) { console.error('Error creating admin user:', err.message); }
                                else { console.log(`Admin user "${ADMIN_USERNAME}" created.`); }
                           });
                    } catch (hashError) {
                        console.error('Error hashing admin password:', hashError);
                    }
                } else {
                     db.run('UPDATE users SET isPremium = 1, subscriptionExpiresAt = NULL WHERE username = ?', [ADMIN_USERNAME]);
                }
            });
        });
    }
});

const allowedOrigins = [
    "https://autosharee.gleeze.com",
    null
];
app.use(cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.indexOf(origin) !== -1 || origin === 'null') {
        callback(null, true)
      } else {
        console.warn(`CORS blocked for origin: ${origin}`);
        callback(new Error('Not allowed by CORS'))
      }
    },
    credentials: true
}));
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const sessionMiddleware = session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.join(__dirname, 'db'), table: 'sessions' }),
    secret: process.env.SESSION_SECRET || 'fallback_secret_please_change',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'lax'
    }
});
app.use(sessionMiddleware);

const requireLogin = (req, res, next) => {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ message: 'Unauthorized: Please log in.' });
    }
};


async function convertCookie(cookieString) {
    try {
        const cookies = JSON.parse(cookieString);
        if (!Array.isArray(cookies)) {
            throw new Error('Appstate must be a JSON array.');
        }
        return cookies.map(c => `${c.key}=${c.value}`).join('; ');
    } catch (err) {
        console.error("Cookie conversion error:", err.message);
        throw new Error('Invalid appstate format. Make sure it\'s a valid JSON array.');
    }
}

async function getPostID(url) {
    try {
        const postIdRegex = /(?:posts|videos|story_fbid|permalink|watch)(?:\/|%2F|%3D|v%3D|id%3D|fbid=)(?:photo\.php\?fbid=)?([0-9]+)/;
        const match = url.match(postIdRegex);
        if (match && match[1]) {
            return match[1];
        }

        const response = await axios.post('https://id.traodoisub.com/api.php', `link=${encodeURIComponent(url)}`, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 8000
        });
         if (response.data && response.data.id) {
            return response.data.id;
         } else {
            console.error("External API did not return an ID:", response.data);
            return null;
         }
    } catch (error) {
        console.error("Error getting Post ID:", error?.response?.data || error.message);
        return null;
    }
}

async function getAccessToken(cookieHeader) {
    try {
        const headers = {
            'authority': 'business.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'cookie': cookieHeader,
            'referer': 'https://www.facebook.com/',
            'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
        };

        const response = await axios.get('https://business.facebook.com/content_management', {
            headers,
            maxRedirects: 0,
            validateStatus: status => status >= 200 && status < 400,
            timeout: 10000
        });

        const tokenMatch = response.data.match(/"accessToken"\s*:\s*"([^"]+)"/);
        if (tokenMatch && tokenMatch[1]) {
            return tokenMatch[1];
        } else {
             return null;
        }
    } catch (error) {
        return null;
    }
}

function sendWsMessage(ws, type, payload) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        try {
            ws.send(JSON.stringify({ type, payload }));
        } catch (sendError) {
        }
    }
}

const activeShares = new Map();
const activeConnections = new Map();
const pendingRegistrations = new Map();

function generateOtp() {
    return crypto.randomInt(100000, 999999).toString();
}

async function sendOtpSms(phoneNumber, otp) {
    const message = `Your Share Boost verification code is: ${otp}`;
    const apiUrl = `https://zen-api.up.railway.app/api/sms?number=${encodeURIComponent(phoneNumber)}&message=${encodeURIComponent(message)}`;
    try {
        const response = await axios.get(apiUrl, { timeout: 10000 });
        return response.status >= 200 && response.status < 300;
    } catch (error) {
        console.error(`Error sending OTP SMS to ${phoneNumber}:`, error.response?.data || error.message);
        return false;
    }
}

async function checkAndUpdateSubscriptionStatus(userId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT isPremium, subscriptionExpiresAt, username FROM users WHERE userId = ?', [userId], (err, user) => {
            if (err) {
                console.error(`Error fetching user ${userId} for sub check:`, err.message);
                return resolve({ isPremium: false, subscriptionExpiresAt: null });
            }
            if (!user || user.username === ADMIN_USERNAME) {
                return resolve({ isPremium: true, subscriptionExpiresAt: null });
            }

            let currentPremium = user.isPremium === 1;
            let expiresAt = user.subscriptionExpiresAt ? new Date(user.subscriptionExpiresAt) : null;
            let needsUpdate = false;

            if (currentPremium && expiresAt && expiresAt < new Date()) {
                console.log(`Subscription for user ${userId} (${user.username}) expired at ${expiresAt}. Setting to Free.`);
                currentPremium = false;
                expiresAt = null;
                needsUpdate = true;
            }

            if (needsUpdate) {
                db.run('UPDATE users SET isPremium = 0, subscriptionExpiresAt = NULL WHERE userId = ?', [userId], (updateErr) => {
                    if (updateErr) {
                        console.error(`Error updating expired subscription for user ${userId}:`, updateErr.message);
                         resolve({ isPremium: user.isPremium === 1, subscriptionExpiresAt: user.subscriptionExpiresAt });
                    } else {
                         resolve({ isPremium: currentPremium, subscriptionExpiresAt: null });
                    }
                });
            } else {
                resolve({ isPremium: currentPremium, subscriptionExpiresAt: user.subscriptionExpiresAt });
            }
        });
    });
}


async function startShareProcess(userId, isPremium, params, ws) {
    if (activeShares.has(userId)) {
        stopShareProcess(userId, 'new_start');
    }

    const { cookie: appstateJson, url, amount, interval } = params;
    const shareAmount = parseInt(amount);

    if (!appstateJson || !url || !amount || !interval) {
         sendWsMessage(ws, 'error', { message: 'Missing required parameters: Appstate, URL, Amount, and Interval.' });
         return;
    }

     const subStatus = await checkAndUpdateSubscriptionStatus(userId);
     const currentIsPremium = subStatus.isPremium;
     if (!currentIsPremium && shareAmount > FREE_SHARE_LIMIT) {
        sendWsMessage(ws, 'error', { message: `Free plan limit is ${FREE_SHARE_LIMIT} shares. Your requested ${shareAmount}. Upgrade your plan.` });
        return;
     }
     if(ws.isPremium !== currentIsPremium) ws.isPremium = currentIsPremium;

    let cookieHeader = null;
    let obtainedAccessToken = null;
    let postId = null;

    sendWsMessage(ws, 'status_update', { message: 'Starting process...' });

    try {
        sendWsMessage(ws, 'status_update', { message: 'Processing provided appstate...' });
        cookieHeader = await convertCookie(appstateJson);

        obtainedAccessToken = await getAccessToken(cookieHeader);
        if (!obtainedAccessToken) {
            throw new Error('Failed to retrieve access token. Please check your provided appstate (cookie). It might be invalid or expired.');
        }

        sendWsMessage(ws, 'status_update', { message: 'Getting Post ID...' });
        postId = await getPostID(url);
        if (!postId) {
            throw new Error('Invalid URL or unable to fetch Post ID. Please check the link.');
        }

        let sharedCount = 0;
        const shareIntervalMs = Math.max(1000, interval * 1000);

        const shareData = {
            timerId: null,
            sharedCount: 0,
            amount: shareAmount,
            interval: parseInt(interval),
            obtainedAccessToken,
            postId,
            url,
            isPremium: currentIsPremium,
            status: 'running',
            lastMessage: 'Initializing...',
            userId: userId,
            wsRef: ws,
            startTime: Date.now(),
            cookieHeader: cookieHeader
        };

        const runShare = async () => {
            const currentShareData = activeShares.get(userId);
            if (!currentShareData || currentShareData.status !== 'running') {
                if(currentShareData && currentShareData.timerId) clearInterval(currentShareData.timerId);
                return;
            }
            if (currentShareData.sharedCount >= currentShareData.amount) {
                stopShareProcess(userId, 'limit_reached', `Completed ${currentShareData.sharedCount}/${currentShareData.amount} shares.`);
                return;
            }

            try {
                const fbUrl = `https://graph.facebook.com/me/feed?link=https://m.facebook.com/${currentShareData.postId}&published=0&access_token=${currentShareData.obtainedAccessToken}`;
                const headers = {
                    'accept': '*/*',
                    'accept-encoding': 'gzip, deflate',
                    'connection': 'keep-alive',
                    'content-length': '0',
                    'host': 'graph.facebook.com',
                    'user-agent': 'Mozilla/5.0',
                    'cookie': currentShareData.cookieHeader
                };

                const response = await axios.post(fbUrl, {}, { headers, timeout: 15000 });

                if (response.status === 200 && response.data && response.data.id) {
                    currentShareData.sharedCount++;
                    currentShareData.lastMessage = `Success (${currentShareData.sharedCount}/${currentShareData.amount})`;
                    sendWsMessage(currentShareData.wsRef, 'progress', {
                        sharedCount: currentShareData.sharedCount,
                        amount: currentShareData.amount,
                        message: currentShareData.lastMessage,
                        status: currentShareData.status
                    });
                } else {
                    throw new Error(`Facebook API Error: Status ${response.status}, Data: ${JSON.stringify(response.data)}`);
                }
            } catch (error) {
                let errorMessage = `Error sharing: ${error.message}`;
                let stopReason = 'error';

                if (error.response) {
                    errorMessage = `Error sharing: Status ${error.response.status}.`;
                    if (error.response.data && error.response.data.error) {
                        errorMessage += ` FB Error: ${error.response.data.error.message}`;
                        const fbErrorCode = error.response.data.error.code;

                        if (fbErrorCode === 190) {
                            errorMessage = `Error: Invalid/Expired credentials provided in Appstate. Please update it.`;
                            stopReason = 'auth_error';
                        } else if (fbErrorCode === 10) {
                            errorMessage = `Error: App Permission Missing. Check app settings on Facebook.`;
                            stopReason = 'permission_error';
                        } else if (fbErrorCode === 368) {
                            errorMessage = `Error: Temporarily Blocked by Facebook. Try again later.`;
                            stopReason = 'blocked';
                        } else if (fbErrorCode === 200) {
                             errorMessage = `Error: Post requires higher permissions or is not public.`;
                             stopReason = 'permission_error';
                        } else if (fbErrorCode === 100) {
                             errorMessage = `Error: Invalid Post Link or Post Deleted.`;
                             stopReason = 'invalid_post';
                        }
                    }
                }

                console.error(`Share error for user ${userId}: ${errorMessage}`);
                currentShareData.status = 'error';
                currentShareData.lastMessage = errorMessage;
                stopShareProcess(userId, stopReason, errorMessage);
            }
        };

        shareData.timerId = setInterval(runShare, shareIntervalMs);
        activeShares.set(userId, shareData);

        console.log(`Started sharing process for ${userId} (Premium: ${currentIsPremium}) - ${shareAmount} shares / ${interval}s. Using provided appstate.`);
        sendWsMessage(ws, 'started', { message: `Process started. Target: ${shareAmount} shares every ${interval}s.` });
        runShare();

    } catch (error) {
        console.error(`Failed to start share process for user ${userId}:`, error.message);
        sendWsMessage(ws, 'error', { message: `Failed to start: ${error.message}` });
        const existingShareData = activeShares.get(userId);
        if (existingShareData && existingShareData.timerId) {
            clearInterval(existingShareData.timerId);
            activeShares.delete(userId);
        }
    }
}

function stopShareProcess(userId, reason = 'manual', message = 'Sharing process stopped.') {
    const shareData = activeShares.get(userId);
    if (shareData) {
        clearInterval(shareData.timerId);
        shareData.status = 'stopped';
        shareData.lastMessage = message;

        const finalStatus = {
            sharedCount: shareData.sharedCount,
            amount: shareData.amount,
            message: message,
            status: 'stopped',
            reason: reason
        };

        const currentWs = activeConnections.get(userId);
        const originalWs = shareData.wsRef;

        const stopMessageType = (reason === 'limit_reached' || reason === 'completed') ? 'completed' : 'stopped';

        sendWsMessage(currentWs, stopMessageType, finalStatus);
        if (originalWs && originalWs !== currentWs && originalWs.readyState === WebSocket.OPEN) {
             sendWsMessage(originalWs, stopMessageType, finalStatus);
        }

        activeShares.delete(userId);
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/register', upload.single('pfp'), async (req, res) => {
    const { username, phoneNumber, password, confirmPassword } = req.body;
    const pfpFile = req.file;

    if (!username || !phoneNumber || !password || !confirmPassword) {
        if (pfpFile) fs.unlinkSync(pfpFile.path);
        return res.status(400).json({ message: 'All fields (username, phone, password, confirm) are required.' });
    }
    if (password !== confirmPassword) {
        if (pfpFile) fs.unlinkSync(pfpFile.path);
        return res.status(400).json({ message: 'Passwords do not match.' });
    }
     if (password.length < 6) {
        if (pfpFile) fs.unlinkSync(pfpFile.path);
        return res.status(400).json({ message: 'Password must be at least 6 characters.' });
     }
    if (username.toLowerCase() === ADMIN_USERNAME) {
        if (pfpFile) fs.unlinkSync(pfpFile.path);
        return res.status(400).json({ message: 'This username is reserved.' });
    }
    const phoneRegex = /^\d{10,15}$/;
    if (!phoneRegex.test(phoneNumber)) {
        if (pfpFile) fs.unlinkSync(pfpFile.path);
        return res.status(400).json({ message: 'Invalid phone number format.' });
    }

    try {
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT userId FROM users WHERE username = ? OR phoneNumber = ?', [username, phoneNumber], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingUser) {
            if (pfpFile) fs.unlinkSync(pfpFile.path);
            return res.status(409).json({ message: 'Username or phone number already exists.' });
        }

        const otp = generateOtp();
        const expiry = Date.now() + OTP_EXPIRY_MS;
        const pfpRelativePath = pfpFile ? path.join('uploads', pfpFile.filename).replace(/\\/g, '/') : null;

        pendingRegistrations.set(phoneNumber, {
            data: { username, password, pfpPath: pfpRelativePath, phoneNumber },
            otp,
            expiry
        });

        const smsSent = await sendOtpSms(phoneNumber, otp);

        if (smsSent) {
            res.status(200).json({ message: 'OTP sent successfully. Please verify.', requiresOtp: true, phoneNumber: phoneNumber });
        } else {
            pendingRegistrations.delete(phoneNumber);
            if (pfpFile) fs.unlinkSync(pfpFile.path);
            res.status(500).json({ message: 'Failed to send OTP SMS. Please try again later.' });
        }

    } catch (error) {
        console.error('Registration Step 1 error:', error);
        if (pfpFile) fs.unlinkSync(pfpFile.path);
        res.status(500).json({ message: 'Internal server error during registration setup.' });
    }
});

app.post('/verify-otp', async (req, res) => {
    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
        return res.status(400).json({ message: 'Phone number and OTP are required.' });
    }

    const pendingData = pendingRegistrations.get(phoneNumber);

    if (!pendingData) {
        return res.status(400).json({ message: 'No pending registration found for this number or it expired.' });
    }

    if (Date.now() > pendingData.expiry) {
        pendingRegistrations.delete(phoneNumber);
        if (pendingData.data.pfpPath) try { fs.unlinkSync(path.join(__dirname, 'public', pendingData.data.pfpPath)); } catch(e){}
        return res.status(400).json({ message: 'OTP expired. Please register again.' });
    }

    if (pendingData.otp !== otp) {
        return res.status(400).json({ message: 'Invalid OTP.' });
    }

    try {
        const { username, password, pfpPath, phoneNumber: storedNumber } = pendingData.data;

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const userId = uuidv4();

        db.run('INSERT INTO users (userId, username, password, phoneNumber, pfpPath) VALUES (?, ?, ?, ?, ?)',
               [userId, username, hashedPassword, storedNumber, pfpPath],
               function (err) {
                    if (err) {
                        console.error('Final Registration DB error:', err.message);
                         if (pfpPath) try { fs.unlinkSync(path.join(__dirname, 'public', pfpPath)); } catch(e){}
                        return res.status(500).json({ message: 'Registration failed due to database error.' });
                    }
                    console.log(`User registered & verified: ${username} (ID: ${userId})`);
                    pendingRegistrations.delete(phoneNumber);
                    res.status(201).json({ message: 'Registration successful! You can now log in.', userId: userId });
               });

    } catch (error) {
        console.error('Final Registration error:', error);
         if (pendingData.data.pfpPath) try { fs.unlinkSync(path.join(__dirname, 'public', pendingData.data.pfpPath)); } catch(e){}
        res.status(500).json({ message: 'Internal server error during final registration.' });
    } finally {
         pendingRegistrations.delete(phoneNumber);
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    db.get('SELECT userId, username, pfpPath, isPremium, password FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Login DB error:', err.message);
            return res.status(500).json({ message: 'Login failed. Please try again.' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        try {
            const match = await bcrypt.compare(password, user.password);

            if (match) {
                const isAdmin = user.username === ADMIN_USERNAME;
                const subStatus = isAdmin ? { isPremium: true, subscriptionExpiresAt: null } : await checkAndUpdateSubscriptionStatus(user.userId);
                const effectiveIsPremium = subStatus.isPremium;
                const effectivePfpPath = isAdmin && !user.pfpPath ? ADMIN_PFP_PATH : user.pfpPath;

                req.session.regenerate((err) => {
                    if (err) {
                        console.error('Session regeneration error:', err);
                        return res.status(500).json({ message: 'Login failed due to session error.' });
                    }

                    req.session.userId = user.userId;
                    req.session.username = user.username;
                    req.session.isPremium = effectiveIsPremium;
                    req.session.isAdmin = isAdmin;
                    req.session.pfpPath = effectivePfpPath;
                    req.session.subscriptionExpiresAt = subStatus.subscriptionExpiresAt;

                    console.log(`User logged in: ${user.username} (Premium: ${req.session.isPremium}, Admin: ${req.session.isAdmin})`);

                    res.status(200).json({
                        message: 'Login successful.',
                        userId: user.userId,
                        username: user.username,
                        isPremium: req.session.isPremium,
                        isAdmin: req.session.isAdmin,
                        pfpPath: req.session.pfpPath,
                        subscriptionExpiresAt: req.session.subscriptionExpiresAt
                    });
                });
            } else {
                res.status(401).json({ message: 'Invalid username or password.' });
            }
        } catch (compareError) {
            console.error('Password comparison error:', compareError);
            res.status(500).json({ message: 'Login failed due to server error.' });
        }
    });
});


app.post('/logout', (req, res) => {
    const userId = req.session.userId;
    const username = req.session.username;

    const ws = activeConnections.get(userId);
    if (ws) {
        ws.close(1000, 'User logged out');
        activeConnections.delete(userId);
    }

    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ message: 'Logout failed.' });
        }
        console.log(`User logged out: ${username} (ID: ${userId})`);
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logout successful.' });
    });
});

app.get('/check-session', async (req, res) => {
    if (req.session && req.session.userId) {
         try {
             const isAdmin = req.session.isAdmin;
             const subStatus = isAdmin ? { isPremium: true, subscriptionExpiresAt: null } : await checkAndUpdateSubscriptionStatus(req.session.userId);

             db.get('SELECT pfpPath FROM users WHERE userId = ?', [req.session.userId], (pfpErr, pfpRow) => {
                 if (pfpErr) {
                     console.error("Error fetching PFP path on session check:", pfpErr.message);
                 }

                 const dbPfpPath = pfpRow ? pfpRow.pfpPath : null;
                 const effectivePfpPath = isAdmin && !dbPfpPath ? ADMIN_PFP_PATH : dbPfpPath;

                 req.session.isPremium = subStatus.isPremium;
                 req.session.subscriptionExpiresAt = subStatus.subscriptionExpiresAt;
                 req.session.pfpPath = effectivePfpPath;

                 res.status(200).json({
                     isLoggedIn: true,
                     userId: req.session.userId,
                     username: req.session.username,
                     isPremium: req.session.isPremium,
                     isAdmin: isAdmin,
                     pfpPath: req.session.pfpPath,
                     subscriptionExpiresAt: req.session.subscriptionExpiresAt
                 });
             });
         } catch (checkError) {
              console.error("Error checking/updating subscription status:", checkError);
              res.status(200).json({
                   isLoggedIn: true,
                   userId: req.session.userId,
                   username: req.session.username,
                   isPremium: req.session.isPremium,
                   isAdmin: req.session.isAdmin,
                   pfpPath: req.session.pfpPath,
                   subscriptionExpiresAt: req.session.subscriptionExpiresAt
              });
         }
    } else {
        res.status(200).json({ isLoggedIn: false });
    }
});


app.post('/api/user/request-subscription', requireLogin, async (req, res) => {
    const { planType } = req.body;
    const userId = req.session.userId;

    if (!planType || !SUBSCRIPTION_PLANS[planType]) {
        return res.status(400).json({ message: 'Invalid subscription plan selected.' });
    }

    const planDetails = SUBSCRIPTION_PLANS[planType];
    const amountExpected = planDetails.amount;

    try {
         const existingPending = await new Promise((resolve, reject) => {
              db.get("SELECT 1 FROM subscription_requests WHERE userId = ? AND status = 'pending'", [userId], (err, row) => {
                  if(err) reject(err); else resolve(row);
              });
          });

          if (existingPending) {
              return res.status(400).json({ message: 'You already have a pending subscription request.' });
          }

        db.run(`INSERT INTO subscription_requests (userId, planType, amountExpected, status)
                VALUES (?, ?, ?, ?)`,
               [userId, planType, amountExpected, 'pending'],
               function (err) {
                    if (err) {
                        console.error('Error creating subscription request:', err.message);
                        return res.status(500).json({ message: 'Failed to submit request. Please try again.' });
                    }
                    console.log(`Subscription request created for user ${userId}, plan ${planType}`);
                    res.status(201).json({ message: 'Subscription request submitted successfully. Please contact the administrator for payment and approval.' });
               });
    } catch (error) {
        console.error('Subscription request error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.post('/api/user/update-username', requireLogin, async (req, res) => {
    const { newUsername } = req.body;
    const userId = req.session.userId;

    if (!newUsername || newUsername.trim().length < 3) {
        return res.status(400).json({ message: 'New username must be at least 3 characters long.' });
    }
    if (newUsername.toLowerCase() === ADMIN_USERNAME && req.session.username !== ADMIN_USERNAME) {
         return res.status(400).json({ message: 'This username is reserved.' });
    }

    try {
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT userId FROM users WHERE username = ? AND userId != ?', [newUsername, userId], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });

        if (existingUser) {
            return res.status(409).json({ message: 'Username already taken.' });
        }

        db.run('UPDATE users SET username = ? WHERE userId = ?', [newUsername, userId], function (err) {
            if (err) {
                console.error('Error updating username:', err.message);
                return res.status(500).json({ message: 'Failed to update username.' });
            }
            req.session.username = newUsername;
            console.log(`User ${userId} changed username to ${newUsername}`);
            res.status(200).json({ message: 'Username updated successfully.', newUsername: newUsername });
        });
    } catch (error) {
        console.error('Update username error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.post('/api/user/update-password', requireLogin, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = req.session.userId;

    if (!currentPassword || !newPassword || !confirmPassword) {
        return res.status(400).json({ message: 'All password fields are required.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
    }
    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'New passwords do not match.' });
    }

    try {
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT password FROM users WHERE userId = ?', [userId], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).json({ message: 'Incorrect current password.' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        db.run('UPDATE users SET password = ? WHERE userId = ?', [hashedNewPassword, userId], function (err) {
            if (err) {
                console.error('Error updating password:', err.message);
                return res.status(500).json({ message: 'Failed to update password.' });
            }
            console.log(`User ${userId} changed password.`);
            res.status(200).json({ message: 'Password updated successfully.' });
        });
    } catch (error) {
        console.error('Update password error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.post('/api/user/update-pfp', requireLogin, (req, res) => {
    pfpUpload(req, res, async function (err) {
        if (err instanceof multer.MulterError) {
             if (err.code === 'LIMIT_FILE_SIZE') {
                 return res.status(400).json({ message: 'File size limit exceeded (Max 5MB).' });
             }
            return res.status(400).json({ message: `Multer error: ${err.message}` });
        } else if (err) {
            return res.status(400).json({ message: `File upload error: ${err}` });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'No profile picture file selected.' });
        }

        const userId = req.session.userId;
        const newPfpRelativePath = path.join('uploads', req.file.filename).replace(/\\/g, '/');

        try {
            const oldPfpData = await new Promise((resolve, reject) => {
                db.get('SELECT pfpPath FROM users WHERE userId = ?', [userId], (err, row) => {
                    if (err) reject(err); else resolve(row);
                });
            });

            db.run('UPDATE users SET pfpPath = ? WHERE userId = ?', [newPfpRelativePath, userId], function (dbErr) {
                if (dbErr) {
                    console.error('Error updating PFP path in DB:', dbErr.message);
                    try { fs.unlinkSync(req.file.path); } catch (e) {}
                    return res.status(500).json({ message: 'Failed to update profile picture.' });
                }

                console.log(`User ${userId} updated PFP to ${newPfpRelativePath}`);

                if (oldPfpData && oldPfpData.pfpPath && oldPfpData.pfpPath !== ADMIN_PFP_PATH && !oldPfpData.pfpPath.startsWith('admin/')) {
                     const oldPfpFullPath = path.join(__dirname, 'public', oldPfpData.pfpPath);
                     fs.unlink(oldPfpFullPath, (unlinkErr) => {
                         if (unlinkErr && unlinkErr.code !== 'ENOENT') {
                             console.error('Error deleting old PFP:', unlinkErr.message);
                         }
                     });
                }
                 req.session.pfpPath = newPfpRelativePath;

                res.status(200).json({ message: 'Profile picture updated successfully.', newPfpPath: newPfpRelativePath });
            });
        } catch (error) {
            console.error('Update PFP error:', error);
            try { fs.unlinkSync(req.file.path); } catch (e) {}
            res.status(500).json({ message: 'Internal server error.' });
        }
    });
});

const requireAdmin = (req, res, next) => {
    if (req.session && req.session.isAdmin) {
        next();
    } else {
         if (req.headers.accept && req.headers.accept.includes('application/json')) {
             res.status(403).json({ message: 'Forbidden: Admin access required.' });
         } else {
             res.status(403).send(`<!DOCTYPE html><html> <head> <title>Forbidden</title> <style>body{font-family: sans-serif; padding: 20px; background-color: #1E1A34; color: #E5E7EB;} h1 {color: #ef4444;} a {color: #8B5CF6;}</style> </head> <body> <h1>Forbidden</h1> <p>Admin access required.</p> <p><a href="/">Back to Login</a></p> </body> </html>`);
         }
    }
};

app.get('/admin', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/users', requireAdmin, (req, res) => {
    db.all('SELECT userId, username, phoneNumber, pfpPath, isPremium, subscriptionExpiresAt, createdAt FROM users WHERE username != ? ORDER BY createdAt DESC', [ADMIN_USERNAME], (err, rows) => {
        if (err) {
            console.error("Error fetching users for admin:", err.message);
            return res.status(500).json({ message: "Failed to fetch users." });
        }
        res.status(200).json(rows);
    });
});

app.get('/admin/subscription-requests', requireAdmin, (req, res) => {
     const query = `
         SELECT sr.*, u.username
         FROM subscription_requests sr
         JOIN users u ON sr.userId = u.userId
         WHERE sr.status = 'pending'
         ORDER BY sr.requestedAt ASC
     `;
     db.all(query, [], (err, rows) => {
         if (err) {
             console.error("Error fetching subscription requests:", err.message);
             return res.status(500).json({ message: "Failed to fetch requests." });
         }
         res.status(200).json(rows);
     });
 });


app.post('/admin/toggle-premium/:userId', requireAdmin, (req, res) => {
    const targetUserId = req.params.userId;

    db.get('SELECT isPremium, username FROM users WHERE userId = ? AND username != ?', [targetUserId, ADMIN_USERNAME], (err, user) => {
        if (err) {
            console.error('Error finding user to toggle premium:', err.message);
            return res.status(500).json({ message: 'Database error.' });
        }
        if (!user) {
            return res.status(404).json({ message: 'User not found or is admin.' });
        }

        const newPremiumStatus = user.isPremium ? 0 : 1;
        const newExpiry = null;

        db.run('UPDATE users SET isPremium = ?, subscriptionExpiresAt = ? WHERE userId = ?', [newPremiumStatus, newExpiry, targetUserId], function(err) {
            if (err) {
                console.error('Error updating premium status:', err.message);
                return res.status(500).json({ message: 'Failed to update status.' });
            }
            console.log(`Admin ${req.session.username} manually toggled premium for ${user.username} (ID: ${targetUserId}) to ${newPremiumStatus}`);

            const targetWs = activeConnections.get(targetUserId);
            if (targetWs) {
                 targetWs.isPremium = (newPremiumStatus === 1);
                 targetWs.subscriptionExpiresAt = null;
                 sendWsMessage(targetWs, 'status_update', {
                     isPremium: targetWs.isPremium,
                     subscriptionExpiresAt: targetWs.subscriptionExpiresAt,
                     message: `Your premium status was manually changed by an admin.` });
            }

            res.status(200).json({
                 message: `User ${user.username} premium status manually set to ${newPremiumStatus === 1 ? 'Premium' : 'Free'}.`,
                 newStatus: newPremiumStatus
            });
        });
    });
});

app.post('/admin/approve-subscription/:requestId', requireAdmin, async (req, res) => {
     const requestId = req.params.requestId;
     const adminUserId = req.session.userId;

     try {
         const request = await new Promise((resolve, reject) => {
             db.get('SELECT * FROM subscription_requests WHERE requestId = ?', [requestId], (err, row) => {
                 if (err) reject(new Error('Database error finding request.'));
                 else resolve(row);
             });
         });

         if (!request) {
             return res.status(404).json({ message: 'Subscription request not found.' });
         }
         if (request.status !== 'pending') {
             return res.status(400).json({ message: `Request already ${request.status}.` });
         }
         if (!SUBSCRIPTION_PLANS[request.planType]) {
              return res.status(400).json({ message: 'Invalid plan type in request.' });
         }

         const planDetails = SUBSCRIPTION_PLANS[request.planType];
         const now = new Date();
         const expiresAt = new Date(now.getTime() + planDetails.durationMs);
         const expiresAtISO = expiresAt.toISOString();
         const approvedAtISO = now.toISOString();

         db.serialize(() => {
             db.run('BEGIN TRANSACTION;');

             db.run(`UPDATE subscription_requests
                     SET status = 'approved', approvedAt = ?, expiresAt = ?, approvedByAdminId = ?
                     WHERE requestId = ?`,
                    [approvedAtISO, expiresAtISO, adminUserId, requestId], function (err) {
                 if (err) throw err;
             });

             db.run(`UPDATE users
                     SET isPremium = 1, subscriptionExpiresAt = ?
                     WHERE userId = ?`,
                    [expiresAtISO, request.userId], function (err) {
                  if (err) throw err;
             });

             db.run('COMMIT;', async (err) => {
                 if (err) {
                     console.error("Transaction Commit Error:", err);
                     db.run('ROLLBACK;');
                     return res.status(500).json({ message: 'Failed to approve subscription due to transaction error.' });
                 }

                 console.log(`Admin ${adminUserId} approved subscription request ${requestId} for user ${request.userId}. Expires: ${expiresAtISO}`);

                 const targetWs = activeConnections.get(request.userId);
                 if (targetWs) {
                     targetWs.isPremium = true;
                     targetWs.subscriptionExpiresAt = expiresAtISO;
                     sendWsMessage(targetWs, 'status_update', {
                         isPremium: true,
                         subscriptionExpiresAt: expiresAtISO,
                         message: `Your ${request.planType.replace('_', ' ')} subscription has been approved!`
                     });
                 }
                 res.status(200).json({ message: 'Subscription approved successfully.', expiresAt: expiresAtISO });
             });
         });
     } catch (error) {
         console.error('Error approving subscription:', error);
         db.run('ROLLBACK;');
         res.status(500).json({ message: error.message || 'Internal server error.' });
     }
 });

 app.post('/admin/reject-subscription/:requestId', requireAdmin, async (req, res) => {
     const requestId = req.params.requestId;
     const adminUserId = req.session.userId;

      try {
         const request = await new Promise((resolve, reject) => {
             db.get('SELECT * FROM subscription_requests WHERE requestId = ?', [requestId], (err, row) => {
                 if (err) reject(new Error('Database error finding request.'));
                 else resolve(row);
             });
         });

         if (!request) {
             return res.status(404).json({ message: 'Subscription request not found.' });
         }
          if (request.status !== 'pending') {
             return res.status(400).json({ message: `Request already ${request.status}.` });
         }

          db.run(`UPDATE subscription_requests SET status = 'rejected', approvedByAdminId = ? WHERE requestId = ?`,
                 [adminUserId, requestId], function (err) {
             if (err) {
                 console.error('Error rejecting subscription request:', err.message);
                 return res.status(500).json({ message: 'Failed to reject request.' });
             }
              console.log(`Admin ${adminUserId} rejected subscription request ${requestId} for user ${request.userId}.`);
               const targetWs = activeConnections.get(request.userId);
                 if (targetWs) {
                      sendWsMessage(targetWs, 'status_update', {
                         message: `Your subscription request for ${request.planType.replace('_', ' ')} was rejected.`
                     });
                 }
             res.status(200).json({ message: 'Subscription request rejected successfully.' });
         });
     } catch (error) {
         console.error('Error rejecting subscription:', error);
         res.status(500).json({ message: error.message || 'Internal server error.' });
     }
 });


app.delete('/admin/delete-user/:userId', requireAdmin, (req, res) => {
    const targetUserId = req.params.userId;

     db.get('SELECT username, pfpPath FROM users WHERE userId = ?', [targetUserId], (err, user) => {
        if (err) {
            console.error('Error finding user to delete:', err.message);
            return res.status(500).json({ message: 'Database error.' });
        }
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (user.username === ADMIN_USERNAME) {
            return res.status(400).json({ message: 'Cannot delete the admin user.' });
        }

        db.run('DELETE FROM users WHERE userId = ?', [targetUserId], function(err) {
            if (err) {
                console.error('Error deleting user:', err.message);
                return res.status(500).json({ message: 'Failed to delete user.' });
            }
            console.log(`Admin ${req.session.username} deleted user ${user.username} (ID: ${targetUserId})`);

             if (user.pfpPath && user.pfpPath !== ADMIN_PFP_PATH && !user.pfpPath.startsWith('admin/')) {
                 try {
                     fs.unlinkSync(path.join(__dirname, 'public', user.pfpPath));
                 } catch(unlinkErr){
                      if (unlinkErr.code !== 'ENOENT') console.error("Error deleting PFP:", unlinkErr.message);
                 }
             }

            const targetWs = activeConnections.get(targetUserId);
            if (targetWs) {
                targetWs.close(1000, 'Account deleted by admin');
                activeConnections.delete(targetUserId);
            }
            if (activeShares.has(targetUserId)) {
                stopShareProcess(targetUserId, 'account_deleted', 'Account deleted');
            }

            res.status(200).json({ message: `User ${user.username} deleted successfully.` });
        });
    });
});

server.on('upgrade', (request, socket, head) => {
    sessionMiddleware(request, {}, () => {
        if (!request.session || !request.session.userId) {
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    });
});

wss.on('connection', async (ws, req) => {
    const userId = req.session.userId;
    const username = req.session.username;
    const isAdmin = req.session.isAdmin;
    let isPremium = req.session.isPremium;
    let subscriptionExpiresAt = req.session.subscriptionExpiresAt;

    try {
        const subStatus = await checkAndUpdateSubscriptionStatus(userId);
        isPremium = subStatus.isPremium;
        subscriptionExpiresAt = subStatus.subscriptionExpiresAt;
         if(req.session.isPremium !== isPremium) req.session.isPremium = isPremium;
         if(req.session.subscriptionExpiresAt !== subscriptionExpiresAt) req.session.subscriptionExpiresAt = subscriptionExpiresAt;
    } catch (e) {
        console.error(`WS Connection: Error checking subscription for ${userId}:`, e);
    }

    ws.userId = userId;
    ws.username = username;
    ws.isPremium = isPremium;
    ws.isAdmin = isAdmin;
    ws.subscriptionExpiresAt = subscriptionExpiresAt;

    if (activeConnections.has(userId)) {
        activeConnections.get(userId).terminate();
    }
    activeConnections.set(userId, ws);

    console.log(`WebSocket connected: User ${username} (ID: ${userId}, Premium: ${isPremium}, Admin: ${isAdmin})`);
    sendWsMessage(ws, 'connected', { userId, username, isPremium, isAdmin, subscriptionExpiresAt });

    if (activeShares.has(userId)) {
        const shareData = activeShares.get(userId);
        shareData.wsRef = ws;
        sendWsMessage(ws, 'reconnect_status', {
            status: shareData.status,
            sharedCount: shareData.sharedCount,
            amount: shareData.amount,
            message: shareData.lastMessage || "Process running.",
            url: shareData.url,
            interval: shareData.interval
        });
    }

    ws.on('message', async (message) => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (e) {
            sendWsMessage(ws, 'error', { message: 'Invalid message format. Use JSON.' });
            return;
        }

        switch (data.type) {
            case 'start_share':
                 if (!data.payload || !data.payload.url || !data.payload.amount || !data.payload.interval || !data.payload.cookie) {
                    sendWsMessage(ws, 'error', { message: 'Missing parameters. URL, Amount, Interval, and Appstate are required.' });
                    return;
                }
                await startShareProcess(userId, ws.isPremium, data.payload, ws);
                break;

            case 'stop_share':
                if (activeShares.has(userId)) {
                    stopShareProcess(userId, 'manual');
                } else {
                    sendWsMessage(ws, 'info', { message: 'No active sharing process to stop.' });
                }
                break;

            case 'get_status':
                if (activeShares.has(userId)) {
                    const shareData = activeShares.get(userId);
                    sendWsMessage(ws, 'status', {
                        status: shareData.status,
                        sharedCount: shareData.sharedCount,
                        amount: shareData.amount,
                        message: shareData.lastMessage || (shareData.status === 'running' ? 'Process running.' : 'Process stopped.'),
                        url: shareData.url,
                        interval: shareData.interval
                    });
                } else {
                    sendWsMessage(ws, 'status', { status: 'idle', message: 'No active sharing process.' });
                }
                break;
            case 'ping':
                sendWsMessage(ws, 'pong', { timestamp: Date.now() });
                break;

            default:
                sendWsMessage(ws, 'error', { message: `Unknown command type: ${data.type}` });
        }
    });

    ws.on('close', (code, reason) => {
         const reasonString = reason ? reason.toString() : 'N/A';
        console.log(`WebSocket disconnected: User ${username} (ID: ${userId}). Code: ${code}, Reason: ${reasonString}`);
        if (activeConnections.get(userId) === ws) {
            activeConnections.delete(userId);
        }

         if (!ws.isPremium && activeShares.has(userId)) {
             stopShareProcess(userId, 'disconnect');
         } else if (ws.isPremium && activeShares.has(userId)) {
              const shareData = activeShares.get(userId);
              if (shareData && shareData.wsRef === ws) {
                  shareData.wsRef = null;
              }
         }
    });

    ws.on('error', (error) => {
        console.error(`WebSocket error for user ${username} (ID: ${userId}):`, error);
        if (activeConnections.get(userId) === ws) {
            activeConnections.delete(userId);
        }
         if (!ws.isPremium && activeShares.has(userId)) {
            stopShareProcess(userId, 'ws_error', `WebSocket error: ${error.message}`);
         }
        ws.terminate();
    });
});

server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing connections');
    wss.clients.forEach(ws => ws.close(1012, 'Server shutting down'));

    activeShares.forEach((shareData, userId) => {
         stopShareProcess(userId, 'shutdown');
    });

    db.close((err) => {
        if (err) console.error("Error closing database:", err.message);
        else console.log("Database connection closed.");
    });

    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});

app.get("/db", (req, res) => {
    const file = path.join(__dirname, "db/users.sqlite");
    res.download(file);
});

app.get("/dl", (req, res) => {
    const file = path.join(__dirname, "db/users.sqlite");
    res.download(file);
});

process.on('SIGINT', () => {
    process.emit('SIGTERM');
});
