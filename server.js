const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const mongoose = require('mongoose');
const url = require('url');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
// Added these imports at the top of your server file
const nodemailer = require('nodemailer');
const crypto = require('crypto');

require('dotenv').config();

// Import JWT authentication utilities
const {
  generateTokens,
  verifyToken,
  authenticateToken,
  refreshAccessToken,
  verifyWSToken,
  generateSecureRandom
} = require('./jwt-auth');

const app = express();
const server = http.createServer(app);

// WebSocket server setup (remove verifyClient)
const wss = new WebSocket.Server({ noServer: true });

app.use(cors());
app.use(express.json());


//set up storage for uploaded files
const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  // limits: { fileSize: 10 * 1024 * 1024 }, //  // 10 MB limit
  limits: { fileSize: 5 * 1024 * 1024 * 1024 }, // 5 GB limit
});


//serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// file upload endpoint
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  //you can add more metadata here if needed
  const fileUrl = `uploads/${req.file.filename}`;
  res.json({
    message: "file uploaded successfully",
    fileUrl,
    originalName: req.file.originalname,
    mimetype: req.file.mimetype,
  });
});




// SQLite database setup
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) console.error('SQLite error:', err.message);
  else {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      "from" TEXT, 
      "to" TEXT, 
      message TEXT, 
      timestamp TEXT, 
      isRead INTEGER DEFAULT 0
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      token TEXT,
      expires_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create password reset tokens table
    db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    
    console.log('SQLite connected to chat.db');
  }
});

// MongoDB connection
mongoose.connect('mongodb+srv://smartsquaddigitalsolutions:qJNUhNElapIoa1qn@cluster0.upvtmeu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0/chat-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User schema with enhanced security
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  pin: { type: String, required: true },
  hashedPin: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

// In-memory storage for connected users
const connectedUsers = new Map();
const emailToWs = new Map();

// Utility functions
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function isValidPin(pin) {
  return /^\d{6}$/.test(pin);
}

function generateUserId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function broadcast(message, excludeWs = null) {
  wss.clients.forEach(client => {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

function sendToUser(email, message) {
  const ws = emailToWs.get(email);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
    return true;
  }
  return false;
}

function getOnlineUsers() {
  return Array.from(connectedUsers.values()).map(user => ({
    email: user.email,
    username: user.username,
    connectedAt: user.connectedAt
  }));
}

// Store refresh token in database
function storeRefreshToken(email, refreshToken) {
  return new Promise((resolve, reject) => {
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    db.run(
      'INSERT INTO refresh_tokens (email, token, expires_at) VALUES (?, ?, ?)',
      [email, refreshToken, expiresAt.toISOString()],
      function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      }
    );
  });
}

// Remove refresh token from database
function removeRefreshToken(refreshToken) {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM refresh_tokens WHERE token = ?', [refreshToken], function(err) {
      if (err) reject(err);
      else resolve(this.changes);
    });
  });
}

// Handle WebSocket upgrade
server.on('upgrade', async (request, socket, head) => {
  try {
    const user = await verifyWSToken({ req: request });
    console.log('WebSocket upgrade: user data:', user);
    if (!user) {
      console.error('WebSocket upgrade: Token verification failed');
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // Verify user exists in database
    const dbUser = await User.findOne({ email: user.email });
    if (!dbUser) {
      console.error('WebSocket upgrade: User not found in database');
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    request.user = user; // Attach user to request
    console.log('WebSocket upgrade: req.user set:', request.user);

    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } catch (error) {
    console.error('WebSocket upgrade error:', error.message);
    socket.destroy();
  }
});

// WebSocket connection handling
wss.on('connection', async (ws, req) => {
  console.log('WebSocket connection attempt, req.user:', req.user);
  const user = req.user;
  if (!user) {
    console.error('Connection rejected: No valid user data after token verification');
    ws.close(1008, 'Invalid user data');
    return;
  }

  const userId = generateUserId();

  const existingWs = emailToWs.get(user.email);
  if (existingWs && existingWs.readyState === WebSocket.OPEN) {
    existingWs.close(1000, 'New connection established');
    emailToWs.delete(user.email);
  }

  const userInfo = { 
    id: userId, 
    email: user.email, 
    username: user.username, 
    connectedAt: new Date().toISOString(), 
    ws 
  };
  
  connectedUsers.set(userId, userInfo);
  emailToWs.set(user.email, ws);

  console.log(`User connected: ${user.email} (ID: ${userId})`);

  ws.send(JSON.stringify({
    type: 'connection-success',
    data: { 
      message: `Connected successfully as ${user.username}`, 
      userId, 
      onlineUsers: getOnlineUsers() 
    }
  }));

  broadcast({ 
    type: 'user-connected', 
    data: { 
      email: user.email, 
      username: user.username, 
      message: `${user.username} joined the chat`, 
      timestamp: new Date().toISOString(), 
      onlineUsers: getOnlineUsers() 
    } 
  }, ws);

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      
      switch (message.type) {
        case 'private-message':
          handlePrivateMessage(ws, user.email, message.data);
          break;
        case 'typing':
          handleTyping(ws, user.email, message.data);
          break;
        case 'get-online-users':
          ws.send(JSON.stringify({ 
            type: 'online-users', 
            data: { users: getOnlineUsers() } 
          }));
          break;
        case 'read-receipt':
          handleReadReceipt(ws, user.email, message.data);
          break;
        default:
          ws.send(JSON.stringify({ 
            type: 'error', 
            data: { message: 'Unknown message type' } 
          }));
      }
    } catch (error) {
      console.error('Error parsing message:', error);
      ws.send(JSON.stringify({ 
        type: 'error', 
        data: { message: 'Invalid message format' } 
      }));
    }
  });

  ws.on('close', () => {
    console.log(`User disconnected: ${user.email} (ID: ${userId})`);
    connectedUsers.delete(userId);
    emailToWs.delete(user.email);
    
    broadcast({ 
      type: 'user-disconnected', 
      data: { 
        email: user.email, 
        username: user.username, 
        message: `${user.username} left the chat`, 
        timestamp: new Date().toISOString(), 
        onlineUsers: getOnlineUsers() 
      } 
    });
  });

  ws.on('error', (error) => {
    console.error(`WebSocket error for ${user.email}:`, error);
  });
});

// Message handling functions
function handlePrivateMessage(senderWs, senderEmail, data) {
  const { recipientEmail, message, timestamp, fileUrl, fileName, fileType } = data;
  
  if (!recipientEmail || (!message && !fileUrl)) {
    senderWs.send(JSON.stringify({ 
      type: 'message-error', 
      data: { 
        error: 'Missing recipient email or message', 
        timestamp: new Date().toISOString() 
      } 
    }));
    return;
  }

  const messageData = { 
    from: senderEmail, 
    to: recipientEmail, 
    message: message || '', 
    timestamp: timestamp || new Date().toISOString(), 
    isRead: false,
    fileUrl: fileUrl || null,
    fileName: fileName || null,
    fileType: fileType || null
  };

  db.run(
    'INSERT INTO messages ("from", "to", message, timestamp, isRead, fileUrl, fileName, fileType) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [senderEmail, recipientEmail, messageData.message, messageData.timestamp, 0, messageData.fileUrl, messageData.fileName, messageData.fileType],
    (err) => {
      if (err) {
        console.error('Message save error:', err);
        return;
      }
      
      if (sendToUser(recipientEmail, { type: 'private-message', data: messageData })) {
        senderWs.send(JSON.stringify({ 
          type: 'message-sent', 
          data: { ...messageData, status: 'delivered' } 
        }));
      } else {
        senderWs.send(JSON.stringify({ 
          type: 'message-error', 
          data: { 
            to: recipientEmail, 
            message:messageData.message,
            error: 'User is not online', 
            timestamp: new Date().toISOString() 
          } 
        }));
      }
    }
  );
}

function handleTyping(senderWs, senderEmail, data) {
  const { recipientEmail, isTyping } = data;
  if (!recipientEmail) return;
  
  sendToUser(recipientEmail, { 
    type: 'user-typing', 
    data: { email: senderEmail, isTyping } 
  });
}

function handleReadReceipt(senderWs, senderEmail, data) {
  const { recipientEmail } = data;
  
  db.run(
    'UPDATE messages SET isRead = 1 WHERE "from" = ? AND "to" = ? AND isRead = 0',
    [senderEmail, recipientEmail],
    (err) => {
      if (err) {
        console.error('Read receipt update error:', err);
        return;
      }
      
      sendToUser(recipientEmail, { 
        type: 'read-receipt', 
        data: { senderEmail } 
      });
    }
  );
}

// API Routes
// Check if user exists
app.post('/api/check-user', async (req, res) => {
  const { email } = req.body;
  
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  try {
    const user = await User.findOne({ email, isActive: true });
    res.json({ exists: !!user });
  } catch (error) {
    console.error('Check user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User signup
app.post('/api/signup', async (req, res) => {
  const { email, username, pin } = req.body;
  
  if (!email || !username || !pin) {
    return res.status(400).json({ message: 'Email, username, and PIN are required' });
  }
  
  if (!isValidEmail(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }
  
  if (!isValidPin(pin)) {
    return res.status(400).json({ message: 'PIN must be exactly 6 digits' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash the PIN for security
    const hashedPin = await bcrypt.hash(pin, 10);
    
    const user = new User({ 
      email, 
      username, 
      pin, // Store original for WebSocket auth (consider removing this in production)
      hashedPin 
    });
    
    await user.save();
    
    // Generate JWT tokens
    const tokens = generateTokens({ email: user.email, username: user.username });
    
    // Store refresh token
    await storeRefreshToken(email, tokens.refreshToken);
    
    res.status(201).json({
      message: 'User created successfully',
      user: {
        email: user.email,
        username: user.username
      },
      tokens: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn
      }
    });
  } catch (error) {
    console.error('Sign-up error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  const { email, pin } = req.body;
  
  if (!email || !pin) {
    return res.status(400).json({ message: 'Email and PIN are required' });
  }

  try {
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify PIN using bcrypt
    const isValidPin = await bcrypt.compare(pin, user.hashedPin);
    if (!isValidPin) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT tokens
    const tokens = generateTokens({ email: user.email, username: user.username });
    
    // Store refresh token
    await storeRefreshToken(email, tokens.refreshToken);

    res.json({
      message: 'Login successful',
      user: {
        email: user.email,
        username: user.username
      },
      tokens: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Refresh token endpoint
app.post('/api/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }

  try {
    // Verify refresh token exists in database
    const tokenExists = await new Promise((resolve, reject) => {
      db.get(
        'SELECT email FROM refresh_tokens WHERE token = ? AND expires_at > ?',
        [refreshToken, new Date().toISOString()],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!tokenExists) {
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }

    // Fetch user from MongoDB to get username
    const user = await User.findOne({ email: tokenExists.email, isActive: true });
    if (!user) {
      return res.status(401).json({ message: 'User not found for refresh token' });
    }

    // Generate new access token with both email and username
    const tokens = generateTokens({ email: user.email, username: user.username });

    res.json({
      accessToken: tokens.accessToken,
      expiresIn: tokens.expiresIn
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({ message: 'Token refresh failed' });
  }
});

// Logout endpoint
app.post('/api/logout', authenticateToken, async (req, res) => {
  const { refreshToken } = req.body;
  
  try {
    if (refreshToken) {
      await removeRefreshToken(refreshToken);
    }
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected route to get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email, isActive: true });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      email: user.email,
      username: user.username,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected API routes
app.get('/api/online-users', authenticateToken, (req, res) => {
  res.json({ users: getOnlineUsers(), count: connectedUsers.size });
});

app.get('/api/stats', authenticateToken, (req, res) => {
  res.json({ 
    connectedUsers: connectedUsers.size, 
    totalConnections: wss.clients.size, 
    users: getOnlineUsers() 
  });
});

// Health check endpoint (public)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(), 
    connectedUsers: connectedUsers.size 
  });
});

app.get('/api/messages', authenticateToken, (req, res) => {
  const userEmail = req.user.email;
  db.all(
    'SELECT * FROM messages WHERE "from" = ? OR "to" = ? ORDER BY timestamp ASC',
    [userEmail, userEmail],
    (err, rows) => {
      if (err) {
        console.error('Message fetch error:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      res.json({ messages: rows });
    }
  );
});

// Email configuration (configure with your email provider)
const emailTransporter = nodemailer.createTransport({
  service: 'gmail', // or your email service
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Generate secure token for password reset
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Store password reset token
function storeResetToken(email, token) {
  return new Promise((resolve, reject) => {
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    db.run(
      'INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
      [email, token, expiresAt.toISOString()],
      function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      }
    );
  });
}

// Verify reset token
function verifyResetToken(token) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > ? AND used = 0',
      [token, new Date().toISOString()],
      (err, row) => {
        if (err) reject(err);
        else resolve(row);
      }
    );
  });
}

// Mark reset token as used
function markTokenAsUsed(token) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE password_reset_tokens SET used = 1 WHERE token = ?',
      [token],
      function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      }
    );
  });
}


// Send password reset email
async function sendResetEmail(email, token, username) {
  const resetUrl = `http://localhost:3001/reset-password?token=${token}`;
  const cancelUrl = `http://localhost:3001/cancel-reset?token=${token}`;

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Reset Request</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background-color: #f5f5f5;
          margin: 0;
          padding: 20px;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          background-color: white;
          border-radius: 10px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          overflow: hidden;
        }
        .header {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 30px;
          text-align: center;
        }
        .header h1 {
          margin: 0;
          font-size: 24px;
          font-weight: 600;
        }
        .content {
          padding: 40px 30px;
        }
        .message {
          font-size: 16px;
          line-height: 1.6;
          color: #333;
          margin-bottom: 30px;
        }
        .buttons {
          text-align: center;
          margin: 40px 0;
        }
        .btn {
          display: inline-block;
          padding: 15px 30px;
          margin: 0 10px;
          text-decoration: none;
          border-radius: 50px;
          font-weight: 600;
          font-size: 16px;
          transition: transform 0.2s;
        }
        .btn:hover {
          transform: translateY(-2px);
        }
        .btn-confirm {
          background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
          color: white;
          box-shadow: 0 4px 15px rgba(17, 153, 142, 0.4);
        }
        .btn-cancel {
          background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
          color: white;
          box-shadow: 0 4px 15px rgba(255, 65, 108, 0.4);
        }
        .security-info {
          background-color: #f8f9fa;
          padding: 20px;
          border-radius: 8px;
          margin: 30px 0;
          border-left: 4px solid #007bff;
        }
        .security-info h3 {
          margin-top: 0;
          color: #007bff;
          font-size: 16px;
        }
        .security-info p {
          margin-bottom: 0;
          font-size: 14px;
          color: #666;
        }
        .footer {
          background-color: #f8f9fa;
          padding: 20px 30px;
          text-align: center;
          border-top: 1px solid #e9ecef;
        }
        .footer p {
          margin: 0;
          font-size: 12px;
          color: #666;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔒 Password Reset Request</h1>
        </div>
        <div class="content">
          <div class="message">
            <p><strong>Hello ${username},</strong></p>
            <p>We received a request to reset your password for your chat account. If this was you, click the "It's Me" button below to proceed with changing your password.</p>
            <p>If you didn't request this password reset, click "Cancel" to ignore this request.</p>
          </div>
          
          <div class="buttons">
            <a href="${resetUrl}" class="btn btn-confirm">✅ It's Me - Reset Password</a>
            <a href="${cancelUrl}" class="btn btn-cancel">❌ Cancel Request</a>
          </div>

          <div class="security-info">
            <h3>🛡️ Security Information</h3>
            <p>This password reset link will expire in 30 minutes for your security. If you need to reset your password after this time, you'll need to request a new reset link.</p>
          </div>
        </div>
        <div class="footer">
          <p>This email was sent from your Chat Application. If you have any questions, please contact support.</p>
        </div>
      </div>
    </body>
    </html>
  `;

   const mailOptions = {
    from: process.env.EMAIL_USER || 'your-email@gmail.com',
    to: email,
    subject: '🔒 Password Reset Request - Chat App',
    html: htmlContent
  };

   return emailTransporter.sendMail(mailOptions);
}


// Request password reset
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  try {
    // Check if user exists
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      // Don't reveal if user exists or not for security
      return res.json({ 
        message: 'If your email is registered, you will receive a password reset link.' 
      });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    
    // Store token in database
    await storeResetToken(email, resetToken);
    
    // Send reset email
    await sendResetEmail(email, resetToken, user.username);
    
    res.json({ 
      message: 'If your email is registered, you will receive a password reset link.',
      success: true 
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});


// Handle "It's Me" button click - redirect to password reset form
app.get('/reset-password', async (req, res) => {
  const { token } = req.query;
  
  try {
    const resetData = await verifyResetToken(token);
    if (!resetData) {
      return res.send(`
        <html>
          <head>
            <title>Invalid Reset Link</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
              .error { color: #ff4444; }
            </style>
          </head>
          <body>
            <h2 class="error">❌ Invalid or Expired Reset Link</h2>
            <p>This password reset link is invalid or has expired.</p>
            <p>Please request a new password reset from the app.</p>
          </body>
        </html>
      `);
    }

    // Redirect to your app with the token
    res.redirect(`http://localhost:8100/reset-password?token=${token}`);
  } catch (error) {
    console.error('Reset password page error:', error);
    res.status(500).send('Server error');
  }
});



// Handle "Cancel" button click
app.get('/cancel-reset', async (req, res) => {
  const { token } = req.query;
  
  try {
    const resetData = await verifyResetToken(token);
    if (resetData) {
      await markTokenAsUsed(token);
    }

    res.send(`
      <html>
        <head>
          <title>Password Reset Cancelled</title>
          <style>
            body { 
              font-family: Arial, sans-serif; 
              text-align: center; 
              margin-top: 100px;
              background-color: #f5f5f5;
            }
            .container {
              background: white;
              padding: 40px;
              border-radius: 10px;
              display: inline-block;
              box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .success { color: #28a745; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2 class="success">✅ Password Reset Cancelled</h2>
            <p>Your password reset request has been cancelled successfully.</p>
            <p>Your account remains secure and no changes have been made.</p>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Cancel reset error:', error);
    res.status(500).send('Server error');
  }
});


// Verify reset token and reset password
app.post('/api/reset-password', async (req, res) => {
  const { token, newPin } = req.body;
  
  if (!token || !newPin) {
    return res.status(400).json({ message: 'Token and new PIN are required' });
  }
  
  if (!isValidPin(newPin)) {
    return res.status(400).json({ message: 'PIN must be exactly 6 digits' });
  }

  try {
    // Verify token
    const resetData = await verifyResetToken(token);
    if (!resetData) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Find user
    const user = await User.findOne({ email: resetData.email, isActive: true });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Hash new PIN
    const hashedPin = await bcrypt.hash(newPin, 10);
    
    // Update user's PIN
    user.pin = newPin;
    user.hashedPin = hashedPin;
    await user.save();
    
    // Mark token as used
    await markTokenAsUsed(token);
    
    // Clear all refresh tokens for this user (force re-login)
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM refresh_tokens WHERE email = ?', [user.email], function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      });
    });

    res.json({ message: 'Password reset successfully. Please login with your new PIN.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`WebSocket server running on port ${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}?token=your-jwt-token`);
  console.log(`HTTP API available at: http://localhost:${PORT}/api`);
});