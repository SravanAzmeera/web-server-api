
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
const fs = require('fs');
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

const uploadsDir = path.join(__dirname, 'uploads');

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// WebSocket server setup
const wss = new WebSocket.Server({ noServer: true });

app.use(cors());
app.use(express.json());

// Set up storage for uploaded files
const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  limits: { fileSize: 5 * 1024 * 1024 * 1024 }, // 5 GB limit
});

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// File upload endpoint
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

 const fileUrl = `${process.env.API_URL || 'https://web-server-api.onrender.com'}/uploads/${req.file.filename}`;
  res.json({
    message: "File uploaded successfully",
    fileUrl,
    originalName: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size
  });
});

// Delete files from server after local storage
app.delete('/api/delete-file/:filename', authenticateToken, (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(uploadsDir, filename);

  fs.unlink(filePath, (err) => {
    if (err) {
      console.error('File deletion error:', err);
      if (err.code === 'ENOENT') {
        // File doesn't exist, consider it already deleted
        return res.json({ message: 'File already deleted or does not exist' });
      }
      return res.status(500).json({ message: 'Failed to delete file' });
    }
    console.log('File deleted successfully:', filename);
    res.json({ message: 'File deleted successfully' });
  });
});

// Cleanup old files endpoint (optional - for maintenance)
app.post('/api/cleanup-old-files', authenticateToken, (req, res) => {
  const cutoffTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago
  
  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading uploads directory' });
    }
    
    let deletedCount = 0;
    let totalFiles = files.length;
    
    if (totalFiles === 0) {
      return res.json({ message: 'No files to cleanup', deletedCount: 0 });
    }
    
    files.forEach((file) => {
      const filePath = path.join(uploadsDir, file);
      fs.stat(filePath, (err, stats) => {
        if (err) return;
        
        if (stats.mtimeMs < cutoffTime) {
          fs.unlink(filePath, (err) => {
            if (!err) deletedCount++;
            totalFiles--;
            if (totalFiles === 0) {
              res.json({ message: `Cleanup completed. Deleted ${deletedCount} old files.`, deletedCount });
            }
          });
        } else {
          totalFiles--;
          if (totalFiles === 0) {
            res.json({ message: `Cleanup completed. Deleted ${deletedCount} old files.`, deletedCount });
          }
        }
      });
    });
  });
});

// SQLite database setup with updated schema
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) console.error('SQLite error:', err.message);
  else {
    // Updated messages table to include file fields
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      "from" TEXT, 
      "to" TEXT, 
      message TEXT, 
      timestamp TEXT, 
      isRead INTEGER DEFAULT 0,
      fileUrl TEXT NULL,
      fileName TEXT NULL,
      fileType TEXT NULL
    )`, (err) => {
      if (err) {
        console.error('Error creating messages table:', err);
      } else {
        // Add new columns to existing table if they don't exist
        db.run(`ALTER TABLE messages ADD COLUMN fileUrl TEXT NULL`, () => {});
        db.run(`ALTER TABLE messages ADD COLUMN fileName TEXT NULL`, () => {});
        db.run(`ALTER TABLE messages ADD COLUMN fileType TEXT NULL`, () => {});
      }
    });
    
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

     // 🔹 NEW: Create user_contacts table for 5-user limit
    db.run(`CREATE TABLE IF NOT EXISTS user_contacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      contact_email TEXT NOT NULL,
      contact_username TEXT NOT NULL,
      added_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_email, contact_email)
    )`, (err) => {
      if (err) {
        console.error('Error creating user_contacts table:', err);
      } else {
        console.log('User contacts table created successfully');
      }
    });
    
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

// 🔹 NEW: User contact management functions
function addUserContact(userEmail, contactEmail, contactUsername) {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO user_contacts (user_email, contact_email, contact_username) VALUES (?, ?, ?)',
      [userEmail, contactEmail, contactUsername],
      function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            reject(new Error('User already added'));
          } else {
            reject(err);
          }
        } else {
          resolve(this.lastID);
        }
      }
    );
  });
}

function getUserContacts(userEmail) {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT contact_email, contact_username, added_at FROM user_contacts WHERE user_email = ? ORDER BY added_at DESC',
      [userEmail],
      (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      }
    );
  });
}

function removeUserContact(userEmail, contactEmail) {
  return new Promise((resolve, reject) => {
    db.run(
      'DELETE FROM user_contacts WHERE user_email = ? AND contact_email = ?',
      [userEmail, contactEmail],
      function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      }
    );
  });
}

function getUserContactCount(userEmail) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT COUNT(*) as count FROM user_contacts WHERE user_email = ?',
      [userEmail],
      (err, row) => {
        if (err) reject(err);
        else resolve(row.count);
      }
    );
  });
}

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

// 🔹 UPDATED: Modified to include added users
async function getOnlineUsers(currentUserEmail = null) {
  const onlineUsers = Array.from(connectedUsers.values()).map(user => ({
    email: user.email,
    username: user.username,
    connectedAt: user.connectedAt
  }));

  if (currentUserEmail) {
    // Get user's added contacts
    try {
      const addedContacts = await getUserContacts(currentUserEmail);
      
      // Create a combined list: online users + added contacts (avoiding duplicates)
      const combinedUsers = [];
      const seenEmails = new Set();

      // Add online users first
      onlineUsers.forEach(user => {
        if (user.email !== currentUserEmail) {
          combinedUsers.push({ ...user, isOnline: true });
          seenEmails.add(user.email);
        }
      });

      // Add offline contacts that aren't already included
      addedContacts.forEach(contact => {
        if (!seenEmails.has(contact.contact_email)) {
          combinedUsers.push({
            email: contact.contact_email,
            username: contact.contact_username,
            connectedAt: null,
            isOnline: false
          });
          seenEmails.add(contact.contact_email);
        }
      });

      return combinedUsers;
    } catch (error) {
      console.error('Error getting combined user list:', error);
      // Return just online users if there's an error
      return onlineUsers.filter(user => user.email !== currentUserEmail);
    }
  }

  return onlineUsers;
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

  // 🔹 UPDATED: Send combined user list including added contacts
  const combinedUsers = await getOnlineUsers(user.email);

  ws.send(JSON.stringify({
    type: 'connection-success',
    data: { 
      message: `Connected successfully as ${user.username}`, 
      userId, 
      onlineUsers: combinedUsers // Send combined users on connection    
      }
  }));

  broadcast({ 
    type: 'user-connected', 
    data: { 
      email: user.email, 
      username: user.username, 
      message: `${user.username} joined the chat`, 
      timestamp: new Date().toISOString(), 
      onlineUsers: await getOnlineUsers() 
    } 
  }, ws);

  ws.on('message', async (data) => {
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
          // 🔹 FIXED: Send combined users list as array
          const usersList = await getOnlineUsers(user.email);
          ws.send(JSON.stringify({ 
            type: 'online-users', 
            data: { users: usersList } 
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

  ws.on('close', async () => {
    console.log(`User disconnected: ${user.email} (ID: ${userId})`);
    connectedUsers.delete(userId);
    emailToWs.delete(user.email);
    
      // 🔹 FIXED: Send updated users list on disconnect
    const updatedUsers = await getOnlineUsers();
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



// 🔹 FIXED: Make sure getOnlineUsers always returns an array
async function getOnlineUsers(currentUserEmail = null) {
  const onlineUsers = Array.from(connectedUsers.values()).map(user => ({
    email: user.email,
    username: user.username,
    connectedAt: user.connectedAt
  }));

  if (currentUserEmail) {
    // Get user's added contacts
    try {
      const addedContacts = await getUserContacts(currentUserEmail);
      
      // Create a combined list: online users + added contacts (avoiding duplicates)
      const combinedUsers = [];
      const seenEmails = new Set();

      // Add online users first
      onlineUsers.forEach(user => {
        if (user.email !== currentUserEmail) {
          combinedUsers.push({ ...user, isOnline: true });
          seenEmails.add(user.email);
        }
      });

      // Add offline contacts that aren't already included
      addedContacts.forEach(contact => {
        if (!seenEmails.has(contact.contact_email)) {
          combinedUsers.push({
            email: contact.contact_email,
            username: contact.contact_username,
            connectedAt: null,
            isOnline: false
          });
          seenEmails.add(contact.contact_email);
        }
      });

      console.log(`Returning ${combinedUsers.length} users for ${currentUserEmail}`);
      return combinedUsers;
    } catch (error) {
      console.error('Error getting combined user list:', error);
      // Return just online users if there's an error
      return onlineUsers.filter(user => user.email !== currentUserEmail);
    }
  }

  return onlineUsers;
}

// Message handling functions
function handlePrivateMessage(senderWs, senderEmail, data) {
  const { recipientEmail, message, timestamp, fileUrl, fileName, fileType } = data;
  
  if (!recipientEmail || (!message && !fileUrl)) {
    senderWs.send(JSON.stringify({ 
      type: 'message-error', 
      data: { 
        error: 'Missing recipient email or message content', 
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

  // Save message to database with file information
  db.run(
    'INSERT INTO messages ("from", "to", message, timestamp, isRead, fileUrl, fileName, fileType) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [senderEmail, recipientEmail, messageData.message, messageData.timestamp, 0, messageData.fileUrl, messageData.fileName, messageData.fileType],
    (err) => {
      if (err) {
        console.error('Message save error:', err);
        senderWs.send(JSON.stringify({ 
          type: 'message-error', 
          data: { 
            error: 'Failed to save message', 
            timestamp: new Date().toISOString() 
          } 
        }));
        return;
      }
      
      console.log('Message saved:', {
        from: senderEmail,
        to: recipientEmail,
        hasText: !!message,
        hasFile: !!fileUrl,
        fileName: fileName
      });
      
      // Try to deliver to recipient
      if (sendToUser(recipientEmail, { type: 'private-message', data: messageData })) {
        senderWs.send(JSON.stringify({ 
          type: 'message-sent', 
          data: { ...messageData, status: 'delivered' } 
        }));
      } else {
        // Recipient is offline, message is saved and will be delivered when they connect
        senderWs.send(JSON.stringify({ 
          type: 'message-sent', 
          data: { ...messageData, status: 'saved' } 
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
    connectedUsers: connectedUsers.size,
    uploadsDir: uploadsDir
  });
});

// Get message history with file information
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
      console.log(`Fetched ${rows.length} messages for user: ${userEmail}`);
      res.json({ messages: rows });
    }
  );
});

// Get file information (optional endpoint)
app.get('/api/file-info/:filename', authenticateToken, (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(uploadsDir, filename);
  
  fs.stat(filePath, (err, stats) => {
    if (err) {
      if (err.code === 'ENOENT') {
        return res.status(404).json({ message: 'File not found' });
      }
      return res.status(500).json({ message: 'File access error' });
    }
    
    res.json({
      filename,
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
      exists: true
    });
  });
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

// 🔹 FIXED: Add validate-token endpoint
app.get('/validate-token', authenticateToken, (req, res) => {
  // If this route is reached, token is valid (assuming auth middleware)
  res.json({ 
    valid: true, 
    user: {
      email: req.user.email,
      username: req.user.username
    }
  });
});

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

// Add this to your server code
app.get('/check-user/:email', authenticateToken, async (req, res) => {
  const { email } = req.params;
  const currentUserEmail = req.user.email;
  
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

   if (email === currentUserEmail) {
    return res.status(400).json({ message: 'Cannot add yourself' });
  }

  try {
    const user = await User.findOne({ email, isActive: true });
    if (user) {
       // Check if user is already added
      const contactCount = await getUserContactCount(currentUserEmail);
      const isAlreadyAdded = await new Promise((resolve, reject) => {
        db.get(
          'SELECT 1 FROM user_contacts WHERE user_email = ? AND contact_email = ?',
          [currentUserEmail, email],
          (err, row) => {
            if (err) reject(err);
            else resolve(!!row);
          }
        );
      });

      res.json({ 
        exists: true,
        username: user.username,
        canAdd: contactCount < 5 && !isAlreadyAdded,
        isAlreadyAdded,
        currentContactCount: contactCount
      });
    } else {
      res.json({ exists: false });
    }
  } catch (error) {
    console.error('Check user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add this to your server code
app.post('/add-user', authenticateToken, async (req, res) => {
  const { email } = req.body;
  const currentUserEmail = req.user.email;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  if (email === currentUserEmail) {
    return res.status(400).json({ message: 'Cannot add yourself' });
  }

  try {
     // Check current contact count
    const currentCount = await getUserContactCount(currentUserEmail);
    if (currentCount >= 5) {
      return res.status(400).json({ 
        message: 'You can only add up to 5 users. Remove a user first to add a new one.',
        currentCount
      });
    }

     // Check if user exists
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Add user to contacts
    await addUserContact(currentUserEmail, email, user.username);

    // Check if already added (you might want to store this in a database)
    // For now, we'll just return success
    res.json({
      success: true,
      message: 'User added successfully',
      user: {
        email: user.email,
        username: user.username
      },
      currentCount: currentCount + 1
    });
 } catch (error) {
    console.error('Add user error:', error);
    if (error.message === 'User already added') {
      return res.status(400).json({ message: 'User is already in your contacts' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Add this to your server code
app.get('/added-users', authenticateToken, async (req, res) => {
  const currentUserEmail = req.user.email;

  try {
    const contacts = await getUserContacts(currentUserEmail);
    res.json({
      users: contacts.map(contact => ({
        email: contact.contact_email,
        username: contact.contact_username,
        addedAt: contact.added_at
      })),
      count: contacts.length,
      maxCount: 5
    });
  } catch (error) {
    console.error('Get added users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add this to your server code Remove user
app.delete('/remove-user/:email', authenticateToken, async (req, res) => {
  const { email } = req.params;
  const currentUserEmail = req.user.email;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  try {
    const removedCount = await removeUserContact(currentUserEmail, email);
    
    if (removedCount === 0) {
      return res.status(404).json({ message: 'User not found in your contacts' });
    }

    const remainingCount = await getUserContactCount(currentUserEmail);

    res.json({
      success: true,
      message: 'User removed successfully',
      remainingCount
    });
  } catch (error) {
    console.error('Remove user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/validate-token', authenticateToken, (req, res) => {
  res.json({ 
    valid: true, 
    user: {
      email: req.user.email,
      username: req.user.username
    }
  });
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`WebSocket server running on port ${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}?token=your-jwt-token`);
  console.log(`HTTP API available at: http://localhost:${PORT}/api`);
  console.log(`Uploads directory: ${uploadsDir}`);
});
