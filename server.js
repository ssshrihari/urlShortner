const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const app = express();

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = '7d';

// Multer configuration for file uploads
const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
      cb(null, true);
    } else {
      cb(new Error('Only CSV files are allowed'));
    }
  }
});

// Enhanced Rate limiting with different tiers
const strictAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many auth attempts, please try again later.' }
});

const urlLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: (req) => {
    // Authenticated users get higher limits
    return req.headers.authorization ? 20 : 5;
  },
  message: { error: 'Rate limit exceeded. Please try again later.' }
});

const bulkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Only 3 bulk operations per hour
  message: { error: 'Bulk upload limit exceeded. Please try again in an hour.' }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // General API limit
  message: { error: 'API rate limit exceeded' }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(apiLimiter); // Apply general rate limiting to all routes

// In-memory storage (use database in production)
const urlDatabase = new Map();
const stats = new Map();
const users = new Map(); // userId -> user data
const userUrls = new Map(); // userId -> Set of shortCodes
const passwordProtectedUrls = new Map(); // shortCode -> hashedPassword

// Utility functions
function isExpired(url) {
  if (!url.expiresAt) return false;
  return new Date() > new Date(url.expiresAt);
}

function parseExpiration(expirationInput) {
  if (!expirationInput) return null;
  
  const now = new Date();
  const input = expirationInput.toLowerCase();
  
  if (input.includes('hour')) {
    const hours = parseInt(input) || 1;
    return new Date(now.getTime() + hours * 60 * 60 * 1000);
  } else if (input.includes('day')) {
    const days = parseInt(input) || 1;
    return new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
  } else if (input.includes('week')) {
    const weeks = parseInt(input) || 1;
    return new Date(now.getTime() + weeks * 7 * 24 * 60 * 60 * 1000);
  } else if (input.includes('month')) {
    const months = parseInt(input) || 1;
    const futureDate = new Date(now);
    futureDate.setMonth(futureDate.getMonth() + months);
    return futureDate;
  }
  
  // Try to parse as date
  const parsed = new Date(expirationInput);
  return isNaN(parsed.getTime()) ? null : parsed;
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Optional authentication middleware (allows both authenticated and anonymous users)
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
}

// Generate short code
function generateShortCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Validate URL
function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// Authentication Routes

// Register new user
app.post('/api/auth/register', strictAuthLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    
    // Check if user already exists
    for (const [userId, userData] of users.entries()) {
      if (userData.email === email || userData.username === username) {
        return res.status(400).json({ error: 'User with this email or username already exists' });
      }
    }
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create user
    const userId = Date.now().toString();
    const user = {
      id: userId,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };
    
    users.set(userId, user);
    userUrls.set(userId, new Set());
    
    // Generate token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      },
      token
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login user
app.post('/api/auth/login', strictAuthLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user by email
    let foundUser = null;
    for (const [userId, userData] of users.entries()) {
      if (userData.email === email) {
        foundUser = userData;
        break;
      }
    }
    
    if (!foundUser) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Check password
    const passwordMatch = await bcrypt.compare(password, foundUser.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: foundUser.id, username: foundUser.username, email: foundUser.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    res.json({
      message: 'Login successful',
      user: {
        id: foundUser.id,
        username: foundUser.username,
        email: foundUser.email,
        createdAt: foundUser.createdAt
      },
      token
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  const user = users.get(req.user.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const userUrlCount = userUrls.get(req.user.userId)?.size || 0;
  let totalClicks = 0;
  
  if (userUrls.has(req.user.userId)) {
    for (const shortCode of userUrls.get(req.user.userId)) {
      const urlData = urlDatabase.get(shortCode);
      if (urlData) {
        totalClicks += urlData.clicks;
      }
    }
  }
  
  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt
    },
    stats: {
      totalUrls: userUrlCount,
      totalClicks
    }
  });
});

// API Routes

// Shorten URL (enhanced with expiration and password protection)
app.post('/api/shorten', urlLimiter, optionalAuth, async (req, res) => {
  const { url, customCode, expiresIn, password } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  if (!isValidUrl(url)) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  
  let shortCode = customCode;
  
  // Check if custom code is provided and available
  if (customCode) {
    if (urlDatabase.has(customCode)) {
      return res.status(400).json({ error: 'Custom code already exists' });
    }
    if (!/^[a-zA-Z0-9]{3,10}$/.test(customCode)) {
      return res.status(400).json({ error: 'Custom code must be 3-10 alphanumeric characters' });
    }
  } else {
    // Generate unique short code
    do {
      shortCode = generateShortCode();
    } while (urlDatabase.has(shortCode));
  }
  
  // Parse expiration
  const expiresAt = expiresIn ? parseExpiration(expiresIn) : null;
  if (expiresIn && !expiresAt) {
    return res.status(400).json({ error: 'Invalid expiration format. Use formats like "1 hour", "2 days", "1 week", or a specific date.' });
  }
  
  // Hash password if provided
  let hashedPassword = null;
  if (password) {
    if (password.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters long' });
    }
    hashedPassword = await bcrypt.hash(password, 8);
    passwordProtectedUrls.set(shortCode, hashedPassword);
  }
  
  // Store URL with metadata
  urlDatabase.set(shortCode, {
    originalUrl: url,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
    clicks: 0,
    userId: req.user ? req.user.userId : null,
    isAnonymous: !req.user,
    hasPassword: !!password
  });
  
  // Add to user's URLs if authenticated
  if (req.user) {
    if (!userUrls.has(req.user.userId)) {
      userUrls.set(req.user.userId, new Set());
    }
    userUrls.get(req.user.userId).add(shortCode);
  }
  
  stats.set(shortCode, []);
  
  const shortUrl = `${req.protocol}://${req.get('host')}/${shortCode}`;
  
  res.json({
    originalUrl: url,
    shortUrl,
    shortCode,
    createdAt: urlDatabase.get(shortCode).createdAt,
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
    hasPassword: !!password
  });
});

// Bulk URL shortening
app.post('/api/bulk-shorten', bulkLimiter, authenticateToken, upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'CSV file is required' });
    }

    const results = [];
    const errors = [];
    
    // Read and parse CSV file
    const csvData = [];
    
    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on('data', (row) => {
        csvData.push(row);
      })
      .on('end', async () => {
        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
        
        // Process each URL
        for (let i = 0; i < csvData.length && i < 100; i++) { // Limit to 100 URLs
          const row = csvData[i];
          const url = row.url || row.URL || row.link || Object.values(row)[0];
          const customCode = row.customCode || row.code;
          const expiresIn = row.expiresIn || row.expiration;
          const password = row.password;
          
          if (!url || !isValidUrl(url)) {
            errors.push({ row: i + 1, error: 'Invalid or missing URL', data: row });
            continue;
          }
          
          try {
            // Generate short code
            let shortCode = customCode;
            if (customCode) {
              if (urlDatabase.has(customCode)) {
                errors.push({ row: i + 1, error: 'Custom code already exists', data: row });
                continue;
              }
              if (!/^[a-zA-Z0-9]{3,10}$/.test(customCode)) {
                errors.push({ row: i + 1, error: 'Invalid custom code format', data: row });
                continue;
              }
            } else {
              do {
                shortCode = generateShortCode();
              } while (urlDatabase.has(shortCode));
            }
            
            // Parse expiration
            const expiresAt = expiresIn ? parseExpiration(expiresIn) : null;
            
            // Hash password if provided
            let hashedPassword = null;
            if (password) {
              if (password.length < 4) {
                errors.push({ row: i + 1, error: 'Password too short', data: row });
                continue;
              }
              hashedPassword = await bcrypt.hash(password, 8);
              passwordProtectedUrls.set(shortCode, hashedPassword);
            }
            
            // Store URL
            urlDatabase.set(shortCode, {
              originalUrl: url,
              createdAt: new Date().toISOString(),
              expiresAt: expiresAt ? expiresAt.toISOString() : null,
              clicks: 0,
              userId: req.user.userId,
              isAnonymous: false,
              hasPassword: !!password
            });
            
            // Add to user's URLs
            if (!userUrls.has(req.user.userId)) {
              userUrls.set(req.user.userId, new Set());
            }
            userUrls.get(req.user.userId).add(shortCode);
            
            stats.set(shortCode, []);
            
            const shortUrl = `${req.protocol}://${req.get('host')}/${shortCode}`;
            
            results.push({
              originalUrl: url,
              shortUrl,
              shortCode,
              expiresAt: expiresAt ? expiresAt.toISOString() : null,
              hasPassword: !!password
            });
            
          } catch (err) {
            errors.push({ row: i + 1, error: err.message, data: row });
          }
        }
        
        res.json({
          success: true,
          processed: results.length,
          errors: errors.length,
          results,
          errors: errors.slice(0, 10) // Limit error details
        });
      })
      .on('error', (err) => {
        // Clean up uploaded file
        if (req.file && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Error processing CSV file' });
      });

  } catch (error) {
    console.error('Bulk upload error:', error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify password for protected URL
app.post('/api/verify-password/:code', (req, res) => {
  const { code } = req.params;
  const { password } = req.body;
  
  if (!urlDatabase.has(code)) {
    return res.status(404).json({ error: 'Short URL not found' });
  }
  
  const urlData = urlDatabase.get(code);
  
  // Check if URL is expired
  if (isExpired(urlData)) {
    return res.status(410).json({ error: 'This URL has expired' });
  }
  
  if (!passwordProtectedUrls.has(code)) {
    return res.status(400).json({ error: 'This URL is not password protected' });
  }
  
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }
  
  bcrypt.compare(password, passwordProtectedUrls.get(code), (err, result) => {
    if (err || !result) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    
    res.json({ 
      success: true, 
      originalUrl: urlData.originalUrl,
      message: 'Password verified successfully' 
    });
  });
});

// Get URL stats
app.get('/api/stats/:code', (req, res) => {
  const { code } = req.params;
  
  if (!urlDatabase.has(code)) {
    return res.status(404).json({ error: 'Short URL not found' });
  }
  
  const urlData = urlDatabase.get(code);
  const clickStats = stats.get(code) || [];
  
  res.json({
    shortCode: code,
    originalUrl: urlData.originalUrl,
    createdAt: urlData.createdAt,
    totalClicks: urlData.clicks,
    recentClicks: clickStats.slice(-10) // Last 10 clicks
  });
});

// List all URLs (now shows user's URLs if authenticated, or all if admin)
app.get('/api/urls', optionalAuth, (req, res) => {
  const urls = [];
  
  if (req.user) {
    // Show only user's URLs
    const userUrlSet = userUrls.get(req.user.userId) || new Set();
    for (const shortCode of userUrlSet) {
      const data = urlDatabase.get(shortCode);
      if (data) {
        urls.push({
          shortCode,
          originalUrl: data.originalUrl,
          createdAt: data.createdAt,
          clicks: data.clicks,
          isOwned: true
        });
      }
    }
  } else {
    // Show all URLs for anonymous users (limited info)
    for (const [code, data] of urlDatabase.entries()) {
      if (data.isAnonymous) {  // Only show anonymous URLs to anonymous users
        urls.push({
          shortCode: code,
          originalUrl: data.originalUrl,
          createdAt: data.createdAt,
          clicks: data.clicks,
          isOwned: false
        });
      }
    }
  }
  
  res.json(urls.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

// Delete URL (authenticated users only, can only delete their own URLs)
app.delete('/api/urls/:code', authenticateToken, (req, res) => {
  const { code } = req.params;
  
  if (!urlDatabase.has(code)) {
    return res.status(404).json({ error: 'Short URL not found' });
  }
  
  const urlData = urlDatabase.get(code);
  
  // Check if user owns this URL
  if (urlData.userId !== req.user.userId) {
    return res.status(403).json({ error: 'You can only delete your own URLs' });
  }
  
  // Remove from database and user's URLs
  urlDatabase.delete(code);
  stats.delete(code);
  if (userUrls.has(req.user.userId)) {
    userUrls.get(req.user.userId).delete(code);
  }
  
  res.json({ message: 'URL deleted successfully' });
});

// Redirect route (enhanced with password protection and expiration)
app.get('/:code', (req, res) => {
  const { code } = req.params;
  
  if (!urlDatabase.has(code)) {
    return res.status(404).send(`
      <html>
        <head><title>URL Not Found</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1>404 - URL Not Found</h1>
          <p>The short URL you're looking for doesn't exist.</p>
          <a href="/">Create a new short URL</a>
        </body>
      </html>
    `);
  }
  
  const urlData = urlDatabase.get(code);
  
  // Check if URL is expired
  if (isExpired(urlData)) {
    return res.status(410).send(`
      <html>
        <head><title>URL Expired</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1>⏰ URL Expired</h1>
          <p>This short URL has expired and is no longer available.</p>
          <p><small>Expired on: ${new Date(urlData.expiresAt).toLocaleString()}</small></p>
          <a href="/">Create a new short URL</a>
        </body>
      </html>
    `);
  }
  
  // Check if URL is password protected
  if (passwordProtectedUrls.has(code)) {
    return res.send(`
      <html>
        <head>
          <title>Password Protected URL</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; margin: 0; display: flex; align-items: center; justify-content: center; }
            .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 400px; width: 100%; }
            h1 { color: #333; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; }
            button { width: 100%; padding: 12px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; }
            button:hover { opacity: 0.9; }
            .error { color: #dc3545; margin-top: 10px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🔒 Password Protected</h1>
            <p>This URL is password protected. Please enter the password to continue.</p>
            <form onsubmit="verifyPassword(event)">
              <input type="password" id="password" placeholder="Enter password" required>
              <button type="submit">Access URL</button>
            </form>
            <div id="error" class="error"></div>
          </div>
          
          <script>
            async function verifyPassword(event) {
              event.preventDefault();
              const password = document.getElementById('password').value;
              const errorDiv = document.getElementById('error');
              
              try {
                const response = await fetch('/api/verify-password/${code}', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                  window.location.href = data.originalUrl;
                } else {
                  errorDiv.textContent = data.error || 'Invalid password';
                }
              } catch (err) {
                errorDiv.textContent = 'Error verifying password';
              }
            }
          </script>
        </body>
      </html>
    `);
  }
  
  // Update click count and stats
  urlData.clicks++;
  const clickData = {
    timestamp: new Date().toISOString(),
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress
  };
  
  if (!stats.has(code)) stats.set(code, []);
  stats.get(code).push(clickData);
  
  // Keep only last 100 clicks per URL
  if (stats.get(code).length > 100) {
    stats.get(code).shift();
  }
  
  res.redirect(urlData.originalUrl);
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`URL Shortener running on the port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to use the service`);
});