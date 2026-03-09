require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_dev_key_change_me_in_prod';

// ── SECURITY: Warn if using default JWT secret ──
if (JWT_SECRET === 'super_secret_dev_key_change_me_in_prod') {
  console.warn('⚠️  WARNING: Using default JWT_SECRET. Set a real secret in .env for production!');
}

// ── SECURITY: Helmet sets secure HTTP headers ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],  // needed for onclick handlers in index.html
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
}));

// ── SECURITY: CORS — restrict in production ──
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000'];
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, same-origin)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));

// ── SECURITY: Limit request body size to 10KB ──
app.use(express.json({ limit: '10kb' }));

// ── SECURITY: Rate limiting — prevent brute force & abuse ──
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // 10 attempts per window
  message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const estimateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,              // 5 estimates per minute
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,            // 100 requests per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

app.use(express.static(path.join(__dirname, 'public')));

// ── Database Setup (SQLite) ──
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Error opening database', err);
  else console.log('✅ Connected to SQLite database.');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      free_credits INTEGER DEFAULT 3,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// ── SECURITY: Input sanitizer ──
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'&]/g, (char) => {
    const map = { '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;', '&': '&amp;' };
    return map[char] || char;
  }).trim().slice(0, 2000); // Cap input length
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

// ── Auth Middleware ──
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Please log in or create an account to continue.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Your session has expired. Please log in again.' });
    req.user = user;
    next();
  });
}

// ── API Route: Register (RATE LIMITED) ──
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  // SECURITY: Validate email format
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!password || password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be 6-128 characters.' });
  }

  try {
    const sanitizedEmail = email.toLowerCase().trim();
    const hash = await bcrypt.hash(password, 12); // SECURITY: increased from 10 to 12 rounds

    db.run(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [sanitizedEmail, hash],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email already exists. Please log in.' });
          }
          console.error(err);
          return res.status(500).json({ error: 'Internal server error.' });
        }

        const userId = this.lastID;
        const token = jwt.sign({ id: userId, email: sanitizedEmail }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
          message: 'Account created successfully!',
          token,
          user: { id: userId, email: sanitizedEmail, free_credits: 3 }
        });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ── API Route: Login (RATE LIMITED) ──
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const sanitizedEmail = email.toLowerCase().trim();

  db.get('SELECT * FROM users WHERE email = ?', [sanitizedEmail], async (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Logged in successfully!',
      token,
      user: { id: user.id, email: user.email, free_credits: user.free_credits }
    });
  });
});

// ── API Route: Get Current User ──
app.get('/api/user/me', authenticateToken, (req, res) => {
  db.get('SELECT id, email, free_credits FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ user });
  });
});

// ── Demo data generator ──
function generateDemoEstimate(services, usecase, region, traffic, pricingModel, environment) {
  const serviceList = services.split(',').map(s => s.trim()).filter(Boolean);

  const servicePricing = {
    'EC2': { base: 62.00, notes: 't3.medium On-Demand Linux' },
    'RDS': { base: 28.50, notes: 'db.t3.small PostgreSQL Single-AZ' },
    'S3': { base: 2.30, notes: 'Standard storage ~50GB + requests' },
    'Lambda': { base: 4.20, notes: '1M invocations/mo, 256MB, 200ms avg' },
    'CloudFront': { base: 8.50, notes: '100GB transfer, 1M requests' },
    'EKS': { base: 73.00, notes: 'Cluster fee + 2 t3.medium nodes' },
    'ECS': { base: 45.00, notes: '2 Fargate tasks, 0.5vCPU/1GB' },
    'ElastiCache': { base: 24.80, notes: 'cache.t3.micro Redis single-node' },
    'SQS': { base: 1.20, notes: '~500K requests/mo Standard queue' },
    'SNS': { base: 0.80, notes: '~100K notifications/mo' },
    'API Gateway': { base: 10.50, notes: 'REST API, 1M requests/mo' },
    'DynamoDB': { base: 12.75, notes: '25 WCU/RCU On-Demand' },
    'Elasticsearch': { base: 38.40, notes: 't3.small.search single-node' },
    'NAT Gateway': { base: 32.40, notes: 'Single AZ + 10GB data processing' },
    'Route 53': { base: 1.50, notes: '1 hosted zone + 1M queries' },
    'ELB': { base: 22.50, notes: 'Application Load Balancer + 10 LCU-hours' },
    'EBS': { base: 8.00, notes: '100GB gp3 volume' },
    'CloudWatch': { base: 3.50, notes: '10 custom metrics + 5 alarms + 1GB logs' },
    'Cognito': { base: 5.25, notes: '10K MAU, basic auth features' },
    'Step Functions': { base: 2.50, notes: '10K state transitions/mo' },
    'Redshift': { base: 180.00, notes: 'dc2.large single-node cluster' },
    'Kinesis': { base: 14.40, notes: '1 shard, 24hr retention' },
    'SES': { base: 1.00, notes: '10K emails/mo' },
    'ECR': { base: 1.50, notes: '~15GB stored images' },
    'Secrets Manager': { base: 2.00, notes: '5 secrets, 10K API calls/mo' },
  };

  const trafficMultiplier = { 'Low': 0.7, 'Medium': 1.0, 'High': 2.2, 'Very High': 4.5 };
  const envMultiplier = { 'Production': 1.0, 'Staging': 0.6, 'Development': 0.35 };
  const pricingMultiplier = { 'On-Demand': 1.0, '1-Year Reserved': 0.65, '3-Year Reserved': 0.42, 'Spot': 0.35 };

  const tMult = Object.entries(trafficMultiplier).find(([k]) => traffic.includes(k))?.[1] || 1.0;
  const eMult = Object.entries(envMultiplier).find(([k]) => environment.includes(k))?.[1] || 1.0;
  const pMult = Object.entries(pricingMultiplier).find(([k]) => pricingModel.includes(k))?.[1] || 1.0;

  const breakdown = serviceList.map(svc => {
    const match = Object.entries(servicePricing).find(([k]) => svc.toLowerCase().includes(k.toLowerCase()));
    const pricing = match ? match[1] : { base: 15.00, notes: 'Estimated usage' };
    const cost = Math.round(pricing.base * tMult * eMult * pMult * 100) / 100;
    return {
      service: sanitize(svc),
      monthly_usd: cost,
      notes: pricing.notes + (pMult < 1 ? ` (${pricingModel.split(' ')[0]} pricing)` : ''),
    };
  });

  if (breakdown.length === 0) {
    breakdown.push(
      { service: 'EC2 (t3.medium x2)', monthly_usd: 124.00 * eMult * pMult, notes: 'On-Demand Linux' },
      { service: 'RDS (db.t3.small)', monthly_usd: 28.50 * eMult * pMult, notes: 'PostgreSQL Single-AZ' },
      { service: 'S3 (50GB)', monthly_usd: 2.30 * eMult, notes: 'Standard storage' },
    );
  }

  const monthly_usd = Math.round(breakdown.reduce((sum, b) => sum + b.monthly_usd, 0) * 100) / 100;

  return {
    monthly_usd,
    annual_usd: Math.round(monthly_usd * 12 * 100) / 100,
    usd_inr_rate: 83.5,
    breakdown: breakdown.map(b => ({ ...b, monthly_usd: Math.round(b.monthly_usd * 100) / 100 })),
    summary: `Estimated monthly cost for a ${sanitize(environment).toLowerCase()} environment in ${sanitize(region).split(' ')[0]} using ${sanitize(pricingModel).split('(')[0].trim()} pricing. Covers ${breakdown.length} service(s) with ${sanitize(traffic).toLowerCase()} traffic.`,
    optimizations: [
      'Consider Reserved Instances for steady-state workloads to save up to 60%',
      'Use S3 Intelligent-Tiering for automatic storage cost optimization',
      'Enable Auto Scaling to match capacity with demand and reduce idle costs'
    ],
    confidence: 'medium',
    demo_mode: true,
  };
}

// ── API Route: Cost Estimate (PROTECTED + RATE LIMITED) ──
app.post('/api/estimate', authenticateToken, estimateLimiter, (req, res) => {
  const { services, usecase, region, traffic, pricingModel, environment, additional } = req.body;
  const userId = req.user.id;

  // SECURITY: Sanitize all user inputs
  const cleanServices = sanitize(services || '');
  const cleanUsecase = sanitize(usecase || '');
  const cleanRegion = sanitize(region || 'us-east-1');
  const cleanTraffic = sanitize(traffic || 'Medium');
  const cleanPricing = sanitize(pricingModel || 'On-Demand');
  const cleanEnv = sanitize(environment || 'Production');
  const cleanAdditional = sanitize(additional || '');

  if (!cleanServices && !cleanUsecase) {
    return res.status(400).json({ error: 'Please provide services or a use case description.' });
  }

  db.get('SELECT free_credits FROM users WHERE id = ?', [userId], async (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error.' });
    if (!row) return res.status(404).json({ error: 'User not found.' });

    if (row.free_credits <= 0) {
      return res.status(403).json({
        error: 'You have NO credits remaining. Please buy more credits.',
        out_of_credits: true
      });
    }

    const apiKey = process.env.ANTHROPIC_API_KEY;
    let estimateResult;

    try {
      if (!apiKey || apiKey === 'your_key_here') {
        console.log(`⚡ [User ${userId}] requested estimate (Demo Mode)`);
        await new Promise(resolve => setTimeout(resolve, 1500));
        estimateResult = generateDemoEstimate(
          cleanServices, cleanUsecase, cleanRegion,
          cleanTraffic, cleanPricing, cleanEnv
        );
      } else {
        console.log(`⚡ [User ${userId}] requested estimate (Live AI)`);

        const prompt = `You are an expert AWS Solutions Architect and cost analyst.
Estimate the monthly AWS infrastructure cost for the following setup:
**AWS Services:** ${cleanServices || 'Not specified'}
**Use Case Description:** ${cleanUsecase || 'Not specified'}
**AWS Region:** ${cleanRegion}
**Expected Traffic:** ${cleanTraffic}
**Pricing Model:** ${cleanPricing}
**Environment:** ${cleanEnv}
**Additional Requirements:** ${cleanAdditional || 'None'}

Provide a detailed response in this EXACT JSON format only, no markdown:
{
  "monthly_usd": 92.80, "annual_usd": 1113.60, "usd_inr_rate": 83.5,
  "breakdown": [{"service": "EC2", "monthly_usd": 62.00, "notes": "notes"}],
  "summary": "...", "optimizations": ["..."], "confidence": "medium"
}
Return ONLY the JSON. No extra text.`;

        const response = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1500,
            messages: [{ role: 'user', content: prompt }],
          }),
        });

        if (!response.ok) throw new Error(`Anthropic API error: ${response.status}`);
        const data = await response.json();
        const rawText = data.content[0].text;
        const clean = rawText.replace(/```json|```/g, '').trim();
        estimateResult = JSON.parse(clean);
      }

      db.run('UPDATE users SET free_credits = free_credits - 1 WHERE id = ?', [userId], function (updateErr) {
        if (updateErr) {
          console.error("Failed to deduct credit, but returning estimate:", updateErr);
        } else {
          estimateResult.remaining_credits = row.free_credits - 1;
        }
        res.json(estimateResult);
      });

    } catch (err) {
      console.error('Estimate error:', err);
      // SECURITY: Don't leak internal error details to the client
      res.status(500).json({ error: 'Failed to generate estimate. Please try again.' });
    }
  });
});

// ── Catch-all: serve index.html for SPA ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ──
app.listen(PORT, () => {
  const hasKey = process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'your_key_here';
  console.log('');
  console.log('  ╔═══════════════════════════════════════════════╗');
  console.log('  ║                                               ║');
  console.log('  ║   ☁  CloudCost.io — AWS Cost Estimator        ║');
  console.log(`  ║   🌐 http://localhost:${PORT}                    ║`);
  console.log(`  ║   🤖 AI Mode: ${hasKey ? 'LIVE (Anthropic API)' : 'DEMO (sample data)'}       ║`);
  console.log('  ║   🔒 Auth: SQLite + JWT Enabled               ║');
  console.log('  ║   🛡️  Security: Helmet + Rate Limit + Sanitize ║');
  console.log('  ║                                               ║');
  console.log('  ╚═══════════════════════════════════════════════╝');
  console.log('');
});
