// ============================================================
// VELA — Complete Production Backend v3.0
// Railway / Node.js — Full feature backend
// Routes: Auth, Users, Tasks, Budget, Diet, Fitness,
//         Habits, Calendar, Travel, Vault, Social, Admin, Payments
// ============================================================

'use strict';

const express      = require('express');
const path         = require('path');
const crypto       = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// ENVIRONMENT VARIABLES
// Set all of these in Railway → Variables tab
// ============================================================
const ENV = {
  SUPABASE_URL:          process.env.SUPABASE_URL          || 'https://rhvwtvzaujxmerqkhdlv.supabase.co',
  SUPABASE_ANON_KEY:     process.env.SUPABASE_ANON_KEY     || '',
  // Railway has this as SUPABASE_SERVICE — support both names
  SUPABASE_SERVICE_KEY:  process.env.SUPABASE_SERVICE_KEY  || process.env.SUPABASE_SERVICE || '',
  RAZORPAY_KEY_ID:       process.env.RAZORPAY_KEY_ID       || '',
  RAZORPAY_KEY_SECRET:   process.env.RAZORPAY_KEY_SECRET   || '',
  RAZORPAY_WEBHOOK_SECRET: process.env.RAZORPAY_WEBHOOK_SECRET || '',
  APP_URL:               process.env.APP_URL               || 'https://vela.grassion.com',
  NODE_ENV:              process.env.NODE_ENV              || 'development',
  ADMIN_EMAIL:           process.env.ADMIN_EMAIL           || 'saisnatadash@grassion.com',
  JWT_SECRET:            process.env.JWT_SECRET            || '',
};

// ============================================================
// SUPABASE CLIENTS
// ============================================================
const sb = createClient(ENV.SUPABASE_URL, ENV.SUPABASE_ANON_KEY);

const sbAdmin = ENV.SUPABASE_SERVICE_KEY
  ? createClient(ENV.SUPABASE_URL, ENV.SUPABASE_SERVICE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false }
    })
  : null;

if (!sbAdmin) {
  console.warn('[WARN] No SUPABASE_SERVICE_KEY — admin operations disabled');
}

// ============================================================
// RAZORPAY
// ============================================================
let Razorpay = null;
try {
  Razorpay = require('razorpay');
} catch (e) {
  console.warn('[WARN] razorpay package not found — payments disabled');
}

function getRzp() {
  if (!Razorpay || !ENV.RAZORPAY_KEY_ID || !ENV.RAZORPAY_KEY_SECRET) return null;
  return new Razorpay({ key_id: ENV.RAZORPAY_KEY_ID, key_secret: ENV.RAZORPAY_KEY_SECRET });
}

// ============================================================
// REQUEST LOGGING
// ============================================================
function log(level, ...args) {
  const ts = new Date().toISOString();
  console[level === 'error' ? 'error' : 'log'](`[${ts}] [${level.toUpperCase()}]`, ...args);
}

// ============================================================
// MIDDLEWARE
// ============================================================

// Raw body for Razorpay webhook
app.use('/webhook/razorpay', express.raw({ type: 'application/json' }));

// JSON body for everything else
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// CORS
app.use((req, res, next) => {
  const allowed = [
    ENV.APP_URL,
    'http://localhost:3000',
    'http://localhost:5500',
    'https://vela.grassion.com',
    'https://vela-production-58a6.up.railway.app',
  ];
  const origin = req.headers.origin;
  if (!origin || allowed.includes(origin) || ENV.NODE_ENV === 'development') {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, apikey, x-requested-with');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    log(level, `${req.method} ${req.path} → ${res.statusCode} (${ms}ms)`);
  });
  next();
});

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization header missing' });
    }
    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const { data: { user }, error } = await sb.auth.getUser(token);
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.user  = user;
    req.token = token;
    next();
  } catch (err) {
    log('error', 'requireAuth error:', err.message);
    res.status(500).json({ error: 'Auth check failed' });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No authorization header' });
    const token = authHeader.replace('Bearer ', '').trim();

    const { data: { user }, error } = await sb.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid token' });

    if (!sbAdmin) return res.status(503).json({ error: 'Admin client not configured' });

    const { data: profile, error: pErr } = await sbAdmin
      .from('profiles')
      .select('role, plan, full_name')
      .eq('id', user.id)
      .single();

    if (pErr || !profile) return res.status(404).json({ error: 'Profile not found' });
    if (!['admin', 'super_admin'].includes(profile.role)) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    req.user    = user;
    req.token   = token;
    req.profile = profile;
    next();
  } catch (err) {
    log('error', 'requireAdmin error:', err.message);
    res.status(500).json({ error: 'Admin check failed' });
  }
}

// ============================================================
// HELPERS
// ============================================================
function ok(res, data = {}) {
  return res.json({ success: true, ...data });
}

function err(res, status, message) {
  return res.status(status).json({ error: message });
}

function today() {
  return new Date().toISOString().split('T')[0];
}

function nowISO() {
  return new Date().toISOString();
}

async function getProfile(userId) {
  if (!sbAdmin) return null;
  const { data } = await sbAdmin.from('profiles').select('*').eq('id', userId).single();
  return data;
}

async function ensureProfile(user) {
  if (!sbAdmin) return null;
  const existing = await getProfile(user.id);
  if (existing) return existing;

  const { data } = await sbAdmin.from('profiles').insert({
    id:        user.id,
    full_name: user.user_metadata?.full_name || 'User',
    email:     user.email,
    plan:      'free',
    role:      user.email === ENV.ADMIN_EMAIL ? 'admin' : 'user',
    created_at: nowISO(),
    updated_at: nowISO(),
  }).select().single();

  return data;
}

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', async (req, res) => {
  let dbOk = false;
  try {
    if (sbAdmin) {
      const { error } = await sbAdmin.from('profiles').select('id').limit(1);
      dbOk = !error;
    }
  } catch (_) {}

  res.json({
    status:     'ok',
    app:        'VELA',
    version:    '3.0.0',
    env:        ENV.NODE_ENV,
    timestamp:  nowISO(),
    db:         dbOk,
    supabase:   !!ENV.SUPABASE_SERVICE_KEY,
    razorpay:   !!ENV.RAZORPAY_KEY_ID,
    app_url:    ENV.APP_URL,
  });
});

app.get('/api/config', (req, res) => {
  res.json({
    razorpay_key_id: ENV.RAZORPAY_KEY_ID,
    app_url:         ENV.APP_URL,
    env:             ENV.NODE_ENV,
  });
});

// ============================================================
// AUTH ROUTES
// ============================================================

/**
 * POST /api/auth/signup
 * Body: { email, password, full_name }
 * Creates Supabase auth user + profile row
 * Sends verification email automatically via Supabase
 */
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, full_name } = req.body;

    if (!email || !password || !full_name) {
      return err(res, 400, 'Email, password, and full name are required');
    }
    if (password.length < 8) {
      return err(res, 400, 'Password must be at least 8 characters');
    }
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
      return err(res, 400, 'Invalid email address');
    }

    const { data, error } = await sb.auth.signUp({
      email:   email.trim().toLowerCase(),
      password,
      options: {
        data:            { full_name: full_name.trim() },
        emailRedirectTo: `${ENV.APP_URL}/`,
      },
    });

    if (error) return err(res, 400, error.message);

    // If user exists (no new identity created)
    if (data.user && data.user.identities?.length === 0) {
      return err(res, 409, 'Email already registered. Please sign in.');
    }

    // Create profile immediately via admin client
    if (data.user && sbAdmin) {
      await sbAdmin.from('profiles').upsert({
        id:         data.user.id,
        full_name:  full_name.trim(),
        email:      email.trim().toLowerCase(),
        plan:       'free',
        role:       email.trim().toLowerCase() === ENV.ADMIN_EMAIL ? 'admin' : 'user',
        created_at: nowISO(),
        updated_at: nowISO(),
      }, { onConflict: 'id' });
    }

    log('info', `New signup: ${email}`);

    return ok(res, {
      message:           'Account created! Check your email to verify before signing in.',
      needs_verification: true,
      user_id:           data.user?.id,
    });
  } catch (e) {
    log('error', 'Signup error:', e.message);
    return err(res, 500, 'Server error during signup');
  }
});

/**
 * POST /api/auth/signin
 * Body: { email, password }
 */
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return err(res, 400, 'Email and password required');

    const { data, error } = await sb.auth.signInWithPassword({
      email:    email.trim().toLowerCase(),
      password,
    });

    if (error) {
      if (error.message.includes('Email not confirmed')) {
        return err(res, 401, 'Please verify your email first. Check your inbox for the verification link.');
      }
      if (error.message.includes('Invalid login credentials')) {
        return err(res, 401, 'Invalid email or password');
      }
      return err(res, 401, error.message);
    }

    const profile = await ensureProfile(data.user);
    log('info', `Signin: ${email}`);

    return ok(res, {
      session: data.session,
      user:    data.user,
      profile,
    });
  } catch (e) {
    log('error', 'Signin error:', e.message);
    return err(res, 500, 'Server error during signin');
  }
});

/**
 * POST /api/auth/signout
 */
app.post('/api/auth/signout', requireAuth, async (req, res) => {
  try {
    await sb.auth.signOut();
    return ok(res, { message: 'Signed out' });
  } catch (_) {
    return ok(res, { message: 'Signed out' });
  }
});

/**
 * POST /api/auth/resend-verification
 * Body: { email }
 */
app.post('/api/auth/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return err(res, 400, 'Email required');

    const { error } = await sb.auth.resend({
      type:    'signup',
      email:   email.trim().toLowerCase(),
      options: { emailRedirectTo: `${ENV.APP_URL}/` },
    });

    if (error) return err(res, 400, error.message);
    return ok(res, { message: 'Verification email sent! Check your inbox.' });
  } catch (e) {
    return err(res, 500, 'Failed to resend verification email');
  }
});

/**
 * POST /api/auth/forgot-password
 * Body: { email }
 */
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return err(res, 400, 'Email required');

    const { error } = await sb.auth.resetPasswordForEmail(
      email.trim().toLowerCase(),
      { redirectTo: `${ENV.APP_URL}/` }
    );

    if (error) return err(res, 400, error.message);
    return ok(res, { message: 'Password reset email sent! Check your inbox.' });
  } catch (e) {
    return err(res, 500, 'Failed to send password reset email');
  }
});

/**
 * POST /api/auth/update-password
 * Body: { password }
 * Requires auth token
 */
app.post('/api/auth/update-password', requireAuth, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 8) {
      return err(res, 400, 'Password must be at least 8 characters');
    }
    const { error } = await sb.auth.updateUser({ password });
    if (error) return err(res, 400, error.message);
    return ok(res, { message: 'Password updated successfully' });
  } catch (e) {
    return err(res, 500, 'Failed to update password');
  }
});

// ============================================================
// USER PROFILE
// ============================================================

/**
 * GET /api/user/profile
 */
app.get('/api/user/profile', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'Admin client not configured');
    const profile = await getProfile(req.user.id);
    if (!profile) {
      const created = await ensureProfile(req.user);
      return ok(res, { profile: created });
    }
    return ok(res, { profile });
  } catch (e) {
    log('error', 'Get profile error:', e.message);
    return err(res, 500, 'Failed to fetch profile');
  }
});

/**
 * PATCH /api/user/profile
 * Body: { full_name?, calorie_goal?, water_goal? }
 */
app.patch('/api/user/profile', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'Admin client not configured');

    const allowed = ['full_name', 'calorie_goal', 'water_goal', 'avatar_url', 'timezone'];
    const updates = {};
    for (const field of allowed) {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    }
    updates.updated_at = nowISO();

    const { data, error } = await sbAdmin
      .from('profiles')
      .update(updates)
      .eq('id', req.user.id)
      .select()
      .single();

    if (error) return err(res, 400, error.message);
    return ok(res, { profile: data });
  } catch (e) {
    log('error', 'Update profile error:', e.message);
    return err(res, 500, 'Failed to update profile');
  }
});

/**
 * DELETE /api/user/account
 * Deletes all user data and auth account
 */
app.delete('/api/user/account', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'Admin client not configured');
    const uid = req.user.id;

    await Promise.all([
      sbAdmin.from('tasks').delete().eq('user_id', uid),
      sbAdmin.from('transactions').delete().eq('user_id', uid),
      sbAdmin.from('foods').delete().eq('user_id', uid),
      sbAdmin.from('habits').delete().eq('user_id', uid),
      sbAdmin.from('habit_checks').delete().eq('user_id', uid),
      sbAdmin.from('events').delete().eq('user_id', uid),
      sbAdmin.from('trips').delete().eq('user_id', uid),
      sbAdmin.from('vault').delete().eq('user_id', uid),
      sbAdmin.from('posts').delete().eq('user_id', uid),
      sbAdmin.from('exercises').delete().eq('user_id', uid),
    ]);
    await sbAdmin.from('profiles').delete().eq('id', uid);
    await sbAdmin.auth.admin.deleteUser(uid);

    log('info', `Account deleted: ${uid}`);
    return ok(res, { message: 'Account deleted' });
  } catch (e) {
    log('error', 'Delete account error:', e.message);
    return err(res, 500, 'Failed to delete account');
  }
});

// ============================================================
// TASKS
// ============================================================

app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { filter, category, priority } = req.query;
    let query = sbAdmin.from('tasks').select('*').eq('user_id', req.user.id);

    if (filter === 'today') query = query.eq('due_date', today());
    if (filter === 'done')  query = query.eq('completed', true);
    if (filter === 'pending') query = query.eq('completed', false);
    if (category) query = query.eq('category', category);
    if (priority) query = query.eq('priority', priority);

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return err(res, 400, error.message);
    return ok(res, { tasks: data, count: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch tasks');
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { title, description, priority, due_date, category } = req.body;
    if (!title || !title.trim()) return err(res, 400, 'Task title is required');

    const { data, error } = await sbAdmin.from('tasks').insert({
      user_id:     req.user.id,
      title:       title.trim(),
      description: description || '',
      priority:    priority || 'medium',
      due_date:    due_date || null,
      category:    category || 'personal',
      completed:   false,
      created_at:  nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { task: data });
  } catch (e) {
    return err(res, 500, 'Failed to create task');
  }
});

app.patch('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;
    updates.updated_at = nowISO();

    const { data, error } = await sbAdmin.from('tasks')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    if (!data)  return err(res, 404, 'Task not found');
    return ok(res, { task: data });
  } catch (e) {
    return err(res, 500, 'Failed to update task');
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { error } = await sbAdmin.from('tasks')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', req.user.id);
    if (error) return err(res, 400, error.message);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete task');
  }
});

// Bulk update (toggle multiple tasks)
app.post('/api/tasks/bulk', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { ids, updates } = req.body;
    if (!ids || !Array.isArray(ids)) return err(res, 400, 'ids array required');

    const safeUpdates = { ...updates };
    delete safeUpdates.user_id;
    safeUpdates.updated_at = nowISO();

    const { data, error } = await sbAdmin.from('tasks')
      .update(safeUpdates)
      .in('id', ids)
      .eq('user_id', req.user.id)
      .select();

    if (error) return err(res, 400, error.message);
    return ok(res, { tasks: data, updated: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to bulk update tasks');
  }
});

// ============================================================
// TRANSACTIONS (Budget & Bills)
// ============================================================

app.get('/api/transactions', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { type, category, status, from_date, to_date, limit = 100 } = req.query;

    let query = sbAdmin.from('transactions').select('*').eq('user_id', req.user.id);
    if (type)      query = query.eq('type', type);
    if (category)  query = query.eq('category', category);
    if (status)    query = query.eq('status', status);
    if (from_date) query = query.gte('date', from_date);
    if (to_date)   query = query.lte('date', to_date);

    const { data, error } = await query
      .order('date', { ascending: false })
      .limit(parseInt(limit));

    if (error) return err(res, 400, error.message);

    // Compute summary
    const income  = data.filter(t => t.type === 'income').reduce((s, t) => s + (t.amount || 0), 0);
    const expense = data.filter(t => t.type === 'expense').reduce((s, t) => s + (t.amount || 0), 0);

    return ok(res, {
      transactions: data,
      count:        data.length,
      summary: { income, expense, balance: income - expense },
    });
  } catch (e) {
    return err(res, 500, 'Failed to fetch transactions');
  }
});

app.post('/api/transactions', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { type, description, amount, date, category, status } = req.body;

    if (!description || !description.trim()) return err(res, 400, 'Description required');
    if (!amount || isNaN(parseFloat(amount))) return err(res, 400, 'Valid amount required');

    const { data, error } = await sbAdmin.from('transactions').insert({
      user_id:     req.user.id,
      type:        type || 'expense',
      description: description.trim(),
      amount:      parseFloat(amount),
      date:        date || today(),
      category:    category || 'other',
      status:      status || 'paid',
      created_at:  nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { transaction: data });
  } catch (e) {
    return err(res, 500, 'Failed to create transaction');
  }
});

app.patch('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;

    const { data, error } = await sbAdmin.from('transactions')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { transaction: data });
  } catch (e) {
    return err(res, 500, 'Failed to update transaction');
  }
});

app.delete('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('transactions')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete transaction');
  }
});

// ============================================================
// FOODS (Diet & Nutrition)
// ============================================================

app.get('/api/foods', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const dateParam = req.query.date || today();

    const { data, error } = await sbAdmin.from('foods')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('date', dateParam)
      .order('created_at', { ascending: true });

    if (error) return err(res, 400, error.message);

    // Compute daily totals
    const totals = data.reduce((acc, f) => ({
      calories: acc.calories + (f.calories || 0),
      protein:  acc.protein  + (f.protein  || 0),
      carbs:    acc.carbs    + (f.carbs    || 0),
      fat:      acc.fat      + (f.fat      || 0),
    }), { calories: 0, protein: 0, carbs: 0, fat: 0 });

    return ok(res, { foods: data, totals, date: dateParam });
  } catch (e) {
    return err(res, 500, 'Failed to fetch foods');
  }
});

app.post('/api/foods', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { name, meal, calories, protein, carbs, fat } = req.body;
    if (!name || !name.trim()) return err(res, 400, 'Food name required');

    const { data, error } = await sbAdmin.from('foods').insert({
      user_id:    req.user.id,
      name:       name.trim(),
      meal:       meal || 'breakfast',
      calories:   parseInt(calories) || 0,
      protein:    parseInt(protein)  || 0,
      carbs:      parseInt(carbs)    || 0,
      fat:        parseInt(fat)      || 0,
      date:       today(),
      created_at: nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { food: data });
  } catch (e) {
    return err(res, 500, 'Failed to add food');
  }
});

app.delete('/api/foods/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('foods').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete food');
  }
});

// Clear all foods for a specific date
app.delete('/api/foods', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const dateParam = req.query.date || today();
    await sbAdmin.from('foods').delete().eq('user_id', req.user.id).eq('date', dateParam);
    return ok(res, { message: `Foods cleared for ${dateParam}` });
  } catch (e) {
    return err(res, 500, 'Failed to clear foods');
  }
});

// ============================================================
// HABITS
// ============================================================

app.get('/api/habits', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const checkDate = req.query.date || today();

    const [habitsRes, checksRes] = await Promise.all([
      sbAdmin.from('habits').select('*').eq('user_id', req.user.id).order('created_at', { ascending: true }),
      sbAdmin.from('habit_checks').select('habit_id').eq('user_id', req.user.id).eq('check_date', checkDate),
    ]);

    if (habitsRes.error) return err(res, 400, habitsRes.error.message);

    const completedIds = new Set((checksRes.data || []).map(c => c.habit_id));
    const habits = (habitsRes.data || []).map(h => ({
      ...h,
      completed_today: completedIds.has(h.id),
    }));

    return ok(res, { habits, date: checkDate });
  } catch (e) {
    return err(res, 500, 'Failed to fetch habits');
  }
});

app.post('/api/habits', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { name, icon, frequency, target_value, unit } = req.body;
    if (!name || !name.trim()) return err(res, 400, 'Habit name required');

    const { data, error } = await sbAdmin.from('habits').insert({
      user_id:      req.user.id,
      name:         name.trim(),
      icon:         icon || '⭐',
      frequency:    frequency || 'daily',
      streak:       0,
      best_streak:  0,
      target_value: target_value || null,
      unit:         unit || null,
      created_at:   nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { habit: data });
  } catch (e) {
    return err(res, 500, 'Failed to create habit');
  }
});

app.patch('/api/habits/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;

    const { data, error } = await sbAdmin.from('habits')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { habit: data });
  } catch (e) {
    return err(res, 500, 'Failed to update habit');
  }
});

// Check/uncheck habit for today
app.post('/api/habits/:id/check', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const checkDate = req.body.date || today();
    const { done }  = req.body;

    if (done) {
      // Add check
      const { error: checkErr } = await sbAdmin.from('habit_checks').upsert({
        user_id:    req.user.id,
        habit_id:   req.params.id,
        check_date: checkDate,
        created_at: nowISO(),
      }, { onConflict: 'user_id,habit_id,check_date' });

      if (checkErr) return err(res, 400, checkErr.message);

      // Increment streak
      const { data: habit } = await sbAdmin.from('habits')
        .select('streak, best_streak')
        .eq('id', req.params.id)
        .single();

      const newStreak = (habit?.streak || 0) + 1;
      const newBest   = Math.max(newStreak, habit?.best_streak || 0);

      await sbAdmin.from('habits')
        .update({ streak: newStreak, best_streak: newBest })
        .eq('id', req.params.id)
        .eq('user_id', req.user.id);

      return ok(res, { checked: true, streak: newStreak });
    } else {
      // Remove check
      await sbAdmin.from('habit_checks')
        .delete()
        .eq('habit_id', req.params.id)
        .eq('user_id', req.user.id)
        .eq('check_date', checkDate);

      // Decrement streak (min 0)
      const { data: habit } = await sbAdmin.from('habits')
        .select('streak')
        .eq('id', req.params.id)
        .single();

      const newStreak = Math.max(0, (habit?.streak || 1) - 1);
      await sbAdmin.from('habits')
        .update({ streak: newStreak })
        .eq('id', req.params.id)
        .eq('user_id', req.user.id);

      return ok(res, { checked: false, streak: newStreak });
    }
  } catch (e) {
    return err(res, 500, 'Failed to update habit check');
  }
});

// Get habit history (last 30 days)
app.get('/api/habits/:id/history', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const from = new Date();
    from.setDate(from.getDate() - 30);
    const fromStr = from.toISOString().split('T')[0];

    const { data, error } = await sbAdmin.from('habit_checks')
      .select('check_date')
      .eq('habit_id', req.params.id)
      .eq('user_id', req.user.id)
      .gte('check_date', fromStr)
      .order('check_date', { ascending: false });

    if (error) return err(res, 400, error.message);
    return ok(res, { history: data.map(h => h.check_date) });
  } catch (e) {
    return err(res, 500, 'Failed to fetch habit history');
  }
});

app.delete('/api/habits/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await Promise.all([
      sbAdmin.from('habit_checks').delete().eq('habit_id', req.params.id).eq('user_id', req.user.id),
      sbAdmin.from('habits').delete().eq('id', req.params.id).eq('user_id', req.user.id),
    ]);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete habit');
  }
});

// ============================================================
// EVENTS (Calendar)
// ============================================================

app.get('/api/events', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { from_date, to_date, month, year } = req.query;

    let query = sbAdmin.from('events').select('*').eq('user_id', req.user.id);

    if (month && year) {
      const m = String(month).padStart(2, '0');
      query = query.gte('event_date', `${year}-${m}-01`).lte('event_date', `${year}-${m}-31`);
    } else if (from_date) {
      query = query.gte('event_date', from_date);
      if (to_date) query = query.lte('event_date', to_date);
    }

    const { data, error } = await query.order('event_date', { ascending: true });
    if (error) return err(res, 400, error.message);
    return ok(res, { events: data, count: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch events');
  }
});

app.post('/api/events', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { title, event_date, event_time, note, color, reminder } = req.body;
    if (!title || !title.trim()) return err(res, 400, 'Event title required');
    if (!event_date) return err(res, 400, 'Event date required');

    const { data, error } = await sbAdmin.from('events').insert({
      user_id:    req.user.id,
      title:      title.trim(),
      event_date,
      event_time: event_time || null,
      note:       note || '',
      color:      color || '#1B3A6B',
      reminder:   reminder || null,
      created_at: nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { event: data });
  } catch (e) {
    return err(res, 500, 'Failed to create event');
  }
});

app.patch('/api/events/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;

    const { data, error } = await sbAdmin.from('events')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { event: data });
  } catch (e) {
    return err(res, 500, 'Failed to update event');
  }
});

app.delete('/api/events/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('events').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete event');
  }
});

// ============================================================
// TRIPS (Travel Planner)
// ============================================================

app.get('/api/trips', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { data, error } = await sbAdmin.from('trips')
      .select('*')
      .eq('user_id', req.user.id)
      .order('from_date', { ascending: false });

    if (error) return err(res, 400, error.message);
    return ok(res, { trips: data, count: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch trips');
  }
});

app.post('/api/trips', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { destination, from_date, to_date, budget, notes, status } = req.body;
    if (!destination || !destination.trim()) return err(res, 400, 'Destination required');

    const { data, error } = await sbAdmin.from('trips').insert({
      user_id:     req.user.id,
      destination: destination.trim(),
      from_date:   from_date  || null,
      to_date:     to_date    || null,
      budget:      parseFloat(budget) || null,
      notes:       notes   || '',
      status:      status  || 'planned',
      created_at:  nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { trip: data });
  } catch (e) {
    return err(res, 500, 'Failed to create trip');
  }
});

app.patch('/api/trips/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;

    const { data, error } = await sbAdmin.from('trips')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { trip: data });
  } catch (e) {
    return err(res, 500, 'Failed to update trip');
  }
});

app.delete('/api/trips/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('trips').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete trip');
  }
});

// ============================================================
// VAULT (Password Manager)
// ============================================================

app.get('/api/vault', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { data, error } = await sbAdmin.from('vault')
      .select('id, site_name, username, url, notes, created_at')
      .eq('user_id', req.user.id)
      .order('site_name', { ascending: true });

    if (error) return err(res, 400, error.message);
    return ok(res, { vault: data, count: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch vault');
  }
});

// Get vault item with password (separate endpoint for security)
app.get('/api/vault/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { data, error } = await sbAdmin.from('vault')
      .select('*')
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .single();

    if (error || !data) return err(res, 404, 'Vault item not found');
    // Decode password
    try {
      data.password = Buffer.from(data.password, 'base64').toString('utf8');
    } catch (_) {}
    return ok(res, { item: data });
  } catch (e) {
    return err(res, 500, 'Failed to fetch vault item');
  }
});

app.post('/api/vault', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { site_name, username, password, url, notes } = req.body;
    if (!site_name || !site_name.trim()) return err(res, 400, 'Site name required');
    if (!password) return err(res, 400, 'Password required');

    const { data, error } = await sbAdmin.from('vault').insert({
      user_id:    req.user.id,
      site_name:  site_name.trim(),
      username:   username || '',
      password:   Buffer.from(password).toString('base64'),
      url:        url      || '',
      notes:      notes    || '',
      created_at: nowISO(),
    }).select('id, site_name, username, url, notes, created_at').single();

    if (error) return err(res, 400, error.message);
    return ok(res, { vault_item: data });
  } catch (e) {
    return err(res, 500, 'Failed to save vault item');
  }
});

app.patch('/api/vault/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = {};
    if (req.body.site_name) updates.site_name = req.body.site_name.trim();
    if (req.body.username !== undefined) updates.username = req.body.username;
    if (req.body.password) updates.password = Buffer.from(req.body.password).toString('base64');
    if (req.body.url !== undefined) updates.url = req.body.url;
    if (req.body.notes !== undefined) updates.notes = req.body.notes;

    const { data, error } = await sbAdmin.from('vault')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select('id, site_name, username, url, notes').single();

    if (error) return err(res, 400, error.message);
    return ok(res, { vault_item: data });
  } catch (e) {
    return err(res, 500, 'Failed to update vault item');
  }
});

app.delete('/api/vault/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('vault').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete vault item');
  }
});

// ============================================================
// POSTS (Social Media Scheduler)
// ============================================================

app.get('/api/posts', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { status, platform } = req.query;
    let query = sbAdmin.from('posts').select('*').eq('user_id', req.user.id);
    if (status)   query = query.eq('status', status);
    if (platform) query = query.eq('platform', platform);

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return err(res, 400, error.message);
    return ok(res, { posts: data, count: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch posts');
  }
});

app.post('/api/posts', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { platform, content, scheduled_at, hashtags, media_url } = req.body;
    if (!content || !content.trim()) return err(res, 400, 'Post content required');

    const { data, error } = await sbAdmin.from('posts').insert({
      user_id:      req.user.id,
      platform:     platform     || 'twitter',
      content:      content.trim(),
      scheduled_at: scheduled_at || null,
      hashtags:     hashtags     || [],
      media_url:    media_url    || null,
      status:       scheduled_at ? 'scheduled' : 'draft',
      created_at:   nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { post: data });
  } catch (e) {
    return err(res, 500, 'Failed to create post');
  }
});

app.patch('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;

    const { data, error } = await sbAdmin.from('posts')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { post: data });
  } catch (e) {
    return err(res, 500, 'Failed to update post');
  }
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('posts').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete post');
  }
});

// ============================================================
// EXERCISES (Fitness)
// ============================================================

app.get('/api/exercises', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { category } = req.query;
    let query = sbAdmin.from('exercises').select('*').eq('user_id', req.user.id);
    if (category) query = query.eq('category', category);

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return err(res, 400, error.message);
    return ok(res, { exercises: data, count: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch exercises');
  }
});

app.post('/api/exercises', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { name, sets, reps_or_duration, category, weight, notes } = req.body;
    if (!name || !name.trim()) return err(res, 400, 'Exercise name required');

    const { data, error } = await sbAdmin.from('exercises').insert({
      user_id:          req.user.id,
      name:             name.trim(),
      sets:             sets             || '3',
      reps_or_duration: reps_or_duration || '10',
      category:         category         || 'strength',
      weight:           weight           || null,
      notes:            notes            || '',
      created_at:       nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { exercise: data });
  } catch (e) {
    return err(res, 500, 'Failed to add exercise');
  }
});

app.patch('/api/exercises/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const updates = { ...req.body };
    delete updates.user_id;
    delete updates.id;

    const { data, error } = await sbAdmin.from('exercises')
      .update(updates)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { exercise: data });
  } catch (e) {
    return err(res, 500, 'Failed to update exercise');
  }
});

app.delete('/api/exercises/:id', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    await sbAdmin.from('exercises').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    return ok(res, { deleted: req.params.id });
  } catch (e) {
    return err(res, 500, 'Failed to delete exercise');
  }
});

// ============================================================
// WORKOUT LOGS
// ============================================================

app.get('/api/workout-logs', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const dateParam = req.query.date || today();

    const { data, error } = await sbAdmin.from('workout_logs')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('log_date', dateParam);

    if (error) {
      // Table might not exist yet - return empty
      return ok(res, { logs: [], date: dateParam });
    }
    return ok(res, { logs: data || [], date: dateParam });
  } catch (e) {
    return ok(res, { logs: [], date: req.query.date || today() });
  }
});

app.post('/api/workout-logs', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { exercise_id, exercise_name, sets_done, reps_done, weight, duration_mins, notes } = req.body;

    const { data, error } = await sbAdmin.from('workout_logs').insert({
      user_id:       req.user.id,
      exercise_id:   exercise_id   || null,
      exercise_name: exercise_name || '',
      sets_done:     sets_done     || 0,
      reps_done:     reps_done     || 0,
      weight:        weight        || null,
      duration_mins: duration_mins || null,
      notes:         notes         || '',
      log_date:      today(),
      created_at:    nowISO(),
    }).select().single();

    if (error) return err(res, 400, error.message);
    return ok(res, { log: data });
  } catch (e) {
    return err(res, 500, 'Failed to log workout');
  }
});

// ============================================================
// NOTIFICATIONS
// ============================================================

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    if (!sbAdmin) return err(res, 503, 'DB not configured');
    const { data, error } = await sbAdmin.from('notifications_queue')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) return ok(res, { notifications: [] });
    return ok(res, { notifications: data || [] });
  } catch (e) {
    return ok(res, { notifications: [] });
  }
});

// ============================================================
// RAZORPAY PAYMENTS
// ============================================================

/**
 * POST /api/payment/create-order
 * Body: { plan: 'pro' | 'premium' }
 * Returns Razorpay order to complete on frontend
 */
app.post('/api/payment/create-order', requireAuth, async (req, res) => {
  try {
    const rzp = getRzp();
    if (!rzp) return err(res, 503, 'Payment gateway not configured');

    const { plan } = req.body;
    const prices   = { pro: 19900, premium: 49900 }; // in paise
    const amount   = prices[plan];
    if (!amount) return err(res, 400, `Invalid plan: ${plan}`);

    const order = await rzp.orders.create({
      amount,
      currency: 'INR',
      receipt:  `vela_${plan}_${req.user.id.slice(0, 8)}_${Date.now()}`,
      notes: {
        user_id:    req.user.id,
        user_email: req.user.email,
        plan,
      },
    });

    log('info', `Payment order created: ${order.id} plan=${plan} user=${req.user.email}`);
    return ok(res, { order, key_id: ENV.RAZORPAY_KEY_ID });
  } catch (e) {
    log('error', 'Create order error:', e.message);
    return err(res, 500, 'Failed to create payment order');
  }
});

/**
 * POST /api/payment/verify
 * Body: { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan }
 * Verifies payment and upgrades user plan
 */
app.post('/api/payment/verify', requireAuth, async (req, res) => {
  try {
    if (!ENV.RAZORPAY_KEY_SECRET) return err(res, 503, 'Payment not configured');

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return err(res, 400, 'Payment verification data incomplete');
    }

    // Verify HMAC signature
    const expectedSig = crypto
      .createHmac('sha256', ENV.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (expectedSig !== razorpay_signature) {
      log('warn', `Payment signature mismatch for ${razorpay_payment_id}`);
      return err(res, 400, 'Payment verification failed — invalid signature');
    }

    // Upgrade plan
    if (sbAdmin) {
      await sbAdmin.from('profiles').update({
        plan,
        razorpay_payment_id: razorpay_payment_id,
        updated_at:          nowISO(),
      }).eq('id', req.user.id);

      // Log as transaction
      await sbAdmin.from('transactions').insert({
        user_id:     req.user.id,
        type:        'expense',
        description: `VELA ${plan} plan subscription`,
        amount:      plan === 'pro' ? 199 : 499,
        date:        today(),
        category:    'subscription',
        status:      'paid',
        created_at:  nowISO(),
      });
    }

    log('info', `Payment verified: ${razorpay_payment_id} → ${plan} for ${req.user.email}`);
    return ok(res, {
      plan,
      payment_id: razorpay_payment_id,
      message:    `Successfully upgraded to ${plan}!`,
    });
  } catch (e) {
    log('error', 'Verify payment error:', e.message);
    return err(res, 500, 'Payment verification error');
  }
});

/**
 * POST /webhook/razorpay
 * Razorpay server-side webhook (backup for frontend payment)
 */
app.post('/webhook/razorpay', async (req, res) => {
  try {
    if (ENV.RAZORPAY_WEBHOOK_SECRET) {
      const sig      = req.headers['x-razorpay-signature'];
      const expected = crypto
        .createHmac('sha256', ENV.RAZORPAY_WEBHOOK_SECRET)
        .update(req.body)
        .digest('hex');

      if (sig !== expected) {
        log('warn', 'Razorpay webhook: invalid signature');
        return err(res, 400, 'Invalid webhook signature');
      }
    }

    const event = JSON.parse(req.body.toString());
    log('info', `Razorpay webhook: ${event.event}`);

    if (event.event === 'payment.captured' && sbAdmin) {
      const payment = event.payload.payment.entity;
      const notes   = payment.notes || {};

      if (notes.user_id && notes.plan) {
        await sbAdmin.from('profiles').update({
          plan:                notes.plan,
          razorpay_payment_id: payment.id,
          updated_at:          nowISO(),
        }).eq('id', notes.user_id);

        log('info', `Webhook: plan updated ${notes.user_id} → ${notes.plan}`);
      }
    }

    res.json({ status: 'ok' });
  } catch (e) {
    log('error', 'Webhook error:', e.message);
    res.status(500).json({ error: 'Webhook processing error' });
  }
});

// ============================================================
// ADMIN ROUTES
// ============================================================

/**
 * GET /api/admin/stats
 * Full platform statistics
 */
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [usersRes, tasksRes, txnRes, habitsRes, postsRes] = await Promise.all([
      sbAdmin.from('profiles').select('*').order('created_at', { ascending: false }),
      sbAdmin.from('tasks').select('id', { count: 'exact', head: true }),
      sbAdmin.from('transactions').select('id', { count: 'exact', head: true }),
      sbAdmin.from('habits').select('id', { count: 'exact', head: true }),
      sbAdmin.from('posts').select('id', { count: 'exact', head: true }),
    ]);

    const users   = usersRes.data || [];
    const pro     = users.filter(u => u.plan === 'pro').length;
    const premium = users.filter(u => u.plan === 'premium').length;
    const free    = users.length - pro - premium;
    const admins  = users.filter(u => ['admin','super_admin'].includes(u.role)).length;

    // Signups in last 7 days
    const weekAgo    = new Date(); weekAgo.setDate(weekAgo.getDate() - 7);
    const newThisWeek = users.filter(u => new Date(u.created_at) > weekAgo).length;

    return ok(res, {
      users,
      stats: {
        total_users:       users.length,
        new_this_week:     newThisWeek,
        pro_users:         pro,
        premium_users:     premium,
        free_users:        free,
        admin_users:       admins,
        estimated_revenue: (pro * 199) + (premium * 499),
        total_tasks:       tasksRes.count  || 0,
        total_transactions: txnRes.count   || 0,
        total_habits:      habitsRes.count || 0,
        total_posts:       postsRes.count  || 0,
      },
    });
  } catch (e) {
    log('error', 'Admin stats error:', e.message);
    return err(res, 500, 'Failed to fetch admin stats');
  }
});

/**
 * GET /api/admin/users
 * List all users with optional search
 */
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { search, plan, role } = req.query;
    let query = sbAdmin.from('profiles').select('*').order('created_at', { ascending: false });

    if (plan) query = query.eq('plan', plan);
    if (role) query = query.eq('role', role);

    const { data, error } = await query;
    if (error) return err(res, 400, error.message);

    let users = data || [];
    if (search) {
      const q = search.toLowerCase();
      users = users.filter(u =>
        (u.full_name || '').toLowerCase().includes(q) ||
        (u.email     || '').toLowerCase().includes(q)
      );
    }

    return ok(res, { users, count: users.length });
  } catch (e) {
    return err(res, 500, 'Failed to fetch users');
  }
});

/**
 * POST /api/admin/grant-plan
 * Body: { email, plan }
 */
app.post('/api/admin/grant-plan', requireAdmin, async (req, res) => {
  try {
    const { email, plan, user_id } = req.body;
    if (!plan) return err(res, 400, 'Plan required');

    let query = sbAdmin.from('profiles').update({ plan, updated_at: nowISO() });
    if (user_id) query = query.eq('id', user_id);
    else if (email) query = query.eq('email', email.toLowerCase().trim());
    else return err(res, 400, 'Email or user_id required');

    const { data, error } = await query.select();
    if (error)         return err(res, 400, error.message);
    if (!data?.length) return err(res, 404, 'User not found');

    log('info', `Admin granted plan=${plan} to ${email || user_id}`);
    return ok(res, { message: `Plan ${plan} granted`, users_updated: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to grant plan');
  }
});

/**
 * POST /api/admin/grant-role
 * Body: { email, role }
 */
app.post('/api/admin/grant-role', requireAdmin, async (req, res) => {
  try {
    const { email, role, user_id } = req.body;
    if (!role) return err(res, 400, 'Role required');
    if (!['user', 'admin', 'super_admin'].includes(role)) {
      return err(res, 400, 'Invalid role');
    }

    let query = sbAdmin.from('profiles').update({ role, updated_at: nowISO() });
    if (user_id) query = query.eq('id', user_id);
    else if (email) query = query.eq('email', email.toLowerCase().trim());
    else return err(res, 400, 'Email or user_id required');

    const { data, error } = await query.select();
    if (error)         return err(res, 400, error.message);
    if (!data?.length) return err(res, 404, 'User not found');

    log('info', `Admin granted role=${role} to ${email || user_id}`);
    return ok(res, { message: `Role ${role} granted`, users_updated: data.length });
  } catch (e) {
    return err(res, 500, 'Failed to grant role');
  }
});

/**
 * DELETE /api/admin/users/:id
 * Delete user and all their data
 */
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const uid = req.params.id;
    if (uid === req.user.id) return err(res, 400, 'Cannot delete your own account');

    await Promise.all([
      sbAdmin.from('tasks').delete().eq('user_id', uid),
      sbAdmin.from('transactions').delete().eq('user_id', uid),
      sbAdmin.from('foods').delete().eq('user_id', uid),
      sbAdmin.from('habits').delete().eq('user_id', uid),
      sbAdmin.from('habit_checks').delete().eq('user_id', uid),
      sbAdmin.from('events').delete().eq('user_id', uid),
      sbAdmin.from('trips').delete().eq('user_id', uid),
      sbAdmin.from('vault').delete().eq('user_id', uid),
      sbAdmin.from('posts').delete().eq('user_id', uid),
      sbAdmin.from('exercises').delete().eq('user_id', uid),
    ]);
    await sbAdmin.from('profiles').delete().eq('id', uid);

    try {
      await sbAdmin.auth.admin.deleteUser(uid);
    } catch (authErr) {
      log('warn', `Could not delete auth user ${uid}:`, authErr.message);
    }

    log('info', `Admin deleted user: ${uid}`);
    return ok(res, { deleted: uid });
  } catch (e) {
    log('error', 'Delete user error:', e.message);
    return err(res, 500, 'Failed to delete user');
  }
});

/**
 * POST /api/admin/notify
 * Body: { title, body, target_plan }
 */
app.post('/api/admin/notify', requireAdmin, async (req, res) => {
  try {
    const { title, body, target_plan, type } = req.body;
    if (!title || !title.trim()) return err(res, 400, 'Title required');
    if (!body  || !body.trim())  return err(res, 400, 'Body required');

    const { error } = await sbAdmin.from('notifications_queue').insert({
      title:       title.trim(),
      body:        body.trim(),
      type:        type        || 'broadcast',
      target_plan: target_plan || 'all',
      status:      'pending',
      created_at:  nowISO(),
    });

    if (error) return err(res, 400, error.message);

    log('info', `Broadcast queued: "${title}" → ${target_plan || 'all'}`);
    return ok(res, { message: `Notification queued for ${target_plan || 'all'} users` });
  } catch (e) {
    return err(res, 500, 'Failed to queue notification');
  }
});

/**
 * GET /api/admin/notifications
 */
app.get('/api/admin/notifications', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await sbAdmin.from('notifications_queue')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) return err(res, 400, error.message);
    return ok(res, { notifications: data || [] });
  } catch (e) {
    return err(res, 500, 'Failed to fetch notifications');
  }
});

/**
 * GET /api/admin/user/:id/data
 * Get all data for a specific user (for support)
 */
app.get('/api/admin/user/:id/data', requireAdmin, async (req, res) => {
  try {
    const uid = req.params.id;
    const [profile, tasks, txns, habits, events] = await Promise.all([
      sbAdmin.from('profiles').select('*').eq('id', uid).single(),
      sbAdmin.from('tasks').select('*').eq('user_id', uid).limit(50),
      sbAdmin.from('transactions').select('*').eq('user_id', uid).limit(50),
      sbAdmin.from('habits').select('*').eq('user_id', uid),
      sbAdmin.from('events').select('*').eq('user_id', uid).limit(20),
    ]);

    return ok(res, {
      profile:      profile.data,
      tasks:        tasks.data        || [],
      transactions: txns.data         || [],
      habits:       habits.data       || [],
      events:       events.data       || [],
    });
  } catch (e) {
    return err(res, 500, 'Failed to fetch user data');
  }
});

// ============================================================
// SERVE FRONTEND HTML
// ============================================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'vela-app-final.html'));
});

app.get('/admin', (req, res) => {
  const adminFile = path.join(__dirname, 'vela-admin.html');
  const fs = require('fs');
  if (fs.existsSync(adminFile)) {
    res.sendFile(adminFile);
  } else {
    res.sendFile(path.join(__dirname, 'vela-app-final.html'));
  }
});

// SPA catch-all
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/webhook/')) {
    return err(res, 404, `API route not found: ${req.method} ${req.path}`);
  }
  res.sendFile(path.join(__dirname, 'vela-app-final.html'));
});

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================
app.use((error, req, res, next) => {
  log('error', 'Unhandled error:', error.message, error.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================
process.on('SIGTERM', () => {
  log('info', 'SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  log('error', 'Uncaught exception:', err.message);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  log('error', 'Unhandled rejection:', reason);
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  log('info', `
╔══════════════════════════════════════╗
║       VELA — Run Your Life v3.0      ║
╠══════════════════════════════════════╣
║  Port:      ${String(PORT).padEnd(26)}║
║  Env:       ${ENV.NODE_ENV.padEnd(26)}║
║  DB Admin:  ${(!!ENV.SUPABASE_SERVICE_KEY ? 'YES' : 'NO — set SUPABASE_SERVICE_KEY').padEnd(26)}║
║  Razorpay:  ${(!!ENV.RAZORPAY_KEY_ID ? 'YES' : 'NO — set RAZORPAY_KEY_ID').padEnd(26)}║
║  App URL:   ${ENV.APP_URL.padEnd(26)}║
╚══════════════════════════════════════╝
  `);
});

module.exports = app;
