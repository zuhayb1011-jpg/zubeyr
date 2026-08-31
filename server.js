require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const { randomUUID } = require('crypto');

const { initializeDatabase, get, all, run } = require('./db');
const { buildSuccess, buildError } = require('./src/utils/response');
const { createToken, generateRandomToken } = require('./src/utils/auth');
const { requireAuth, requireRole } = require('./src/middleware/auth');
const { errorHandler, notFoundHandler } = require('./src/middleware/errorHandler');
const { AIService } = require('./src/services/aiService');

const app = express();
const PORT = Number(process.env.PORT || 3456);
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const aiService = new AIService();

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: (origin, callback) => {
    const allowed = [FRONTEND_URL, 'http://127.0.0.1:5173', 'http://localhost:5173'];
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

function parsePagination(req) {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(100, Math.max(1, Number(req.query.limit || 20)));
  return { page, limit };
}

async function logActivity(userId, action, entityType, entityId, description, ipAddress = null) {
  await run(
    `INSERT INTO activity_logs (id, user_id, action, entity_type, entity_id, description, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [randomUUID(), userId, action, entityType, entityId, description, ipAddress]
  );
}

app.get('/api/health', async (_req, res) => {
  try {
    await get('SELECT 1');
    return res.json(buildSuccess({ status: 'healthy', database: 'connected' }));
  } catch (error) {
    return res.json(buildSuccess({ status: 'degraded', database: 'unavailable' }));
  }
});

app.get('/api', (_req, res) => {
  return res.json(buildSuccess({ name: 'Aether AI API', version: '1.0.0' }));
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { name, email, password, phone, company } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json(buildError('Name, email, and password are required', 400));
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json(buildError('Email is invalid', 400));
    }
    if (password.length < 8) {
      return res.status(400).json(buildError('Password must be at least 8 characters', 400));
    }

    const existing = await get('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing) {
      return res.status(409).json(buildError('Email is already registered', 409));
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = randomUUID();
    await run(
      `INSERT INTO users (id, name, email, password, role, status, phone, company, avatar)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, name, email.toLowerCase(), hashedPassword, 'user', 'active', phone || '', company || '', 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?auto=format&fit=crop&w=400&q=80']
    );
    await run('INSERT INTO user_settings (id, user_id, theme, language, timezone, ai_preferences, notifications_enabled, security_preferences) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [randomUUID(), userId, 'dark', 'en', 'UTC', '{}', 1, '{}']);
    await logActivity(userId, 'register', 'user', userId, 'New user registered');

    const user = await get('SELECT id, name, email, role, status, phone, company, avatar, created_at FROM users WHERE id = ?', [userId]);
    return res.status(201).json(buildSuccess({ user, token: createToken(user) }, { message: 'Registration successful' }));
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json(buildError('Email and password are required', 400));
    }

    const user = await get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) {
      return res.status(401).json(buildError('Invalid email or password', 401));
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json(buildError('Invalid email or password', 401));
    }

    const safeUser = { ...user, password: undefined };
    await logActivity(user.id, 'login', 'user', user.id, 'User logged in', req.ip);
    return res.json(buildSuccess({ user: safeUser, token: createToken(safeUser) }, { message: 'Login successful' }));
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await logActivity(req.user.id, 'logout', 'user', req.user.id, 'User logged out', req.ip);
  return res.json(buildSuccess(null, { message: 'Logged out successfully' }));
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await get('SELECT id, name, email, role, status, phone, company, avatar, created_at FROM users WHERE id = ?', [req.user.id]);
  return res.json(buildSuccess({ user }));
});

app.post('/api/auth/forgot-password', async (req, res, next) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json(buildError('Email is required', 400));
    }
    const user = await get('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) {
      return res.status(404).json(buildError('No account found for that email', 404));
    }
    const token = generateRandomToken('reset');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await run('INSERT INTO password_resets (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)', [randomUUID(), user.id, token, expiresAt]);
    return res.json(buildSuccess({ message: 'Reset instructions sent' }));
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/reset-password', async (req, res, next) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) {
      return res.status(400).json(buildError('Token and password are required', 400));
    }
    if (password.length < 8) {
      return res.status(400).json(buildError('Password must be at least 8 characters', 400));
    }
    const resetRecord = await get('SELECT * FROM password_resets WHERE token = ? AND (used_at IS NULL)', [token]);
    if (!resetRecord) {
      return res.status(400).json(buildError('Reset token is invalid or expired', 400));
    }
    const hashed = await bcrypt.hash(password, 10);
    await run('UPDATE users SET password = ?, updated_at = ? WHERE id = ?', [hashed, new Date().toISOString(), resetRecord.user_id]);
    await run('UPDATE password_resets SET used_at = ? WHERE id = ?', [new Date().toISOString(), resetRecord.id]);
    await logActivity(resetRecord.user_id, 'password_change', 'user', resetRecord.user_id, 'Password reset completed');
    return res.json(buildSuccess(null, { message: 'Password reset successful' }));
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/verify-email', async (req, res, next) => {
  try {
    const { token } = req.body || {};
    if (!token) {
      return res.status(400).json(buildError('Verification token is required', 400));
    }
    const verification = await get('SELECT * FROM email_verifications WHERE token = ? AND (used_at IS NULL)', [token]);
    if (!verification) {
      return res.status(400).json(buildError('Verification token is invalid', 400));
    }
    await run('UPDATE users SET status = ? WHERE id = ?', ['active', verification.user_id]);
    await run('UPDATE email_verifications SET used_at = ? WHERE id = ?', [new Date().toISOString(), verification.id]);
    return res.json(buildSuccess(null, { message: 'Email verified successfully' }));
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/resend-verification', requireAuth, async (req, res) => {
  const token = generateRandomToken('verify');
  await run('INSERT INTO email_verifications (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)', [randomUUID(), req.user.id, token, new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()]);
  return res.json(buildSuccess({ message: 'Verification email sent' }));
});

app.get('/api/users', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
  const { page, limit } = parsePagination(req);
  const search = (req.query.search || '').trim();
  const where = search ? 'WHERE name LIKE ? OR email LIKE ?' : '';
  const params = search ? [`%${search}%`, `%${search}%`] : [];
  const rows = await all(`SELECT id, name, email, role, status, company, phone, avatar, created_at, updated_at FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, (page - 1) * limit]);
  const total = await get(`SELECT COUNT(*) as count FROM users ${where}`, params);
  return res.json(buildSuccess(rows, { pagination: { page, limit, total: Number(total.count || 0), totalPages: Math.ceil((Number(total.count || 0)) / limit) } }));
});

app.get('/api/users/:id', requireAuth, async (req, res) => {
  const user = await get('SELECT id, name, email, role, status, company, phone, avatar, created_at, updated_at FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json(buildError('User not found', 404));
  if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
    return res.status(403).json(buildError('You cannot access this user data', 403));
  }
  return res.json(buildSuccess({ user }));
});

app.put('/api/users/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
    return res.status(403).json(buildError('You cannot edit this user', 403));
  }
  const { name, email, phone, company, status } = req.body || {};
  await run('UPDATE users SET name = ?, email = ?, phone = ?, company = ?, status = ?, updated_at = ? WHERE id = ?', [name || req.user.name, email || req.user.email, phone || req.user.phone, company || req.user.company, status || req.user.status, new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'User updated successfully' }));
});

app.delete('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await run('DELETE FROM users WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'User deleted successfully' }));
});

app.get('/api/clients', requireAuth, async (req, res) => {
  const { page, limit } = parsePagination(req);
  const search = (req.query.search || '').trim();
  const rows = await all(
    `SELECT * FROM clients ${search ? 'WHERE name LIKE ? OR company LIKE ?' : ''} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    search ? [`%${search}%`, `%${search}%`, limit, (page - 1) * limit] : [limit, (page - 1) * limit]
  );
  const total = await get(`SELECT COUNT(*) as count FROM clients ${search ? 'WHERE name LIKE ? OR company LIKE ?' : ''}`, search ? [`%${search}%`, `%${search}%`] : []);
  return res.json(buildSuccess(rows, { pagination: { page, limit, total: Number(total.count || 0), totalPages: Math.ceil((Number(total.count || 0)) / limit) } }));
});

app.get('/api/clients/:id', requireAuth, async (req, res) => {
  const client = await get('SELECT * FROM clients WHERE id = ?', [req.params.id]);
  if (!client) return res.status(404).json(buildError('Client not found', 404));
  return res.json(buildSuccess({ client }));
});

app.post('/api/clients', requireAuth, async (req, res, next) => {
  try {
    const { name, email, phone, company } = req.body || {};
    if (!name) return res.status(400).json(buildError('Client name is required', 400));
    const clientId = randomUUID();
    await run('INSERT INTO clients (id, user_id, name, email, phone, company) VALUES (?, ?, ?, ?, ?, ?)', [clientId, req.user.id, name, email || '', phone || '', company || '']);
    await logActivity(req.user.id, 'create_client', 'client', clientId, 'Client created');
    return res.status(201).json(buildSuccess({ id: clientId }, { message: 'Client created successfully' }));
  } catch (error) { next(error); }
});

app.put('/api/clients/:id', requireAuth, async (req, res) => {
  const { name, email, phone, company, status } = req.body || {};
  await run('UPDATE clients SET name = ?, email = ?, phone = ?, company = ?, status = ?, updated_at = ? WHERE id = ?', [name || '', email || '', phone || '', company || '', status || 'active', new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'Client updated successfully' }));
});

app.delete('/api/clients/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await run('DELETE FROM clients WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Client deleted successfully' }));
});

app.get('/api/projects', requireAuth, async (req, res) => {
  const { page, limit } = parsePagination(req);
  const search = (req.query.search || '').trim();
  const rows = await all(
    `SELECT * FROM projects ${search ? 'WHERE name LIKE ? OR description LIKE ?' : ''} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    search ? [`%${search}%`, `%${search}%`, limit, (page - 1) * limit] : [limit, (page - 1) * limit]
  );
  const total = await get(`SELECT COUNT(*) as count FROM projects ${search ? 'WHERE name LIKE ? OR description LIKE ?' : ''}`, search ? [`%${search}%`, `%${search}%`] : []);
  return res.json(buildSuccess(rows, { pagination: { page, limit, total: Number(total.count || 0), totalPages: Math.ceil((Number(total.count || 0)) / limit) } }));
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
  const project = await get('SELECT * FROM projects WHERE id = ?', [req.params.id]);
  if (!project) return res.status(404).json(buildError('Project not found', 404));
  return res.json(buildSuccess({ project }));
});

app.post('/api/projects', requireAuth, async (req, res, next) => {
  try {
    const { name, description, clientId, priority, dueDate, status } = req.body || {};
    if (!name) return res.status(400).json(buildError('Project name is required', 400));
    const projectId = randomUUID();
    await run('INSERT INTO projects (id, user_id, client_id, name, description, priority, due_date, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [projectId, req.user.id, clientId || null, name, description || '', priority || 'medium', dueDate || null, status || 'active']);
    await logActivity(req.user.id, 'create_project', 'project', projectId, 'Project created');
    return res.status(201).json(buildSuccess({ id: projectId }, { message: 'Project created successfully' }));
  } catch (error) { next(error); }
});

app.put('/api/projects/:id', requireAuth, async (req, res) => {
  const { name, description, clientId, priority, dueDate, status } = req.body || {};
  await run('UPDATE projects SET name = ?, description = ?, client_id = ?, priority = ?, due_date = ?, status = ?, updated_at = ? WHERE id = ?', [name || '', description || '', clientId || null, priority || 'medium', dueDate || null, status || 'active', new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'Project updated successfully' }));
});

app.delete('/api/projects/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await run('DELETE FROM projects WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Project deleted successfully' }));
});

app.get('/api/tasks', requireAuth, async (req, res) => {
  const { page, limit } = parsePagination(req);
  const rows = await all('SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?', [limit, (page - 1) * limit]);
  const total = await get('SELECT COUNT(*) as count FROM tasks');
  return res.json(buildSuccess(rows, { pagination: { page, limit, total: Number(total.count || 0), totalPages: Math.ceil((Number(total.count || 0)) / limit) } }));
});

app.get('/api/tasks/:id', requireAuth, async (req, res) => {
  const task = await get('SELECT * FROM tasks WHERE id = ?', [req.params.id]);
  if (!task) return res.status(404).json(buildError('Task not found', 404));
  return res.json(buildSuccess({ task }));
});

app.post('/api/tasks', requireAuth, async (req, res, next) => {
  try {
    const { title, description, projectId, priority, dueDate, status } = req.body || {};
    if (!title) return res.status(400).json(buildError('Task title is required', 400));
    const taskId = randomUUID();
    await run('INSERT INTO tasks (id, user_id, project_id, title, description, priority, due_date, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [taskId, req.user.id, projectId || null, title, description || '', priority || 'medium', dueDate || null, status || 'todo']);
    return res.status(201).json(buildSuccess({ id: taskId }, { message: 'Task created successfully' }));
  } catch (error) { next(error); }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  const { title, description, priority, dueDate, status } = req.body || {};
  await run('UPDATE tasks SET title = ?, description = ?, priority = ?, due_date = ?, status = ?, updated_at = ? WHERE id = ?', [title || '', description || '', priority || 'medium', dueDate || null, status || 'todo', new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'Task updated successfully' }));
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  await run('DELETE FROM tasks WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Task deleted successfully' }));
});

app.patch('/api/tasks/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body || {};
  if (!status) return res.status(400).json(buildError('Status is required', 400));
  await run('UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?', [status, new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'Task status updated successfully' }));
});

app.get('/api/conversations', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM conversations WHERE user_id = ? ORDER BY updated_at DESC', [req.user.id]);
  return res.json(buildSuccess(rows));
});

app.get('/api/conversations/:id', requireAuth, async (req, res) => {
  const conversation = await get('SELECT * FROM conversations WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!conversation) return res.status(404).json(buildError('Conversation not found', 404));
  const messages = await all('SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC', [req.params.id]);
  return res.json(buildSuccess({ conversation, messages }));
});

app.post('/api/conversations', requireAuth, async (req, res, next) => {
  try {
    const { title } = req.body || {};
    const conversationId = randomUUID();
    await run('INSERT INTO conversations (id, user_id, title) VALUES (?, ?, ?)', [conversationId, req.user.id, title || 'Conversation']);
    return res.status(201).json(buildSuccess({ id: conversationId }, { message: 'Conversation created successfully' }));
  } catch (error) { next(error); }
});

app.get('/api/messages', requireAuth, async (req, res) => {
  const { page, limit } = parsePagination(req);
  const rows = await all('SELECT * FROM messages ORDER BY created_at DESC LIMIT ? OFFSET ?', [limit, (page - 1) * limit]);
  const total = await get('SELECT COUNT(*) as count FROM messages');
  return res.json(buildSuccess(rows, { pagination: { page, limit, total: Number(total.count || 0), totalPages: Math.ceil((Number(total.count || 0)) / limit) } }));
});

app.get('/api/messages/:id', requireAuth, async (req, res) => {
  const message = await get('SELECT * FROM messages WHERE id = ?', [req.params.id]);
  if (!message) return res.status(404).json(buildError('Message not found', 404));
  return res.json(buildSuccess({ message }));
});

app.post('/api/messages', requireAuth, async (req, res, next) => {
  try {
    const { conversationId, receiverId, body } = req.body || {};
    if (!conversationId || !body) return res.status(400).json(buildError('Conversation and message body are required', 400));
    const messageId = randomUUID();
    await run('INSERT INTO messages (id, conversation_id, sender_id, receiver_id, body) VALUES (?, ?, ?, ?, ?)', [messageId, conversationId, req.user.id, receiverId || null, body]);
    await run('UPDATE conversations SET updated_at = ? WHERE id = ?', [new Date().toISOString(), conversationId]);
    return res.status(201).json(buildSuccess({ id: messageId }, { message: 'Message sent successfully' }));
  } catch (error) { next(error); }
});

app.patch('/api/messages/:id/read', requireAuth, async (req, res) => {
  await run('UPDATE messages SET is_read = 1 WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Message marked as read' }));
});

app.delete('/api/messages/:id', requireAuth, async (req, res) => {
  await run('DELETE FROM messages WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Message deleted successfully' }));
});

app.post('/api/ai/chat', requireAuth, async (req, res, next) => {
  try {
    const { message, conversationId } = req.body || {};
    if (!message || !message.trim()) return res.status(400).json(buildError('Message is required', 400));

    const plan = await get('SELECT p.* FROM subscriptions s JOIN plans p ON p.id = s.plan_id WHERE s.user_id = ? AND s.status = ? ORDER BY s.created_at DESC LIMIT 1', [req.user.id, 'active']);
    const usageCount = await get('SELECT COUNT(*) as count FROM ai_usage WHERE user_id = ?', [req.user.id]);
    const limit = plan ? plan.ai_limit : 50;

    if (Number(usageCount.count || 0) >= limit) {
      return res.status(429).json(buildError('AI usage limit reached for your current plan', 429));
    }

    const conversation = conversationId ? await get('SELECT id FROM conversations WHERE id = ? AND user_id = ?', [conversationId, req.user.id]) : null;
    if (!conversation && conversationId) {
      return res.status(404).json(buildError('Conversation not found', 404));
    }

    const responseText = await aiService.chat(message);
    const usageId = randomUUID();
    await run('INSERT INTO ai_usage (id, user_id, model, total_tokens, request_count) VALUES (?, ?, ?, ?, ?)', [usageId, req.user.id, process.env.AI_MODEL || 'gemini-2.5-flash', 0, 1]);

    if (!conversationId) {
      const newConversationId = randomUUID();
      await run('INSERT INTO conversations (id, user_id, title) VALUES (?, ?, ?)', [newConversationId, req.user.id, 'AI Chat']);
      await run('INSERT INTO messages (id, conversation_id, sender_id, body) VALUES (?, ?, ?, ?)', [randomUUID(), newConversationId, req.user.id, message]);
      await run('INSERT INTO messages (id, conversation_id, sender_id, body) VALUES (?, ?, ?, ?)', [randomUUID(), newConversationId, 'ai-assistant', responseText]);
    }

    await logActivity(req.user.id, 'ai_request', 'ai_usage', usageId, 'AI request processed');
    return res.json(buildSuccess({ response: responseText, usage: { count: Number(usageCount.count || 0) + 1, limit } }, { message: 'AI response generated successfully' }));
  } catch (error) {
    next(error);
  }
});

app.get('/api/ai/usage', requireAuth, async (req, res) => {
  const usage = await all('SELECT * FROM ai_usage WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  return res.json(buildSuccess(usage));
});

app.get('/api/ai/usage/summary', requireAuth, async (req, res) => {
  const result = await get('SELECT COUNT(*) as requests, COALESCE(SUM(total_tokens), 0) as tokens FROM ai_usage WHERE user_id = ?', [req.user.id]);
  return res.json(buildSuccess({ requests: Number(result.requests || 0), tokens: Number(result.tokens || 0) }));
});

app.get('/api/files', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  return res.json(buildSuccess(rows));
});

app.get('/api/files/:id', requireAuth, async (req, res) => {
  const file = await get('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!file) return res.status(404).json(buildError('File not found', 404));
  return res.json(buildSuccess({ file }));
});

app.post('/api/files', requireAuth, async (req, res) => {
  const { filename, mimeType, size, projectId, url } = req.body || {};
  if (!filename) return res.status(400).json(buildError('Filename is required', 400));
  const fileId = randomUUID();
  await run('INSERT INTO files (id, user_id, project_id, filename, mime_type, size, url, storage_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [fileId, req.user.id, projectId || null, filename, mimeType || 'application/octet-stream', Number(size || 0), url || '', `storage/${fileId}`]);
  return res.status(201).json(buildSuccess({ id: fileId }, { message: 'File uploaded successfully' }));
});

app.delete('/api/files/:id', requireAuth, async (req, res) => {
  await run('DELETE FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  return res.json(buildSuccess(null, { message: 'File deleted successfully' }));
});

app.get('/api/notifications', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  return res.json(buildSuccess(rows));
});

app.patch('/api/notifications/:id/read', requireAuth, async (req, res) => {
  await run('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  return res.json(buildSuccess(null, { message: 'Notification marked as read' }));
});

app.patch('/api/notifications/read-all', requireAuth, async (req, res) => {
  await run('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.user.id]);
  return res.json(buildSuccess(null, { message: 'All notifications marked as read' }));
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
  await run('DELETE FROM notifications WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  return res.json(buildSuccess(null, { message: 'Notification deleted successfully' }));
});

app.get('/api/services', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM services ORDER BY created_at DESC');
  return res.json(buildSuccess(rows));
});

app.post('/api/services', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { name, description, price, status } = req.body || {};
    if (!name) return res.status(400).json(buildError('Service name is required', 400));
    const id = randomUUID();
    await run('INSERT INTO services (id, name, description, price, status) VALUES (?, ?, ?, ?, ?)', [id, name, description || '', Number(price || 0), status || 'active']);
    return res.status(201).json(buildSuccess({ id }, { message: 'Service created successfully' }));
  } catch (error) { next(error); }
});

app.put('/api/services/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { name, description, price, status } = req.body || {};
  await run('UPDATE services SET name = ?, description = ?, price = ?, status = ?, updated_at = ? WHERE id = ?', [name || '', description || '', Number(price || 0), status || 'active', new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'Service updated successfully' }));
});

app.delete('/api/services/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await run('DELETE FROM services WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Service deleted successfully' }));
});

app.get('/api/plans', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM plans ORDER BY monthly_price ASC');
  return res.json(buildSuccess(rows));
});

app.post('/api/plans', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { name, description, monthlyPrice, yearlyPrice, aiLimit, projectLimit, clientLimit, status } = req.body || {};
    if (!name) return res.status(400).json(buildError('Plan name is required', 400));
    const id = randomUUID();
    await run('INSERT INTO plans (id, name, description, monthly_price, yearly_price, ai_limit, project_limit, client_limit, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [id, name, description || '', Number(monthlyPrice || 0), Number(yearlyPrice || 0), Number(aiLimit || 0), Number(projectLimit || 0), Number(clientLimit || 0), status || 'active']);
    return res.status(201).json(buildSuccess({ id }, { message: 'Plan created successfully' }));
  } catch (error) { next(error); }
});

app.put('/api/plans/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { name, description, monthlyPrice, yearlyPrice, aiLimit, projectLimit, clientLimit, status } = req.body || {};
  await run('UPDATE plans SET name = ?, description = ?, monthly_price = ?, yearly_price = ?, ai_limit = ?, project_limit = ?, client_limit = ?, status = ?, updated_at = ? WHERE id = ?', [name || '', description || '', Number(monthlyPrice || 0), Number(yearlyPrice || 0), Number(aiLimit || 0), Number(projectLimit || 0), Number(clientLimit || 0), status || 'active', new Date().toISOString(), req.params.id]);
  return res.json(buildSuccess(null, { message: 'Plan updated successfully' }));
});

app.delete('/api/plans/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await run('DELETE FROM plans WHERE id = ?', [req.params.id]);
  return res.json(buildSuccess(null, { message: 'Plan deleted successfully' }));
});

app.get('/api/subscriptions/me', requireAuth, async (req, res) => {
  const rows = await all('SELECT s.*, p.name as plan_name FROM subscriptions s JOIN plans p ON p.id = s.plan_id WHERE s.user_id = ? ORDER BY s.created_at DESC', [req.user.id]);
  return res.json(buildSuccess(rows));
});

app.post('/api/subscriptions', requireAuth, async (req, res, next) => {
  try {
    const { planId, status } = req.body || {};
    if (!planId) return res.status(400).json(buildError('Plan is required', 400));
    const subscriptionId = randomUUID();
    await run('INSERT INTO subscriptions (id, user_id, plan_id, status) VALUES (?, ?, ?, ?)', [subscriptionId, req.user.id, planId, status || 'active']);
    return res.status(201).json(buildSuccess({ id: subscriptionId }, { message: 'Subscription created successfully' }));
  } catch (error) { next(error); }
});

app.get('/api/payments', requireAuth, requireRole('admin'), async (req, res) => {
  const rows = await all('SELECT * FROM payments ORDER BY created_at DESC');
  return res.json(buildSuccess(rows));
});

app.get('/api/payments/:id', requireAuth, async (req, res) => {
  const payment = await get('SELECT * FROM payments WHERE id = ?', [req.params.id]);
  if (!payment) return res.status(404).json(buildError('Payment not found', 404));
  return res.json(buildSuccess({ payment }));
});

app.get('/api/analytics/dashboard', requireAuth, async (_req, res) => {
  const data = {
    totalUsers: await get('SELECT COUNT(*) as count FROM users'),
    activeUsers: await get('SELECT COUNT(*) as count FROM users WHERE status = ?', ['active']),
    totalClients: await get('SELECT COUNT(*) as count FROM clients'),
    totalProjects: await get('SELECT COUNT(*) as count FROM projects'),
    completedProjects: await get('SELECT COUNT(*) as count FROM projects WHERE status = ?', ['completed']),
    activeProjects: await get('SELECT COUNT(*) as count FROM projects WHERE status = ?', ['active']),
    totalTasks: await get('SELECT COUNT(*) as count FROM tasks'),
    completedTasks: await get('SELECT COUNT(*) as count FROM tasks WHERE status = ?', ['done']),
    totalMessages: await get('SELECT COUNT(*) as count FROM messages'),
    unreadMessages: await get('SELECT COUNT(*) as count FROM messages WHERE is_read = ?', [0]),
    aiRequests: await get('SELECT COUNT(*) as count FROM ai_usage'),
    aiTokens: await get('SELECT COALESCE(SUM(total_tokens), 0) as count FROM ai_usage'),
    subscriptions: await get('SELECT COUNT(*) as count FROM subscriptions'),
    revenue: await get('SELECT COALESCE(SUM(amount), 0) as count FROM payments WHERE status = ?', ['paid']),
  };

  return res.json(buildSuccess({
    totalUsers: Number(data.totalUsers.count || 0),
    activeUsers: Number(data.activeUsers.count || 0),
    totalClients: Number(data.totalClients.count || 0),
    totalProjects: Number(data.totalProjects.count || 0),
    completedProjects: Number(data.completedProjects.count || 0),
    activeProjects: Number(data.activeProjects.count || 0),
    totalTasks: Number(data.totalTasks.count || 0),
    completedTasks: Number(data.completedTasks.count || 0),
    totalMessages: Number(data.totalMessages.count || 0),
    unreadMessages: Number(data.unreadMessages.count || 0),
    aiRequests: Number(data.aiRequests.count || 0),
    aiTokens: Number(data.aiTokens.count || 0),
    subscriptions: Number(data.subscriptions.count || 0),
    revenue: Number(data.revenue.count || 0),
  }));
});

app.get('/api/settings', requireAuth, async (req, res) => {
  const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id]);
  return res.json(buildSuccess({ settings }));
});

app.put('/api/settings', requireAuth, async (req, res) => {
  const { theme, language, timezone, aiPreferences, notificationsEnabled } = req.body || {};
  const existing = await get('SELECT id FROM user_settings WHERE user_id = ?', [req.user.id]);
  if (existing) {
    await run('UPDATE user_settings SET theme = ?, language = ?, timezone = ?, ai_preferences = ?, notifications_enabled = ?, updated_at = ? WHERE user_id = ?', [theme || 'dark', language || 'en', timezone || 'UTC', JSON.stringify(aiPreferences || {}), notificationsEnabled !== undefined ? Number(notificationsEnabled) : 1, new Date().toISOString(), req.user.id]);
  } else {
    await run('INSERT INTO user_settings (id, user_id, theme, language, timezone, ai_preferences, notifications_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)', [randomUUID(), req.user.id, theme || 'dark', language || 'en', timezone || 'UTC', JSON.stringify(aiPreferences || {}), notificationsEnabled !== undefined ? Number(notificationsEnabled) : 1]);
  }
  return res.json(buildSuccess(null, { message: 'Settings updated successfully' }));
});

app.get('/api/activity', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
  return res.json(buildSuccess(rows));
});

app.get('/api/admin/users', requireAuth, requireRole('admin'), async (_req, res) => {
  const rows = await all('SELECT id, name, email, role, status, company, phone, avatar, created_at FROM users ORDER BY created_at DESC');
  return res.json(buildSuccess(rows));
});

app.get('/api/admin/analytics', requireAuth, requireRole('admin'), async (_req, res) => {
  const analytics = await get('SELECT COUNT(*) as totalUsers FROM users');
  return res.json(buildSuccess({ totalUsers: Number(analytics.totalUsers || 0) }));
});

app.get('/api/admin/activity', requireAuth, requireRole('admin'), async (_req, res) => {
  const rows = await all('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 100');
  return res.json(buildSuccess(rows));
});

app.get('/api/admin/settings', requireAuth, requireRole('admin'), async (_req, res) => {
  return res.json(buildSuccess({ system: 'Aether AI SaaS', status: 'healthy' }));
});

app.post('/api/webhooks/payment', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['stripe-signature'];
  if (!signature) {
    return res.status(400).json(buildError('Missing signature', 400));
  }
  return res.json(buildSuccess({ received: true }, { message: 'Webhook received' }));
});

app.use(notFoundHandler);
app.use(errorHandler);

async function initializeApp() {
  await initializeDatabase();
  if (!app.server) {
    app.server = app.listen(PORT, '127.0.0.1', () => {
      console.log(`Server started on port ${PORT}`);
    });
  }
  return app.server;
}

if (require.main === module) {
  initializeApp().catch((error) => {
    console.error('Failed to start server', error);
    process.exit(1);
  });
}

module.exports = { app, initializeApp };

// GET ALL USERS (Admin)
app.get("/users", async (req, res) => {
  try {
    const result = await sql.query(`
      SELECT UserID, FullName, Email, Phone, Role
      FROM Users
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});
// DELETE USER
app.delete("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await sql.query`
      DELETE FROM Users
      WHERE UserID = ${id}
    `;

    res.json({
      message: "User deleted successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});

// ADD USER
app.post("/users", async (req, res) => {
  try {
    const { FullName, Email, Phone, Password, Role } = req.body;

    await sql.query`
      INSERT INTO Users (FullName, Email, Phone, Password, Role)
      VALUES (
        ${FullName},
        ${Email},
        ${Phone},
        ${Password},
        ${Role}
      )
    `;

    res.json({
      message: "User added successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });

  }
});
// SEND MESSAGE
app.post("/messages", async (req, res) => {
  console.log(req.body);
  try {
    const { FullName, Email, Subject, Message } = req.body;

    await sql.query`
      INSERT INTO Messages (FullName, Email, Subject, Message)
      VALUES (${FullName}, ${Email}, ${Subject}, ${Message})
    `;

    res.status(201).json({
      message: "Message sent successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});

// GET ALL MESSAGES
app.get("/messages", async (req, res) => {
  try {
    const result = await sql.query(`
      SELECT *
      FROM Messages
      ORDER BY CreatedAt DESC
    `);

    res.json(result.recordset);

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});

// DELETE MESSAGE
app.delete("/messages/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await sql.query`
      DELETE FROM Messages
      WHERE MessageID = ${id}
    `;

    res.json({
      message: "Message deleted successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});
// DASHBOARD STATISTICS
app.get("/dashboard-stats", async (req, res) => {
  try {
    const users = await sql.query(`
      SELECT COUNT(*) AS TotalUsers
      FROM Users
    `);

    const services = await sql.query(`
      SELECT COUNT(*) AS TotalServices
      FROM Services
    `);

    const messages = await sql.query(`
      SELECT COUNT(*) AS TotalMessages
      FROM Messages
    `);

    const bookings = await sql.query(`
      SELECT COUNT(*) AS TotalBookings
      FROM Bookings
    `);

    const revenue = await sql.query(`
      SELECT SUM(
        TRY_CAST(
          REPLACE(Price, '$', '') AS FLOAT
        )
      ) AS TotalRevenue
      FROM Services
    `);

    res.json({
      users: users.recordset[0].TotalUsers,
      services: services.recordset[0].TotalServices,
      messages: messages.recordset[0].TotalMessages,
      bookings: bookings.recordset[0].TotalBookings,
      revenue: revenue.recordset[0].TotalRevenue || 0,
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});
// AI CHAT
app.post("/ai-chat", async (req, res) => {
  try {
    const { message } = req.body;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-pro",
      contents: [
        {
          role: "user",
          parts: [{ text: message }],
        },
      ],
    });

    console.log(response);

    res.json({
      reply: response.text,
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: err.message,
    });
  }
});
// CREATE BOOKING
app.post("/bookings", async (req, res) => {
  try {
    const {
      FullName,
      Email,
      Phone,
      Service,
      BookingDate,
      BookingTime,
      Message,
    } = req.body;

    await sql.query`
      INSERT INTO Bookings
      (
        FullName,
        Email,
        Phone,
        Service,
        BookingDate,
        BookingTime,
        Message
      )
      VALUES
      (
        ${FullName},
        ${Email},
        ${Phone},
        ${Service},
        ${BookingDate},
        ${BookingTime},
        ${Message}
      )
    `;

    res.status(201).json({
      message: "Booking created successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});
// GET BOOKINGS
app.get("/bookings", async (req, res) => {
  try {

    const result = await sql.query(`
      SELECT *
      FROM Bookings
      ORDER BY CreatedAt DESC
    `);

    res.json(result.recordset);

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});
// UPDATE BOOKING STATUS
app.put("/bookings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { Status } = req.body;

    await sql.query`
      UPDATE Bookings
      SET Status = ${Status}
      WHERE BookingID = ${id}
    `;

    res.json({
      message: "Booking updated successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});
// DELETE BOOKING
app.delete("/bookings/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await sql.query`
      DELETE FROM Bookings
      WHERE BookingID = ${id}
    `;

    res.json({
      message: "Booking deleted successfully",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Database Error",
    });
  }
});

app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { service, price, planId, billingInterval = 'monthly' } = req.body;

    if (!STRIPE_SECRET_KEY || !stripe) {
      return res.status(501).json({
        message: 'Stripe is not configured. Add STRIPE_SECRET_KEY to your backend environment variables before enabling real payments.',
      });
    }

    const selectedPlan = plans.find((plan) => plan.id === planId || plan.name === service);
    const unitAmount = Number(price || selectedPlan?.price || 0) * 100;

    if (!service || !unitAmount || unitAmount <= 0) {
      return res.status(400).json({ message: 'A valid service name and price are required.' });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: service,
              metadata: {
                billingInterval,
                planId: planId || selectedPlan?.id || service,
              },
            },
            unit_amount: Number(unitAmount),
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${FRONTEND_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/payment-cancel`,
      metadata: {
        service,
        planId: planId || selectedPlan?.id || service,
        billingInterval,
      },
    });

    res.json({ id: session.id, url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: err.message || 'Payment session could not be created.' });
  }
});

app.post('/api/webhooks/stripe', async (req, res) => {
  if (!STRIPE_SECRET_KEY || !stripe) {
    return res.status(501).json({ message: 'Stripe webhook support is disabled until STRIPE_SECRET_KEY is configured.' });
  }

  const signature = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
  } catch (err) {
    console.error('Webhook verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    console.log('Payment received for:', session.metadata?.service || 'unknown service');
  }

  res.json({ received: true });
});

// Start Server
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
  });
});