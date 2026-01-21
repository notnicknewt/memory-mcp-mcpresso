/**
 * Memory MCP Server with OAuth 2.1
 * Built with MCPresso + mcpresso-oauth-server
 */
import { createMCPServer, createResource } from 'mcpresso';
import { MCPOAuthServer, MemoryStorage } from 'mcpresso-oauth-server';
import type { OAuthUser, UserAuthContext } from 'mcpresso-oauth-server';
import { Pool } from 'pg';
import { z } from 'zod';
import crypto from 'crypto';
import type { Request, Response } from 'express';

// =============================================================================
// Configuration
// =============================================================================

const PORT = parseInt(process.env.PORT || '3000');
const DATABASE_URL = process.env.DATABASE_URL!;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;

// =============================================================================
// Database Connection
// =============================================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database schema
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        scopes TEXT[] DEFAULT ARRAY['read', 'write'],
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, name)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ended_at TIMESTAMP,
        summary TEXT,
        outcome TEXT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS change_log (
        id SERIAL PRIMARY KEY,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        file_path TEXT,
        change_type TEXT NOT NULL,
        what_changed TEXT NOT NULL,
        why_changed TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS lessons_learned (
        id SERIAL PRIMARY KEY,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        problem TEXT NOT NULL,
        solution TEXT,
        avoid TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS context_snapshots (
        id SERIAL PRIMARY KEY,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        snapshot_type TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database schema initialized');
  } finally {
    client.release();
  }
}

// =============================================================================
// User Authentication
// =============================================================================

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  const verify = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return hash === verify;
}

async function authenticateUser(credentials: { username: string; password: string }): Promise<OAuthUser | null> {
  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1 OR email = $1',
    [credentials.username]
  );

  if (result.rows.length === 0) return null;

  const user = result.rows[0];
  const valid = await verifyPassword(credentials.password, user.password_hash);

  if (!valid) return null;

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    scopes: user.scopes || ['read', 'write'],
    createdAt: new Date(user.created_at),
    updatedAt: new Date(user.updated_at)
  };
}

async function createUser(username: string, email: string, password: string) {
  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  await pool.query(
    `INSERT INTO users (id, username, email, password_hash)
     VALUES ($1, $2, $3, $4)`,
    [id, username, email, passwordHash]
  );

  return { id, username, email };
}

// =============================================================================
// Memory Context (per-user project selection)
// =============================================================================

const userContexts = new Map<string, { projectId: number; projectName: string }>();

function getUserContext(userId: string) {
  return userContexts.get(userId);
}

function setUserContext(userId: string, projectId: number, projectName: string) {
  userContexts.set(userId, { projectId, projectName });
}

// =============================================================================
// Memory Resource (MCP Tools)
// =============================================================================

const memoryResource = createResource({
  name: 'memory',
  uri_template: 'memory:///{id}',
  schema: z.object({
    id: z.string(),
    type: z.string(),
    content: z.string(),
    createdAt: z.string()
  }) as any,

  methods: {
    // List all projects for the authenticated user
    list_projects: {
      description: 'List all projects in memory',
      inputSchema: z.object({}),
      handler: async (_args: any, user: any) => {
        if (!user) throw new Error('Authentication required');

        const result = await pool.query(
          'SELECT name, description FROM projects WHERE user_id = $1 ORDER BY name',
          [user.id || user.sub]
        );

        if (result.rows.length === 0) {
          return 'No projects yet. Use create_project to create one.';
        }

        let output = 'Projects:\n';
        for (const row of result.rows) {
          output += `- ${row.name}: ${row.description || 'No description'}\n`;
        }
        return output;
      }
    },

    // Create a new project
    create_project: {
      description: 'Create a new project',
      inputSchema: z.object({
        name: z.string().describe('Project name (unique identifier)'),
        description: z.string().optional().describe('Project description')
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;

        try {
          const result = await pool.query(
            'INSERT INTO projects (user_id, name, description) VALUES ($1, $2, $3) RETURNING id',
            [userId, args.name, args.description || '']
          );

          setUserContext(userId, result.rows[0].id, args.name);
          return `Created and selected project: ${args.name}`;
        } catch (e: any) {
          if (e.code === '23505') {
            return `Project '${args.name}' already exists. Use select_project.`;
          }
          throw e;
        }
      }
    },

    // Select an existing project
    select_project: {
      description: 'Select a project to work with',
      inputSchema: z.object({
        name: z.string().describe('Project name')
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;

        const result = await pool.query(
          'SELECT id FROM projects WHERE user_id = $1 AND name = $2',
          [userId, args.name]
        );

        if (result.rows.length === 0) {
          return `Project '${args.name}' not found. Use list_projects or create_project.`;
        }

        setUserContext(userId, result.rows[0].id, args.name);
        return `Selected project: ${args.name}`;
      }
    },

    // Get current project status
    status: {
      description: 'Get current project memory status',
      inputSchema: z.object({}),
      handler: async (_args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected. Use select_project first.';

        let output = `=== ${ctx.projectName} ===\n\n`;

        const session = await pool.query(
          'SELECT summary, started_at FROM sessions WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1',
          [ctx.projectId]
        );
        if (session.rows.length > 0) {
          output += `Last session: ${session.rows[0].summary} (${session.rows[0].started_at})\n`;
        }

        const changes = await pool.query(
          'SELECT what_changed FROM change_log WHERE project_id = $1 ORDER BY created_at DESC LIMIT 5',
          [ctx.projectId]
        );
        if (changes.rows.length > 0) {
          output += '\n--- Recent Changes ---\n';
          for (const c of changes.rows) {
            output += `  - ${c.what_changed.slice(0, 60)}\n`;
          }
        }

        const lessons = await pool.query(
          'SELECT COUNT(*) as count FROM lessons_learned WHERE project_id = $1',
          [ctx.projectId]
        );
        output += `\nLessons learned: ${lessons.rows[0].count}\n`;

        return output;
      }
    },

    // Start a session
    session_start: {
      description: 'Start a new session',
      inputSchema: z.object({
        summary: z.string().describe('Session focus')
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        const result = await pool.query(
          'INSERT INTO sessions (project_id, summary) VALUES ($1, $2) RETURNING id',
          [ctx.projectId, args.summary]
        );

        return `Session started (ID: ${result.rows[0].id}): ${args.summary}`;
      }
    },

    // End a session
    session_end: {
      description: 'End the current session',
      inputSchema: z.object({
        summary: z.string().describe('What was accomplished'),
        outcome: z.string().optional().describe('completed/paused/blocked')
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        await pool.query(
          `UPDATE sessions SET ended_at = CURRENT_TIMESTAMP, summary = $1, outcome = $2
           WHERE id = (SELECT MAX(id) FROM sessions WHERE project_id = $3)`,
          [args.summary, args.outcome || 'completed', ctx.projectId]
        );

        return `Session ended: ${args.summary} (${args.outcome || 'completed'})`;
      }
    },

    // Log a change
    log_change: {
      description: 'Log a change with reasoning',
      inputSchema: z.object({
        file_path: z.string(),
        change_type: z.string(),
        what_changed: z.string(),
        why_changed: z.string()
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        const result = await pool.query(
          `INSERT INTO change_log (project_id, file_path, change_type, what_changed, why_changed)
           VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [ctx.projectId, args.file_path, args.change_type, args.what_changed, args.why_changed]
        );

        return `Change logged (ID: ${result.rows[0].id})`;
      }
    },

    // Add a lesson learned
    add_lesson: {
      description: 'Record a lesson learned',
      inputSchema: z.object({
        problem: z.string(),
        solution: z.string(),
        avoid: z.string().optional()
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        const result = await pool.query(
          `INSERT INTO lessons_learned (project_id, problem, solution, avoid)
           VALUES ($1, $2, $3, $4) RETURNING id`,
          [ctx.projectId, args.problem, args.solution, args.avoid || null]
        );

        return `Lesson recorded (ID: ${result.rows[0].id})`;
      }
    },

    // Mark a phase complete
    phase_complete: {
      description: 'Mark a phase complete',
      inputSchema: z.object({
        phase_name: z.string(),
        summary: z.string()
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        await pool.query(
          `INSERT INTO context_snapshots (project_id, snapshot_type, summary)
           VALUES ($1, 'phase_complete', $2)`,
          [ctx.projectId, `${args.phase_name}: ${args.summary}`]
        );

        return `Phase '${args.phase_name}' saved to memory`;
      }
    },

    // Get lessons learned
    get_lessons: {
      description: 'Get all lessons learned',
      inputSchema: z.object({}),
      handler: async (_args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        const result = await pool.query(
          'SELECT problem, solution, avoid FROM lessons_learned WHERE project_id = $1 ORDER BY created_at DESC',
          [ctx.projectId]
        );

        if (result.rows.length === 0) return 'No lessons recorded yet.';

        let output = 'Lessons Learned:\n\n';
        for (const l of result.rows) {
          output += `Problem: ${l.problem}\nSolution: ${l.solution}\n`;
          if (l.avoid) output += `Avoid: ${l.avoid}\n`;
          output += '\n';
        }
        return output;
      }
    },

    // Get recent changes
    recent_changes: {
      description: 'Get recent changes',
      inputSchema: z.object({
        limit: z.number().optional().default(10)
      }),
      handler: async (args: any, user: any) => {
        if (!user) throw new Error('Authentication required');
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected.';

        const result = await pool.query(
          `SELECT file_path, change_type, what_changed, why_changed
           FROM change_log WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2`,
          [ctx.projectId, args.limit || 10]
        );

        if (result.rows.length === 0) return 'No changes logged yet.';

        let output = `Recent Changes (last ${args.limit || 10}):\n\n`;
        for (const c of result.rows) {
          output += `[${c.change_type}] ${c.file_path}\n`;
          output += `  What: ${c.what_changed}\n`;
          output += `  Why: ${c.why_changed}\n\n`;
        }
        return output;
      }
    }
  }
});

// =============================================================================
// Server Setup
// =============================================================================

async function main() {
  // Initialize database
  await initDatabase();

  // Create storage for OAuth (using in-memory for simplicity - tokens stored in memory)
  const storage = new MemoryStorage();

  // Create OAuth server
  const oauthServer = new MCPOAuthServer({
    issuer: SERVER_URL,
    serverUrl: SERVER_URL,
    jwtSecret: JWT_SECRET,
    auth: {
      authenticateUser: async (credentials: { username: string; password: string }, _context: UserAuthContext) => {
        return authenticateUser(credentials);
      },
      getCurrentUser: async (_sessionData: any, _context: UserAuthContext) => null,
      renderLoginPage: async (context: UserAuthContext, error?: string) => {
        return `
<!DOCTYPE html>
<html>
<head>
  <title>Memory MCP - Login</title>
  <style>
    body { font-family: system-ui; max-width: 400px; margin: 100px auto; padding: 20px; }
    h2 { color: #333; }
    form { display: flex; flex-direction: column; gap: 15px; }
    input { padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
    button { padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background: #0056b3; }
    .error { color: red; margin-bottom: 10px; }
    .info { color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <h2>Memory MCP Server</h2>
  <p class="info">Login to connect Claude to your memory</p>
  ${error ? `<p class="error">${error}</p>` : ''}
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="${context.clientId}">
    <input type="hidden" name="redirect_uri" value="${context.redirectUri}">
    <input type="hidden" name="scope" value="${context.scope || ''}">
    <input type="text" name="username" placeholder="Username or Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login & Authorize</button>
  </form>
</body>
</html>`;
      }
    }
  }, storage);

  // Create MCP server with integrated OAuth
  const app = createMCPServer({
    name: 'memory-mcp',
    serverUrl: SERVER_URL,
    resources: [memoryResource],
    auth: {
      oauth: oauthServer,
      userLookup: async (jwtPayload: any) => {
        const result = await pool.query(
          'SELECT id, username, email, scopes FROM users WHERE id = $1',
          [jwtPayload.sub]
        );
        if (result.rows.length === 0) return null;
        return {
          id: result.rows[0].id,
          username: result.rows[0].username,
          email: result.rows[0].email,
          scopes: result.rows[0].scopes
        };
      }
    },
    serverMetadata: {
      name: 'Memory MCP',
      version: '1.0.0',
      description: 'Persistent memory for Claude - stores project context, changes, and lessons learned',
      capabilities: {
        authentication: true,
        streaming: true
      }
    }
  });

  // Health check
  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', database: 'connected' });
  });

  // User registration endpoint (for initial setup)
  app.post('/register-user', async (req: Request, res: Response) => {
    try {
      const { username, email, password } = req.body;
      if (!username || !email || !password) {
        res.status(400).json({ error: 'username, email, and password required' });
        return;
      }
      const user = await createUser(username, email, password);
      res.json({ success: true, user: { id: user.id, username: user.username, email: user.email } });
    } catch (e: any) {
      if (e.code === '23505') {
        res.status(400).json({ error: 'Username or email already exists' });
        return;
      }
      res.status(500).json({ error: e.message });
    }
  });

  app.listen(PORT, () => {
    console.log(`Memory MCP Server running on ${SERVER_URL}`);
    console.log(`OAuth endpoints: ${SERVER_URL}/authorize, ${SERVER_URL}/token`);
    console.log(`MCP endpoint: ${SERVER_URL}/mcp`);
    console.log(`Health: ${SERVER_URL}/health`);
    console.log(`Register user: POST ${SERVER_URL}/register-user`);
  });
}

main().catch(console.error);
