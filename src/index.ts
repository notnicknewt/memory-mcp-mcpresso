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
const ADMIN_SECRET = process.env.ADMIN_SECRET; // Required to access admin page

// =============================================================================
// Database Connection
// =============================================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database schema with migrations
async function initDatabase() {
  const client = await pool.connect();
  try {
    console.log('=== Database Schema Initialization ===');

    // Helper to add column if it doesn't exist
    const addColumn = async (table: string, column: string, definition: string) => {
      try {
        await client.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
        console.log(`    + Added column ${table}.${column}`);
      } catch (e: any) {
        if (e.message.includes('already exists')) {
          console.log(`    - Column ${table}.${column} exists`);
        } else {
          throw e;
        }
      }
    };

    // Helper to check if table exists
    const tableExists = async (table: string): Promise<boolean> => {
      const result = await client.query(
        `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)`,
        [table]
      );
      return result.rows[0].exists;
    };

    // =========================================================================
    // USERS TABLE
    // =========================================================================
    console.log('\n[1/9] users table...');
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
    console.log('  OK');

    // =========================================================================
    // PROJECTS TABLE
    // =========================================================================
    console.log('\n[2/9] projects table...');
    const projectsExisted = await tableExists('projects');
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    // Migration: Add user_id if missing
    await addColumn('projects', 'user_id', 'TEXT');
    // Set default user_id for existing rows
    if (projectsExisted) {
      const updated = await client.query(`
        UPDATE projects SET user_id = COALESCE(
          (SELECT id FROM users LIMIT 1),
          'legacy'
        ) WHERE user_id IS NULL
        RETURNING id
      `);
      if (updated.rowCount && updated.rowCount > 0) {
        console.log(`    Migrated ${updated.rowCount} existing projects with user_id`);
      }
    }
    console.log('  OK');

    // =========================================================================
    // SESSIONS TABLE
    // =========================================================================
    console.log('\n[3/9] sessions table...');
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
    // Migration: Add user_id if missing (for sessions not tied to projects)
    await addColumn('sessions', 'user_id', 'TEXT');
    console.log('  OK');

    // =========================================================================
    // CHANGE_LOG TABLE
    // =========================================================================
    console.log('\n[4/9] change_log table...');
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
    console.log('  OK');

    // =========================================================================
    // LESSONS_LEARNED TABLE
    // =========================================================================
    console.log('\n[5/9] lessons_learned table...');
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
    console.log('  OK');

    // =========================================================================
    // CONTEXT_SNAPSHOTS TABLE
    // =========================================================================
    console.log('\n[6/9] context_snapshots table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS context_snapshots (
        id SERIAL PRIMARY KEY,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        snapshot_type TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  OK');

    // =========================================================================
    // COMMITMENTS TABLE (Accountability)
    // =========================================================================
    console.log('\n[7/9] commitments table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS commitments (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
        description TEXT NOT NULL,
        type VARCHAR(20) DEFAULT 'one-off',
        due_date DATE NOT NULL,
        status VARCHAR(20) DEFAULT 'open',
        reschedule_count INTEGER DEFAULT 0,
        outcome_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      )
    `);
    console.log('  OK');

    // =========================================================================
    // PATTERNS TABLE (Accountability)
    // =========================================================================
    console.log('\n[8/9] patterns table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS patterns (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        category VARCHAR(50),
        valence VARCHAR(20) DEFAULT 'neutral',
        examples TEXT[] DEFAULT ARRAY[]::TEXT[],
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  OK');

    // =========================================================================
    // CHECK_INS TABLE (Accountability)
    // =========================================================================
    console.log('\n[9/9] check_ins table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS check_ins (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        date DATE DEFAULT CURRENT_DATE,
        commitments_due INTEGER[] DEFAULT ARRAY[]::INTEGER[],
        commitments_completed INTEGER[] DEFAULT ARRAY[]::INTEGER[],
        notes TEXT,
        patterns_observed INTEGER[] DEFAULT ARRAY[]::INTEGER[],
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  OK');

    // =========================================================================
    // VERIFY ALL TABLES
    // =========================================================================
    console.log('\n=== Verification ===');
    const tables = ['users', 'projects', 'sessions', 'change_log', 'lessons_learned',
                    'context_snapshots', 'commitments', 'patterns', 'check_ins'];
    for (const table of tables) {
      const exists = await tableExists(table);
      console.log(`  ${exists ? '✓' : '✗'} ${table}`);
    }

    console.log('\n=== Database schema initialized successfully ===');
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
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
        console.log(`[list_projects] Called`);
        if (!user) return 'Error: Authentication required';

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
      description: 'Create a new project. REQUIRED: name parameter.',
      inputSchema: z.object({
        name: z.string().default('').describe('Project name (unique identifier) - REQUIRED'),
        description: z.string().default('').describe('Project description')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[create_project] Called with args:`, JSON.stringify(args));

        // Validate required param (Zod allows empty string via default, we check here)
        if (!args || !args.name || args.name.trim() === '') {
          return 'Error: name parameter is required. Usage: create_project(name: "my-project", description: "optional")';
        }

        if (!user) {
          console.log(`[create_project] No user context`);
          return 'Error: Authentication required';
        }
        const userId = user.id || user.sub;

        console.log(`[create_project] User: ${userId}, Name: ${args.name}`);

        try {
          const result = await pool.query(
            'INSERT INTO projects (user_id, name, description) VALUES ($1, $2, $3) RETURNING id',
            [userId, args.name, args.description || '']
          );

          console.log(`[create_project] Created project ID: ${result.rows[0].id}`);
          setUserContext(userId, result.rows[0].id, args.name);
          return `Created and selected project: ${args.name}`;
        } catch (e: any) {
          console.error(`[create_project] Error:`, e.message, e.code);
          if (e.code === '23505') {
            return `Project '${args.name}' already exists. Use select_project.`;
          }
          return `Error creating project: ${e.message}`;
        }
      }
    },

    // Select an existing project
    select_project: {
      description: 'Select a project to work with. REQUIRED: name parameter.',
      inputSchema: z.object({
        name: z.string().default('').describe('Project name - REQUIRED')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[select_project] Called with args:`, JSON.stringify(args));

        if (!args || !args.name || args.name.trim() === '') {
          return 'Error: name parameter is required. Usage: select_project(name: "my-project")';
        }

        if (!user) return 'Error: Authentication required';
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
        if (!user) return 'Error: Authentication required';
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
      description: 'Start a new session. REQUIRED: summary parameter.',
      inputSchema: z.object({
        summary: z.string().default('').describe('Session focus - REQUIRED')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[session_start] Called with args:`, JSON.stringify(args));

        if (!args || !args.summary || args.summary.trim() === '') {
          return 'Error: summary parameter is required. Usage: session_start(summary: "Working on feature X")';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;
        const ctx = getUserContext(userId);

        if (!ctx) return 'No project selected. Use select_project first.';

        const result = await pool.query(
          'INSERT INTO sessions (project_id, summary) VALUES ($1, $2) RETURNING id',
          [ctx.projectId, args.summary]
        );

        return `Session started (ID: ${result.rows[0].id}): ${args.summary}`;
      }
    },

    // End a session
    session_end: {
      description: 'End the current session. REQUIRED: summary parameter.',
      inputSchema: z.object({
        summary: z.string().default('').describe('What was accomplished - REQUIRED'),
        outcome: z.string().default('completed').describe('completed/paused/blocked')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[session_end] Called with args:`, JSON.stringify(args));

        if (!args || !args.summary || args.summary.trim() === '') {
          return 'Error: summary parameter is required. Usage: session_end(summary: "Completed feature X", outcome: "completed")';
        }

        if (!user) return 'Error: Authentication required';
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
      description: 'Log a change with reasoning. ALL parameters REQUIRED.',
      inputSchema: z.object({
        file_path: z.string().default('').describe('File path - REQUIRED'),
        change_type: z.string().default('').describe('Change type - REQUIRED'),
        what_changed: z.string().default('').describe('What changed - REQUIRED'),
        why_changed: z.string().default('').describe('Why changed - REQUIRED')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[log_change] Called with args:`, JSON.stringify(args));

        if (!args || !args.file_path || !args.change_type || !args.what_changed || !args.why_changed) {
          return 'Error: all parameters required. Usage: log_change(file_path, change_type, what_changed, why_changed)';
        }

        if (!user) return 'Error: Authentication required';
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
      description: 'Record a lesson learned. REQUIRED: problem, solution.',
      inputSchema: z.object({
        problem: z.string().default('').describe('Problem description - REQUIRED'),
        solution: z.string().default('').describe('Solution - REQUIRED'),
        avoid: z.string().default('').describe('What to avoid')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[add_lesson] Called with args:`, JSON.stringify(args));

        if (!args || !args.problem || !args.solution) {
          return 'Error: problem and solution are required. Usage: add_lesson(problem, solution, avoid?)';
        }

        if (!user) return 'Error: Authentication required';
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
        if (!user) return 'Error: Authentication required';
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
        if (!user) return 'Error: Authentication required';
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
        if (!user) return 'Error: Authentication required';
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
    },

    // =========================================================================
    // COMMITMENT TOOLS
    // =========================================================================

    create_commitment: {
      description: 'Create a new commitment/accountability item. REQUIRED: description, due_date.',
      inputSchema: z.object({
        description: z.string().default('').describe('What you are committing to - REQUIRED'),
        due_date: z.string().default('').describe('Due date (YYYY-MM-DD) - REQUIRED'),
        type: z.enum(['one-off', 'recurring']).default('one-off').describe('one-off or recurring'),
        project_name: z.string().default('').describe('Associated project (optional)')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[create_commitment] Called with args:`, JSON.stringify(args));

        if (!args || !args.description || !args.due_date) {
          return 'Error: description and due_date are required. Usage: create_commitment(description: "task", due_date: "2026-01-25")';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        let projectId = null;
        if (args.project_name) {
          const proj = await pool.query(
            'SELECT id FROM projects WHERE user_id = $1 AND name = $2',
            [userId, args.project_name]
          );
          if (proj.rows.length > 0) projectId = proj.rows[0].id;
        }

        const result = await pool.query(
          `INSERT INTO commitments (user_id, project_id, description, type, due_date)
           VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [userId, projectId, args.description, args.type || 'one-off', args.due_date]
        );

        return `Commitment created (ID: ${result.rows[0].id}): "${args.description}" due ${args.due_date}`;
      }
    },

    list_commitments: {
      description: 'List commitments by status',
      inputSchema: z.object({
        status: z.enum(['open', 'done', 'missed', 'rescheduled', 'all']).optional(),
        include_overdue: z.boolean().optional()
      }),
      handler: async (args: any, user: any) => {
        try {
          if (!user) return 'Error: Authentication required';
          const userId = user.id || user.sub;
          const status = args.status || 'open';

          console.log(`[list_commitments] User: ${userId}, Status: ${status}`);

          let query = `SELECT c.*, p.name as project_name
                       FROM commitments c
                       LEFT JOIN projects p ON c.project_id = p.id
                       WHERE c.user_id = $1`;
          const params: any[] = [userId];

          if (status !== 'all') {
            query += ` AND c.status = $2`;
            params.push(status);
          }

          query += ' ORDER BY c.due_date ASC';

          const result = await pool.query(query, params);

        if (result.rows.length === 0) {
          return `No ${args.status || 'open'} commitments found.`;
        }

        const today = new Date().toISOString().split('T')[0];
        let output = `Commitments (${args.status || 'open'}):\n\n`;

        for (const c of result.rows) {
          const dueDate = c.due_date.toISOString().split('T')[0];
          const isOverdue = c.status === 'open' && dueDate < today;
          const overdueFlag = isOverdue ? ' ⚠️ OVERDUE' : '';
          const projectTag = c.project_name ? ` [${c.project_name}]` : '';
          const rescheduleNote = c.reschedule_count > 0 ? ` (rescheduled ${c.reschedule_count}x)` : '';

          output += `#${c.id} [${c.status.toUpperCase()}]${overdueFlag}${projectTag}\n`;
          output += `  "${c.description}"\n`;
          output += `  Due: ${dueDate}${rescheduleNote}\n`;
          if (c.outcome_notes) output += `  Notes: ${c.outcome_notes}\n`;
          output += '\n';
        }

        return output;
        } catch (e: any) {
          console.error(`[list_commitments] Error:`, e.message);
          return `Error listing commitments: ${e.message}`;
        }
      }
    },

    update_commitment: {
      description: 'Update commitment status (done/missed). REQUIRED: id, status.',
      inputSchema: z.object({
        id: z.number().default(0).describe('Commitment ID - REQUIRED'),
        status: z.enum(['done', 'missed']).default('done').describe('New status: done or missed - REQUIRED'),
        outcome_notes: z.string().default('').describe('What happened')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[update_commitment] Called with args:`, JSON.stringify(args));

        if (!args || args.id === undefined || !args.status) {
          return 'Error: id and status are required. Usage: update_commitment(id: 1, status: "done", outcome_notes?: "...")';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        const completedAt = args.status === 'done' ? 'CURRENT_TIMESTAMP' : 'NULL';

        const result = await pool.query(
          `UPDATE commitments
           SET status = $1, outcome_notes = $2, completed_at = ${completedAt}
           WHERE id = $3 AND user_id = $4
           RETURNING description`,
          [args.status, args.outcome_notes || null, args.id, userId]
        );

        if (result.rows.length === 0) {
          return `Commitment #${args.id} not found.`;
        }

        return `Commitment #${args.id} marked as ${args.status.toUpperCase()}: "${result.rows[0].description}"`;
      }
    },

    reschedule_commitment: {
      description: 'Reschedule a commitment to a new date. REQUIRED: id, new_due_date.',
      inputSchema: z.object({
        id: z.number().default(0).describe('Commitment ID - REQUIRED'),
        new_due_date: z.string().default('').describe('New due date (YYYY-MM-DD) - REQUIRED'),
        reason: z.string().default('').describe('Reason for rescheduling')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[reschedule_commitment] Called with args:`, JSON.stringify(args));

        if (!args || args.id === undefined || !args.new_due_date) {
          return 'Error: id and new_due_date are required. Usage: reschedule_commitment(id: 1, new_due_date: "2026-01-30")';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        const result = await pool.query(
          `UPDATE commitments
           SET due_date = $1, status = 'rescheduled', reschedule_count = reschedule_count + 1,
               outcome_notes = COALESCE(outcome_notes || E'\\n', '') || $2
           WHERE id = $3 AND user_id = $4
           RETURNING description, reschedule_count`,
          [args.new_due_date, args.reason ? `Rescheduled: ${args.reason}` : 'Rescheduled', args.id, userId]
        );

        if (result.rows.length === 0) {
          return `Commitment #${args.id} not found.`;
        }

        // Reset status to open after rescheduling
        await pool.query(
          `UPDATE commitments SET status = 'open' WHERE id = $1`,
          [args.id]
        );

        return `Commitment #${args.id} rescheduled to ${args.new_due_date} (${result.rows[0].reschedule_count}x total): "${result.rows[0].description}"`;
      }
    },

    // =========================================================================
    // PATTERN TOOLS
    // =========================================================================

    create_pattern: {
      description: 'Record a behavioral pattern/tendency. REQUIRED: name, description, category, valence.',
      inputSchema: z.object({
        name: z.string().default('').describe('Pattern name - REQUIRED'),
        description: z.string().default('').describe('What this pattern looks like - REQUIRED'),
        category: z.enum(['business', 'personal', 'health', 'mindset']).default('personal').describe('Category: business, personal, health, or mindset - REQUIRED'),
        valence: z.enum(['positive', 'negative', 'neutral']).default('neutral').describe('Valence: positive, negative, or neutral - REQUIRED'),
        initial_example: z.string().default('').describe('First example of this pattern')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[create_pattern] Called with args:`, JSON.stringify(args));

        if (!args || !args.name || !args.description || !args.category || !args.valence) {
          return 'Error: name, description, category, and valence are required. Usage: create_pattern(name, description, category: business|personal|health|mindset, valence: positive|negative|neutral)';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        const examples = args.initial_example ? [args.initial_example] : [];

        const result = await pool.query(
          `INSERT INTO patterns (user_id, name, description, category, valence, examples)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
          [userId, args.name, args.description, args.category, args.valence, examples]
        );

        return `Pattern recorded (ID: ${result.rows[0].id}): "${args.name}" [${args.valence}/${args.category}]`;
      }
    },

    list_patterns: {
      description: 'List all tracked patterns',
      inputSchema: z.object({
        category: z.enum(['business', 'personal', 'health', 'mindset', 'all']).optional(),
        valence: z.enum(['positive', 'negative', 'neutral', 'all']).optional()
      }),
      handler: async (args: any, user: any) => {
        try {
          if (!user) return 'Error: Authentication required';
          const userId = user.id || user.sub;
          const category = args.category || 'all';
          const valence = args.valence || 'all';

          console.log(`[list_patterns] User: ${userId}, Category: ${category}, Valence: ${valence}`);

          let query = 'SELECT * FROM patterns WHERE user_id = $1';
          const params: any[] = [userId];
          let paramCount = 2;

          if (category !== 'all') {
            query += ` AND category = $${paramCount++}`;
            params.push(category);
          }
          if (valence !== 'all') {
            query += ` AND valence = $${paramCount++}`;
            params.push(valence);
          }

          query += ' ORDER BY category, name';

          const result = await pool.query(query, params);

        if (result.rows.length === 0) {
          return 'No patterns recorded yet.';
        }

        let output = 'Patterns:\n\n';
        let currentCategory = '';

        for (const p of result.rows) {
          if (p.category !== currentCategory) {
            currentCategory = p.category;
            output += `--- ${currentCategory.toUpperCase()} ---\n`;
          }

          const valenceIcon = p.valence === 'positive' ? '✅' : p.valence === 'negative' ? '⚠️' : '◯';
          output += `${valenceIcon} #${p.id} ${p.name}\n`;
          output += `   ${p.description}\n`;
          if (p.examples && p.examples.length > 0) {
            output += `   Examples: ${p.examples.length} recorded\n`;
          }
          output += '\n';
        }

        return output;
        } catch (e: any) {
          console.error(`[list_patterns] Error:`, e.message);
          return `Error listing patterns: ${e.message}`;
        }
      }
    },

    add_pattern_example: {
      description: 'Add an example/instance of a pattern occurring. REQUIRED: id, example.',
      inputSchema: z.object({
        id: z.number().default(0).describe('Pattern ID - REQUIRED'),
        example: z.string().default('').describe('Description of this instance - REQUIRED')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[add_pattern_example] Called with args:`, JSON.stringify(args));

        if (!args || args.id === undefined || !args.example) {
          return 'Error: id and example are required. Usage: add_pattern_example(id: 1, example: "Did X today")';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        const result = await pool.query(
          `UPDATE patterns
           SET examples = array_append(examples, $1), updated_at = CURRENT_TIMESTAMP
           WHERE id = $2 AND user_id = $3
           RETURNING name, array_length(examples, 1) as count`,
          [args.example, args.id, userId]
        );

        if (result.rows.length === 0) {
          return `Pattern #${args.id} not found.`;
        }

        return `Example added to pattern "${result.rows[0].name}" (${result.rows[0].count} total examples)`;
      }
    },

    get_pattern: {
      description: 'Get detailed info about a pattern including all examples. REQUIRED: id.',
      inputSchema: z.object({
        id: z.number().default(0).describe('Pattern ID - REQUIRED')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[get_pattern] Called with args:`, JSON.stringify(args));

        if (!args || args.id === undefined) {
          return 'Error: id is required. Usage: get_pattern(id: 1)';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        const result = await pool.query(
          'SELECT * FROM patterns WHERE id = $1 AND user_id = $2',
          [args.id, userId]
        );

        if (result.rows.length === 0) {
          return `Pattern #${args.id} not found.`;
        }

        const p = result.rows[0];
        const valenceIcon = p.valence === 'positive' ? '✅' : p.valence === 'negative' ? '⚠️' : '◯';

        let output = `${valenceIcon} Pattern #${p.id}: ${p.name}\n`;
        output += `Category: ${p.category} | Valence: ${p.valence}\n`;
        output += `Description: ${p.description}\n\n`;

        if (p.examples && p.examples.length > 0) {
          output += `Examples (${p.examples.length}):\n`;
          p.examples.forEach((ex: string, i: number) => {
            output += `  ${i + 1}. ${ex}\n`;
          });
        } else {
          output += 'No examples recorded yet.\n';
        }

        return output;
      }
    },

    // =========================================================================
    // CHECK-IN TOOLS
    // =========================================================================

    create_check_in: {
      description: 'Record an accountability check-in. REQUIRED: notes.',
      inputSchema: z.object({
        notes: z.string().default('').describe('Check-in notes - REQUIRED'),
        commitment_ids_completed: z.array(z.number()).default([]).describe('IDs of completed commitments'),
        pattern_ids_observed: z.array(z.number()).default([]).describe('IDs of patterns that showed up')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[create_check_in] Called with args:`, JSON.stringify(args));

        if (!args || !args.notes) {
          return 'Error: notes are required. Usage: create_check_in(notes: "Session summary", commitment_ids_completed?: [1, 2], pattern_ids_observed?: [3])';
        }

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        // Get commitments that were due by today
        const today = new Date().toISOString().split('T')[0];
        const dueResult = await pool.query(
          `SELECT id FROM commitments WHERE user_id = $1 AND due_date <= $2 AND status = 'open'`,
          [userId, today]
        );
        const commitmentsDue = dueResult.rows.map(r => r.id);

        const result = await pool.query(
          `INSERT INTO check_ins (user_id, commitments_due, commitments_completed, notes, patterns_observed)
           VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [
            userId,
            commitmentsDue,
            args.commitment_ids_completed || [],
            args.notes,
            args.pattern_ids_observed || []
          ]
        );

        // Auto-update completed commitments
        if (args.commitment_ids_completed && args.commitment_ids_completed.length > 0) {
          await pool.query(
            `UPDATE commitments SET status = 'done', completed_at = CURRENT_TIMESTAMP
             WHERE id = ANY($1) AND user_id = $2`,
            [args.commitment_ids_completed, userId]
          );
        }

        const completed = args.commitment_ids_completed?.length || 0;
        const due = commitmentsDue.length;

        return `Check-in recorded (ID: ${result.rows[0].id})\nCommitments: ${completed}/${due} completed`;
      }
    },

    list_check_ins: {
      description: 'List recent check-ins',
      inputSchema: z.object({
        limit: z.number().optional().default(10)
      }),
      handler: async (args: any, user: any) => {
        console.log(`[list_check_ins] Called with args:`, JSON.stringify(args));

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;

        const result = await pool.query(
          `SELECT * FROM check_ins WHERE user_id = $1 ORDER BY date DESC LIMIT $2`,
          [userId, args.limit || 10]
        );

        if (result.rows.length === 0) {
          return 'No check-ins recorded yet.';
        }

        let output = 'Recent Check-ins:\n\n';

        for (const c of result.rows) {
          const due = c.commitments_due?.length || 0;
          const completed = c.commitments_completed?.length || 0;
          const patterns = c.patterns_observed?.length || 0;

          output += `#${c.id} - ${c.date.toISOString().split('T')[0]}\n`;
          output += `  Commitments: ${completed}/${due} completed\n`;
          if (patterns > 0) output += `  Patterns observed: ${patterns}\n`;
          output += `  Notes: ${c.notes?.slice(0, 100) || 'None'}${c.notes?.length > 100 ? '...' : ''}\n\n`;
        }

        return output;
      }
    },

    accountability_summary: {
      description: 'Get accountability summary showing commitment completion rate and pattern trends',
      inputSchema: z.object({
        days: z.number().optional().default(30).describe('Number of days to analyze')
      }),
      handler: async (args: any, user: any) => {
        console.log(`[accountability_summary] Called with args:`, JSON.stringify(args));

        if (!user) return 'Error: Authentication required';
        const userId = user.id || user.sub;
        const days = args.days || 30;

        // Commitment stats
        const commitmentStats = await pool.query(
          `SELECT status, COUNT(*) as count FROM commitments
           WHERE user_id = $1 AND created_at > NOW() - INTERVAL '${days} days'
           GROUP BY status`,
          [userId]
        );

        const stats: Record<string, number> = { open: 0, done: 0, missed: 0, rescheduled: 0 };
        for (const row of commitmentStats.rows) {
          stats[row.status] = parseInt(row.count);
        }
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const completionRate = total > 0 ? Math.round((stats.done / total) * 100) : 0;

        // Pattern frequency
        const patternStats = await pool.query(
          `SELECT p.id, p.name, p.valence, array_length(p.examples, 1) as example_count
           FROM patterns p WHERE p.user_id = $1 ORDER BY example_count DESC NULLS LAST LIMIT 5`,
          [userId]
        );

        // Reschedule frequency
        const rescheduleStats = await pool.query(
          `SELECT AVG(reschedule_count) as avg_reschedules FROM commitments
           WHERE user_id = $1 AND created_at > NOW() - INTERVAL '${days} days'`,
          [userId]
        );

        let output = `=== Accountability Summary (${days} days) ===\n\n`;

        output += `📊 Commitment Stats:\n`;
        output += `  Total: ${total}\n`;
        output += `  ✅ Done: ${stats.done} | ⏳ Open: ${stats.open}\n`;
        output += `  ❌ Missed: ${stats.missed} | 🔄 Rescheduled: ${stats.rescheduled}\n`;
        output += `  Completion Rate: ${completionRate}%\n`;
        output += `  Avg Reschedules: ${parseFloat(rescheduleStats.rows[0]?.avg_reschedules || 0).toFixed(1)}\n\n`;

        if (patternStats.rows.length > 0) {
          output += `🔍 Top Patterns:\n`;
          for (const p of patternStats.rows) {
            const icon = p.valence === 'positive' ? '✅' : p.valence === 'negative' ? '⚠️' : '◯';
            output += `  ${icon} ${p.name} (${p.example_count || 0} examples)\n`;
          }
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
    allowDynamicClientRegistration: true, // Required for Claude.ai
    requirePkce: false, // Claude.ai may not send PKCE in some flows
    allowRefreshTokens: true,
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
  <form method="POST" action="/authorize" id="login-form">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="client_id" value="${context.clientId}">
    <input type="hidden" name="redirect_uri" value="${context.redirectUri}">
    <input type="hidden" name="scope" value="${context.scope || ''}">
    <input type="hidden" name="resource" value="${context.resource || ''}">
    <input type="hidden" name="state" id="state" value="">
    <input type="hidden" name="code_challenge" id="code_challenge" value="">
    <input type="hidden" name="code_challenge_method" id="code_challenge_method" value="">
    <input type="text" name="username" placeholder="Username or Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login & Authorize</button>
  </form>
  <script>
    // Capture OAuth params from URL and add to form
    const params = new URLSearchParams(window.location.search);
    ['state', 'code_challenge', 'code_challenge_method'].forEach(p => {
      const el = document.getElementById(p);
      if (el && params.get(p)) el.value = params.get(p);
    });
  </script>
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

  // Admin page - protected by ADMIN_SECRET
  app.get('/admin', (req: Request, res: Response) => {
    const secret = req.query.secret as string;

    if (!ADMIN_SECRET) {
      res.status(503).send('Admin page disabled. Set ADMIN_SECRET environment variable.');
      return;
    }

    if (secret !== ADMIN_SECRET) {
      res.status(401).send('Unauthorized. Access: /admin?secret=YOUR_ADMIN_SECRET');
      return;
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Memory MCP - Admin</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      max-width: 500px;
      margin: 40px auto;
      padding: 20px;
      background: #f5f5f5;
    }
    h1 { color: #333; margin-bottom: 5px; }
    .subtitle { color: #666; margin-bottom: 30px; }
    .card {
      background: white;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    h2 { margin-top: 0; color: #444; font-size: 18px; }
    label { display: block; margin-bottom: 5px; color: #555; font-size: 14px; }
    input {
      width: 100%;
      padding: 10px;
      margin-bottom: 15px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }
    input:focus { outline: none; border-color: #007bff; }
    button {
      width: 100%;
      padding: 12px;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
    }
    button:hover { background: #0056b3; }
    .message {
      padding: 10px;
      border-radius: 4px;
      margin-bottom: 15px;
      font-size: 14px;
    }
    .success { background: #d4edda; color: #155724; }
    .error { background: #f8d7da; color: #721c24; }
    .info { background: #e7f3ff; color: #004085; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>Memory MCP Admin</h1>
  <p class="subtitle">Manage your account</p>

  <div class="info">
    <strong>Server:</strong> ${SERVER_URL}<br>
    <strong>Status:</strong> Online
  </div>

  <div class="card">
    <h2>Change Password</h2>
    <div id="pw-message"></div>
    <form id="password-form">
      <label>Username</label>
      <input type="text" name="username" required>
      <label>Current Password</label>
      <input type="password" name="current_password" required>
      <label>New Password</label>
      <input type="password" name="new_password" required>
      <button type="submit">Change Password</button>
    </form>
  </div>

  <div class="card">
    <h2>Update Profile</h2>
    <div id="profile-message"></div>
    <form id="profile-form">
      <label>Username (to authenticate)</label>
      <input type="text" name="username" required>
      <label>Password (to authenticate)</label>
      <input type="password" name="password" required>
      <label>New Username (optional)</label>
      <input type="text" name="new_username" placeholder="Leave blank to keep current">
      <label>New Email (optional)</label>
      <input type="email" name="new_email" placeholder="Leave blank to keep current">
      <button type="submit">Update Profile</button>
    </form>
  </div>

  <div class="card">
    <h2>Create New User</h2>
    <div id="create-message"></div>
    <form id="create-form">
      <input type="hidden" name="admin_secret" value="${secret}">
      <label>Username</label>
      <input type="text" name="username" required>
      <label>Email</label>
      <input type="email" name="email" required>
      <label>Password</label>
      <input type="password" name="password" required>
      <button type="submit">Create User</button>
    </form>
  </div>

  <script>
    async function submitForm(form, url, messageEl) {
      const data = Object.fromEntries(new FormData(form));
      // Remove empty fields
      Object.keys(data).forEach(k => { if (!data[k]) delete data[k]; });

      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const json = await res.json();

        if (json.success) {
          messageEl.className = 'message success';
          messageEl.textContent = json.message || 'Success!';
          form.reset();
        } else {
          messageEl.className = 'message error';
          messageEl.textContent = json.error || 'Something went wrong';
        }
      } catch (e) {
        messageEl.className = 'message error';
        messageEl.textContent = 'Network error: ' + e.message;
      }
    }

    document.getElementById('password-form').onsubmit = (e) => {
      e.preventDefault();
      submitForm(e.target, '/change-password', document.getElementById('pw-message'));
    };

    document.getElementById('profile-form').onsubmit = (e) => {
      e.preventDefault();
      submitForm(e.target, '/update-user', document.getElementById('profile-message'));
    };

    document.getElementById('create-form').onsubmit = (e) => {
      e.preventDefault();
      submitForm(e.target, '/register-user', document.getElementById('create-message'));
    };
  </script>
</body>
</html>
    `);
  });

  // User registration endpoint - protected by ADMIN_SECRET
  app.post('/register-user', async (req: Request, res: Response) => {
    try {
      const { username, email, password, admin_secret } = req.body;

      // Require admin secret
      if (!ADMIN_SECRET) {
        res.status(503).json({ error: 'User registration disabled. Set ADMIN_SECRET.' });
        return;
      }
      if (admin_secret !== ADMIN_SECRET) {
        res.status(401).json({ error: 'Invalid admin secret' });
        return;
      }

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

  // Change password endpoint
  app.post('/change-password', async (req: Request, res: Response) => {
    try {
      const { username, current_password, new_password } = req.body;
      if (!username || !current_password || !new_password) {
        res.status(400).json({ error: 'username, current_password, and new_password required' });
        return;
      }

      // Verify current password
      const user = await authenticateUser({ username, password: current_password });
      if (!user) {
        res.status(401).json({ error: 'Invalid username or current password' });
        return;
      }

      // Update password
      const newHash = await hashPassword(new_password);
      await pool.query(
        'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [newHash, user.id]
      );

      res.json({ success: true, message: 'Password changed successfully' });
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // Update user details endpoint
  app.post('/update-user', async (req: Request, res: Response) => {
    try {
      const { username, password, new_username, new_email } = req.body;
      if (!username || !password) {
        res.status(400).json({ error: 'username and password required for authentication' });
        return;
      }

      // Verify credentials
      const user = await authenticateUser({ username, password });
      if (!user) {
        res.status(401).json({ error: 'Invalid username or password' });
        return;
      }

      // Build update query
      const updates: string[] = [];
      const values: any[] = [];
      let paramCount = 1;

      if (new_username) {
        updates.push(`username = $${paramCount++}`);
        values.push(new_username);
      }
      if (new_email) {
        updates.push(`email = $${paramCount++}`);
        values.push(new_email);
      }

      if (updates.length === 0) {
        res.status(400).json({ error: 'No updates provided (new_username or new_email)' });
        return;
      }

      updates.push(`updated_at = CURRENT_TIMESTAMP`);
      values.push(user.id);

      await pool.query(
        `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount}`,
        values
      );

      res.json({
        success: true,
        message: 'User updated successfully',
        user: {
          username: new_username || user.username,
          email: new_email || user.email
        }
      });
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
