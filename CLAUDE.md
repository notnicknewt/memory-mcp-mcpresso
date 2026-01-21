# Memory MCP Server (MCPresso)

## Overview
Persistent memory system for Claude across all platforms (Claude Code, Desktop, Web/Mobile) with OAuth 2.1 authentication.

**Deployed URL:** `https://memory-mcp-server-production-01c0.up.railway.app`
**GitHub:** `https://github.com/notnicknewt/memory-mcp-mcpresso`
**Platform:** Railway (Postgres + Node.js)

## Architecture
- **Framework:** MCPresso + mcpresso-oauth-server
- **Auth:** OAuth 2.1 with PKCE, Dynamic Client Registration (RFC 7591)
- **Database:** PostgreSQL on Railway
- **Runtime:** Node.js 20 (Alpine Docker)

## Database Schema

### Core Tables
| Table | Purpose |
|-------|---------|
| `users` | User accounts with password hashes |
| `projects` | Project containers (CoachingHub, etc.) |
| `sessions` | Conversation/work session records |
| `change_log` | Code/work changes with reasoning |
| `lessons_learned` | Problem → solution patterns |
| `context_snapshots` | Point-in-time summaries |

### Accountability Tables (Added 2026-01-21)
| Table | Purpose |
|-------|---------|
| `commitments` | Accountability items with due dates, status tracking, reschedule count |
| `patterns` | Behavioral tendencies (positive/negative/neutral) with examples |
| `check_ins` | Accountability check-in records linking commitments and patterns |

## MCP Tools

### Project Management
- `list_projects`, `create_project`, `select_project`
- `status`, `session_start`, `session_end`

### Memory
- `log_change`, `recent_changes`
- `add_lesson`, `get_lessons`
- `phase_complete`

### Accountability
- `create_commitment` - Track commitments with due dates
- `list_commitments` - Filter by status, shows overdue items
- `update_commitment` - Mark done/missed with outcome notes
- `reschedule_commitment` - Move date, tracks reschedule count
- `create_pattern` - Record behavioral tendencies
- `list_patterns` - Filter by category/valence
- `add_pattern_example` - Add instance of pattern occurring
- `get_pattern` - See all examples for a pattern
- `create_check_in` - Record accountability session
- `list_check_ins` - Recent check-in history
- `accountability_summary` - Completion rate, pattern trends

## Configuration

### Environment Variables (Railway)
- `DATABASE_URL` - Postgres connection string (auto-set by Railway)
- `JWT_SECRET` - For OAuth tokens
- `SERVER_URL` - `https://memory-mcp-server-production-01c0.up.railway.app`
- `ADMIN_SECRET` - Protects /admin page and user registration

### Admin Access
```
https://memory-mcp-server-production-01c0.up.railway.app/admin?secret=<ADMIN_SECRET>
```

## Connecting Claude

### Claude.ai (Web/Mobile)
Settings → MCP Connectors → Add → Enter server URL → OAuth login

### Claude Desktop
```json
{
  "mcpServers": {
    "memory": {
      "url": "https://memory-mcp-server-production-01c0.up.railway.app"
    }
  }
}
```

### Claude Code
```bash
claude mcp add memory --url https://memory-mcp-server-production-01c0.up.railway.app
```

## Key Files
- `src/index.ts` - Main server with all tools and OAuth
- `Dockerfile` - Production build
- `railway.json` - Railway deployment config

## OAuth Notes
- Custom login page captures `state` param via JavaScript (library bug workaround)
- PKCE optional (Claude.ai doesn't always send it)
- Dynamic client registration enabled for Claude.ai connectors
