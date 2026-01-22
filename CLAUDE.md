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
- **Zod:** v3.x (v4 breaks MCP schema visibility)

## Database Schema (10 tables)

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

### Quick Facts Table (Added 2026-01-22)
| Table | Purpose |
|-------|---------|
| `facts` | Key-value storage for profile/context info (categories: personal, schedule, business, health, etc.) |

## MCP Tools

### Project Management
- `list_projects`, `create_project`, `select_project`
- `status`, `session_start`, `session_end`

### Memory
- `log_change`, `recent_changes`
- `add_lesson`, `get_lessons`
- `phase_complete`

### Quick Facts (Added 2026-01-22)
- `add_fact` - Store key-value facts (e.g., "elise_age" = "11, school 8:30am/3:15pm")
- `get_facts` - List all facts, optionally filter by category
- `update_fact` - Update existing fact
- `delete_fact` - Remove a fact

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
- `accountability_summary` - **Full snapshot in one call:**
  - Overdue commitments
  - Due in next 7 days
  - Completion rate (last 30 days)
  - Recent patterns from check-ins

## Configuration

### Environment Variables (Railway) - CRITICAL
| Variable | Purpose | Notes |
|----------|---------|-------|
| `DATABASE_URL` | Postgres connection | Auto-set by Railway |
| `JWT_SECRET` | OAuth token signing | **Must be stable across restarts** |
| `SERVER_URL` | `https://memory-mcp-server-production-01c0.up.railway.app` | **Must match exactly** |
| `ADMIN_SECRET` | Protects /admin and /register-user | |

### Admin Access
```
https://memory-mcp-server-production-01c0.up.railway.app/admin?secret=<ADMIN_SECRET>
```

## Connecting Claude

### Claude.ai (Web/Mobile)
Settings → MCP Connectors → Add → Enter server URL → OAuth login

**If "Invalid authorization" error:** Remove and re-add the connector to force fresh OAuth flow.

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

## Known Issues & Fixes

### Zod v4 breaks MCP schemas (Fixed 2026-01-22)
- **Symptom:** Tools show "empty objects" for parameters in Claude.ai
- **Cause:** Zod v4 incompatible with MCP SDK schema generation
- **Fix:** Downgrade to Zod v3.x in package.json

### "Invalid authorization" after deploy
- **Cause:** Stale OAuth token cached by Claude.ai
- **Fix:** Remove and re-add MCP connector in Claude.ai settings

### OAuth tokens lost on restart
- **Cause:** MemoryStorage for OAuth (in-memory)
- **Mitigation:** JWT_SECRET must be stable; users re-auth after restart

## OAuth Notes
- Custom login page captures `state` param via JavaScript (library bug workaround)
- PKCE optional (Claude.ai doesn't always send it)
- Dynamic client registration enabled for Claude.ai connectors
