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
- **OAuth Storage:** PostgresStorage (tokens survive restarts)
- **Runtime:** Node.js 20 (Alpine Docker)
- **Zod:** v3.x (v4 breaks MCP schema visibility)

## Database Schema (14 tables)

### Core Tables
| Table | Purpose |
|-------|---------|
| `users` | User accounts with password hashes |
| `projects` | Project containers (CoachingHub, etc.) |
| `sessions` | Conversation/work session records |
| `change_log` | Code/work changes with reasoning |
| `lessons_learned` | Problem → solution patterns |
| `context_snapshots` | Point-in-time summaries |

### Accountability Tables
| Table | Purpose |
|-------|---------|
| `commitments` | Accountability items with due dates, status tracking, reschedule count |
| `patterns` | Behavioral tendencies (positive/negative/neutral) with examples |
| `check_ins` | Accountability check-in records linking commitments and patterns |

### Quick Facts Table
| Table | Purpose |
|-------|---------|
| `facts` | Key-value storage for profile/context info (categories: personal, schedule, business, health, etc.) |

### OAuth Tables (PostgresStorage)
| Table | Purpose |
|-------|---------|
| `oauth_clients` | Dynamically registered OAuth clients |
| `oauth_authorization_codes` | Auth codes with resource field |
| `oauth_access_tokens` | Access tokens with audience field |
| `oauth_refresh_tokens` | Refresh tokens with audience field |

## MCP Tools

### Project Management
- `list_projects`, `create_project`, `select_project`
- `status`, `session_start`, `session_end`

### Memory
- `log_change`, `recent_changes`
- `add_lesson`, `get_lessons`
- `phase_complete`

### Quick Facts
- `add_fact` - Store key-value facts (e.g., "elise_age" = "11, school 8:30am/3:15pm")
- `get_facts` - List all facts, optionally filter by category
- `update_fact` - Update existing fact
- `delete_fact` - Remove a fact

### Search & Briefing
- `search_all` - Full-text search across facts, lessons, patterns, commitments, change_log
- `daily_briefing` - Morning snapshot: key facts, due today, overdue, upcoming week, recent patterns

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
| `JWT_SECRET` | OAuth token signing | **REQUIRED in production - must be stable** |
| `SERVER_URL` | `https://memory-mcp-server-production-01c0.up.railway.app` | **REQUIRED in production - must match exactly** |
| `ADMIN_SECRET` | Protects /admin, /register-user, /debug/oauth | |

Server will **fail fast** if JWT_SECRET or SERVER_URL missing in production.

### Admin Access
```
https://memory-mcp-server-production-01c0.up.railway.app/admin?secret=<ADMIN_SECRET>
```

### Debug OAuth (check tokens/clients)
```
https://memory-mcp-server-production-01c0.up.railway.app/debug/oauth?secret=<ADMIN_SECRET>
```

## Connecting Claude

### Claude.ai Web & Desktop (Native Connectors)
Settings → Connectors → Add → Enter server URL → OAuth login

**URL:** `https://memory-mcp-server-production-01c0.up.railway.app`

Connectors sync automatically between Claude.ai web and Claude Desktop via your account.

### Claude Code
```bash
claude mcp add memory --url https://memory-mcp-server-production-01c0.up.railway.app
```

### DO NOT use claude_desktop_config.json for remote MCPs
Remote MCP servers with OAuth should be added via **Settings → Connectors**, NOT via the JSON config file. The JSON config is only for local MCP servers.

## Key Files
- `src/index.ts` - Main server with all tools, OAuth, and PostgresStorage
- `Dockerfile` - Production build
- `railway.json` - Railway deployment config

## Known Issues & Fixes

### Zod v4 breaks MCP schemas (Fixed)
- **Symptom:** Tools show "empty objects" for parameters in Claude.ai
- **Cause:** Zod v4 incompatible with MCP SDK schema generation
- **Fix:** Downgrade to Zod v3.x in package.json

### "Invalid authorization" after deploy
- **Cause:** Stale OAuth token cached by Claude.ai
- **Fix:** Remove and re-add MCP connector in Claude.ai settings

### "Continue" button shows error after OAuth login
- **Symptom:** After successful login, clicking "Continue" shows "Invalid authorization"
- **Cause:** Unknown issue in mcpresso-oauth-server success page
- **Workaround:** Don't click Continue - let it auto-redirect (works fine)
- **Status:** Minor UX issue, doesn't affect functionality

### Port conflict on Claude Desktop (mcp-remote)
- **Symptom:** `EADDRINUSE: address already in use 127.0.0.1:27683`
- **Cause:** Leftover mcp-remote process from failed OAuth attempt
- **Fix:** Kill the process or clear `~/.mcp-auth` cache

## OAuth Notes
- PostgresStorage persists OAuth tokens across restarts
- Custom login page captures `state` param via JavaScript (library bug workaround)
- PKCE optional (Claude.ai doesn't always send it)
- Dynamic client registration enabled for Claude.ai connectors
- Claude's OAuth callback: `https://claude.ai/api/mcp/auth_callback`
