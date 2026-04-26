# Discord Server Audit Logger

A Discord bot that logs essentially every action that happens in your server to a designated channel and to a local file (`server_audit.log`) as a backup.

## What it logs

**Messages** — deletions (single + bulk), edits (with before/after diff)
**Members** — joins, leaves, nickname changes, role changes, timeouts, username/avatar/display-name changes
**Moderation** — bans (with moderator + reason from audit log), unbans
**Channels** — create, delete, name/topic/position/NSFW updates
**Threads** — create, delete, archive/lock changes
**Roles** — create, delete, name/color/permission/hoist/mentionable updates
**Voice** — channel join/leave/switch, mute/deafen/stream/camera changes
**Reactions** — add, remove
**Server** — name/icon/owner/verification changes, emoji add/remove
**Invites** — create, delete

## Setup

### 1. Create your bot
1. Go to <https://discord.com/developers/applications> → **New Application**
2. **Bot** tab → enable all three **Privileged Gateway Intents**:
   - Presence Intent
   - Server Members Intent
   - Message Content Intent
3. Copy the bot **Token**
4. **OAuth2 → URL Generator**: select scopes `bot` + `applications.commands`, then permissions `Administrator` (or at minimum: View Audit Log, View Channels, Read Message History, Send Messages, Embed Links). Use the generated URL to invite the bot.

### 2. Install + run

```bash
cd discord-logger-bot
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                # then edit .env and paste your token
python bot.py
```

### 3. Configure in your server

```
!setlog #audit-log     # tell the bot which channel to post logs to
!unsetlog              # stop logging
```

Only members with **Manage Server** permission can run these.

## Notes & limits

- **Reaction logging is noisy.** Comment out `on_reaction_add` / `on_reaction_remove` if you don't want it.
- **Edits/deletes only fire for messages the bot can see** since startup. Discord doesn't give us history for messages predating the bot's session unless you implement a message cache (which would multiply storage and complexity — happy to add it if you want).
- **Audit-log lookups for ban moderators** require the bot to have the *View Audit Log* permission.
- The local `server_audit.log` file grows forever — rotate it with `logging.handlers.RotatingFileHandler` if this matters for you.
- For large servers, consider sending logs to a database (Postgres, SQLite) instead of/in addition to a channel.

## File layout

```
discord-logger-bot/
├── bot.py              # main bot
├── requirements.txt
├── .env.example        # copy to .env, add your token
├── .env                # (you create this — gitignored)
├── log_channels.json   # auto-generated; per-guild log channel config
└── server_audit.log    # auto-generated; backup log file
```
