"""
Discord Server Audit Logger Bot
--------------------------------
Logs essentially every action that occurs in a Discord server to a designated
log channel (and to a local file as a backup).

Setup:
  1. Create an application + bot at https://discord.com/developers/applications
  2. Enable ALL Privileged Gateway Intents (Presence, Server Members, Message Content)
  3. Invite the bot to your server with the "Administrator" permission (or at minimum:
     View Audit Log, View Channels, Read Message History, Send Messages, Embed Links)
  4. Put your token in a .env file (see .env.example)
  5. In your server, run:  !setlog #your-log-channel
"""

import os
import json
import logging
import datetime
from pathlib import Path

import discord
from discord.ext import commands
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
COMMAND_PREFIX = os.getenv("COMMAND_PREFIX", "!")
CONFIG_PATH = Path("log_channels.json")
LOG_FILE_PATH = Path("server_audit.log")

# File logger (backup of everything that gets posted to Discord)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("audit")

# Per-guild log channel mapping, persisted to disk
def load_config() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    return {}

def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

log_channels: dict = load_config()  # {guild_id (str): channel_id (int)}

# ---------------------------------------------------------------------------
# Bot setup — request every intent we need to observe events
# ---------------------------------------------------------------------------
intents = discord.Intents.all()
bot = commands.Bot(command_prefix=COMMAND_PREFIX, intents=intents)


async def send_log(guild: discord.Guild | None, embed: discord.Embed) -> None:
    """Send an embed to the configured log channel for this guild + write to file."""
    if guild is None:
        return

    # Always write to local file
    log.info(f"[{guild.name}] {embed.title} :: {embed.description or ''}")
    for field in embed.fields:
        log.info(f"    {field.name}: {field.value}")

    channel_id = log_channels.get(str(guild.id))
    if channel_id is None:
        return
    channel = guild.get_channel(channel_id)
    if channel is None:
        return
    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        log.warning(f"Missing permissions to send in #{channel} of {guild.name}")
    except discord.HTTPException as e:
        log.error(f"Failed to send log: {e}")


def make_embed(title: str, description: str = "", color: discord.Color = discord.Color.blurple()) -> discord.Embed:
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    return embed


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching {len(bot.guilds)} guild(s)")


@bot.command(name="setlog")
@commands.has_permissions(manage_guild=True)
async def setlog(ctx: commands.Context, channel: discord.TextChannel | None = None):
    """Set the channel where audit logs should be posted. Defaults to the current channel."""
    channel = channel or ctx.channel
    log_channels[str(ctx.guild.id)] = channel.id
    save_config(log_channels)
    await ctx.reply(f"✅ Audit logs will now be posted in {channel.mention}.")


@bot.command(name="unsetlog")
@commands.has_permissions(manage_guild=True)
async def unsetlog(ctx: commands.Context):
    """Stop logging to a channel for this server."""
    if str(ctx.guild.id) in log_channels:
        del log_channels[str(ctx.guild.id)]
        save_config(log_channels)
        await ctx.reply("🛑 Audit logging disabled for this server.")
    else:
        await ctx.reply("No log channel was set.")


# ---------------------------------------------------------------------------
# MESSAGE EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot:
        return
    embed = make_embed(
        "🗑️ Message Deleted",
        color=discord.Color.red(),
    )
    embed.add_field(name="Author", value=f"{message.author.mention} (`{message.author}`)", inline=True)
    embed.add_field(name="Channel", value=message.channel.mention, inline=True)
    if message.content:
        embed.add_field(name="Content", value=message.content[:1024], inline=False)
    if message.attachments:
        embed.add_field(
            name="Attachments",
            value="\n".join(a.filename for a in message.attachments),
            inline=False,
        )
    await send_log(message.guild, embed)


@bot.event
async def on_bulk_message_delete(messages: list[discord.Message]):
    if not messages:
        return
    embed = make_embed(
        "🗑️ Bulk Message Delete",
        f"{len(messages)} messages were deleted in {messages[0].channel.mention}",
        color=discord.Color.red(),
    )
    await send_log(messages[0].guild, embed)


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if before.author.bot or before.content == after.content:
        return
    embed = make_embed(
        "✏️ Message Edited",
        color=discord.Color.orange(),
    )
    embed.add_field(name="Author", value=f"{before.author.mention} (`{before.author}`)", inline=True)
    embed.add_field(name="Channel", value=before.channel.mention, inline=True)
    embed.add_field(name="Before", value=(before.content or "*empty*")[:1024], inline=False)
    embed.add_field(name="After", value=(after.content or "*empty*")[:1024], inline=False)
    embed.add_field(name="Jump", value=f"[Go to message]({after.jump_url})", inline=False)
    await send_log(before.guild, embed)


# ---------------------------------------------------------------------------
# MEMBER EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_member_join(member: discord.Member):
    embed = make_embed(
        "📥 Member Joined",
        f"{member.mention} (`{member}`)",
        color=discord.Color.green(),
    )
    embed.add_field(name="Account Created", value=discord.utils.format_dt(member.created_at, "R"))
    embed.add_field(name="Member Count", value=str(member.guild.member_count))
    await send_log(member.guild, embed)


@bot.event
async def on_member_remove(member: discord.Member):
    embed = make_embed(
        "📤 Member Left",
        f"{member.mention} (`{member}`)",
        color=discord.Color.dark_gray(),
    )
    embed.add_field(name="Joined", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "Unknown")
    roles = [r.mention for r in member.roles if r.name != "@everyone"]
    if roles:
        embed.add_field(name="Roles", value=" ".join(roles)[:1024], inline=False)
    await send_log(member.guild, embed)


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    changes = []
    if before.nick != after.nick:
        changes.append(f"**Nickname:** `{before.nick}` → `{after.nick}`")
    if before.roles != after.roles:
        added = [r.mention for r in after.roles if r not in before.roles]
        removed = [r.mention for r in before.roles if r not in after.roles]
        if added:
            changes.append(f"**Roles added:** {' '.join(added)}")
        if removed:
            changes.append(f"**Roles removed:** {' '.join(removed)}")
    if before.timed_out_until != after.timed_out_until and after.timed_out_until:
        changes.append(f"**Timed out until:** {discord.utils.format_dt(after.timed_out_until)}")

    if not changes:
        return

    embed = make_embed(
        "👤 Member Updated",
        f"{after.mention} (`{after}`)\n" + "\n".join(changes),
        color=discord.Color.blue(),
    )
    await send_log(after.guild, embed)


@bot.event
async def on_user_update(before: discord.User, after: discord.User):
    """Username / global avatar / display name changes."""
    changes = []
    if before.name != after.name:
        changes.append(f"**Username:** `{before.name}` → `{after.name}`")
    if before.global_name != after.global_name:
        changes.append(f"**Display name:** `{before.global_name}` → `{after.global_name}`")
    if before.avatar != after.avatar:
        changes.append("**Avatar changed.**")
    if not changes:
        return
    # Push to every guild the user shares with the bot
    for guild in bot.guilds:
        if guild.get_member(after.id):
            embed = make_embed(
                "🪪 User Profile Updated",
                f"{after.mention}\n" + "\n".join(changes),
                color=discord.Color.blue(),
            )
            await send_log(guild, embed)


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    embed = make_embed(
        "🔨 Member Banned",
        f"{user.mention} (`{user}`)",
        color=discord.Color.dark_red(),
    )
    # Try to grab the moderator from audit log
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
            if entry.target.id == user.id:
                embed.add_field(name="Moderator", value=entry.user.mention)
                if entry.reason:
                    embed.add_field(name="Reason", value=entry.reason, inline=False)
                break
    except discord.Forbidden:
        pass
    await send_log(guild, embed)


@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.User):
    embed = make_embed(
        "♻️ Member Unbanned",
        f"`{user}` (`{user.id}`)",
        color=discord.Color.green(),
    )
    await send_log(guild, embed)


# ---------------------------------------------------------------------------
# CHANNEL EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    embed = make_embed(
        "📁 Channel Created",
        f"{channel.mention} (`{channel.name}`)\nType: {channel.type}",
        color=discord.Color.green(),
    )
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    embed = make_embed(
        "🗑️ Channel Deleted",
        f"`#{channel.name}` (Type: {channel.type})",
        color=discord.Color.red(),
    )
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    changes = []
    if before.name != after.name:
        changes.append(f"**Name:** `{before.name}` → `{after.name}`")
    if hasattr(before, "topic") and before.topic != after.topic:
        changes.append(f"**Topic:** `{before.topic}` → `{after.topic}`")
    if before.position != after.position:
        changes.append(f"**Position:** {before.position} → {after.position}")
    if hasattr(before, "nsfw") and before.nsfw != after.nsfw:
        changes.append(f"**NSFW:** {before.nsfw} → {after.nsfw}")
    if not changes:
        return
    embed = make_embed(
        "🔧 Channel Updated",
        f"{after.mention}\n" + "\n".join(changes),
        color=discord.Color.orange(),
    )
    await send_log(after.guild, embed)


# ---------------------------------------------------------------------------
# ROLE EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_guild_role_create(role: discord.Role):
    embed = make_embed(
        "✨ Role Created",
        f"{role.mention} (`{role.name}`)",
        color=discord.Color.green(),
    )
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_delete(role: discord.Role):
    embed = make_embed(
        "🗑️ Role Deleted",
        f"`{role.name}`",
        color=discord.Color.red(),
    )
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    changes = []
    if before.name != after.name:
        changes.append(f"**Name:** `{before.name}` → `{after.name}`")
    if before.color != after.color:
        changes.append(f"**Color:** {before.color} → {after.color}")
    if before.permissions != after.permissions:
        changes.append("**Permissions changed.**")
    if before.hoist != after.hoist:
        changes.append(f"**Hoist:** {before.hoist} → {after.hoist}")
    if before.mentionable != after.mentionable:
        changes.append(f"**Mentionable:** {before.mentionable} → {after.mentionable}")
    if not changes:
        return
    embed = make_embed(
        "🔧 Role Updated",
        f"{after.mention}\n" + "\n".join(changes),
        color=discord.Color.orange(),
    )
    await send_log(after.guild, embed)


# ---------------------------------------------------------------------------
# VOICE EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    if before.channel == after.channel:
        # Mute/deafen/stream changes
        changes = []
        if before.self_mute != after.self_mute:
            changes.append(f"Self mute: {before.self_mute} → {after.self_mute}")
        if before.self_deaf != after.self_deaf:
            changes.append(f"Self deafen: {before.self_deaf} → {after.self_deaf}")
        if before.self_stream != after.self_stream:
            changes.append(f"Streaming: {before.self_stream} → {after.self_stream}")
        if before.self_video != after.self_video:
            changes.append(f"Camera: {before.self_video} → {after.self_video}")
        if not changes:
            return
        embed = make_embed(
            "🎙️ Voice State Changed",
            f"{member.mention} in {after.channel.mention}\n" + "\n".join(changes),
            color=discord.Color.blue(),
        )
    elif before.channel is None:
        embed = make_embed(
            "🔊 Joined Voice",
            f"{member.mention} joined {after.channel.mention}",
            color=discord.Color.green(),
        )
    elif after.channel is None:
        embed = make_embed(
            "🔇 Left Voice",
            f"{member.mention} left {before.channel.mention}",
            color=discord.Color.dark_gray(),
        )
    else:
        embed = make_embed(
            "🔁 Switched Voice Channels",
            f"{member.mention}: {before.channel.mention} → {after.channel.mention}",
            color=discord.Color.blue(),
        )
    await send_log(member.guild, embed)


# ---------------------------------------------------------------------------
# REACTION EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_reaction_add(reaction: discord.Reaction, user: discord.User):
    if user.bot:
        return
    embed = make_embed(
        "➕ Reaction Added",
        f"{user.mention} added {reaction.emoji} to a message in {reaction.message.channel.mention}\n[Jump]({reaction.message.jump_url})",
        color=discord.Color.gold(),
    )
    await send_log(reaction.message.guild, embed)


@bot.event
async def on_reaction_remove(reaction: discord.Reaction, user: discord.User):
    if user.bot:
        return
    embed = make_embed(
        "➖ Reaction Removed",
        f"{user.mention} removed {reaction.emoji} from a message in {reaction.message.channel.mention}\n[Jump]({reaction.message.jump_url})",
        color=discord.Color.dark_gold(),
    )
    await send_log(reaction.message.guild, embed)


# ---------------------------------------------------------------------------
# THREAD EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_thread_create(thread: discord.Thread):
    embed = make_embed(
        "🧵 Thread Created",
        f"{thread.mention} in {thread.parent.mention if thread.parent else 'unknown'}",
        color=discord.Color.green(),
    )
    if thread.owner:
        embed.add_field(name="Created by", value=thread.owner.mention)
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_delete(thread: discord.Thread):
    embed = make_embed(
        "🗑️ Thread Deleted",
        f"`{thread.name}` from {thread.parent.mention if thread.parent else 'unknown'}",
        color=discord.Color.red(),
    )
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_update(before: discord.Thread, after: discord.Thread):
    changes = []
    if before.name != after.name:
        changes.append(f"**Name:** `{before.name}` → `{after.name}`")
    if before.archived != after.archived:
        changes.append(f"**Archived:** {before.archived} → {after.archived}")
    if before.locked != after.locked:
        changes.append(f"**Locked:** {before.locked} → {after.locked}")
    if not changes:
        return
    embed = make_embed(
        "🔧 Thread Updated",
        f"{after.mention}\n" + "\n".join(changes),
        color=discord.Color.orange(),
    )
    await send_log(after.guild, embed)


# ---------------------------------------------------------------------------
# GUILD / INTEGRATION EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    changes = []
    if before.name != after.name:
        changes.append(f"**Name:** `{before.name}` → `{after.name}`")
    if before.icon != after.icon:
        changes.append("**Server icon changed.**")
    if before.owner_id != after.owner_id:
        changes.append(f"**Owner:** <@{before.owner_id}> → <@{after.owner_id}>")
    if before.verification_level != after.verification_level:
        changes.append(f"**Verification:** {before.verification_level} → {after.verification_level}")
    if not changes:
        return
    embed = make_embed(
        "🏛️ Server Updated",
        "\n".join(changes),
        color=discord.Color.purple(),
    )
    await send_log(after, embed)


@bot.event
async def on_guild_emojis_update(guild: discord.Guild, before: tuple, after: tuple):
    added = set(after) - set(before)
    removed = set(before) - set(after)
    desc = []
    if added:
        desc.append("**Added:** " + " ".join(str(e) for e in added))
    if removed:
        desc.append("**Removed:** " + " ".join(f"`:{e.name}:`" for e in removed))
    embed = make_embed("😀 Emojis Updated", "\n".join(desc), color=discord.Color.gold())
    await send_log(guild, embed)


@bot.event
async def on_invite_create(invite: discord.Invite):
    embed = make_embed(
        "🔗 Invite Created",
        f"`{invite.code}` for {invite.channel.mention}",
        color=discord.Color.green(),
    )
    if invite.inviter:
        embed.add_field(name="By", value=invite.inviter.mention)
    embed.add_field(name="Max Uses", value=str(invite.max_uses or "∞"))
    embed.add_field(name="Expires", value=discord.utils.format_dt(invite.expires_at) if invite.expires_at else "Never")
    await send_log(invite.guild, embed)


@bot.event
async def on_invite_delete(invite: discord.Invite):
    embed = make_embed(
        "🔗 Invite Deleted",
        f"`{invite.code}` for {invite.channel.mention if invite.channel else 'unknown'}",
        color=discord.Color.red(),
    )
    await send_log(invite.guild, embed)


# ---------------------------------------------------------------------------
# Error handler — quiet command-permission errors but log the rest
# ---------------------------------------------------------------------------
@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingPermissions):
        await ctx.reply("❌ You don't have permission to do that.")
    elif isinstance(error, commands.CommandNotFound):
        return
    else:
        log.error(f"Command error: {error}")
        await ctx.reply(f"⚠️ Error: {error}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in your .env file before running.")
    bot.run(TOKEN)
