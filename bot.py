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
    """監査ログを投稿するチャンネルを設定します。省略した場合は現在のチャンネルになります。"""
    channel = channel or ctx.channel
    log_channels[str(ctx.guild.id)] = channel.id
    save_config(log_channels)
    await ctx.reply(f"✅ 監査ログは {channel.mention} に投稿されます。")


@bot.command(name="unsetlog")
@commands.has_permissions(manage_guild=True)
async def unsetlog(ctx: commands.Context):
    """このサーバーのログ投稿を停止します。"""
    if str(ctx.guild.id) in log_channels:
        del log_channels[str(ctx.guild.id)]
        save_config(log_channels)
        await ctx.reply("🛑 このサーバーの監査ログを無効にしました。")
    else:
        await ctx.reply("ログチャンネルが設定されていません。")


# ---------------------------------------------------------------------------
# MESSAGE EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot:
        return
    embed = make_embed(
        "🗑️ メッセージ削除",
        color=discord.Color.red(),
    )
    embed.add_field(name="送信者", value=f"{message.author.mention} (`{message.author}`)", inline=True)
    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
    if message.content:
        embed.add_field(name="内容", value=message.content[:1024], inline=False)
    if message.attachments:
        embed.add_field(
            name="添付ファイル",
            value="\n".join(a.filename for a in message.attachments),
            inline=False,
        )
    await send_log(message.guild, embed)


@bot.event
async def on_bulk_message_delete(messages: list[discord.Message]):
    if not messages:
        return
    embed = make_embed(
        "🗑️ 一括メッセージ削除",
        f"{messages[0].channel.mention} で {len(messages)} 件のメッセージが削除されました",
        color=discord.Color.red(),
    )
    await send_log(messages[0].guild, embed)


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if before.author.bot or before.content == after.content:
        return
    embed = make_embed(
        "✏️ メッセージ編集",
        color=discord.Color.orange(),
    )
    embed.add_field(name="送信者", value=f"{before.author.mention} (`{before.author}`)", inline=True)
    embed.add_field(name="チャンネル", value=before.channel.mention, inline=True)
    embed.add_field(name="変更前", value=(before.content or "*空*")[:1024], inline=False)
    embed.add_field(name="変更後", value=(after.content or "*空*")[:1024], inline=False)
    embed.add_field(name="ジャンプ", value=f"[メッセージへジャンプ]({after.jump_url})", inline=False)
    await send_log(before.guild, embed)


# ---------------------------------------------------------------------------
# MEMBER EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_member_join(member: discord.Member):
    embed = make_embed(
        "📥 メンバー参加",
        f"{member.mention} (`{member}`)",
        color=discord.Color.green(),
    )
    embed.add_field(name="アカウント作成日", value=discord.utils.format_dt(member.created_at, "R"))
    embed.add_field(name="メンバー数", value=str(member.guild.member_count))
    await send_log(member.guild, embed)


@bot.event
async def on_member_remove(member: discord.Member):
    embed = make_embed(
        "📤 メンバー退出",
        f"{member.mention} (`{member}`)",
        color=discord.Color.dark_gray(),
    )
    embed.add_field(name="参加日", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "不明")
    roles = [r.mention for r in member.roles if r.name != "@everyone"]
    if roles:
        embed.add_field(name="ロール", value=" ".join(roles)[:1024], inline=False)
    await send_log(member.guild, embed)


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    changes = []
    if before.nick != after.nick:
        changes.append(f"**ニックネーム:** `{before.nick}` → `{after.nick}`")
    if before.roles != after.roles:
        added = [r.mention for r in after.roles if r not in before.roles]
        removed = [r.mention for r in before.roles if r not in after.roles]
        if added:
            changes.append(f"**追加されたロール:** {' '.join(added)}")
        if removed:
            changes.append(f"**削除されたロール:** {' '.join(removed)}")
    if before.timed_out_until != after.timed_out_until and after.timed_out_until:
        changes.append(f"**タイムアウト期限:** {discord.utils.format_dt(after.timed_out_until)}")

    if not changes:
        return

    embed = make_embed(
        "👤 メンバー更新",
        f"{after.mention} (`{after}`)\n" + "\n".join(changes),
        color=discord.Color.blue(),
    )
    await send_log(after.guild, embed)


@bot.event
async def on_user_update(before: discord.User, after: discord.User):
    """ユーザー名・グローバルアバター・表示名の変更を記録します。"""
    changes = []
    if before.name != after.name:
        changes.append(f"**ユーザー名:** `{before.name}` → `{after.name}`")
    if before.global_name != after.global_name:
        changes.append(f"**表示名:** `{before.global_name}` → `{after.global_name}`")
    if before.avatar != after.avatar:
        changes.append("**アバターが変更されました。**")
    if not changes:
        return
    # Push to every guild the user shares with the bot
    for guild in bot.guilds:
        if guild.get_member(after.id):
            embed = make_embed(
                "🪪 ユーザープロフィール更新",
                f"{after.mention}\n" + "\n".join(changes),
                color=discord.Color.blue(),
            )
            await send_log(guild, embed)


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    embed = make_embed(
        "🔨 メンバーBAN",
        f"{user.mention} (`{user}`)",
        color=discord.Color.dark_red(),
    )
    # Try to grab the moderator from audit log
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
            if entry.target.id == user.id:
                embed.add_field(name="モデレーター", value=entry.user.mention)
                if entry.reason:
                    embed.add_field(name="理由", value=entry.reason, inline=False)
                break
    except discord.Forbidden:
        pass
    await send_log(guild, embed)


@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.User):
    embed = make_embed(
        "♻️ メンバーBAN解除",
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
        "📁 チャンネル作成",
        f"{channel.mention} (`{channel.name}`)\nタイプ: {channel.type}",
        color=discord.Color.green(),
    )
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    embed = make_embed(
        "🗑️ チャンネル削除",
        f"`#{channel.name}` (タイプ: {channel.type})",
        color=discord.Color.red(),
    )
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    changes = []
    if before.name != after.name:
        changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if hasattr(before, "topic") and before.topic != after.topic:
        changes.append(f"**トピック:** `{before.topic}` → `{after.topic}`")
    if before.position != after.position:
        changes.append(f"**位置:** {before.position} → {after.position}")
    if hasattr(before, "nsfw") and before.nsfw != after.nsfw:
        changes.append(f"**NSFW:** {before.nsfw} → {after.nsfw}")
    if not changes:
        return
    embed = make_embed(
        "🔧 チャンネル更新",
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
        "✨ ロール作成",
        f"{role.mention} (`{role.name}`)",
        color=discord.Color.green(),
    )
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_delete(role: discord.Role):
    embed = make_embed(
        "🗑️ ロール削除",
        f"`{role.name}`",
        color=discord.Color.red(),
    )
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    changes = []
    if before.name != after.name:
        changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.color != after.color:
        changes.append(f"**カラー:** {before.color} → {after.color}")
    if before.permissions != after.permissions:
        changes.append("**権限が変更されました。**")
    if before.hoist != after.hoist:
        changes.append(f"**ホイスト:** {before.hoist} → {after.hoist}")
    if before.mentionable != after.mentionable:
        changes.append(f"**メンション可能:** {before.mentionable} → {after.mentionable}")
    if not changes:
        return
    embed = make_embed(
        "🔧 ロール更新",
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
            changes.append(f"自己ミュート: {before.self_mute} → {after.self_mute}")
        if before.self_deaf != after.self_deaf:
            changes.append(f"自己スピーカーミュート: {before.self_deaf} → {after.self_deaf}")
        if before.self_stream != after.self_stream:
            changes.append(f"配信: {before.self_stream} → {after.self_stream}")
        if before.self_video != after.self_video:
            changes.append(f"カメラ: {before.self_video} → {after.self_video}")
        if not changes:
            return
        embed = make_embed(
            "🎙️ ボイス状態変更",
            f"{member.mention} ({after.channel.mention} 内)\n" + "\n".join(changes),
            color=discord.Color.blue(),
        )
    elif before.channel is None:
        embed = make_embed(
            "🔊 ボイス参加",
            f"{member.mention} が {after.channel.mention} に参加しました",
            color=discord.Color.green(),
        )
    elif after.channel is None:
        embed = make_embed(
            "🔇 ボイス退出",
            f"{member.mention} が {before.channel.mention} を退出しました",
            color=discord.Color.dark_gray(),
        )
    else:
        embed = make_embed(
            "🔁 ボイスチャンネル移動",
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
        "➕ リアクション追加",
        f"{user.mention} が {reaction.message.channel.mention} のメッセージに {reaction.emoji} を追加しました\n[ジャンプ]({reaction.message.jump_url})",
        color=discord.Color.gold(),
    )
    await send_log(reaction.message.guild, embed)


@bot.event
async def on_reaction_remove(reaction: discord.Reaction, user: discord.User):
    if user.bot:
        return
    embed = make_embed(
        "➖ リアクション削除",
        f"{user.mention} が {reaction.message.channel.mention} のメッセージから {reaction.emoji} を削除しました\n[ジャンプ]({reaction.message.jump_url})",
        color=discord.Color.dark_gold(),
    )
    await send_log(reaction.message.guild, embed)


# ---------------------------------------------------------------------------
# THREAD EVENTS
# ---------------------------------------------------------------------------
@bot.event
async def on_thread_create(thread: discord.Thread):
    embed = make_embed(
        "🧵 スレッド作成",
        f"{thread.mention}（{thread.parent.mention if thread.parent else '不明'} 内）",
        color=discord.Color.green(),
    )
    if thread.owner:
        embed.add_field(name="作成者", value=thread.owner.mention)
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_delete(thread: discord.Thread):
    embed = make_embed(
        "🗑️ スレッド削除",
        f"`{thread.name}`（{thread.parent.mention if thread.parent else '不明'} 内）",
        color=discord.Color.red(),
    )
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_update(before: discord.Thread, after: discord.Thread):
    changes = []
    if before.name != after.name:
        changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.archived != after.archived:
        changes.append(f"**アーカイブ:** {before.archived} → {after.archived}")
    if before.locked != after.locked:
        changes.append(f"**ロック:** {before.locked} → {after.locked}")
    if not changes:
        return
    embed = make_embed(
        "🔧 スレッド更新",
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
        changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.icon != after.icon:
        changes.append("**サーバーアイコンが変更されました。**")
    if before.owner_id != after.owner_id:
        changes.append(f"**オーナー:** <@{before.owner_id}> → <@{after.owner_id}>")
    if before.verification_level != after.verification_level:
        changes.append(f"**認証レベル:** {before.verification_level} → {after.verification_level}")
    if not changes:
        return
    embed = make_embed(
        "🏛️ サーバー更新",
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
        desc.append("**追加:** " + " ".join(str(e) for e in added))
    if removed:
        desc.append("**削除:** " + " ".join(f"`:{e.name}:`" for e in removed))
    embed = make_embed("😀 絵文字更新", "\n".join(desc), color=discord.Color.gold())
    await send_log(guild, embed)


@bot.event
async def on_invite_create(invite: discord.Invite):
    embed = make_embed(
        "🔗 招待作成",
        f"`{invite.code}`（{invite.channel.mention} 向け）",
        color=discord.Color.green(),
    )
    if invite.inviter:
        embed.add_field(name="作成者", value=invite.inviter.mention)
    embed.add_field(name="最大使用回数", value=str(invite.max_uses or "∞"))
    embed.add_field(name="有効期限", value=discord.utils.format_dt(invite.expires_at) if invite.expires_at else "なし")
    await send_log(invite.guild, embed)


@bot.event
async def on_invite_delete(invite: discord.Invite):
    embed = make_embed(
        "🔗 招待削除",
        f"`{invite.code}`（{invite.channel.mention if invite.channel else '不明'} 向け）",
        color=discord.Color.red(),
    )
    await send_log(invite.guild, embed)


# ---------------------------------------------------------------------------
# Error handler — quiet command-permission errors but log the rest
# ---------------------------------------------------------------------------
@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingPermissions):
        await ctx.reply("❌ その操作を行う権限がありません。")
    elif isinstance(error, commands.CommandNotFound):
        return
    else:
        log.error(f"Command error: {error}")
        await ctx.reply(f"⚠️ エラー: {error}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in your .env file before running.")
    bot.run(TOKEN)
