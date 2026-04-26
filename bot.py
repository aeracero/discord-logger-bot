"""
Discord Server Audit Logger Bot
--------------------------------
Logs essentially every action that occurs in a Discord server to a designated
log channel (and to a local file as a backup).

Setup:
  1. Create an application + bot at https://discord.com/developers/applications
  2. Enable ALL Privileged Gateway Intents (Presence, Server Members, Message Content)
  3. Invite the bot to your server with the "Administrator" permission
  4. Put your token in a .env file (see .env.example)
  5. In your server, run:  !setlog #your-log-channel
  6. Enable alt detection with:  !altdetection on
  7. Manage NG words with:  /ngword add | remove | list | clear
  8. View/change bot settings: /settings show | mute_duration | alt_similarity | alt_max_age
"""

import os
import json
import logging
import difflib
import datetime
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()
TOKEN          = os.getenv("DISCORD_TOKEN")
COMMAND_PREFIX = os.getenv("COMMAND_PREFIX", "!")
CONFIG_PATH          = Path("log_channels.json")
LOG_FILE_PATH        = Path("server_audit.log")
BANNED_USERS_PATH    = Path("banned_users.json")
ALT_CONFIG_PATH      = Path("alt_detection.json")
NG_WORDS_PATH        = Path("ng_words.json")
GUILD_SETTINGS_PATH  = Path("guild_settings.json")

# Default values (used when no per-guild setting is saved)
DEFAULT_MUTE_DURATION_MINUTES  = 10    # How long an auto-mute lasts
DEFAULT_ALT_SIMILARITY         = 0.75  # 75 % username similarity triggers alt flag
DEFAULT_ALT_MAX_AGE_DAYS       = 30    # Accounts newer than this are suspicious

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("audit")

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}

def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

log_channels:   dict = load_json(CONFIG_PATH)
banned_users:   dict = load_json(BANNED_USERS_PATH)
alt_config:     dict = load_json(ALT_CONFIG_PATH)
ng_words:       dict = load_json(NG_WORDS_PATH)
guild_settings: dict = load_json(GUILD_SETTINGS_PATH)
# ng_words structure:     {guild_id: [{"word": str, "action": "mute"|"ban", "added_by": int}]}
# guild_settings structure: {guild_id: {"mute_duration": int, "alt_similarity": float, "alt_max_age": int}}

# ---------------------------------------------------------------------------
# Bot setup
# ---------------------------------------------------------------------------
intents = discord.Intents.all()
bot = commands.Bot(command_prefix=COMMAND_PREFIX, intents=intents)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
async def send_log(guild: discord.Guild | None, embed: discord.Embed) -> None:
    if guild is None:
        return
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
    return discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )


def username_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


def get_setting(guild_id: str, key: str):
    """Return a per-guild setting, falling back to the global default."""
    defaults = {
        "mute_duration":  DEFAULT_MUTE_DURATION_MINUTES,
        "alt_similarity": DEFAULT_ALT_SIMILARITY,
        "alt_max_age":    DEFAULT_ALT_MAX_AGE_DAYS,
    }
    return guild_settings.get(guild_id, {}).get(key, defaults[key])


def set_setting(guild_id: str, key: str, value) -> None:
    guild_settings.setdefault(guild_id, {})[key] = value
    save_json(GUILD_SETTINGS_PATH, guild_settings)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching {len(bot.guilds)} guild(s)")
    try:
        synced = await bot.tree.sync()
        log.info(f"Synced {len(synced)} slash command(s)")
    except Exception as e:
        log.error(f"Failed to sync slash commands: {e}")


# ===========================================================================
# PREFIX COMMANDS
# ===========================================================================

@bot.command(name="sync")
@commands.has_permissions(manage_guild=True)
async def sync_commands(ctx: commands.Context):
    """Instantly syncs slash commands to this server."""
    await ctx.reply("⏳ スラッシュコマンドを同期中...")
    try:
        bot.tree.copy_global_to(guild=ctx.guild)
        synced = await bot.tree.sync(guild=ctx.guild)
        await ctx.reply(f"✅ {len(synced)} 個のスラッシュコマンドをこのサーバーに同期しました。")
        log.info(f"Synced {len(synced)} command(s) to guild {ctx.guild.name}")
    except Exception as e:
        await ctx.reply(f"⚠️ 同期に失敗しました: {e}")
        log.error(f"Failed to sync to guild: {e}")


@bot.command(name="setlog")
@commands.has_permissions(manage_guild=True)
async def setlog(ctx: commands.Context, channel: discord.TextChannel | None = None):
    channel = channel or ctx.channel
    log_channels[str(ctx.guild.id)] = channel.id
    save_json(CONFIG_PATH, log_channels)
    await ctx.reply(f"✅ 監査ログは {channel.mention} に投稿されます。")


@bot.command(name="unsetlog")
@commands.has_permissions(manage_guild=True)
async def unsetlog(ctx: commands.Context):
    if str(ctx.guild.id) in log_channels:
        del log_channels[str(ctx.guild.id)]
        save_json(CONFIG_PATH, log_channels)
        await ctx.reply("🛑 このサーバーの監査ログを無効にしました。")
    else:
        await ctx.reply("ログチャンネルが設定されていません。")


@bot.command(name="altdetection")
@commands.has_permissions(manage_guild=True)
async def altdetection(ctx: commands.Context, setting: str = ""):
    guild_id = str(ctx.guild.id)
    s = setting.lower()
    if s in ("on", "オン", "有効", "enable"):
        alt_config.setdefault(guild_id, {})["enabled"] = True
        save_json(ALT_CONFIG_PATH, alt_config)
        alt_sim = get_setting(guild_id, "alt_similarity")
        alt_age = get_setting(guild_id, "alt_max_age")
        await ctx.reply(
            f"✅ Altアカウント自動検出を **有効** にしました。\n"
            f"・ユーザー名の類似度が **{alt_sim:.0%}** 以上\n"
            f"・アカウント作成日が **{alt_age}日以内**\n"
            "の条件でBANされたユーザーのAltと判定します。\n"
            "設定変更は `/settings alt_similarity` と `/settings alt_max_age` で行えます。"
        )
    elif s in ("off", "オフ", "無効", "disable"):
        alt_config.setdefault(guild_id, {})["enabled"] = False
        save_json(ALT_CONFIG_PATH, alt_config)
        await ctx.reply("🛑 Altアカウント自動検出を **無効** にしました。")
    else:
        enabled = alt_config.get(guild_id, {}).get("enabled", False)
        status = "有効 ✅" if enabled else "無効 🛑"
        await ctx.reply(
            f"現在の状態: **{status}**\n"
            f"`{COMMAND_PREFIX}altdetection on/off` で切り替えてください。"
        )


# ===========================================================================
# SLASH COMMANDS — NG Word Management
# ===========================================================================

ng_group = app_commands.Group(
    name="ngword",
    description="NGワードの管理",
    default_permissions=discord.Permissions(manage_guild=True),
)


@ng_group.command(name="add", description="NGワードを追加します")
@app_commands.describe(
    word="追加するNGワード",
    action="検出時のアクション",
)
@app_commands.choices(action=[
    app_commands.Choice(name="🔇 ミュート（/settings mute_duration で変更可）", value="mute"),
    app_commands.Choice(name="🔨 BAN", value="ban"),
])
async def ngword_add(interaction: discord.Interaction, word: str, action: app_commands.Choice[str]):
    guild_id = str(interaction.guild_id)
    ng_words.setdefault(guild_id, [])
    word_lower = word.lower().strip()
    if not word_lower:
        await interaction.response.send_message("⚠️ 有効なワードを入力してください。", ephemeral=True)
        return
    for entry in ng_words[guild_id]:
        if entry["word"] == word_lower:
            await interaction.response.send_message(
                f"⚠️ `{word}` はすでにNGワードリストに登録されています。", ephemeral=True
            )
            return
    ng_words[guild_id].append({
        "word": word_lower,
        "action": action.value,
        "added_by": interaction.user.id,
    })
    save_json(NG_WORDS_PATH, ng_words)
    mute_dur = get_setting(str(interaction.guild_id), "mute_duration")
    action_label = f"ミュート（{mute_dur}分）" if action.value == "mute" else "BAN"
    await interaction.response.send_message(
        f"✅ NGワード `{word_lower}` を追加しました。\nアクション: **{action_label}**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] NGワード追加: '{word_lower}' → {action.value} by {interaction.user}")


@ng_group.command(name="remove", description="NGワードを削除します")
@app_commands.describe(word="削除するNGワード")
async def ngword_remove(interaction: discord.Interaction, word: str):
    guild_id = str(interaction.guild_id)
    word_lower = word.lower().strip()
    original = ng_words.get(guild_id, [])
    updated = [e for e in original if e["word"] != word_lower]
    if len(updated) == len(original):
        await interaction.response.send_message(
            f"⚠️ `{word}` はNGワードリストに見つかりません。", ephemeral=True
        )
        return
    ng_words[guild_id] = updated
    save_json(NG_WORDS_PATH, ng_words)
    await interaction.response.send_message(
        f"🗑️ NGワード `{word_lower}` を削除しました。", ephemeral=True
    )


@ng_group.command(name="list", description="NGワードの一覧を表示します")
async def ngword_list(interaction: discord.Interaction):
    guild_id = str(interaction.guild_id)
    entries = ng_words.get(guild_id, [])
    if not entries:
        await interaction.response.send_message(
            "NGワードが設定されていません。`/ngword add` で追加してください。", ephemeral=True
        )
        return
    mute_dur = get_setting(guild_id, "mute_duration")
    lines = []
    for e in entries:
        action_label = f"🔇 ミュート（{mute_dur}分）" if e["action"] == "mute" else "🔨 BAN"
        lines.append(f"`{e['word']}` → {action_label}")
    embed = discord.Embed(
        title="📋 NGワード一覧",
        description="\n".join(lines),
        color=discord.Color.blurple(),
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    embed.set_footer(text=f"{len(entries)} 件登録済み")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@ng_group.command(name="clear", description="このサーバーのNGワードをすべて削除します")
async def ngword_clear(interaction: discord.Interaction):
    guild_id = str(interaction.guild_id)
    count = len(ng_words.get(guild_id, []))
    ng_words[guild_id] = []
    save_json(NG_WORDS_PATH, ng_words)
    await interaction.response.send_message(
        f"🗑️ {count} 件のNGワードをすべて削除しました。", ephemeral=True
    )


bot.tree.add_command(ng_group)


# ===========================================================================
# SLASH COMMANDS — Bot Settings
# ===========================================================================

settings_group = app_commands.Group(
    name="settings",
    description="Botの各種設定を変更します",
    default_permissions=discord.Permissions(manage_guild=True),
)


@settings_group.command(name="show", description="現在の設定を表示します")
async def settings_show(interaction: discord.Interaction):
    guild_id = str(interaction.guild_id)
    mute_dur  = get_setting(guild_id, "mute_duration")
    alt_sim   = get_setting(guild_id, "alt_similarity")
    alt_age   = get_setting(guild_id, "alt_max_age")
    embed = discord.Embed(
        title="⚙️ 現在の設定",
        color=discord.Color.blurple(),
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    embed.add_field(name="🔇 ミュート時間",               value=f"{mute_dur} 分",  inline=True)
    embed.add_field(name="🤖 Alt検出・ユーザー名類似度",   value=f"{alt_sim:.0%}", inline=True)
    embed.add_field(name="🤖 Alt検出・最大アカウント日数", value=f"{alt_age} 日",  inline=True)
    embed.set_footer(text="変更は /settings mute_duration / alt_similarity / alt_max_age で行えます")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@settings_group.command(name="mute_duration", description="NGワード検出時の自動ミュート時間を設定します")
@app_commands.describe(minutes="ミュート時間（分）。1〜1440 の範囲で指定してください。")
async def settings_mute(interaction: discord.Interaction, minutes: int):
    if not 1 <= minutes <= 1440:
        await interaction.response.send_message(
            "⚠️ 1〜1440 分の範囲で指定してください。", ephemeral=True
        )
        return
    guild_id = str(interaction.guild_id)
    set_setting(guild_id, "mute_duration", minutes)
    await interaction.response.send_message(
        f"✅ ミュート時間を **{minutes} 分** に設定しました。", ephemeral=True
    )
    log.info(f"[{interaction.guild.name}] ミュート時間を {minutes} 分に変更 by {interaction.user}")


@settings_group.command(name="alt_similarity", description="Altアカウント検出のユーザー名類似度のしきい値を設定します")
@app_commands.describe(percent="類似度（%）。例: 75 = 75%。50〜100 の範囲で指定してください。")
async def settings_alt_sim(interaction: discord.Interaction, percent: int):
    if not 50 <= percent <= 100:
        await interaction.response.send_message(
            "⚠️ 50〜100 の範囲で指定してください。", ephemeral=True
        )
        return
    guild_id = str(interaction.guild_id)
    set_setting(guild_id, "alt_similarity", percent / 100)
    await interaction.response.send_message(
        f"✅ Alt検出・ユーザー名類似度のしきい値を **{percent}%** に設定しました。", ephemeral=True
    )
    log.info(f"[{interaction.guild.name}] Alt類似度しきい値を {percent}% に変更 by {interaction.user}")


@settings_group.command(name="alt_max_age", description="Alt検出で『新規アカウント』とみなすアカウント作成日数を設定します")
@app_commands.describe(days="アカウント作成からの日数。1〜365 の範囲で指定してください。")
async def settings_alt_age(interaction: discord.Interaction, days: int):
    if not 1 <= days <= 365:
        await interaction.response.send_message(
            "⚠️ 1〜365 日の範囲で指定してください。", ephemeral=True
        )
        return
    guild_id = str(interaction.guild_id)
    set_setting(guild_id, "alt_max_age", days)
    await interaction.response.send_message(
        f"✅ Alt検出・最大アカウント日数を **{days} 日** に設定しました。", ephemeral=True
    )
    log.info(f"[{interaction.guild.name}] Alt最大アカウント日数を {days} 日に変更 by {interaction.user}")


bot.tree.add_command(settings_group)


# ===========================================================================
# NG WORD DETECTION — on_message
# ===========================================================================

@bot.event
async def on_message(message: discord.Message):
    # Always process prefix commands first
    await bot.process_commands(message)

    if message.author.bot or not message.guild:
        return

    # Skip members with manage_guild (mods/admins)
    if isinstance(message.author, discord.Member) and message.author.guild_permissions.manage_guild:
        return

    guild_id = str(message.guild.id)
    entries = ng_words.get(guild_id, [])
    if not entries:
        return

    content_lower = message.content.lower()
    for entry in entries:
        if entry["word"] in content_lower:
            word     = entry["word"]
            action   = entry["action"]
            author   = message.author
            mute_dur = get_setting(guild_id, "mute_duration")

            # Delete the offending message
            try:
                await message.delete()
            except (discord.Forbidden, discord.HTTPException):
                pass

            bot_member = message.guild.me

            if action == "mute":
                # Discord API forbids timing out the server owner
                if author.id == message.guild.owner_id:
                    embed = make_embed(
                        "⚠️ NGワード検出 — サーバーオーナーのためスキップ",
                        f"{author.mention} はサーバーオーナーのためミュートできません。",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                    embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
                    await send_log(message.guild, embed)
                    break

                # Check role hierarchy — bot's top role must be above target's top role
                if bot_member.top_role <= author.top_role:
                    embed = make_embed(
                        "⚠️ NGワード検出 — ミュート失敗（ロール階層）",
                        f"{author.mention} のロールがBotより高いためミュートできませんでした。",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                    embed.add_field(name="対処方法", value="サーバー設定 → ロール で、Botのロールを最上位に移動してください。", inline=False)
                    embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
                    await send_log(message.guild, embed)
                    log.warning(f"[{message.guild.name}] ロール階層エラー: {author} のロールがBotより高い")
                    break

                until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=mute_dur)
                try:
                    await author.timeout(until, reason=f"NGワード検出: {word}")
                    embed = make_embed(
                        "🔇 NGワード検出 — 自動ミュート",
                        f"{author.mention} (`{author}`) をミュートしました。",
                        color=discord.Color.orange(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                    embed.add_field(name="ミュート期間", value=f"{mute_dur}分", inline=True)
                    embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
                except discord.Forbidden:
                    embed = make_embed(
                        "⚠️ NGワード検出 — ミュート失敗（権限不足）",
                        f"{author.mention} をミュートしようとしましたが、権限が不足しています。",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="対処方法", value="Botに **メンバーをタイムアウト** 権限があるか確認してください。", inline=False)
                except discord.HTTPException as e:
                    embed = make_embed(
                        "⚠️ NGワード検出 — ミュートエラー",
                        f"{author.mention} のミュート中にエラーが発生しました: `{e}`",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)

            else:  # ban
                # Skip owner
                if author.id == message.guild.owner_id:
                    embed = make_embed(
                        "⚠️ NGワード検出 — サーバーオーナーのためスキップ",
                        f"{author.mention} はサーバーオーナーのためBANできません。",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                    await send_log(message.guild, embed)
                    break

                # Check role hierarchy for ban too
                if bot_member.top_role <= author.top_role:
                    embed = make_embed(
                        "⚠️ NGワード検出 — BAN失敗（ロール階層）",
                        f"{author.mention} のロールがBotより高いためBANできませんでした。",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="対処方法", value="サーバー設定 → ロール で、Botのロールを最上位に移動してください。", inline=False)
                    await send_log(message.guild, embed)
                    log.warning(f"[{message.guild.name}] ロール階層エラー（BAN）: {author} のロールがBotより高い")
                    break

                try:
                    await message.guild.ban(author, reason=f"NGワード検出: {word}")
                    embed = make_embed(
                        "🔨 NGワード検出 — 自動BAN",
                        f"{author.mention} (`{author}`) をBANしました。",
                        color=discord.Color.dark_red(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                    embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
                except discord.Forbidden:
                    embed = make_embed(
                        "⚠️ NGワード検出 — BAN失敗（権限不足）",
                        f"{author.mention} をBANしようとしましたが、権限が不足しています。",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                except discord.HTTPException as e:
                    embed = make_embed(
                        "⚠️ NGワード検出 — BANエラー",
                        f"{author.mention} のBAN中にエラーが発生しました: `{e}`",
                        color=discord.Color.yellow(),
                    )
                    embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)

            await send_log(message.guild, embed)
            log.info(f"[{message.guild.name}] NGワード '{word}' 検出 → {action} : {author}")
            break  # Only apply one action even if multiple NG words match


# ===========================================================================
# ALT DETECTION
# ===========================================================================

async def check_for_alt(member: discord.Member) -> None:
    guild_id = str(member.guild.id)
    if not alt_config.get(guild_id, {}).get("enabled", False):
        return
    banned_list = banned_users.get(guild_id, [])
    now = datetime.datetime.now(datetime.timezone.utc)
    account_age_days = (now - member.created_at).days

    alt_sim = get_setting(guild_id, "alt_similarity")
    alt_max_age = get_setting(guild_id, "alt_max_age")

    for entry in banned_list:
        if entry["user_id"] == member.id:
            continue
        similarity = username_similarity(member.name, entry["username"])
        banned_at = datetime.datetime.fromisoformat(entry["banned_at"])
        created_after_ban = member.created_at.replace(tzinfo=datetime.timezone.utc) > banned_at
        is_alt = False
        reason_parts = []

        if similarity >= alt_sim:
            reason_parts.append(f"ユーザー名がBANユーザー `{entry['username']}` に類似 (類似度: {similarity:.0%})")
            if created_after_ban:
                reason_parts.append("BAN後にアカウントを作成")
                is_alt = True
            elif account_age_days <= alt_max_age:
                reason_parts.append(f"アカウント作成日が {account_age_days} 日前（新規）")
                is_alt = True

        if is_alt:
            reason_str = " / ".join(reason_parts)
            try:
                await member.guild.ban(member, reason=f"[Alt検出] {reason_str}")
                embed = make_embed(
                    "🤖 Altアカウント自動BAN",
                    f"{member.mention} (`{member}`) をAltアカウントとして自動BANしました。",
                    color=discord.Color.dark_red(),
                )
                embed.add_field(name="理由", value=reason_str, inline=False)
                embed.add_field(name="アカウント作成日", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
                embed.add_field(name="元のBANユーザー", value=f"`{entry['username']}` (ID: {entry['user_id']})", inline=True)
                await send_log(member.guild, embed)
            except (discord.Forbidden, discord.HTTPException) as e:
                log.warning(f"Cannot auto-ban suspected alt {member}: {e}")
            break


# ===========================================================================
# AUDIT LOG EVENTS
# ===========================================================================

# ── Messages ────────────────────────────────────────────────────────────────

@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot:
        return
    embed = make_embed("🗑️ メッセージ削除", color=discord.Color.red())
    embed.add_field(name="送信者", value=f"{message.author.mention} (`{message.author}`)", inline=True)
    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
    if message.content:
        embed.add_field(name="内容", value=message.content[:1024], inline=False)
    if message.attachments:
        embed.add_field(name="添付ファイル", value="\n".join(a.filename for a in message.attachments), inline=False)
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
    embed = make_embed("✏️ メッセージ編集", color=discord.Color.orange())
    embed.add_field(name="送信者", value=f"{before.author.mention} (`{before.author}`)", inline=True)
    embed.add_field(name="チャンネル", value=before.channel.mention, inline=True)
    embed.add_field(name="変更前", value=(before.content or "*空*")[:1024], inline=False)
    embed.add_field(name="変更後", value=(after.content or "*空*")[:1024], inline=False)
    embed.add_field(name="ジャンプ", value=f"[メッセージへジャンプ]({after.jump_url})", inline=False)
    await send_log(before.guild, embed)


# ── Members ─────────────────────────────────────────────────────────────────

@bot.event
async def on_member_join(member: discord.Member):
    embed = make_embed("📥 メンバー参加", f"{member.mention} (`{member}`)", color=discord.Color.green())
    embed.add_field(name="アカウント作成日", value=discord.utils.format_dt(member.created_at, "R"))
    embed.add_field(name="メンバー数", value=str(member.guild.member_count))
    await send_log(member.guild, embed)
    await check_for_alt(member)


@bot.event
async def on_member_remove(member: discord.Member):
    embed = make_embed("📤 メンバー退出", f"{member.mention} (`{member}`)", color=discord.Color.dark_gray())
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
        added   = [r.mention for r in after.roles  if r not in before.roles]
        removed = [r.mention for r in before.roles if r not in after.roles]
        if added:   changes.append(f"**追加されたロール:** {' '.join(added)}")
        if removed: changes.append(f"**削除されたロール:** {' '.join(removed)}")
    if before.timed_out_until != after.timed_out_until and after.timed_out_until:
        changes.append(f"**タイムアウト期限:** {discord.utils.format_dt(after.timed_out_until)}")
    if not changes:
        return
    embed = make_embed("👤 メンバー更新", f"{after.mention} (`{after}`)\n" + "\n".join(changes), color=discord.Color.blue())
    await send_log(after.guild, embed)


@bot.event
async def on_user_update(before: discord.User, after: discord.User):
    changes = []
    if before.name != after.name:
        changes.append(f"**ユーザー名:** `{before.name}` → `{after.name}`")
    if before.global_name != after.global_name:
        changes.append(f"**表示名:** `{before.global_name}` → `{after.global_name}`")
    if before.avatar != after.avatar:
        changes.append("**アバターが変更されました。**")
    if not changes:
        return
    for guild in bot.guilds:
        if guild.get_member(after.id):
            embed = make_embed("🪪 ユーザープロフィール更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.blue())
            await send_log(guild, embed)


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    guild_id = str(guild.id)
    banned_users.setdefault(guild_id, [])
    if not any(e["user_id"] == user.id for e in banned_users[guild_id]):
        banned_users[guild_id].append({
            "user_id": user.id,
            "username": user.name,
            "banned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "account_created_at": user.created_at.isoformat(),
        })
        save_json(BANNED_USERS_PATH, banned_users)
    embed = make_embed("🔨 メンバーBAN", f"{user.mention} (`{user}`)", color=discord.Color.dark_red())
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
    guild_id = str(guild.id)
    if guild_id in banned_users:
        banned_users[guild_id] = [e for e in banned_users[guild_id] if e["user_id"] != user.id]
        save_json(BANNED_USERS_PATH, banned_users)
    embed = make_embed("♻️ メンバーBAN解除", f"`{user}` (`{user.id}`)", color=discord.Color.green())
    await send_log(guild, embed)


# ── Channels ─────────────────────────────────────────────────────────────────

@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    embed = make_embed("📁 チャンネル作成", f"{channel.mention} (`{channel.name}`)\nタイプ: {channel.type}", color=discord.Color.green())
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    embed = make_embed("🗑️ チャンネル削除", f"`#{channel.name}` (タイプ: {channel.type})", color=discord.Color.red())
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
    embed = make_embed("🔧 チャンネル更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.orange())
    await send_log(after.guild, embed)


# ── Roles ─────────────────────────────────────────────────────────────────────

@bot.event
async def on_guild_role_create(role: discord.Role):
    embed = make_embed("✨ ロール作成", f"{role.mention} (`{role.name}`)", color=discord.Color.green())
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_delete(role: discord.Role):
    embed = make_embed("🗑️ ロール削除", f"`{role.name}`", color=discord.Color.red())
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
    embed = make_embed("🔧 ロール更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.orange())
    await send_log(after.guild, embed)


# ── Voice ─────────────────────────────────────────────────────────────────────

@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    if before.channel == after.channel:
        changes = []
        if before.self_mute   != after.self_mute:   changes.append(f"自己ミュート: {before.self_mute} → {after.self_mute}")
        if before.self_deaf   != after.self_deaf:   changes.append(f"自己スピーカーミュート: {before.self_deaf} → {after.self_deaf}")
        if before.self_stream != after.self_stream: changes.append(f"配信: {before.self_stream} → {after.self_stream}")
        if before.self_video  != after.self_video:  changes.append(f"カメラ: {before.self_video} → {after.self_video}")
        if not changes:
            return
        embed = make_embed("🎙️ ボイス状態変更", f"{member.mention} ({after.channel.mention} 内)\n" + "\n".join(changes), color=discord.Color.blue())
    elif before.channel is None:
        embed = make_embed("🔊 ボイス参加", f"{member.mention} が {after.channel.mention} に参加しました", color=discord.Color.green())
    elif after.channel is None:
        embed = make_embed("🔇 ボイス退出", f"{member.mention} が {before.channel.mention} を退出しました", color=discord.Color.dark_gray())
    else:
        embed = make_embed("🔁 ボイスチャンネル移動", f"{member.mention}: {before.channel.mention} → {after.channel.mention}", color=discord.Color.blue())
    await send_log(member.guild, embed)


# ── Reactions ─────────────────────────────────────────────────────────────────

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


# ── Threads ───────────────────────────────────────────────────────────────────

@bot.event
async def on_thread_create(thread: discord.Thread):
    embed = make_embed("🧵 スレッド作成", f"{thread.mention}（{thread.parent.mention if thread.parent else '不明'} 内）", color=discord.Color.green())
    if thread.owner:
        embed.add_field(name="作成者", value=thread.owner.mention)
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_delete(thread: discord.Thread):
    embed = make_embed("🗑️ スレッド削除", f"`{thread.name}`（{thread.parent.mention if thread.parent else '不明'} 内）", color=discord.Color.red())
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_update(before: discord.Thread, after: discord.Thread):
    changes = []
    if before.name     != after.name:     changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.archived != after.archived: changes.append(f"**アーカイブ:** {before.archived} → {after.archived}")
    if before.locked   != after.locked:   changes.append(f"**ロック:** {before.locked} → {after.locked}")
    if not changes:
        return
    embed = make_embed("🔧 スレッド更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.orange())
    await send_log(after.guild, embed)


# ── Guild ─────────────────────────────────────────────────────────────────────

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
    embed = make_embed("🏛️ サーバー更新", "\n".join(changes), color=discord.Color.purple())
    await send_log(after, embed)


@bot.event
async def on_guild_emojis_update(guild: discord.Guild, before: tuple, after: tuple):
    added   = set(after) - set(before)
    removed = set(before) - set(after)
    desc = []
    if added:   desc.append("**追加:** " + " ".join(str(e) for e in added))
    if removed: desc.append("**削除:** " + " ".join(f"`:{e.name}:`" for e in removed))
    embed = make_embed("😀 絵文字更新", "\n".join(desc), color=discord.Color.gold())
    await send_log(guild, embed)


@bot.event
async def on_invite_create(invite: discord.Invite):
    embed = make_embed("🔗 招待作成", f"`{invite.code}`（{invite.channel.mention} 向け）", color=discord.Color.green())
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


# ── Error handler ─────────────────────────────────────────────────────────────

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
