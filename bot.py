"""
Discord Server Audit Logger Bot  +  Security Module
-----------------------------------------------------
Logs essentially every action that occurs in a Discord server to a designated
log channel (and to a local file as a backup).  Also includes a full security
suite that can be configured entirely from within Discord.

Setup:
 1. Create an application + bot at https://discord.com/developers/applications
 2. Enable ALL Privileged Gateway Intents (Presence, Server Members, Message Content)
 3. Invite the bot to your server with the "Administrator" permission
 4. Put your token in a .env file:  DISCORD_TOKEN=your_token_here
 5. In your server, run:  !setlog #your-log-channel
 6. Enable alt detection with:  !altdetection on
 7. Manage NG words with:  /ngword add | remove | list | clear
 8. View/change bot settings:  /settings show | mute_duration | alt_similarity | alt_max_age | toggle
 9. Security features:  /security show | raid | account_age | link_filter | antispam | mention_spam | antihoisting
10. Manual lockdown:  !lockdown on | off
11. AI moderation (requires GEMINI_API_KEY env var):  /ai show | configure | test
"""

import os
import json
import logging
import difflib
import datetime
import asyncio
import re
from collections import defaultdict
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# AI Integration (Gemini) — graceful degradation if package/key absent
# ---------------------------------------------------------------------------
try:
    import google.generativeai as genai
    _GENAI_PKG_AVAILABLE = True
except ImportError:
    genai = None
    _GENAI_PKG_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()
TOKEN          = os.getenv("DISCORD_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
COMMAND_PREFIX = os.getenv("COMMAND_PREFIX", "!")
CONFIG_PATH          = Path("log_channels.json")
LOG_FILE_PATH        = Path("server_audit.log")
BANNED_USERS_PATH    = Path("banned_users.json")
ALT_CONFIG_PATH      = Path("alt_detection.json")
NG_WORDS_PATH        = Path("ng_words.json")
GUILD_SETTINGS_PATH  = Path("guild_settings.json")

# Default values (used when no per-guild setting is saved)
DEFAULT_MUTE_DURATION_MINUTES = 10    # How long an auto-mute lasts
DEFAULT_ALT_SIMILARITY        = 0.75  # 75 % username similarity triggers alt flag
DEFAULT_ALT_MAX_AGE_DAYS      = 30    # Accounts newer than this are suspicious

# Security defaults
DEFAULT_RAID_THRESHOLD      = 5    # joins within window before raid fires
DEFAULT_RAID_WINDOW_SECONDS = 10   # seconds to watch for mass-join
DEFAULT_MIN_ACCOUNT_AGE_DAYS = 7   # kick accounts newer than this many days
DEFAULT_SPAM_MAX_MESSAGES   = 5    # messages in window before spam fires
DEFAULT_SPAM_WINDOW_SECONDS = 5    # seconds window for spam check
DEFAULT_MAX_MENTIONS        = 5    # unique @mentions in one message

# Regex patterns
URL_REGEX            = re.compile(r'https?://\S+', re.IGNORECASE)
DISCORD_INVITE_REGEX = re.compile(
    r'(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/\S+', re.IGNORECASE
)
# A name that starts with a non-letter/non-number is considered "hoisting"
HOISTING_REGEX = re.compile(r'^[^a-zA-Z0-9぀-ヿ一-鿿㐀-䶿]')

# AI RAM efficiency constants
AI_MAX_USERS_PER_GUILD = 500   # max users tracked per guild
AI_MAX_MSGS_PER_USER   = 3     # messages kept per user for context
AI_MAX_MSG_CHARS       = 120   # chars stored per message

# Soft signals that trigger AI analysis (not applied to every message)
AI_SUSPICIOUS_KEYWORDS = frozenset({
    "free nitro", "giveaway", "claim your", "airdrop",
    "crypto", "investment", "click here", "win ", "prize",
    "limited time", "discord gift", "http://", "https://t.me",
})

# ---------------------------------------------------------------------------
# Log event categories
# ---------------------------------------------------------------------------
LOG_EVENT_CATEGORIES: dict[str, str] = {
    "messages":  "メッセージ（削除・編集）",
    "members":   "メンバー（参加・退出・BAN・更新）",
    "channels":  "チャンネル（作成・削除・更新）",
    "roles":     "ロール（作成・削除・更新）",
    "voice":     "ボイス（参加・退出・状態変更）",
    "reactions": "リアクション（追加・削除）",
    "threads":   "スレッド（作成・削除・更新）",
    "server":    "サーバー（名前・アイコン・絵文字）",
    "invites":   "招待（作成・削除）",
}

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

# ---------------------------------------------------------------------------
# In-memory security trackers  (reset on restart — that is fine)
# ---------------------------------------------------------------------------
# guild_id -> list of UTC datetimes for recent joins
join_tracker: dict[str, list[datetime.datetime]] = defaultdict(list)

# guild_id -> {user_id: list of UTC datetimes for recent messages}
message_tracker: dict[str, dict[int, list[datetime.datetime]]] = defaultdict(
    lambda: defaultdict(list)
)

# ---------------------------------------------------------------------------
# Log message cache — makes bot log messages inerasable
# message_id -> discord.Embed  (capped to avoid unbounded memory growth)
# ---------------------------------------------------------------------------
LOG_MSG_CACHE_MAX = 1000   # keep the last N log embeds in memory
log_msg_cache: dict[int, discord.Embed] = {}   # message_id -> embed

# AI in-memory context (bounded to stay RAM-friendly on Railway free tier)
# guild_id -> {user_id: list of short message strings}
user_message_history: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
# guild_id -> {user_id: last_ai_check_datetime}
ai_cooldowns: dict[str, dict[int, datetime.datetime]] = defaultdict(dict)

# Global AI state (set during on_ready via init_ai())
ai_model = None
AI_ENABLED = False

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
        log.info(f"  {field.name}: {field.value}")
    channel_id = log_channels.get(str(guild.id))
    if channel_id is None:
        return
    channel = guild.get_channel(channel_id)
    if channel is None:
        return
    try:
        sent = await channel.send(embed=embed)
        # Cache this message so we can repost it if someone deletes it.
        if len(log_msg_cache) >= LOG_MSG_CACHE_MAX:
            # Evict the oldest entry to stay under the cap.
            oldest_id = next(iter(log_msg_cache))
            del log_msg_cache[oldest_id]
        log_msg_cache[sent.id] = embed
    except discord.Forbidden:
        log.warning(f"Missing permissions to send in #{channel} of {guild.name}")
    except discord.HTTPException as e:
        log.error(f"Failed to send log: {e}")


def make_embed(
    title: str,
    description: str = "",
    color: discord.Color = discord.Color.blurple(),
) -> discord.Embed:
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
        "mute_duration": DEFAULT_MUTE_DURATION_MINUTES,
        "alt_similarity": DEFAULT_ALT_SIMILARITY,
        "alt_max_age":    DEFAULT_ALT_MAX_AGE_DAYS,
    }
    return guild_settings.get(guild_id, {}).get(key, defaults[key])


def set_setting(guild_id: str, key: str, value) -> None:
    guild_settings.setdefault(guild_id, {})[key] = value
    save_json(GUILD_SETTINGS_PATH, guild_settings)


def is_log_enabled(guild_id: str, category: str) -> bool:
    events = guild_settings.get(guild_id, {}).get("log_events", {})
    return events.get(category, True)


def set_log_enabled(guild_id: str, category: str, enabled: bool) -> None:
    guild_settings.setdefault(guild_id, {}).setdefault("log_events", {})[category] = enabled
    save_json(GUILD_SETTINGS_PATH, guild_settings)

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------
_SECURITY_DEFAULTS: dict[str, dict] = {
    "raid_detection": {
        "enabled":        False,
        "threshold":      DEFAULT_RAID_THRESHOLD,
        "window_seconds": DEFAULT_RAID_WINDOW_SECONDS,
        "action":         "alert",   # "alert" | "kick" | "lockdown"
    },
    "account_age_kick": {
        "enabled":  False,
        "min_days": DEFAULT_MIN_ACCOUNT_AGE_DAYS,
    },
    "link_filter": {
        "enabled":        False,
        "block_invites":  True,
        "block_urls":     False,
        "action":         "delete",  # "delete" | "mute" | "ban"
    },
    "antispam": {
        "enabled":        False,
        "max_messages":   DEFAULT_SPAM_MAX_MESSAGES,
        "window_seconds": DEFAULT_SPAM_WINDOW_SECONDS,
        "action":         "mute",    # "mute" | "ban"
    },
    "mention_spam": {
        "enabled":      False,
        "max_mentions": DEFAULT_MAX_MENTIONS,
        "action":       "mute",      # "mute" | "ban"
    },
    "antihoisting": {
        "enabled": False,
    },
    "ai_moderation": {
        "enabled":              False,
        "analyze_joins":        True,
        "analyze_messages":     True,
        "action_suspicious":    "flag",  # "flag" | "mute" | "kick"
        "action_attacker":      "mute",  # "flag" | "mute" | "kick" | "ban"
        "confidence_threshold": 70,      # 0-100; only act if AI is this confident
        "cooldown_seconds":     60,      # min seconds between checks per user
    },
}


def get_security(guild_id: str, feature: str) -> dict:
    """Return security settings for one feature, merged with defaults."""
    base   = dict(_SECURITY_DEFAULTS.get(feature, {}))
    stored = guild_settings.get(guild_id, {}).get("security", {}).get(feature, {})
    base.update(stored)
    return base


def set_security(guild_id: str, feature: str, key: str, value) -> None:
    (guild_settings
        .setdefault(guild_id, {})
        .setdefault("security", {})
        .setdefault(feature, {})
    )[key] = value
    save_json(GUILD_SETTINGS_PATH, guild_settings)


async def apply_mute(
    member: discord.Member,
    duration_minutes: int,
    reason: str,
) -> bool:
    """Timeout a member. Returns True on success."""
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=duration_minutes)
    try:
        await member.timeout(until, reason=reason)
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.warning(f"Could not mute {member}: {e}")
        return False


async def apply_ban(member: discord.Member, reason: str) -> bool:
    """Ban a member. Returns True on success."""
    try:
        await member.guild.ban(member, reason=reason)
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.warning(f"Could not ban {member}: {e}")
        return False


async def lockdown_guild(guild: discord.Guild, lock: bool) -> int:
    """
    Deny (lock=True) or restore (lock=False) Send Messages for @everyone
    in every text channel.  Returns the number of channels modified.
    """
    count = 0
    everyone = guild.default_role
    for channel in guild.text_channels:
        overwrite = channel.overwrites_for(everyone)
        if lock:
            overwrite.send_messages = False
        else:
            overwrite.send_messages = None  # revert to role default
        try:
            await channel.set_permissions(
                everyone,
                overwrite=overwrite,
                reason="Security lockdown" if lock else "Lockdown lifted",
            )
            count += 1
        except (discord.Forbidden, discord.HTTPException):
            pass
    return count

# ===========================================================================
# AI (Gemini) — initialization, analysis, helpers
# ===========================================================================

def init_ai() -> None:
    """Initialize Gemini model if the package and API key are both available."""
    global ai_model, AI_ENABLED
    if not _GENAI_PKG_AVAILABLE:
        log.info("AI: google-generativeai not installed — AI features disabled.")
        return
    if not GEMINI_API_KEY:
        log.info("AI: GEMINI_API_KEY not set — AI features disabled.")
        return
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        ai_model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                max_output_tokens=200,
            ),
        )
        AI_ENABLED = True
        log.info("AI: Gemini 1.5 Flash initialized successfully.")
    except Exception as e:
        log.warning(f"AI: Failed to initialize Gemini: {e}")
        AI_ENABLED = False


def _should_trigger_ai_message(message: discord.Message) -> bool:
    """Return True if a message has soft signals that warrant AI analysis."""
    content_lower = message.content.lower()
    if any(kw in content_lower for kw in AI_SUSPICIOUS_KEYWORDS):
        return True
    if message.mention_everyone:
        return True
    if len(message.mentions) >= 3:
        return True
    # Short message with a URL — common phishing pattern
    if URL_REGEX.search(message.content) and len(message.content) < 100:
        return True
    return False


def update_message_history(guild_id: str, user_id: int, content: str) -> None:
    """Store a truncated message in per-user history, capped for RAM efficiency."""
    guild_hist = user_message_history[guild_id]
    # If guild is at the per-guild user cap, evict the oldest tracked user
    if user_id not in guild_hist and len(guild_hist) >= AI_MAX_USERS_PER_GUILD:
        oldest_uid = next(iter(guild_hist))
        del guild_hist[oldest_uid]
    hist = guild_hist[user_id]
    hist.append(content[:AI_MAX_MSG_CHARS])
    if len(hist) > AI_MAX_MSGS_PER_USER:
        hist.pop(0)


async def analyze_with_ai(context: str) -> dict:
    """
    Send context to Gemini and parse the verdict.
    Returns {"verdict": "normal"|"suspicious"|"attacker", "confidence": 0-100, "reason": str}.
    Falls back gracefully on any error.
    """
    if not AI_ENABLED or ai_model is None:
        return {"verdict": "normal", "confidence": 0, "reason": "AI is not enabled"}

    prompt = (
        "You are a Discord server security bot.\n"
        "Classify the user described below as ONE of:\n"
        "  normal     — regular user, no threat\n"
        "  suspicious — unusual behaviour, possible threat but not confirmed\n"
        "  attacker   — clear threat: spam, phishing, scam, or harassment\n\n"
        "Reply ONLY in this exact format (no extra text):\n"
        "VERDICT: <normal|suspicious|attacker>\n"
        "CONFIDENCE: <0-100>\n"
        "REASON: <one concise sentence>\n\n"
        f"Context:\n{context}"
    )

    try:
        response = await asyncio.to_thread(
            lambda: ai_model.generate_content(prompt).text
        )
        lines = {}
        for line in response.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                lines[k.strip().upper()] = v.strip()
        verdict    = lines.get("VERDICT", "normal").lower()
        confidence = int(lines.get("CONFIDENCE", "0"))
        reason     = lines.get("REASON", "No reason provided.")
        if verdict not in ("normal", "suspicious", "attacker"):
            verdict = "normal"
        confidence = max(0, min(100, confidence))
        return {"verdict": verdict, "confidence": confidence, "reason": reason}
    except Exception as e:
        log.warning(f"AI analysis error: {e}")
        return {"verdict": "normal", "confidence": 0, "reason": f"Analysis error: {e}"}


async def handle_ai_verdict(
    guild: discord.Guild,
    member: discord.Member,
    result: dict,
    cfg: dict,
    context_label: str,
) -> None:
    """Log and apply the configured action when AI returns a non-normal verdict."""
    verdict    = result["verdict"]
    confidence = result["confidence"]
    reason     = result["reason"]

    if verdict == "normal" or confidence < cfg["confidence_threshold"]:
        return

    action = cfg["action_attacker"] if verdict == "attacker" else cfg["action_suspicious"]

    color_map = {
        "flag": discord.Color.yellow(),
        "mute": discord.Color.orange(),
        "kick": discord.Color.red(),
        "ban":  discord.Color.dark_red(),
    }
    verdict_emoji = {"suspicious": "⚠️", "attacker": "🚨"}
    embed = make_embed(
        f"🤖 AI判定 — {verdict_emoji.get(verdict, '?')} {verdict.upper()} ({confidence}%)",
        f"{member.mention} (`{member}`) が AI によって **{verdict}** と判定されました。",
        color=color_map.get(action, discord.Color.yellow()),
    )
    embed.add_field(name="判定理由",       value=reason,       inline=False)
    embed.add_field(name="コンテキスト",   value=context_label, inline=True)
    embed.add_field(name="アクション",     value=action,        inline=True)
    embed.add_field(name="信頼度",         value=f"{confidence}%", inline=True)

    mute_dur = get_setting(str(guild.id), "mute_duration")
    action_result = ""

    if action == "flag":
        action_result = "🚩 フラグを立てました（ログのみ）"
    elif action == "mute":
        success = await apply_mute(member, mute_dur, reason=f"AI判定: {verdict} ({confidence}%)")
        action_result = f"{'✅' if success else '❌'} {mute_dur}分ミュート"
    elif action == "kick":
        try:
            await member.kick(reason=f"AI判定: {verdict} ({confidence}%)")
            action_result = "✅ キックしました"
        except (discord.Forbidden, discord.HTTPException) as e:
            action_result = f"❌ キック失敗: {e}"
    elif action == "ban":
        success = await apply_ban(member, reason=f"AI判定: {verdict} ({confidence}%)")
        action_result = "✅ BANしました" if success else "❌ BAN失敗"

    embed.add_field(name="実行結果", value=action_result, inline=False)
    await send_log(guild, embed)
    log.info(f"[{guild.name}] AI verdict: {verdict} ({confidence}%) → {action}: {member} | {reason}")


async def check_ai_join(member: discord.Member) -> None:
    """Analyze a new member's profile with AI on join."""
    if not AI_ENABLED:
        return
    guild_id = str(member.guild.id)
    cfg = get_security(guild_id, "ai_moderation")
    if not cfg["enabled"] or not cfg["analyze_joins"]:
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    account_age_days = (now - member.created_at).days
    context = (
        f"A user just joined the server.\n"
        f"Username: {member.name}\n"
        f"Display name: {member.display_name}\n"
        f"Account age: {account_age_days} days\n"
        f"Server member count: {member.guild.member_count}\n"
        f"Has avatar: {'yes' if member.avatar else 'no'}"
    )
    result = await analyze_with_ai(context)
    await handle_ai_verdict(member.guild, member, result, cfg, "参加時のプロフィール分析")


async def check_ai_message(message: discord.Message) -> None:
    """Analyze a message with AI if soft-signal heuristics fire."""
    if not AI_ENABLED:
        return
    guild_id = str(message.guild.id)
    cfg = get_security(guild_id, "ai_moderation")
    if not cfg["enabled"] or not cfg["analyze_messages"]:
        return

    author = message.author
    now    = datetime.datetime.now(datetime.timezone.utc)

    # Per-user cooldown check
    last = ai_cooldowns[guild_id].get(author.id)
    if last and (now - last).total_seconds() < cfg["cooldown_seconds"]:
        return

    # Only analyse when soft signals are present
    if not _should_trigger_ai_message(message):
        return

    update_message_history(guild_id, author.id, message.content)
    history      = user_message_history[guild_id].get(author.id, [])
    history_text = "\n".join(f"  - {m}" for m in history) or "  (no history)"
    account_age_days = (now - author.created_at).days

    context = (
        f"A server member sent a message that triggered a security signal.\n"
        f"Username: {author.name}\n"
        f"Account age: {account_age_days} days\n"
        f"Current message: {message.content[:300]}\n"
        f"Recent message history ({len(history)} messages):\n{history_text}\n"
        f"Mentions @everyone: {message.mention_everyone}\n"
        f"User mentions: {len(message.mentions)}\n"
        f"Contains URLs: {bool(URL_REGEX.search(message.content))}"
    )

    ai_cooldowns[guild_id][author.id] = now
    result = await analyze_with_ai(context)
    await handle_ai_verdict(
        message.guild, author, result, cfg,
        f"メッセージ分析（{message.channel.mention}）",
    )


@tasks.loop(minutes=10)
async def cleanup_ai_data() -> None:
    """Periodically purge stale AI cooldowns and message history to free RAM."""
    now   = datetime.datetime.now(datetime.timezone.utc)
    cutoff = 300  # seconds — remove cooldowns older than 5 min
    for guild_id in list(ai_cooldowns.keys()):
        stale = [uid for uid, ts in ai_cooldowns[guild_id].items()
                 if (now - ts).total_seconds() > cutoff]
        for uid in stale:
            del ai_cooldowns[guild_id][uid]
        if not ai_cooldowns[guild_id]:
            del ai_cooldowns[guild_id]


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching {len(bot.guilds)} guild(s)")
    init_ai()
    if not cleanup_ai_data.is_running():
        cleanup_ai_data.start()
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
    """スラッシュコマンドを即座に同期します。"""
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


@bot.command(name="lockdown")
@commands.has_permissions(manage_guild=True)
async def lockdown_cmd(ctx: commands.Context, setting: str = ""):
    """Manually lock or unlock all text channels.  !lockdown on | off"""
    s = setting.lower()
    if s in ("on", "lock", "enable"):
        msg = await ctx.reply("🔒 サーバーをロックダウン中...")
        count = await lockdown_guild(ctx.guild, lock=True)
        await msg.edit(content=f"🔒 **ロックダウン開始** — {count} 個のチャンネルをロックしました。\n解除するには `{COMMAND_PREFIX}lockdown off` を使用してください。")
        embed = make_embed("🔒 手動ロックダウン開始", f"{ctx.author.mention} がサーバーをロックダウンしました。{count} チャンネルをロック。", color=discord.Color.red())
        await send_log(ctx.guild, embed)
        log.info(f"[{ctx.guild.name}] Manual lockdown STARTED by {ctx.author}")
    elif s in ("off", "unlock", "disable"):
        msg = await ctx.reply("🔓 ロックダウンを解除中...")
        count = await lockdown_guild(ctx.guild, lock=False)
        await msg.edit(content=f"🔓 **ロックダウン解除** — {count} 個のチャンネルを復元しました。")
        embed = make_embed("🔓 ロックダウン解除", f"{ctx.author.mention} がロックダウンを解除しました。{count} チャンネルを復元。", color=discord.Color.green())
        await send_log(ctx.guild, embed)
        log.info(f"[{ctx.guild.name}] Manual lockdown LIFTED by {ctx.author}")
    else:
        await ctx.reply(f"使い方: `{COMMAND_PREFIX}lockdown on` / `{COMMAND_PREFIX}lockdown off`")

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
        "word":     word_lower,
        "action":   action.value,
        "added_by": interaction.user.id,
    })
    save_json(NG_WORDS_PATH, ng_words)
    mute_dur     = get_setting(str(interaction.guild_id), "mute_duration")
    action_label = f"ミュート（{mute_dur}分）" if action.value == "mute" else "BAN"
    await interaction.response.send_message(
        f"✅ NGワード `{word_lower}` を追加しました。\nアクション: **{action_label}**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] NGワード追加: '{word_lower}' → {action.value} by {interaction.user}")


@ng_group.command(name="remove", description="NGワードを削除します")
@app_commands.describe(word="削除するNGワード")
async def ngword_remove(interaction: discord.Interaction, word: str):
    guild_id   = str(interaction.guild_id)
    word_lower = word.lower().strip()
    original   = ng_words.get(guild_id, [])
    updated    = [e for e in original if e["word"] != word_lower]
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
    entries  = ng_words.get(guild_id, [])
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
    count    = len(ng_words.get(guild_id, []))
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
    mute_dur = get_setting(guild_id, "mute_duration")
    alt_sim  = get_setting(guild_id, "alt_similarity")
    alt_age  = get_setting(guild_id, "alt_max_age")

    embed = discord.Embed(
        title="⚙️ 現在の設定",
        color=discord.Color.blurple(),
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    embed.add_field(name="🔇 ミュート時間",               value=f"{mute_dur} 分",  inline=True)
    embed.add_field(name="🤖 Alt検出・ユーザー名類似度",  value=f"{alt_sim:.0%}",  inline=True)
    embed.add_field(name="🤖 Alt検出・最大アカウント日数", value=f"{alt_age} 日",   inline=True)

    cat_lines = []
    for key, label in LOG_EVENT_CATEGORIES.items():
        icon = "✅" if is_log_enabled(guild_id, key) else "🛑"
        cat_lines.append(f"{icon} {label}")
    embed.add_field(
        name="📋 ログカテゴリ（`/settings toggle` で変更）",
        value="\n".join(cat_lines),
        inline=False,
    )
    embed.set_footer(text="変更は /settings mute_duration / alt_similarity / alt_max_age / toggle で行えます")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@settings_group.command(name="mute_duration", description="NGワード検出時の自動ミュート時間を設定します")
@app_commands.describe(minutes="ミュート時間（分）、1〜1440 の範囲で指定してください。")
async def settings_mute(interaction: discord.Interaction, minutes: int):
    if not 1 <= minutes <= 1440:
        await interaction.response.send_message("⚠️ 1〜1440 分の範囲で指定してください。", ephemeral=True)
        return
    set_setting(str(interaction.guild_id), "mute_duration", minutes)
    await interaction.response.send_message(f"✅ ミュート時間を **{minutes} 分** に設定しました。", ephemeral=True)
    log.info(f"[{interaction.guild.name}] ミュート時間を {minutes} 分に変更 by {interaction.user}")


@settings_group.command(name="alt_similarity", description="Altアカウント検出のユーザー名類似度のしきい値を設定します")
@app_commands.describe(percent="類似度（%）。例: 75 = 75%。50〜100 の範囲で指定してください。")
async def settings_alt_sim(interaction: discord.Interaction, percent: int):
    if not 50 <= percent <= 100:
        await interaction.response.send_message("⚠️ 50〜100 の範囲で指定してください。", ephemeral=True)
        return
    set_setting(str(interaction.guild_id), "alt_similarity", percent / 100)
    await interaction.response.send_message(f"✅ Alt検出・ユーザー名類似度のしきい値を **{percent}%** に設定しました。", ephemeral=True)
    log.info(f"[{interaction.guild.name}] Alt類似度しきい値を {percent}% に変更 by {interaction.user}")


@settings_group.command(name="alt_max_age", description="Alt検出で『新規アカウント』とみなすアカウント作成日数を設定します")
@app_commands.describe(days="アカウント作成からの日数、1〜365 の範囲で指定してください。")
async def settings_alt_age(interaction: discord.Interaction, days: int):
    if not 1 <= days <= 365:
        await interaction.response.send_message("⚠️ 1〜365 日の範囲で指定してください。", ephemeral=True)
        return
    set_setting(str(interaction.guild_id), "alt_max_age", days)
    await interaction.response.send_message(f"✅ Alt検出・最大アカウント日数を **{days} 日** に設定しました。", ephemeral=True)
    log.info(f"[{interaction.guild.name}] Alt最大アカウント日数を {days} 日に変更 by {interaction.user}")


@settings_group.command(name="toggle", description="ログカテゴリのON/OFFを切り替えます")
@app_commands.describe(category="切り替えるログカテゴリ")
@app_commands.choices(category=[
    app_commands.Choice(name="📨 メッセージ（削除・編集）",          value="messages"),
    app_commands.Choice(name="👥 メンバー（参加・退出・BAN・更新）",  value="members"),
    app_commands.Choice(name="📁 チャンネル（作成・削除・更新）",     value="channels"),
    app_commands.Choice(name="🎭 ロール（作成・削除・更新）",         value="roles"),
    app_commands.Choice(name="🔊 ボイス（参加・退出・状態変更）",     value="voice"),
    app_commands.Choice(name="😀 リアクション（追加・削除）",         value="reactions"),
    app_commands.Choice(name="🧵 スレッド（作成・削除・更新）",       value="threads"),
    app_commands.Choice(name="🏛️ サーバー（名前・アイコン・絵文字）", value="server"),
    app_commands.Choice(name="🔗 招待（作成・削除）",                 value="invites"),
])
async def settings_toggle(interaction: discord.Interaction, category: app_commands.Choice[str]):
    guild_id  = str(interaction.guild_id)
    current   = is_log_enabled(guild_id, category.value)
    new_state = not current
    set_log_enabled(guild_id, category.value, new_state)
    status_icon = "✅ ON" if new_state else "🛑 OFF"
    state_text  = "有効" if new_state else "無効"
    await interaction.response.send_message(
        f"{status_icon} — **{category.name}** のログを **{state_text}** にしました。", ephemeral=True
    )
    log.info(f"[{interaction.guild.name}] ログカテゴリ '{category.value}' を {'ON' if new_state else 'OFF'} に変更 by {interaction.user}")

bot.tree.add_command(settings_group)

# ===========================================================================
# SLASH COMMANDS — Security Settings  (/security ...)
# ===========================================================================
security_group = app_commands.Group(
    name="security",
    description="セキュリティ機能の設定",
    default_permissions=discord.Permissions(manage_guild=True),
)


# ── /security show ──────────────────────────────────────────────────────────
@security_group.command(name="show", description="現在のセキュリティ設定をすべて表示します")
async def security_show(interaction: discord.Interaction):
    guild_id = str(interaction.guild_id)

    def _status(feature: str) -> str:
        return "✅ ON" if get_security(guild_id, feature)["enabled"] else "🛑 OFF"

    raid  = get_security(guild_id, "raid_detection")
    age   = get_security(guild_id, "account_age_kick")
    link  = get_security(guild_id, "link_filter")
    spam  = get_security(guild_id, "antispam")
    mspam = get_security(guild_id, "mention_spam")
    hoist = get_security(guild_id, "antihoisting")
    ai    = get_security(guild_id, "ai_moderation")

    action_labels = {"alert": "🔔 アラート", "kick": "👢 キック", "lockdown": "🔒 ロックダウン",
                     "delete": "🗑️ 削除", "mute": "🔇 ミュート", "ban": "🔨 BAN"}

    embed = discord.Embed(
        title="🛡️ セキュリティ設定",
        color=discord.Color.dark_red(),
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )

    embed.add_field(
        name=f"🌊 レイド検出  {_status('raid_detection')}",
        value=(
            f"しきい値: **{raid['threshold']}人 / {raid['window_seconds']}秒**\n"
            f"アクション: **{action_labels.get(raid['action'], raid['action'])}**"
        ),
        inline=False,
    )
    embed.add_field(
        name=f"🆕 アカウント年齢キック  {_status('account_age_kick')}",
        value=f"最低アカウント日数: **{age['min_days']}日**",
        inline=False,
    )
    embed.add_field(
        name=f"🔗 リンクフィルター  {_status('link_filter')}",
        value=(
            f"招待リンクをブロック: **{'はい' if link['block_invites'] else 'いいえ'}**\n"
            f"URLをブロック: **{'はい' if link['block_urls'] else 'いいえ'}**\n"
            f"アクション: **{action_labels.get(link['action'], link['action'])}**"
        ),
        inline=False,
    )
    embed.add_field(
        name=f"💬 スパム対策  {_status('antispam')}",
        value=(
            f"上限: **{spam['max_messages']}件 / {spam['window_seconds']}秒**\n"
            f"アクション: **{action_labels.get(spam['action'], spam['action'])}**"
        ),
        inline=False,
    )
    embed.add_field(
        name=f"📢 メンションスパム  {_status('mention_spam')}",
        value=(
            f"1メッセージあたりの上限: **{mspam['max_mentions']}件**\n"
            f"アクション: **{action_labels.get(mspam['action'], mspam['action'])}**"
        ),
        inline=False,
    )
    embed.add_field(
        name=f"⬆️ ホイスト防止  {_status('antihoisting')}",
        value="名前が記号で始まるユーザーを自動リネームします",
        inline=False,
    )
    ai_api_status = (
        "✅ 動作中" if AI_ENABLED
        else ("📦 パッケージ未インストール" if not _GENAI_PKG_AVAILABLE else "🔑 APIキー未設定")
    )
    embed.add_field(
        name=f"🤖 AI モデレーション  {_status('ai_moderation')}",
        value=(
            f"Gemini API: **{ai_api_status}**\n"
            f"参加分析: **{'✅' if ai['analyze_joins'] else '🛑'}** | "
            f"メッセージ分析: **{'✅' if ai['analyze_messages'] else '🛑'}**\n"
            f"suspicious → **{ai['action_suspicious']}** | attacker → **{ai['action_attacker']}**\n"
            f"信頼度しきい値: **{ai['confidence_threshold']}%**"
        ),
        inline=False,
    )
    embed.set_footer(text="変更は /security <機能名> または /ai configure で行えます")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ── /security raid ───────────────────────────────────────────────────────────
@security_group.command(name="raid", description="レイド（大量参加）検出を設定します")
@app_commands.describe(
    enabled="有効にするか無効にするか",
    threshold="何人の参加でレイドと判定するか（例: 5）",
    window_seconds="何秒以内の参加を監視するか（例: 10）",
    action="検出時のアクション",
)
@app_commands.choices(action=[
    app_commands.Choice(name="🔔 アラートのみ（ログに通知）",         value="alert"),
    app_commands.Choice(name="👢 参加者を全員キック + アラート",       value="kick"),
    app_commands.Choice(name="🔒 サーバーをロックダウン + アラート",   value="lockdown"),
])
async def security_raid(
    interaction: discord.Interaction,
    enabled: bool,
    threshold: int | None = None,
    window_seconds: int | None = None,
    action: app_commands.Choice[str] | None = None,
):
    guild_id = str(interaction.guild_id)
    set_security(guild_id, "raid_detection", "enabled", enabled)
    if threshold is not None:
        if not 2 <= threshold <= 100:
            await interaction.response.send_message("⚠️ しきい値は 2〜100 の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "raid_detection", "threshold", threshold)
    if window_seconds is not None:
        if not 3 <= window_seconds <= 300:
            await interaction.response.send_message("⚠️ ウィンドウは 3〜300 秒の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "raid_detection", "window_seconds", window_seconds)
    if action is not None:
        set_security(guild_id, "raid_detection", "action", action.value)

    cfg = get_security(guild_id, "raid_detection")
    status = "✅ 有効" if enabled else "🛑 無効"
    await interaction.response.send_message(
        f"🌊 **レイド検出** を **{status}** にしました。\n"
        f"しきい値: **{cfg['threshold']}人 / {cfg['window_seconds']}秒**\n"
        f"アクション: **{cfg['action']}**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] Raid detection → {enabled}, "
             f"threshold={cfg['threshold']}, window={cfg['window_seconds']}s, action={cfg['action']} by {interaction.user}")


# ── /security account_age ───────────────────────────────────────────────────
@security_group.command(name="account_age", description="新規アカウントを自動キックする機能を設定します")
@app_commands.describe(
    enabled="有効にするか無効にするか",
    min_days="アカウント作成から最低何日経過していないとキックするか（例: 7）",
)
async def security_account_age(
    interaction: discord.Interaction,
    enabled: bool,
    min_days: int | None = None,
):
    guild_id = str(interaction.guild_id)
    set_security(guild_id, "account_age_kick", "enabled", enabled)
    if min_days is not None:
        if not 1 <= min_days <= 365:
            await interaction.response.send_message("⚠️ 1〜365 日の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "account_age_kick", "min_days", min_days)

    cfg    = get_security(guild_id, "account_age_kick")
    status = "✅ 有効" if enabled else "🛑 無効"
    await interaction.response.send_message(
        f"🆕 **アカウント年齢キック** を **{status}** にしました。\n"
        f"最低日数: **{cfg['min_days']} 日**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] Account age kick → {enabled}, min_days={cfg['min_days']} by {interaction.user}")


# ── /security link_filter ───────────────────────────────────────────────────
@security_group.command(name="link_filter", description="メッセージ内のリンク・招待を検出してアクションを実行します")
@app_commands.describe(
    enabled="有効にするか無効にするか",
    block_invites="Discord招待リンク（discord.gg など）をブロックするか",
    block_urls="すべてのURLをブロックするか",
    action="検出時のアクション",
)
@app_commands.choices(action=[
    app_commands.Choice(name="🗑️ メッセージを削除するのみ",              value="delete"),
    app_commands.Choice(name="🔇 削除 + 送信者をミュート",               value="mute"),
    app_commands.Choice(name="🔨 削除 + 送信者をBAN",                    value="ban"),
])
async def security_link_filter(
    interaction: discord.Interaction,
    enabled: bool,
    block_invites: bool | None = None,
    block_urls: bool | None = None,
    action: app_commands.Choice[str] | None = None,
):
    guild_id = str(interaction.guild_id)
    set_security(guild_id, "link_filter", "enabled", enabled)
    if block_invites is not None:
        set_security(guild_id, "link_filter", "block_invites", block_invites)
    if block_urls is not None:
        set_security(guild_id, "link_filter", "block_urls", block_urls)
    if action is not None:
        set_security(guild_id, "link_filter", "action", action.value)

    cfg    = get_security(guild_id, "link_filter")
    status = "✅ 有効" if enabled else "🛑 無効"
    await interaction.response.send_message(
        f"🔗 **リンクフィルター** を **{status}** にしました。\n"
        f"招待リンクをブロック: **{'はい' if cfg['block_invites'] else 'いいえ'}**\n"
        f"URLをブロック: **{'はい' if cfg['block_urls'] else 'いいえ'}**\n"
        f"アクション: **{cfg['action']}**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] Link filter → {enabled}, block_invites={cfg['block_invites']}, "
             f"block_urls={cfg['block_urls']}, action={cfg['action']} by {interaction.user}")


# ── /security antispam ───────────────────────────────────────────────────────
@security_group.command(name="antispam", description="メッセージ連投（スパム）を検出してアクションを実行します")
@app_commands.describe(
    enabled="有効にするか無効にするか",
    max_messages="何件のメッセージでスパムと判定するか（例: 5）",
    window_seconds="何秒以内を監視するか（例: 5）",
    action="検出時のアクション",
)
@app_commands.choices(action=[
    app_commands.Choice(name="🔇 ミュート", value="mute"),
    app_commands.Choice(name="🔨 BAN",      value="ban"),
])
async def security_antispam(
    interaction: discord.Interaction,
    enabled: bool,
    max_messages: int | None = None,
    window_seconds: int | None = None,
    action: app_commands.Choice[str] | None = None,
):
    guild_id = str(interaction.guild_id)
    set_security(guild_id, "antispam", "enabled", enabled)
    if max_messages is not None:
        if not 2 <= max_messages <= 50:
            await interaction.response.send_message("⚠️ 2〜50 の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "antispam", "max_messages", max_messages)
    if window_seconds is not None:
        if not 1 <= window_seconds <= 60:
            await interaction.response.send_message("⚠️ 1〜60 秒の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "antispam", "window_seconds", window_seconds)
    if action is not None:
        set_security(guild_id, "antispam", "action", action.value)

    cfg    = get_security(guild_id, "antispam")
    status = "✅ 有効" if enabled else "🛑 無効"
    await interaction.response.send_message(
        f"💬 **スパム対策** を **{status}** にしました。\n"
        f"上限: **{cfg['max_messages']}件 / {cfg['window_seconds']}秒**\n"
        f"アクション: **{cfg['action']}**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] Anti-spam → {enabled}, max={cfg['max_messages']}, "
             f"window={cfg['window_seconds']}s, action={cfg['action']} by {interaction.user}")


# ── /security mention_spam ────────────────────────────────────────────────────
@security_group.command(name="mention_spam", description="1つのメッセージで大量メンションを検出してアクションを実行します")
@app_commands.describe(
    enabled="有効にするか無効にするか",
    max_mentions="1メッセージあたりの上限メンション数（例: 5）",
    action="検出時のアクション",
)
@app_commands.choices(action=[
    app_commands.Choice(name="🔇 ミュート", value="mute"),
    app_commands.Choice(name="🔨 BAN",      value="ban"),
])
async def security_mention_spam(
    interaction: discord.Interaction,
    enabled: bool,
    max_mentions: int | None = None,
    action: app_commands.Choice[str] | None = None,
):
    guild_id = str(interaction.guild_id)
    set_security(guild_id, "mention_spam", "enabled", enabled)
    if max_mentions is not None:
        if not 2 <= max_mentions <= 50:
            await interaction.response.send_message("⚠️ 2〜50 の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "mention_spam", "max_mentions", max_mentions)
    if action is not None:
        set_security(guild_id, "mention_spam", "action", action.value)

    cfg    = get_security(guild_id, "mention_spam")
    status = "✅ 有効" if enabled else "🛑 無効"
    await interaction.response.send_message(
        f"📢 **メンションスパム対策** を **{status}** にしました。\n"
        f"1メッセージあたりの上限: **{cfg['max_mentions']} 件**\n"
        f"アクション: **{cfg['action']}**",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] Mention spam → {enabled}, max={cfg['max_mentions']}, "
             f"action={cfg['action']} by {interaction.user}")


# ── /security antihoisting ───────────────────────────────────────────────────
@security_group.command(
    name="antihoisting",
    description="名前が記号で始まるユーザーを自動リネームして、リストの先頭に表示させないようにします",
)
@app_commands.describe(enabled="有効にするか無効にするか")
async def security_antihoisting(interaction: discord.Interaction, enabled: bool):
    guild_id = str(interaction.guild_id)
    set_security(guild_id, "antihoisting", "enabled", enabled)
    status = "✅ 有効" if enabled else "🛑 無効"
    await interaction.response.send_message(
        f"⬆️ **ホイスト防止** を **{status}** にしました。\n"
        "名前が `!`, `@`, `-` 等の記号で始まるユーザーは参加時・更新時にニックネームが `[hoisting]` に変更されます。",
        ephemeral=True,
    )
    log.info(f"[{interaction.guild.name}] Anti-hoisting → {enabled} by {interaction.user}")

bot.tree.add_command(security_group)

# ===========================================================================
# SLASH COMMANDS — AI Moderation  (/ai ...)
# ===========================================================================
ai_group = app_commands.Group(
    name="ai",
    description="AI（Gemini）モデレーション機能の設定",
    default_permissions=discord.Permissions(manage_guild=True),
)


# ── /ai show ────────────────────────────────────────────────────────────────
@ai_group.command(name="show", description="AI モデレーション設定と現在のステータスを表示します")
async def ai_show(interaction: discord.Interaction):
    guild_id = str(interaction.guild_id)
    cfg = get_security(guild_id, "ai_moderation")

    ai_api_status = (
        "✅ APIキー設定済み・動作中"
        if AI_ENABLED
        else ("⚠️ google-generativeai パッケージ未インストール" if not _GENAI_PKG_AVAILABLE
              else "🛑 GEMINI_API_KEY が未設定")
    )
    action_labels = {
        "flag": "🚩 フラグ（ログのみ）",
        "mute": "🔇 ミュート",
        "kick": "👢 キック",
        "ban":  "🔨 BAN",
    }
    embed = discord.Embed(
        title="🤖 AI モデレーション設定",
        color=discord.Color.purple(),
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    embed.add_field(name="機能ステータス", value="✅ 有効" if cfg["enabled"] else "🛑 無効", inline=True)
    embed.add_field(name="Gemini API",     value=ai_api_status,                              inline=True)
    embed.add_field(name="​",         value="​",                                    inline=True)
    embed.add_field(name="参加時の分析",   value="✅" if cfg["analyze_joins"]    else "🛑",   inline=True)
    embed.add_field(name="メッセージ分析", value="✅" if cfg["analyze_messages"] else "🛑",   inline=True)
    embed.add_field(name="​",         value="​",                                    inline=True)
    embed.add_field(name="suspicious アクション", value=action_labels.get(cfg["action_suspicious"], cfg["action_suspicious"]), inline=True)
    embed.add_field(name="attacker アクション",   value=action_labels.get(cfg["action_attacker"],   cfg["action_attacker"]),   inline=True)
    embed.add_field(name="​",         value="​",                                    inline=True)
    embed.add_field(name="信頼度しきい値", value=f"{cfg['confidence_threshold']}%",           inline=True)
    embed.add_field(name="クールダウン",   value=f"{cfg['cooldown_seconds']}秒",              inline=True)
    embed.set_footer(text="設定変更: /ai configure | テスト: /ai test")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ── /ai configure ────────────────────────────────────────────────────────────
@ai_group.command(name="configure", description="AI モデレーション設定を変更します")
@app_commands.describe(
    enabled="AI モデレーションを有効にするか",
    analyze_joins="参加時にユーザーを AI で分析するか",
    analyze_messages="メッセージを AI で分析するか",
    action_suspicious="suspicious 判定時のアクション",
    action_attacker="attacker 判定時のアクション",
    confidence_threshold="このパーセント以上の信頼度でアクションを実行（50〜99）",
    cooldown_seconds="同一ユーザーへの AI 分析の最小間隔・秒（10〜3600）",
)
@app_commands.choices(
    action_suspicious=[
        app_commands.Choice(name="🚩 フラグ（ログのみ）", value="flag"),
        app_commands.Choice(name="🔇 ミュート",          value="mute"),
        app_commands.Choice(name="👢 キック",            value="kick"),
    ],
    action_attacker=[
        app_commands.Choice(name="🚩 フラグ（ログのみ）", value="flag"),
        app_commands.Choice(name="🔇 ミュート",          value="mute"),
        app_commands.Choice(name="👢 キック",            value="kick"),
        app_commands.Choice(name="🔨 BAN",              value="ban"),
    ],
)
async def ai_configure(
    interaction: discord.Interaction,
    enabled: bool | None = None,
    analyze_joins: bool | None = None,
    analyze_messages: bool | None = None,
    action_suspicious: app_commands.Choice[str] | None = None,
    action_attacker: app_commands.Choice[str] | None = None,
    confidence_threshold: int | None = None,
    cooldown_seconds: int | None = None,
):
    if enabled and not AI_ENABLED:
        await interaction.response.send_message(
            "⚠️ Gemini AI が動作していません。\n"
            "環境変数 `GEMINI_API_KEY` を設定し、`google-generativeai` パッケージをインストールしてください。\n"
            "設定自体は保存されますが、APIキーが揃うまで AI 分析は行われません。",
            ephemeral=True,
        )
        # Still allow saving the config so it activates once the key is set
    guild_id = str(interaction.guild_id)
    if enabled is not None:
        set_security(guild_id, "ai_moderation", "enabled", enabled)
    if analyze_joins is not None:
        set_security(guild_id, "ai_moderation", "analyze_joins", analyze_joins)
    if analyze_messages is not None:
        set_security(guild_id, "ai_moderation", "analyze_messages", analyze_messages)
    if action_suspicious is not None:
        set_security(guild_id, "ai_moderation", "action_suspicious", action_suspicious.value)
    if action_attacker is not None:
        set_security(guild_id, "ai_moderation", "action_attacker", action_attacker.value)
    if confidence_threshold is not None:
        if not 50 <= confidence_threshold <= 99:
            await interaction.response.send_message("⚠️ 50〜99 の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "ai_moderation", "confidence_threshold", confidence_threshold)
    if cooldown_seconds is not None:
        if not 10 <= cooldown_seconds <= 3600:
            await interaction.response.send_message("⚠️ 10〜3600 秒の範囲で指定してください。", ephemeral=True)
            return
        set_security(guild_id, "ai_moderation", "cooldown_seconds", cooldown_seconds)

    if not interaction.response.is_done():
        cfg = get_security(guild_id, "ai_moderation")
        await interaction.response.send_message(
            f"🤖 **AI モデレーション** 設定を更新しました。\n"
            f"有効: **{'✅' if cfg['enabled'] else '🛑'}**\n"
            f"参加分析: **{'✅' if cfg['analyze_joins'] else '🛑'}** | "
            f"メッセージ分析: **{'✅' if cfg['analyze_messages'] else '🛑'}**\n"
            f"suspicious → **{cfg['action_suspicious']}** | attacker → **{cfg['action_attacker']}**\n"
            f"信頼度しきい値: **{cfg['confidence_threshold']}%** | クールダウン: **{cfg['cooldown_seconds']}秒**",
            ephemeral=True,
        )
    log.info(f"[{interaction.guild.name}] AI moderation config updated by {interaction.user}")


# ── /ai test ─────────────────────────────────────────────────────────────────
@ai_group.command(name="test", description="テキストを AI で分析して判定結果を確認します")
@app_commands.describe(text="AI に分析させるテキスト（最大 300 文字）")
async def ai_test(interaction: discord.Interaction, text: str):
    if not AI_ENABLED:
        await interaction.response.send_message(
            "⚠️ Gemini AI が有効になっていません。`GEMINI_API_KEY` を環境変数に設定してください。",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True)
    context = f"Test analysis requested by a server moderator.\nText to analyze: {text[:300]}"
    result  = await analyze_with_ai(context)

    verdict_display = {"normal": "✅ NORMAL", "suspicious": "⚠️ SUSPICIOUS", "attacker": "🚨 ATTACKER"}
    color_map = {"normal": discord.Color.green(), "suspicious": discord.Color.yellow(), "attacker": discord.Color.red()}
    embed = discord.Embed(
        title=f"🤖 AI テスト結果: {verdict_display.get(result['verdict'], result['verdict'])}",
        color=color_map.get(result["verdict"], discord.Color.blurple()),
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    embed.add_field(name="判定",   value=result["verdict"],       inline=True)
    embed.add_field(name="信頼度", value=f"{result['confidence']}%", inline=True)
    embed.add_field(name="理由",   value=result["reason"],        inline=False)
    embed.add_field(name="入力テキスト", value=text[:500],        inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)

bot.tree.add_command(ai_group)

# ===========================================================================
# NG WORD DETECTION
# ===========================================================================
async def check_ng_words(message: discord.Message) -> bool:
    """
    Check message for NG words.  Returns True if a violation was found and
    handled (caller should stop further processing).
    """
    guild_id = str(message.guild.id)
    entries  = ng_words.get(guild_id, [])
    if not entries:
        return False

    content_lower = message.content.lower()
    for entry in entries:
        if entry["word"] not in content_lower:
            continue

        word   = entry["word"]
        action = entry["action"]
        author = message.author
        mute_dur = get_setting(guild_id, "mute_duration")

        try:
            await message.delete()
        except (discord.Forbidden, discord.HTTPException):
            pass

        bot_member = message.guild.me

        if action == "mute":
            if author.id == message.guild.owner_id:
                embed = make_embed("⚠️ NGワード検出 — サーバーオーナーのためスキップ",
                                   f"{author.mention} はサーバーオーナーのためミュートできません。", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
                await send_log(message.guild, embed)
                return True
            if bot_member.top_role <= author.top_role:
                embed = make_embed("⚠️ NGワード検出 — ミュート失敗（ロール階層）",
                                   f"{author.mention} のロールがBotより高いためミュートできませんでした。", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                embed.add_field(name="対処方法", value="サーバー設定 → ロール で、Botのロールを最上位に移動してください。", inline=False)
                embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
                await send_log(message.guild, embed)
                return True
            until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=mute_dur)
            try:
                await author.timeout(until, reason=f"NGワード検出: {word}")
                embed = make_embed("🔇 NGワード検出 — 自動ミュート",
                                   f"{author.mention} (`{author}`) をミュートしました。", color=discord.Color.orange())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                embed.add_field(name="ミュート期間", value=f"{mute_dur}分", inline=True)
                embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
            except discord.Forbidden:
                embed = make_embed("⚠️ NGワード検出 — ミュート失敗（権限不足）",
                                   f"{author.mention} をミュートしようとしましたが、権限が不足しています。", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                embed.add_field(name="対処方法", value="Botに **メンバーをタイムアウト** 権限があるか確認してください。", inline=False)
            except discord.HTTPException as e:
                embed = make_embed("⚠️ NGワード検出 — ミュートエラー",
                                   f"{author.mention} のミュート中にエラーが発生しました: `{e}`", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
        else:  # ban
            if author.id == message.guild.owner_id:
                embed = make_embed("⚠️ NGワード検出 — サーバーオーナーのためスキップ",
                                   f"{author.mention} はサーバーオーナーのためBANできません。", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                await send_log(message.guild, embed)
                return True
            if bot_member.top_role <= author.top_role:
                embed = make_embed("⚠️ NGワード検出 — BAN失敗（ロール階層）",
                                   f"{author.mention} のロールがBotより高いためBANできませんでした。", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                embed.add_field(name="対処方法", value="サーバー設定 → ロール で、Botのロールを最上位に移動してください。", inline=False)
                await send_log(message.guild, embed)
                return True
            try:
                await message.guild.ban(author, reason=f"NGワード検出: {word}")
                embed = make_embed("🔨 NGワード検出 — 自動BAN",
                                   f"{author.mention} (`{author}`) をBANしました。", color=discord.Color.dark_red())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
                embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
                embed.add_field(name="メッセージ内容", value=f"||{message.content[:500]}||", inline=False)
            except discord.Forbidden:
                embed = make_embed("⚠️ NGワード検出 — BAN失敗（権限不足）",
                                   f"{author.mention} をBANしようとしましたが、権限が不足しています。", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)
            except discord.HTTPException as e:
                embed = make_embed("⚠️ NGワード検出 — BANエラー",
                                   f"{author.mention} のBAN中にエラーが発生しました: `{e}`", color=discord.Color.yellow())
                embed.add_field(name="検出ワード", value=f"||`{word}`||", inline=True)

        await send_log(message.guild, embed)
        log.info(f"[{message.guild.name}] NGワード '{word}' 検出 → {action}: {author}")
        return True

    return False


# ===========================================================================
# SECURITY — Anti-Spam  (message rate limiting)
# ===========================================================================
async def check_antispam(message: discord.Message) -> bool:
    """Returns True if the message was a spam violation and was handled."""
    guild_id = str(message.guild.id)
    cfg = get_security(guild_id, "antispam")
    if not cfg["enabled"]:
        return False

    author = message.author
    now    = datetime.datetime.now(datetime.timezone.utc)
    window = datetime.timedelta(seconds=cfg["window_seconds"])

    # Append and prune old timestamps
    message_tracker[guild_id][author.id].append(now)
    message_tracker[guild_id][author.id] = [
        t for t in message_tracker[guild_id][author.id] if now - t < window
    ]

    count = len(message_tracker[guild_id][author.id])
    if count <= cfg["max_messages"]:
        return False

    # Violation — clear tracker so we don't fire repeatedly
    message_tracker[guild_id][author.id] = []

    action      = cfg["action"]
    mute_dur    = get_setting(guild_id, "mute_duration")
    bot_member  = message.guild.me

    # Skip owner / higher-role members
    if author.id == message.guild.owner_id or (
        isinstance(author, discord.Member) and bot_member.top_role <= author.top_role
    ):
        embed = make_embed("⚠️ スパム検出 — スキップ",
                           f"{author.mention} のスパムを検出しましたが、権限の問題でアクションを実行できません。",
                           color=discord.Color.yellow())
        embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
        embed.add_field(name="件数", value=f"{count}件 / {cfg['window_seconds']}秒", inline=True)
        await send_log(message.guild, embed)
        return True

    if action == "mute":
        success = await apply_mute(author, mute_dur, reason=f"スパム検出 ({count}件/{cfg['window_seconds']}秒)")
        color   = discord.Color.orange() if success else discord.Color.yellow()
        result  = f"✅ {mute_dur}分ミュートしました。" if success else "❌ ミュートに失敗しました（権限不足）。"
        embed = make_embed("💬 スパム検出 — 自動ミュート", f"{author.mention} (`{author}`) {result}", color=color)
    else:
        success = await apply_ban(author, reason=f"スパム検出 ({count}件/{cfg['window_seconds']}秒)")
        color   = discord.Color.dark_red() if success else discord.Color.yellow()
        result  = "✅ BANしました。" if success else "❌ BANに失敗しました（権限不足）。"
        embed = make_embed("💬 スパム検出 — 自動BAN", f"{author.mention} (`{author}`) {result}", color=color)

    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
    embed.add_field(name="件数", value=f"{count}件 / {cfg['window_seconds']}秒", inline=True)
    await send_log(message.guild, embed)
    log.info(f"[{message.guild.name}] Spam → {action}: {author} ({count}msgs/{cfg['window_seconds']}s)")
    return True


# ===========================================================================
# SECURITY — Mention Spam
# ===========================================================================
async def check_mention_spam(message: discord.Message) -> bool:
    """Returns True if the message contained a mention-spam violation and was handled."""
    guild_id = str(message.guild.id)
    cfg = get_security(guild_id, "mention_spam")
    if not cfg["enabled"]:
        return False

    # Count unique mentions (users + roles, excluding @everyone/@here which are separate)
    unique_mentions = len(set(u.id for u in message.mentions)) + len(set(r.id for r in message.role_mentions))
    if unique_mentions <= cfg["max_mentions"]:
        return False

    author     = message.author
    action     = cfg["action"]
    mute_dur   = get_setting(guild_id, "mute_duration")
    bot_member = message.guild.me

    try:
        await message.delete()
    except (discord.Forbidden, discord.HTTPException):
        pass

    if author.id == message.guild.owner_id or (
        isinstance(author, discord.Member) and bot_member.top_role <= author.top_role
    ):
        embed = make_embed("⚠️ メンションスパム検出 — スキップ",
                           f"{author.mention} のメンションスパムを検出しましたが、権限の問題でアクションを実行できません。",
                           color=discord.Color.yellow())
        embed.add_field(name="メンション数", value=str(unique_mentions), inline=True)
        await send_log(message.guild, embed)
        return True

    if action == "mute":
        success = await apply_mute(author, mute_dur, reason=f"メンションスパム ({unique_mentions}件)")
        result  = f"✅ {mute_dur}分ミュートしました。" if success else "❌ ミュートに失敗しました。"
        color   = discord.Color.orange() if success else discord.Color.yellow()
        embed   = make_embed("📢 メンションスパム検出 — 自動ミュート", f"{author.mention} {result}", color=color)
    else:
        success = await apply_ban(author, reason=f"メンションスパム ({unique_mentions}件)")
        result  = "✅ BANしました。" if success else "❌ BANに失敗しました。"
        color   = discord.Color.dark_red() if success else discord.Color.yellow()
        embed   = make_embed("📢 メンションスパム検出 — 自動BAN", f"{author.mention} {result}", color=color)

    embed.add_field(name="メンション数", value=str(unique_mentions), inline=True)
    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
    await send_log(message.guild, embed)
    log.info(f"[{message.guild.name}] Mention spam → {action}: {author} ({unique_mentions} mentions)")
    return True


# ===========================================================================
# SECURITY — Link / Invite Filter
# ===========================================================================
async def check_link_filter(message: discord.Message) -> bool:
    """Returns True if a link violation was found and handled."""
    guild_id = str(message.guild.id)
    cfg = get_security(guild_id, "link_filter")
    if not cfg["enabled"]:
        return False

    content   = message.content
    triggered = False
    reason    = ""

    if cfg["block_invites"] and DISCORD_INVITE_REGEX.search(content):
        triggered = True
        reason    = "Discord招待リンク"
    elif cfg["block_urls"] and URL_REGEX.search(content):
        triggered = True
        reason    = "URL"

    if not triggered:
        return False

    author     = message.author
    action     = cfg["action"]
    mute_dur   = get_setting(guild_id, "mute_duration")
    bot_member = message.guild.me

    try:
        await message.delete()
    except (discord.Forbidden, discord.HTTPException):
        pass

    if author.id == message.guild.owner_id or (
        isinstance(author, discord.Member) and bot_member.top_role <= author.top_role
    ):
        embed = make_embed(f"⚠️ リンク検出 — スキップ ({reason})",
                           f"{author.mention} のリンクを検出しましたが、権限の問題でアクションを実行できません。",
                           color=discord.Color.yellow())
        embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
        await send_log(message.guild, embed)
        return True

    if action == "delete":
        embed = make_embed(f"🔗 リンク検出 — 削除 ({reason})",
                           f"{author.mention} のメッセージを削除しました。", color=discord.Color.orange())
        embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
    elif action == "mute":
        success = await apply_mute(author, mute_dur, reason=f"リンク送信 ({reason})")
        result  = f"✅ {mute_dur}分ミュートしました。" if success else "❌ ミュートに失敗しました。"
        color   = discord.Color.orange() if success else discord.Color.yellow()
        embed   = make_embed(f"🔗 リンク検出 — 削除 + ミュート ({reason})", f"{author.mention} {result}", color=color)
        embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)
    else:  # ban
        success = await apply_ban(author, reason=f"リンク送信 ({reason})")
        result  = "✅ BANしました。" if success else "❌ BANに失敗しました。"
        color   = discord.Color.dark_red() if success else discord.Color.yellow()
        embed   = make_embed(f"🔗 リンク検出 — 削除 + BAN ({reason})", f"{author.mention} {result}", color=color)
        embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)

    await send_log(message.guild, embed)
    log.info(f"[{message.guild.name}] Link filter ({reason}) → {action}: {author}")
    return True


# ===========================================================================
# MESSAGE EVENT  (NG words + security checks)
# ===========================================================================
@bot.event
async def on_message(message: discord.Message):
    await bot.process_commands(message)
    if message.author.bot or not message.guild:
        return

    # Mods are exempt from all automated enforcement
    if isinstance(message.author, discord.Member) and message.author.guild_permissions.manage_guild:
        return

    # Run checks in priority order; stop after first hit
    if await check_ng_words(message):
        return
    if await check_mention_spam(message):
        return
    if await check_link_filter(message):
        return
    if await check_antispam(message):
        return
    # AI check runs last (non-blocking, soft-signal only)
    await check_ai_message(message)


# ===========================================================================
# ALT DETECTION
# ===========================================================================
async def check_for_alt(member: discord.Member) -> None:
    guild_id = str(member.guild.id)
    if not alt_config.get(guild_id, {}).get("enabled", False):
        return
    banned_list      = banned_users.get(guild_id, [])
    now              = datetime.datetime.now(datetime.timezone.utc)
    account_age_days = (now - member.created_at).days
    alt_sim          = get_setting(guild_id, "alt_similarity")
    alt_max_age      = get_setting(guild_id, "alt_max_age")
    for entry in banned_list:
        if entry["user_id"] == member.id:
            continue
        similarity        = username_similarity(member.name, entry["username"])
        banned_at         = datetime.datetime.fromisoformat(entry["banned_at"])
        created_after_ban = member.created_at.replace(tzinfo=datetime.timezone.utc) > banned_at
        is_alt       = False
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
                embed = make_embed("🤖 Altアカウント自動BAN",
                                   f"{member.mention} (`{member}`) をAltアカウントとして自動BANしました。",
                                   color=discord.Color.dark_red())
                embed.add_field(name="理由", value=reason_str, inline=False)
                embed.add_field(name="アカウント作成日", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
                embed.add_field(name="元のBANユーザー", value=f"`{entry['username']}` (ID: {entry['user_id']})", inline=True)
                await send_log(member.guild, embed)
            except (discord.Forbidden, discord.HTTPException) as e:
                log.warning(f"Cannot auto-ban suspected alt {member}: {e}")
            break


# ===========================================================================
# SECURITY — Raid Detection
# ===========================================================================
async def check_raid(member: discord.Member) -> None:
    guild_id = str(member.guild.id)
    cfg = get_security(guild_id, "raid_detection")
    if not cfg["enabled"]:
        return

    now    = datetime.datetime.now(datetime.timezone.utc)
    window = datetime.timedelta(seconds=cfg["window_seconds"])

    join_tracker[guild_id].append(now)
    # Prune entries outside the window
    join_tracker[guild_id] = [t for t in join_tracker[guild_id] if now - t < window]

    count = len(join_tracker[guild_id])
    if count < cfg["threshold"]:
        return

    # Raid detected — clear tracker to prevent repeated firing
    raid_members = list(join_tracker[guild_id])
    join_tracker[guild_id] = []

    action = cfg["action"]
    log.warning(f"[{member.guild.name}] RAID DETECTED: {count} joins in {cfg['window_seconds']}s — action={action}")

    embed = make_embed(
        "🚨 レイド検出！",
        f"**{count}人** が **{cfg['window_seconds']}秒以内** に参加しました。",
        color=discord.Color.red(),
    )
    embed.add_field(name="しきい値", value=f"{cfg['threshold']}人 / {cfg['window_seconds']}秒", inline=True)
    embed.add_field(name="アクション", value=action, inline=True)

    if action == "kick":
        # Kick everyone who joined in the raid window (approximate: last `count` members)
        kicked = 0
        failed = 0
        for m in member.guild.members:
            if m.joined_at and now - m.joined_at.replace(tzinfo=datetime.timezone.utc) < window:
                if m.bot or m.id == member.guild.owner_id:
                    continue
                try:
                    await m.kick(reason="レイド検出による自動キック")
                    kicked += 1
                except (discord.Forbidden, discord.HTTPException):
                    failed += 1
        embed.add_field(name="キック結果", value=f"✅ {kicked}人キック / ❌ {failed}人失敗", inline=False)

    elif action == "lockdown":
        lock_count = await lockdown_guild(member.guild, lock=True)
        embed.add_field(name="ロックダウン", value=f"🔒 {lock_count} チャンネルをロックしました。\n解除: `!lockdown off`", inline=False)

    await send_log(member.guild, embed)


# ===========================================================================
# SECURITY — Account Age Kick
# ===========================================================================
async def check_account_age(member: discord.Member) -> bool:
    """Kick the member if their account is too new. Returns True if kicked."""
    guild_id = str(member.guild.id)
    cfg = get_security(guild_id, "account_age_kick")
    if not cfg["enabled"]:
        return False

    now              = datetime.datetime.now(datetime.timezone.utc)
    account_age_days = (now - member.created_at).days

    if account_age_days >= cfg["min_days"]:
        return False

    try:
        await member.send(
            f"申し訳ありませんが、**{member.guild.name}** サーバーへの参加には "
            f"アカウント作成から **{cfg['min_days']} 日以上** 経過している必要があります。\n"
            f"あなたのアカウントはまだ **{account_age_days} 日** です。"
        )
    except (discord.Forbidden, discord.HTTPException):
        pass

    try:
        await member.kick(reason=f"アカウントが新しすぎます ({account_age_days}日 < {cfg['min_days']}日)")
    except (discord.Forbidden, discord.HTTPException) as e:
        log.warning(f"Could not kick new account {member}: {e}")
        return False

    embed = make_embed(
        "🆕 新規アカウント自動キック",
        f"{member.mention} (`{member}`) をキックしました。",
        color=discord.Color.orange(),
    )
    embed.add_field(name="アカウント作成日", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    embed.add_field(name="アカウント日数", value=f"{account_age_days} 日", inline=True)
    embed.add_field(name="必要日数", value=f"{cfg['min_days']} 日", inline=True)
    await send_log(member.guild, embed)
    log.info(f"[{member.guild.name}] New account kicked: {member} ({account_age_days} days old)")
    return True


# ===========================================================================
# SECURITY — Anti-Hoisting
# ===========================================================================
async def check_hoisting(member: discord.Member) -> None:
    """Rename member if their display name starts with a hoisting character."""
    guild_id = str(member.guild.id)
    cfg = get_security(guild_id, "antihoisting")
    if not cfg["enabled"]:
        return

    display_name = member.display_name
    if not HOISTING_REGEX.match(display_name):
        return

    new_nick = f"[renamed] {display_name}"[:32]  # Discord nickname max is 32 chars
    try:
        await member.edit(nick=new_nick, reason="ホイスト防止: 名前が記号で始まっています")
        embed = make_embed(
            "⬆️ ホイスト防止 — ニックネーム変更",
            f"{member.mention} の名前が記号で始まっているためニックネームを変更しました。",
            color=discord.Color.blue(),
        )
        embed.add_field(name="変更前", value=f"`{display_name}`", inline=True)
        embed.add_field(name="変更後", value=f"`{new_nick}`", inline=True)
        await send_log(member.guild, embed)
        log.info(f"[{member.guild.name}] Anti-hoist rename: '{display_name}' → '{new_nick}' for {member}")
    except (discord.Forbidden, discord.HTTPException) as e:
        log.warning(f"Could not rename hoisting member {member}: {e}")


# ===========================================================================
# AUDIT LOG EVENTS
# ===========================================================================

@bot.event
async def on_message_delete(message: discord.Message):
    # ── Bot's own log message was deleted → repost it immediately ──────────
    if message.author.id == bot.user.id:
        original_embed = log_msg_cache.pop(message.id, None)
        if original_embed is not None:
            # Add a footer so everyone can see it was forcibly deleted.
            repost = original_embed.copy()
            repost.set_footer(text="⚠️ このログは削除されたため自動再投稿されました")
            try:
                sent = await message.channel.send(embed=repost)
                # Re-cache the reposted message so it too is protected.
                if len(log_msg_cache) >= LOG_MSG_CACHE_MAX:
                    oldest_id = next(iter(log_msg_cache))
                    del log_msg_cache[oldest_id]
                log_msg_cache[sent.id] = original_embed  # keep original (no stacking footers)
                log.info(f"[{message.guild.name}] Log message {message.id} was deleted — reposted.")
            except (discord.Forbidden, discord.HTTPException) as e:
                log.warning(f"Could not repost deleted log message: {e}")
        return  # don't log bot-message deletions as normal events

    if not is_log_enabled(str(message.guild.id), "messages"):
        return

    # Wait briefly so Discord's audit log has time to register the deletion.
    await asyncio.sleep(0.8)

    # Try to find who deleted the message via the audit log.
    deleter: discord.Member | discord.User | None = None
    try:
        async for entry in message.guild.audit_logs(
            limit=5, action=discord.AuditLogAction.message_delete
        ):
            age = (datetime.datetime.now(datetime.timezone.utc) - entry.created_at).total_seconds()
            if (
                age < 8
                and entry.target.id == message.author.id
                and entry.extra.channel.id == message.channel.id
            ):
                deleter = entry.user
                break
    except (discord.Forbidden, discord.HTTPException):
        pass  # bot lacks View Audit Log permission — silently skip

    # Use a darker red when someone *else* deleted the message (more notable).
    deleted_by_other = deleter is not None and deleter.id != message.author.id
    color = discord.Color.dark_red() if deleted_by_other else discord.Color.red()

    embed = make_embed("🗑️ メッセージ削除", color=color)
    embed.add_field(name="送信者",    value=f"{message.author.mention} (`{message.author}`)", inline=True)
    embed.add_field(name="チャンネル", value=message.channel.mention, inline=True)

    if deleter is not None:
        if deleted_by_other:
            embed.add_field(name="🚨 削除者（他ユーザー）", value=f"{deleter.mention} (`{deleter}`)", inline=True)
        else:
            embed.add_field(name="削除者", value=f"{deleter.mention} (`{deleter}`) — 本人", inline=True)
    else:
        embed.add_field(name="削除者", value="不明（本人削除または権限不足）", inline=True)

    if message.content:
        embed.add_field(name="内容", value=message.content[:1024], inline=False)
    if message.attachments:
        embed.add_field(name="添付ファイル", value="\n".join(a.filename for a in message.attachments), inline=False)
    await send_log(message.guild, embed)


@bot.event
async def on_bulk_message_delete(messages: list[discord.Message]):
    if not messages:
        return
    if not is_log_enabled(str(messages[0].guild.id), "messages"):
        return

    # Wait briefly so Discord's audit log has time to register the bulk delete.
    await asyncio.sleep(0.8)

    # Try to find who triggered the bulk delete via the audit log.
    deleter: discord.Member | discord.User | None = None
    try:
        async for entry in messages[0].guild.audit_logs(
            limit=5, action=discord.AuditLogAction.message_bulk_delete
        ):
            age = (datetime.datetime.now(datetime.timezone.utc) - entry.created_at).total_seconds()
            if age < 8:
                deleter = entry.user
                break
    except (discord.Forbidden, discord.HTTPException):
        pass

    embed = make_embed(
        "🗑️ 一括メッセージ削除",
        f"{messages[0].channel.mention} で {len(messages)} 件のメッセージが削除されました",
        color=discord.Color.dark_red(),
    )
    if deleter is not None:
        embed.add_field(name="🚨 削除者", value=f"{deleter.mention} (`{deleter}`)", inline=True)
    else:
        embed.add_field(name="削除者", value="不明（権限不足の可能性）", inline=True)
    await send_log(messages[0].guild, embed)


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if before.author.bot or before.content == after.content:
        return
    if not is_log_enabled(str(before.guild.id), "messages"):
        return
    embed = make_embed("✏️ メッセージ編集", color=discord.Color.orange())
    embed.add_field(name="送信者",    value=f"{before.author.mention} (`{before.author}`)", inline=True)
    embed.add_field(name="チャンネル", value=before.channel.mention, inline=True)
    embed.add_field(name="変更前",    value=(before.content or "*空*")[:1024], inline=False)
    embed.add_field(name="変更後",    value=(after.content  or "*空*")[:1024], inline=False)
    embed.add_field(name="ジャンプ",  value=f"[メッセージへジャンプ]({after.jump_url})", inline=False)
    await send_log(before.guild, embed)


@bot.event
async def on_member_join(member: discord.Member):
    if is_log_enabled(str(member.guild.id), "members"):
        embed = make_embed("📥 メンバー参加", f"{member.mention} (`{member}`)", color=discord.Color.green())
        embed.add_field(name="アカウント作成日", value=discord.utils.format_dt(member.created_at, "R"))
        embed.add_field(name="メンバー数",       value=str(member.guild.member_count))
        await send_log(member.guild, embed)

    # Security checks (run concurrently where order doesn't matter)
    await asyncio.gather(
        check_for_alt(member),
        check_raid(member),
        check_account_age(member),
        check_hoisting(member),
        check_ai_join(member),
    )


@bot.event
async def on_member_remove(member: discord.Member):
    if not is_log_enabled(str(member.guild.id), "members"):
        return
    embed = make_embed("📤 メンバー退出", f"{member.mention} (`{member}`)", color=discord.Color.dark_gray())
    embed.add_field(name="参加日", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "不明")
    roles = [r.mention for r in member.roles if r.name != "@everyone"]
    if roles:
        embed.add_field(name="ロール", value=" ".join(roles)[:1024], inline=False)
    await send_log(member.guild, embed)


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    if is_log_enabled(str(after.guild.id), "members"):
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
        if changes:
            embed = make_embed("👤 メンバー更新", f"{after.mention} (`{after}`)\n" + "\n".join(changes), color=discord.Color.blue())
            await send_log(after.guild, embed)

    # Re-check hoisting whenever a member's nick changes
    if before.nick != after.nick:
        await check_hoisting(after)


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
        member = guild.get_member(after.id)
        if member:
            if is_log_enabled(str(guild.id), "members"):
                embed = make_embed("🪦 ユーザープロフィール更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.blue())
                await send_log(guild, embed)
            # Check if new username is hoisting
            await check_hoisting(member)


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    guild_id = str(guild.id)
    banned_users.setdefault(guild_id, [])
    if not any(e["user_id"] == user.id for e in banned_users[guild_id]):
        banned_users[guild_id].append({
            "user_id":           user.id,
            "username":          user.name,
            "banned_at":         datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "account_created_at": user.created_at.isoformat(),
        })
        save_json(BANNED_USERS_PATH, banned_users)
    if not is_log_enabled(guild_id, "members"):
        return
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
    if not is_log_enabled(guild_id, "members"):
        return
    embed = make_embed("♻️ メンバーBAN解除", f"`{user}` (`{user.id}`)", color=discord.Color.green())
    await send_log(guild, embed)


@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    if not is_log_enabled(str(channel.guild.id), "channels"):
        return
    embed = make_embed("📁 チャンネル作成", f"{channel.mention} (`{channel.name}`)\nタイプ: {channel.type}", color=discord.Color.green())
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    if not is_log_enabled(str(channel.guild.id), "channels"):
        return
    embed = make_embed("🗑️ チャンネル削除", f"`#{channel.name}` (タイプ: {channel.type})", color=discord.Color.red())
    await send_log(channel.guild, embed)


@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    if not is_log_enabled(str(after.guild.id), "channels"):
        return
    changes = []
    if before.name != after.name: changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if hasattr(before, "topic") and before.topic != after.topic: changes.append(f"**トピック:** `{before.topic}` → `{after.topic}`")
    if before.position != after.position: changes.append(f"**位置:** {before.position} → {after.position}")
    if hasattr(before, "nsfw") and before.nsfw != after.nsfw: changes.append(f"**NSFW:** {before.nsfw} → {after.nsfw}")
    if not changes: return
    embed = make_embed("🔧 チャンネル更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.orange())
    await send_log(after.guild, embed)


@bot.event
async def on_guild_role_create(role: discord.Role):
    if not is_log_enabled(str(role.guild.id), "roles"): return
    embed = make_embed("✨ ロール作成", f"{role.mention} (`{role.name}`)", color=discord.Color.green())
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_delete(role: discord.Role):
    if not is_log_enabled(str(role.guild.id), "roles"): return
    embed = make_embed("🗑️ ロール削除", f"`{role.name}`", color=discord.Color.red())
    await send_log(role.guild, embed)


@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    if not is_log_enabled(str(after.guild.id), "roles"): return
    changes = []
    if before.name != after.name: changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.color != after.color: changes.append(f"**カラー:** {before.color} → {after.color}")
    if before.permissions != after.permissions: changes.append("**権限が変更されました。**")
    if before.hoist != after.hoist: changes.append(f"**ホイスト:** {before.hoist} → {after.hoist}")
    if before.mentionable != after.mentionable: changes.append(f"**メンション可能:** {before.mentionable} → {after.mentionable}")
    if not changes: return
    embed = make_embed("🔧 ロール更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.orange())
    await send_log(after.guild, embed)


@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    if not is_log_enabled(str(member.guild.id), "voice"): return
    if before.channel == after.channel:
        changes = []
        if before.self_mute  != after.self_mute:   changes.append(f"自己ミュート: {before.self_mute} → {after.self_mute}")
        if before.self_deaf  != after.self_deaf:   changes.append(f"自己スピーカーミュート: {before.self_deaf} → {after.self_deaf}")
        if before.self_stream != after.self_stream: changes.append(f"配信: {before.self_stream} → {after.self_stream}")
        if before.self_video  != after.self_video:  changes.append(f"カメラ: {before.self_video} → {after.self_video}")
        if not changes: return
        embed = make_embed("🎤 ボイス状態変更", f"{member.mention} ({after.channel.mention} 内)\n" + "\n".join(changes), color=discord.Color.blue())
    elif before.channel is None:
        embed = make_embed("🔊 ボイス参加",  f"{member.mention} が {after.channel.mention} に参加しました", color=discord.Color.green())
    elif after.channel is None:
        embed = make_embed("🔇 ボイス退出",  f"{member.mention} が {before.channel.mention} を退出しました", color=discord.Color.dark_gray())
    else:
        embed = make_embed("🔁 ボイスチャンネル移動", f"{member.mention}: {before.channel.mention} → {after.channel.mention}", color=discord.Color.blue())
    await send_log(member.guild, embed)


@bot.event
async def on_reaction_add(reaction: discord.Reaction, user: discord.User):
    if user.bot: return
    if not is_log_enabled(str(reaction.message.guild.id), "reactions"): return
    embed = make_embed("➕ リアクション追加",
                       f"{user.mention} が {reaction.message.channel.mention} のメッセージに {reaction.emoji} を追加しました\n[ジャンプ]({reaction.message.jump_url})",
                       color=discord.Color.gold())
    await send_log(reaction.message.guild, embed)


@bot.event
async def on_reaction_remove(reaction: discord.Reaction, user: discord.User):
    if user.bot: return
    if not is_log_enabled(str(reaction.message.guild.id), "reactions"): return
    embed = make_embed("➖ リアクション削除",
                       f"{user.mention} が {reaction.message.channel.mention} のメッセージから {reaction.emoji} を削除しました\n[ジャンプ]({reaction.message.jump_url})",
                       color=discord.Color.dark_gold())
    await send_log(reaction.message.guild, embed)


@bot.event
async def on_thread_create(thread: discord.Thread):
    if not is_log_enabled(str(thread.guild.id), "threads"): return
    embed = make_embed("🧵 スレッド作成", f"{thread.mention}（{thread.parent.mention if thread.parent else '不明'} 内）", color=discord.Color.green())
    if thread.owner: embed.add_field(name="作成者", value=thread.owner.mention)
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_delete(thread: discord.Thread):
    if not is_log_enabled(str(thread.guild.id), "threads"): return
    embed = make_embed("🗑️ スレッド削除", f"`{thread.name}`（{thread.parent.mention if thread.parent else '不明'} 内）", color=discord.Color.red())
    await send_log(thread.guild, embed)


@bot.event
async def on_thread_update(before: discord.Thread, after: discord.Thread):
    if not is_log_enabled(str(after.guild.id), "threads"): return
    changes = []
    if before.name     != after.name:     changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.archived != after.archived: changes.append(f"**アーカイブ:** {before.archived} → {after.archived}")
    if before.locked   != after.locked:   changes.append(f"**ロック:** {before.locked} → {after.locked}")
    if not changes: return
    embed = make_embed("🔧 スレッド更新", f"{after.mention}\n" + "\n".join(changes), color=discord.Color.orange())
    await send_log(after.guild, embed)


@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    if not is_log_enabled(str(after.id), "server"): return
    changes = []
    if before.name             != after.name:             changes.append(f"**名前:** `{before.name}` → `{after.name}`")
    if before.icon             != after.icon:             changes.append("**サーバーアイコンが変更されました。**")
    if before.owner_id         != after.owner_id:         changes.append(f"**オーナー:** <@{before.owner_id}> → <@{after.owner_id}>")
    if before.verification_level != after.verification_level: changes.append(f"**認証レベル:** {before.verification_level} → {after.verification_level}")
    if not changes: return
    embed = make_embed("🏛️ サーバー更新", "\n".join(changes), color=discord.Color.purple())
    await send_log(after, embed)


@bot.event
async def on_guild_emojis_update(guild: discord.Guild, before: tuple, after: tuple):
    if not is_log_enabled(str(guild.id), "server"): return
    added   = set(after) - set(before)
    removed = set(before) - set(after)
    desc = []
    if added:   desc.append("**追加:** " + " ".join(str(e) for e in added))
    if removed: desc.append("**削除:** " + " ".join(f"`:{e.name}:`" for e in removed))
    embed = make_embed("😀 絵文字更新", "\n".join(desc), color=discord.Color.gold())
    await send_log(guild, embed)


@bot.event
async def on_invite_create(invite: discord.Invite):
    if not is_log_enabled(str(invite.guild.id), "invites"): return
    embed = make_embed("🔗 招待作成", f"`{invite.code}`（{invite.channel.mention} 向け）", color=discord.Color.green())
    if invite.inviter: embed.add_field(name="作成者", value=invite.inviter.mention)
    embed.add_field(name="最大使用回数", value=str(invite.max_uses or "∞"))
    embed.add_field(name="有効期限", value=discord.utils.format_dt(invite.expires_at) if invite.expires_at else "なし")
    await send_log(invite.guild, embed)


@bot.event
async def on_invite_delete(invite: discord.Invite):
    if not is_log_enabled(str(invite.guild.id), "invites"): return
    embed = make_embed("🔗 招待削除", f"`{invite.code}`（{invite.channel.mention if invite.channel else '不明'} 向け）", color=discord.Color.red())
    await send_log(invite.guild, embed)


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
