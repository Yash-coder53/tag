#!/usr/bin/env python3
"""
Permanent Tag Bot — Clean SCAM/FAKE Tags
Single session file — never creates new sessions
"""

import os
import asyncio
import logging
import sqlite3
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
from telethon import TelegramClient, events, Button
from telethon.errors import FloodWaitError, UsernameNotOccupiedError, UserIdInvalidError

# Load environment variables
load_dotenv()

# --- Configuration ---
API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")
SESSION_NAME = os.getenv("SESSION_NAME", "perma_tag_session")
ADMIN_IDS = [int(x.strip()) for x in os.getenv("ADMIN_USER_IDS", "").split(",") if x.strip()]
DATABASE_FILE = os.getenv("DATABASE_FILE", "tags.db")

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Database Setup ---
def init_db():
    """Initialize the database with all tables"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    
    # Permanent Tags Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS permanent_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_user_id INTEGER NOT NULL,
            target_username TEXT,
            target_first_name TEXT,
            target_last_name TEXT,
            tag_type TEXT NOT NULL,
            issued_by INTEGER NOT NULL,
            issued_by_username TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT,
            active INTEGER DEFAULT 1,
            source TEXT DEFAULT 'admin'
        )
    ''')
    
    # Reports Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_user_id INTEGER NOT NULL,
            target_username TEXT,
            target_first_name TEXT,
            reported_by INTEGER NOT NULL,
            reported_by_username TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            tag_id INTEGER
        )
    ''')
    
    # Warning Logs Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS warning_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_user_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            message_id INTEGER
        )
    ''')
    
    # Session Persistence Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS session_state (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Indexes
    c.execute('CREATE INDEX IF NOT EXISTS idx_tags_user_id ON permanent_tags(target_user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_tags_active ON permanent_tags(active)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(target_user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_warnings_user_chat ON warning_logs(target_user_id, chat_id)')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# --- Database Functions ---
def get_tag(user_id):
    """Get active tag for a user"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT * FROM permanent_tags WHERE target_user_id = ? AND active = 1",
        (user_id,)
    )
    tag = c.fetchone()
    conn.close()
    
    if tag:
        return {
            'id': tag[0],
            'target_user_id': tag[1],
            'target_username': tag[2],
            'target_first_name': tag[3],
            'target_last_name': tag[4],
            'tag_type': tag[5],
            'issued_by': tag[6],
            'issued_by_username': tag[7],
            'timestamp': tag[8],
            'reason': tag[9],
            'active': tag[10],
            'source': tag[11]
        }
    return None

def get_all_tags(active_only=True):
    """Get all tags"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    if active_only:
        c.execute("SELECT * FROM permanent_tags WHERE active = 1 ORDER BY timestamp DESC")
    else:
        c.execute("SELECT * FROM permanent_tags ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    
    tags = []
    for row in rows:
        tags.append({
            'id': row[0],
            'target_user_id': row[1],
            'target_username': row[2],
            'target_first_name': row[3],
            'target_last_name': row[4],
            'tag_type': row[5],
            'issued_by': row[6],
            'issued_by_username': row[7],
            'timestamp': row[8],
            'reason': row[9],
            'active': row[10],
            'source': row[11]
        })
    return tags

def create_tag(user_id, username, first_name, last_name, tag_type, issued_by, issued_by_username, reason=None, source='admin', report_id=None):
    """Create a new permanent tag"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    
    # Check if already tagged
    c.execute("SELECT id FROM permanent_tags WHERE target_user_id = ? AND active = 1", (user_id,))
    if c.fetchone():
        conn.close()
        return None, "User already has an active tag"
    
    # Insert tag
    c.execute('''
        INSERT INTO permanent_tags (
            target_user_id, target_username, target_first_name, target_last_name,
            tag_type, issued_by, issued_by_username, reason, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, username, first_name, last_name, tag_type.upper(),
          issued_by, issued_by_username, reason, source))
    
    tag_id = c.lastrowid
    
    # If from report, update report status
    if report_id:
        c.execute("UPDATE reports SET status = 'approved', tag_id = ? WHERE id = ?", (tag_id, report_id))
    
    conn.commit()
    conn.close()
    
    return get_tag(user_id), None

def deactivate_tag(user_id):
    """Deactivate a tag"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("UPDATE permanent_tags SET active = 0 WHERE target_user_id = ? AND active = 1", (user_id,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def submit_report(target_user_id, target_username, target_first_name, reported_by, reported_by_username, reason):
    """Submit a report"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    
    # Check for pending report
    c.execute(
        "SELECT id FROM reports WHERE target_user_id = ? AND status = 'pending'",
        (target_user_id,)
    )
    if c.fetchone():
        conn.close()
        return None, "A report for this user is already pending"
    
    c.execute('''
        INSERT INTO reports (
            target_user_id, target_username, target_first_name,
            reported_by, reported_by_username, reason
        ) VALUES (?, ?, ?, ?, ?, ?)
    ''', (target_user_id, target_username, target_first_name, reported_by, reported_by_username, reason))
    
    report_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return {'id': report_id}, None

def get_pending_reports():
    """Get all pending reports"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM reports WHERE status = 'pending' ORDER BY timestamp ASC")
    rows = c.fetchall()
    conn.close()
    
    reports = []
    for row in rows:
        reports.append({
            'id': row[0],
            'target_user_id': row[1],
            'target_username': row[2],
            'target_first_name': row[3],
            'reported_by': row[4],
            'reported_by_username': row[5],
            'timestamp': row[6],
            'reason': row[7],
            'status': row[8],
            'tag_id': row[9]
        })
    return reports

def get_report_by_id(report_id):
    """Get a specific report"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row[0],
            'target_user_id': row[1],
            'target_username': row[2],
            'target_first_name': row[3],
            'reported_by': row[4],
            'reported_by_username': row[5],
            'timestamp': row[6],
            'reason': row[7],
            'status': row[8],
            'tag_id': row[9]
        }
    return None

def reject_report(report_id):
    """Reject a report"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("UPDATE reports SET status = 'rejected' WHERE id = ?", (report_id,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def log_warning(user_id, chat_id, message_id):
    """Log a warning"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO warning_logs (target_user_id, chat_id, message_id) VALUES (?, ?, ?)",
        (user_id, chat_id, message_id)
    )
    conn.commit()
    conn.close()

def recent_warning(user_id, chat_id, minutes=5):
    """Check if a warning was sent recently"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    cutoff = datetime.now() - timedelta(minutes=minutes)
    c.execute(
        "SELECT COUNT(*) FROM warning_logs WHERE target_user_id = ? AND chat_id = ? AND timestamp >= ?",
        (user_id, chat_id, cutoff.isoformat())
    )
    count = c.fetchone()[0]
    conn.close()
    return count > 0

def get_session_state(key):
    """Get session state from database"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT value FROM session_state WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def set_session_state(key, value):
    """Set session state in database"""
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO session_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (key, value)
    )
    conn.commit()
    conn.close()

# --- Helper Functions ---
def is_admin(user_id):
    """Check if user is admin"""
    return user_id in ADMIN_IDS

async def resolve_user(client, identifier):
    """Resolve username or ID to user entity"""
    try:
        if isinstance(identifier, int) or str(identifier).lstrip('+-').isdigit():
            user_id = int(identifier)
            return await client.get_entity(user_id)
        else:
            clean = str(identifier).replace('@', '')
            return await client.get_entity(f"@{clean}")
    except (UsernameNotOccupiedError, UserIdInvalidError, ValueError):
        return None

def format_box(content, title=None):
    """Format content in a clean box style"""
    lines = content.split('\n')
    max_len = max(len(line) for line in lines if line) if lines else 40
    max_len = min(max_len, 60)
    
    top = "╔" + "═" * (max_len + 4) + "╗"
    bottom = "╚" + "═" * (max_len + 4) + "╝"
    
    result = [top]
    if title:
        title_line = f"║  {title}" + " " * (max_len + 2 - len(title)) + "║"
        result.append(title_line)
        result.append("║" + " " * (max_len + 4) + "║")
    
    for line in lines:
        if line:
            padding = max_len + 2 - len(line)
            result.append(f"║  {line}" + " " * padding + "║")
        else:
            result.append("║" + " " * (max_len + 4) + "║")
    
    result.append(bottom)
    return '\n'.join(result)

def get_tag_display(tag_type):
    """Get display for a tag type - clean version, no BAGAD BILLA"""
    if tag_type.upper() == 'FAKE':
        return "⚠️ FAKE ⚠️"
    elif tag_type.upper() == 'SCAM':
        return "🚨 SCAM 🚨"
    else:
        return f"⚠️ {tag_type.upper()} ⚠️"

# --- Bot Instance (SINGLE SESSION) ---
client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

# --- Command Handlers ---

@client.on(events.NewMessage(pattern=r'^/start\b'))
async def start_command(event):
    await event.reply(format_box(
        "🤖 PERMANENT TAG BOT\n\n"
        "SCAM / FAKE Tagging System\n"
        "═══════════════════════════\n\n"
        "USER COMMANDS:\n"
        "/report @username reason\n"
        "  - Report a suspicious user\n\n"
        "ADMIN COMMANDS:\n"
        "/tag @username - Tag a user\n"
        "/untag @username - Remove tag\n"
        "/list - List all tags\n"
        "/reports - View pending reports\n"
        "/approve <id> - Approve a report\n"
        "/reject <id> - Reject a report\n\n"
        "Tags are PERMANENT and survive\n"
        "bot downtime.",
        "📋 PERMANENT TAG BOT"
    ))

@client.on(events.NewMessage(pattern=r'^/tag\b'))
async def tag_command(event):
    sender = await event.get_sender()
    if not is_admin(sender.id):
        await event.reply("❌ Not authorized.")
        return
    
    parts = event.text.split()
    if len(parts) < 2:
        await event.reply("Usage: /tag @username")
        return
    
    user = await resolve_user(client, parts[1])
    if not user:
        await event.reply("❌ User not found.")
        return
    
    existing = get_tag(user.id)
    if existing:
        display = get_tag_display(existing['tag_type'])
        await event.reply(format_box(
            f"⚠️ USER ALREADY TAGGED\n\n"
            f"{display}\n\n"
            f"Reason: {existing['reason'] or 'N/A'}\n"
            f"Since: {existing['timestamp']}",
            "⚠️ ALREADY TAGGED"
        ))
        return
    
    buttons = [
        [Button.inline("⚠️ FAKE", data=f"tag_fake_{user.id}")],
        [Button.inline("🚨 SCAM", data=f"tag_scam_{user.id}")]
    ]
    
    await event.reply(
        f"Select tag type for:\n"
        f"{user.first_name} (@{user.username or 'no_username'})\n"
        f"ID: `{user.id}`",
        buttons=buttons
    )

@client.on(events.NewMessage(pattern=r'^/untag\b'))
async def untag_command(event):
    sender = await event.get_sender()
    if not is_admin(sender.id):
        await event.reply("❌ Not authorized.")
        return
    
    parts = event.text.split()
    if len(parts) < 2:
        await event.reply("Usage: /untag @username")
        return
    
    user = await resolve_user(client, parts[1])
    if not user:
        await event.reply("❌ User not found.")
        return
    
    if deactivate_tag(user.id):
        await event.reply(f"✅ Tag removed from {user.first_name}")
    else:
        await event.reply("❌ No active tag found for this user.")

@client.on(events.NewMessage(pattern=r'^/list\b'))
async def list_command(event):
    sender = await event.get_sender()
    if not is_admin(sender.id):
        await event.reply("❌ Not authorized.")
        return
    
    tags = get_all_tags(active_only=True)
    if not tags:
        await event.reply("📭 No active tags.")
        return
    
    message = "📋 ACTIVE TAGS:\n\n"
    for tag in tags:
        name = tag['target_first_name'] or "Unknown"
        username = f"@{tag['target_username']}" if tag['target_username'] else "no_username"
        display = get_tag_display(tag['tag_type'])
        message += (
            f"{display}\n"
            f"  {name} {username}\n"
            f"  ID: {tag['target_user_id']}\n"
            f"  Since: {tag['timestamp'][:10]}\n"
            f"  Reason: {tag['reason'] or 'N/A'}\n\n"
        )
    
    await event.reply(message[:4000])

@client.on(events.NewMessage(pattern=r'^/report\b'))
async def report_command(event):
    sender = await event.get_sender()
    
    parts = event.text.split()
    if len(parts) < 3:
        await event.reply(format_box(
            "📝 REPORT A USER\n\n"
            "Usage:\n"
            "/report @username reason\n\n"
            "Example:\n"
            "/report @suspect Tried to scam me",
            "📝 REPORT"
        ))
        return
    
    identifier = parts[1]
    reason = ' '.join(parts[2:])
    
    user = await resolve_user(client, identifier)
    if not user:
        await event.reply("❌ User not found.")
        return
    
    existing = get_tag(user.id)
    if existing:
        display = get_tag_display(existing['tag_type'])
        await event.reply(format_box(
            f"⚠️ USER ALREADY TAGGED\n\n"
            f"{display}\n\n"
            f"Reason: {existing['reason'] or 'N/A'}",
            "⚠️ ALREADY TAGGED"
        ))
        return
    
    report, error = submit_report(
        user.id, user.username, user.first_name,
        sender.id, sender.username, reason
    )
    
    if report:
        await event.reply(format_box(
            f"✅ REPORT SUBMITTED\n\n"
            f"Target: {user.first_name}\n"
            f"@{user.username or 'no_username'}\n"
            f"ID: {user.id}\n"
            f"Report ID: {report['id']}\n\n"
            f"Reason: {reason}\n\n"
            f"📋 Admin review pending.\n"
            f"You'll be notified if approved.",
            "✅ REPORT SUBMITTED"
        ))
        
        for admin_id in ADMIN_IDS:
            try:
                await client.send_message(
                    admin_id,
                    format_box(
                        f"📋 NEW REPORT\n\n"
                        f"Reporter: {sender.first_name}\n"
                        f"@{sender.username or 'no_username'}\n\n"
                        f"Target: {user.first_name}\n"
                        f"@{user.username or 'no_username'}\n"
                        f"ID: {user.id}\n\n"
                        f"Reason: {reason}\n\n"
                        f"/approve {report['id']} or /reject {report['id']}",
                        "📋 NEW REPORT"
                    )
                )
            except:
                pass
    else:
        await event.reply(f"❌ {error}")

@client.on(events.NewMessage(pattern=r'^/approve\b'))
async def approve_command(event):
    sender = await event.get_sender()
    if not is_admin(sender.id):
        await event.reply("❌ Not authorized.")
        return
    
    parts = event.text.split()
    if len(parts) < 2:
        await event.reply("Usage: /approve <report_id>")
        return
    
    report = get_report_by_id(int(parts[1]))
    if not report:
        await event.reply("❌ Report not found.")
        return
    
    if report['status'] != 'pending':
        await event.reply(f"❌ Report already {report['status']}.")
        return
    
    try:
        user = await client.get_entity(report['target_user_id'])
    except:
        await event.reply("❌ User no longer exists.")
        return
    
    buttons = [
        [Button.inline("⚠️ FAKE", data=f"approve_fake_{report['id']}")],
        [Button.inline("🚨 SCAM", data=f"approve_scam_{report['id']}")]
    ]
    
    await event.reply(
        f"Select tag type for:\n"
        f"{user.first_name} (@{user.username or 'no_username'})\n"
        f"Reported by: {report['reported_by_username'] or 'Unknown'}\n"
        f"Reason: {report['reason']}",
        buttons=buttons
    )

@client.on(events.NewMessage(pattern=r'^/reject\b'))
async def reject_command(event):
    sender = await event.get_sender()
    if not is_admin(sender.id):
        await event.reply("❌ Not authorized.")
        return
    
    parts = event.text.split()
    if len(parts) < 2:
        await event.reply("Usage: /reject <report_id>")
        return
    
    if reject_report(int(parts[1])):
        await event.reply(f"✅ Report #{parts[1]} rejected.")
    else:
        await event.reply("❌ Report not found.")

@client.on(events.NewMessage(pattern=r'^/reports\b'))
async def reports_command(event):
    sender = await event.get_sender()
    if not is_admin(sender.id):
        await event.reply("❌ Not authorized.")
        return
    
    reports = get_pending_reports()
    if not reports:
        await event.reply("📭 No pending reports.")
        return
    
    message = "📋 PENDING REPORTS:\n\n"
    for r in reports:
        name = r['target_first_name'] or "Unknown"
        username = f"@{r['target_username']}" if r['target_username'] else "no_username"
        message += (
            f"ID: {r['id']}\n"
            f"Target: {name} {username}\n"
            f"Reporter: {r['reported_by_username'] or 'Unknown'}\n"
            f"Reason: {r['reason']}\n"
            f"Time: {r['timestamp']}\n"
            f"/approve {r['id']} or /reject {r['id']}\n\n"
        )
    
    await event.reply(message[:4000])

@client.on(events.CallbackQuery)
async def callback_handler(event):
    data = event.data.decode('utf-8')
    sender = await event.get_sender()
    
    # Handle approve callback
    if data.startswith("approve_fake_") or data.startswith("approve_scam_"):
        if not is_admin(sender.id):
            await event.answer("❌ Not authorized.", alert=True)
            return
        
        parts = data.split('_')
        tag_type = parts[1].upper()
        report_id = int(parts[2])
        
        report = get_report_by_id(report_id)
        if not report:
            await event.answer("Report not found.", alert=True)
            return
        
        if report['status'] != 'pending':
            await event.answer(f"Report already {report['status']}.", alert=True)
            return
        
        try:
            user = await client.get_entity(report['target_user_id'])
        except:
            await event.answer("User no longer exists.", alert=True)
            return
        
        tag, error = create_tag(
            user.id, user.username, user.first_name,
            getattr(user, 'last_name', None),
            tag_type,
            sender.id, sender.username,
            report['reason'],
            'report',
            report_id
        )
        
        if tag:
            display = get_tag_display(tag_type)
            
            # Notify reporter
            try:
                await client.send_message(
                    report['reported_by'],
                    format_box(
                        f"✅ REPORT APPROVED\n\n"
                        f"{display}\n\n"
                        f"User: {user.first_name}\n"
                        f"@{user.username or 'no_username'}\n\n"
                        f"Reason: {report['reason']}\n\n"
                        f"⚠️ This tag is now PERMANENT.",
                        "✅ REPORT APPROVED"
                    )
                )
            except:
                pass
            
            # Notify tagged user
            try:
                await client.send_message(
                    user.id,
                    format_box(
                        f"⚠️ PERMANENT TAG APPLIED\n\n"
                        f"{display}\n\n"
                        f"Reason: {report['reason']}\n\n"
                        f"This tag was added based on a\n"
                        f"community report.\n\n"
                        f"Contact an admin if this is\n"
                        f"a mistake.",
                        "⚠️ PERMANENT TAG"
                    )
                )
            except:
                pass
            
            await event.edit(format_box(
                f"✅ TAG CREATED\n\n"
                f"{display}\n\n"
                f"User: {user.first_name}\n"
                f"@{user.username or 'no_username'}\n"
                f"ID: {user.id}\n\n"
                f"Reason: {report['reason']}\n"
                f"Report ID: {report_id}\n\n"
                f"⏰ This tag is now PERMANENT.",
                "✅ TAG CREATED"
            ))
        else:
            await event.edit(f"❌ {error}")
        return
    
    # Handle tag callback
    if data.startswith("tag_fake_") or data.startswith("tag_scam_"):
        if not is_admin(sender.id):
            await event.answer("❌ Not authorized.", alert=True)
            return
        
        parts = data.split('_')
        tag_type = parts[1].upper()
        user_id = int(parts[2])
        
        try:
            user = await client.get_entity(user_id)
        except:
            await event.answer("User not found.", alert=True)
            return
        
        await event.edit(
            f"📝 Tagging {user.first_name} as {tag_type}\n"
            f"Send a reason (or type 'skip'):"
        )
        
        try:
            response = await client.wait_for(
                events.NewMessage(from_users=sender.id, pattern=r'.+'),
                timeout=60.0
            )
        except asyncio.TimeoutError:
            await event.reply("⏰ Timed out.")
            return
        
        reason = response.message.text
        if reason.lower() == 'skip':
            reason = None
        
        tag, error = create_tag(
            user.id, user.username, user.first_name,
            getattr(user, 'last_name', None),
            tag_type,
            sender.id, sender.username,
            reason,
            'admin'
        )
        
        if tag:
            display = get_tag_display(tag_type)
            
            try:
                await client.send_message(
                    user.id,
                    format_box(
                        f"⚠️ PERMANENT TAG APPLIED\n\n"
                        f"{display}\n\n"
                        f"Reason: {reason or 'No reason'}\n\n"
                        f"Contact an admin if this is\n"
                        f"a mistake.",
                        "⚠️ PERMANENT TAG"
                    )
                )
            except:
                pass
            
            await response.reply(format_box(
                f"✅ PERMANENT TAG CREATED\n\n"
                f"{display}\n\n"
                f"User: {user.first_name}\n"
                f"@{user.username or 'no_username'}\n"
                f"ID: {user.id}\n\n"
                f"Reason: {reason or 'Not provided'}\n\n"
                f"⏰ This tag is now PERMANENT.",
                "✅ TAG CREATED"
            ))
        else:
            await response.reply(f"❌ {error}")

@client.on(events.NewMessage)
async def auto_warn_handler(event):
    """Auto-warn when a tagged user sends a message"""
    if event.out:
        return
    
    sender = await event.get_sender()
    if not sender:
        return
    
    if is_admin(sender.id) or sender.bot:
        return
    
    tag = get_tag(sender.id)
    if not tag:
        return
    
    if recent_warning(sender.id, event.chat_id, minutes=5):
        return
    
    display = get_tag_display(tag['tag_type'])
    source_text = "📩 Community Report" if tag['source'] == 'report' else "🔧 Admin Action"
    
    warning = format_box(
        f"{display}\n\n"
        f"User: {sender.first_name}\n"
        f"@{sender.username or 'no_username'}\n"
        f"Source: {source_text}\n"
        f"📅 Since: {tag['timestamp'][:10]}\n"
        f"📝 Reason: {tag['reason'] or 'Not provided'}\n\n"
        f"⚠️ EXERCISE EXTREME CAUTION\n"
        f"⚠️ WITH THIS USER",
        "⚠️ PERMANENT TAG WARNING"
    )
    
    try:
        msg = await event.reply(warning)
        log_warning(sender.id, event.chat_id, msg.id)
    except:
        pass

async def main():
    """Main entry point"""
    try:
        # Initialize database
        init_db()
        
        # Check if session file exists
        session_file = f"{SESSION_NAME}.session"
        if os.path.exists(session_file):
            logger.info(f"Using existing session: {session_file}")
        else:
            logger.info(f"Creating new session: {session_file} (this is the ONLY session)")
        
        logger.info("Starting Permanent Tag Bot...")
        await client.start(bot_token=BOT_TOKEN)
        
        me = await client.get_me()
        logger.info(f"✅ Bot started as @{me.username}")
        logger.info(f"📁 Session file: {session_file}")
        logger.info(f"📊 Database: {DATABASE_FILE}")
        logger.info(f"👤 Admins: {ADMIN_IDS}")
        
        # Show active tags count
        tags = get_all_tags(active_only=True)
        logger.info(f"📋 Active tags: {len(tags)}")
        
        await client.run_until_disconnected()
    except FloodWaitError as e:
        logger.error(f"Rate limited: waiting {e.seconds}s")
        await asyncio.sleep(e.seconds)
        await main()
    except Exception as e:
        logger.error(f"Error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
