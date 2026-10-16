import os
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Set JWT_SECRET_KEY in your terminal before starting the app.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        'Set JWT_SECRET_KEY first. PowerShell: '
        '$env:JWT_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"'
    )

DATABASE = "chat.db"
TOKEN_MINUTES = 60 * 12
hasher = PasswordHasher()
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Sabz Chat")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
bearer = HTTPBearer(auto_error=False)


def db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS private_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)


init_db()


class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=24, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginData(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=1, max_length=128)


class MessageData(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials is None:
        raise HTTPException(401, "اول وارد حساب شو")
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat"]},
        )
        uid = int(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "توکن نامعتبر یا منقضی شده است")
    with db() as conn:
        user = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (uid,)
        ).fetchone()
    if user is None:
        raise HTTPException(401, "حساب پیدا نشد")
    return {"id": user["id"], "username": user["username"]}


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


@app.post("/api/register", status_code=201)
@limiter.limit("5/minute")
def register(request: Request, data: RegisterData):
    username = data.username.strip()
    password_hash = hasher.hash(data.password)
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این نام کاربری قبلاً گرفته شده است")
    return {"id": uid, "username": username, "message": "حساب ساخته شد؛ حالا وارد شو"}


@app.post("/api/login")
@limiter.limit("5/minute")
def login(request: Request, data: LoginData):
    with db() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (data.username.strip(),),
        ).fetchone()
    if user is None:
        raise HTTPException(401, "نام کاربری یا رمز اشتباه است")
    try:
        hasher.verify(user["password_hash"], data.password)
    except (VerifyMismatchError, VerificationError):
        raise HTTPException(401, "نام کاربری یا رمز اشتباه است")
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(user["id"]), "iat": now, "exp": now + timedelta(minutes=TOKEN_MINUTES)},
        SECRET_KEY,
        algorithm="HS256",
    )
    return {"access_token": token, "token_type": "bearer", "username": user["username"]}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


@app.get("/api/messages")
def list_messages(after: int = 0, user=Depends(current_user)):
    with db() as conn:
        rows = conn.execute("""
            SELECT messages.id, messages.body, messages.created_at, users.username
            FROM messages JOIN users ON users.id = messages.user_id
            WHERE messages.id > ?
            ORDER BY messages.id ASC LIMIT 100
        """, (max(after, 0),)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/messages", status_code=201)
@limiter.limit("20/minute")
def send_message(request: Request, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "پیام خالی است")
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO messages(user_id,body,created_at) VALUES(?,?,?)",
            (user["id"], body, now),
        )
        message_id = cur.lastrowid
    return {
        "id": message_id, "username": user["username"],
        "body": body, "created_at": now
    }


@app.get("/api/users")
def search_users(q: str = "", user=Depends(current_user)):
    term = q.strip().lower()[:40]
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username FROM users WHERE id != ? AND username LIKE ? ORDER BY username LIMIT 50",
            (user["id"], f"%{term}%"),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/private/{other_id}")
def list_private_messages(other_id: int, after: int = 0, user=Depends(current_user)):
    with db() as conn:
        other = conn.execute("SELECT id FROM users WHERE id = ?", (other_id,)).fetchone()
        if other is None or other_id == user["id"]:
            raise HTTPException(404, "کاربر پیدا نشد")
        rows = conn.execute("""
            SELECT pm.id, pm.sender_id, pm.recipient_id, pm.body, pm.created_at,
                   sender.username AS sender_username, recipient.username AS recipient_username
            FROM private_messages pm
            JOIN users sender ON sender.id = pm.sender_id
            JOIN users recipient ON recipient.id = pm.recipient_id
            WHERE ((pm.sender_id = ? AND pm.recipient_id = ?) OR (pm.sender_id = ? AND pm.recipient_id = ?))
              AND pm.id > ? ORDER BY pm.id ASC LIMIT 100
        """, (user["id"], other_id, other_id, user["id"], max(after, 0))).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/private/{other_id}", status_code=201)
@limiter.limit("30/minute")
def send_private_message(request: Request, other_id: int, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "پیام خالی است")
    if other_id == user["id"]:
        raise HTTPException(400, "نمی‌توانی به خودت پیام بدهی")
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        other = conn.execute("SELECT id FROM users WHERE id = ?", (other_id,)).fetchone()
        if other is None:
            raise HTTPException(404, "کاربر پیدا نشد")
        cur = conn.execute(
            "INSERT INTO private_messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)",
            (user["id"], other_id, body, now),
        )
        message_id = cur.lastrowid
    return {"id": message_id, "sender_id": user["id"], "recipient_id": other_id, "body": body, "created_at": now, "sender_username": user["username"]}


@app.get("/api/stories")
def list_stories(user=Depends(current_user)):
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM stories WHERE expires_at <= ?", (now,))
        rows = conn.execute("""SELECT stories.id, stories.user_id, stories.body, stories.created_at, stories.expires_at, users.username
                              FROM stories JOIN users ON users.id=stories.user_id
                              WHERE stories.expires_at > ? ORDER BY stories.id DESC LIMIT 100""", (now,)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/stories", status_code=201)
@limiter.limit("5/minute")
def create_story(request: Request, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "استوری خالی است")
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    expires = (now_dt + timedelta(hours=24)).isoformat()
    with db() as conn:
        cur = conn.execute("INSERT INTO stories(user_id,body,created_at,expires_at) VALUES(?,?,?,?)", (user["id"], body, now, expires))
        story_id = cur.lastrowid
    return {"id": story_id, "user_id": user["id"], "username": user["username"], "body": body, "created_at": now, "expires_at": expires}


@app.get("/api/users")
def search_users(q: str = "", user=Depends(current_user)):
    term = q.strip().lower()[:40]
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username FROM users WHERE id != ? AND username LIKE ? ORDER BY username LIMIT 50",
            (user["id"], f"%{term}%"),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/private/{other_id}")
def list_private_messages(other_id: int, after: int = 0, user=Depends(current_user)):
    with db() as conn:
        other = conn.execute("SELECT id FROM users WHERE id = ?", (other_id,)).fetchone()
        if other is None or other_id == user["id"]:
            raise HTTPException(404, "کاربر پیدا نشد")
        rows = conn.execute("""
            SELECT pm.id, pm.sender_id, pm.recipient_id, pm.body, pm.created_at,
                   sender.username AS sender_username, recipient.username AS recipient_username
            FROM private_messages pm
            JOIN users sender ON sender.id = pm.sender_id
            JOIN users recipient ON recipient.id = pm.recipient_id
            WHERE ((pm.sender_id = ? AND pm.recipient_id = ?) OR (pm.sender_id = ? AND pm.recipient_id = ?))
              AND pm.id > ? ORDER BY pm.id ASC LIMIT 100
        """, (user["id"], other_id, other_id, user["id"], max(after, 0))).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/private/{other_id}", status_code=201)
@limiter.limit("30/minute")
def send_private_message(request: Request, other_id: int, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "پیام خالی است")
    if other_id == user["id"]:
        raise HTTPException(400, "نمی‌توانی به خودت پیام بدهی")
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        other = conn.execute("SELECT id FROM users WHERE id = ?", (other_id,)).fetchone()
        if other is None:
            raise HTTPException(404, "کاربر پیدا نشد")
        cur = conn.execute(
            "INSERT INTO private_messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)",
            (user["id"], other_id, body, now),
        )
        message_id = cur.lastrowid
    return {"id": message_id, "sender_id": user["id"], "recipient_id": other_id, "body": body, "created_at": now, "sender_username": user["username"]}


@app.get("/api/stories")
def list_stories(user=Depends(current_user)):
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM stories WHERE expires_at <= ?", (now,))
        rows = conn.execute("""SELECT stories.id, stories.user_id, stories.body, stories.created_at, stories.expires_at, users.username
                              FROM stories JOIN users ON users.id=stories.user_id
                              WHERE stories.expires_at > ? ORDER BY stories.id DESC LIMIT 100""", (now,)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/stories", status_code=201)
@limiter.limit("5/minute")
def create_story(request: Request, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "استوری خالی است")
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    expires = (now_dt + timedelta(hours=24)).isoformat()
    with db() as conn:
        cur = conn.execute("INSERT INTO stories(user_id,body,created_at,expires_at) VALUES(?,?,?,?)", (user["id"], body, now, expires))
        story_id = cur.lastrowid
    return {"id": story_id, "user_id": user["id"], "username": user["username"], "body": body, "created_at": now, "expires_at": expires}


HTML = r"""<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#101512"><title>PM Chat</title>
<style>
:root{--bg:#0b0f0d;--side:#111713;--panel:#151d18;--panel2:#1c2820;--line:#29372e;--green:#38e889;--green2:#1fbd68;--text:#effaf2;--muted:#92a69a;--danger:#ff7777}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Tahoma,Arial,sans-serif}button,input,textarea{font:inherit}button{cursor:pointer}button:disabled{opacity:.5;cursor:wait}.hidden{display:none!important}.auth-wrap{min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(ellipse at 50% 0,#163323,transparent 55%),var(--bg)}.auth{width:min(420px,100%);padding:28px;background:var(--side);border:1px solid var(--line);border-radius:24px;box-shadow:0 25px 80px #0008}.brand{display:flex;align-items:center;gap:12px;font-size:22px;font-weight:800}.logo{width:44px;height:44px;border-radius:15px;display:grid;place-items:center;background:var(--green);color:#07130b;font-weight:1000;font-size:23px;box-shadow:0 0 25px #38e88922}.muted{color:var(--muted);font-size:12px;line-height:1.8}.auth h1{font-size:24px;margin:24px 0 8px}.form{display:grid;gap:12px;margin-top:20px}.field{width:100%;border:1px solid #34443a;background:#0c120e;color:var(--text);padding:14px 15px;border-radius:13px;outline:none}.field:focus{border-color:var(--green)}.btn{border:0;background:var(--green);color:#07130b;padding:12px 16px;border-radius:13px;font-weight:800}.btn:hover{background:#5bf29d}.btn.ghost{background:#202b24;color:var(--text);border:1px solid #34453a}.auth-switch{display:flex;gap:10px;margin-top:12px}.auth-switch button{flex:1}.error{min-height:24px;color:#ff9696;font-size:12px;line-height:1.8;margin-top:10px}.shell{height:100dvh;min-height:540px;display:grid;grid-template-columns:340px minmax(0,1fr);max-width:1600px;margin:auto;background:var(--bg);border-inline:1px solid #202a23}.sidebar{background:var(--side);border-left:1px solid var(--line);display:flex;flex-direction:column;min-width:0}.side-head{padding:20px 18px 14px;border-bottom:1px solid var(--line)}.head-row{display:flex;align-items:center;justify-content:space-between;gap:10px}.brand-sm{font-size:19px}.icon-btn{border:1px solid #2c3b31;background:#18211b;color:#dff8e8;border-radius:12px;width:40px;height:40px;display:grid;place-items:center;font-size:18px}.icon-btn:hover{border-color:var(--green);color:var(--green)}.search{margin-top:17px;position:relative}.search input{padding-right:42px}.search:before{content:'⌕';position:absolute;right:15px;top:8px;color:var(--muted);font-size:24px}.stories{padding:14px 15px;border-bottom:1px solid var(--line)}.section-title{font-size:12px;color:var(--muted);margin:0 0 12px}.story-row{display:flex;gap:13px;overflow:auto;padding-bottom:2px}.story{border:0;background:none;color:var(--text);min-width:58px;max-width:70px;padding:0;display:grid;justify-items:center;gap:6px;font-size:11px}.story-ring{width:50px;height:50px;border-radius:50%;padding:3px;background:linear-gradient(135deg,var(--green),#177544);display:grid;place-items:center}.story-avatar{width:100%;height:100%;border-radius:50%;background:#17251b;border:2px solid var(--side);display:grid;place-items:center;font-weight:900;color:var(--green)}.story.add .story-ring{background:#25362a}.story.add .story-avatar{background:#1c2c20;font-size:23px}.tabs{display:flex;padding:10px 12px;gap:8px}.tab{flex:1;padding:9px 6px;border-radius:11px;background:transparent;color:var(--muted);border:1px solid transparent;font-size:12px}.tab.active{background:#1b2b20;color:var(--green);border-color:#2c4a36}.list-head{padding:8px 18px;color:var(--muted);font-size:12px}.user-list{overflow:auto;flex:1}.user-item{width:100%;display:flex;align-items:center;gap:12px;padding:12px 16px;border:0;border-top:1px solid #1e2821;background:transparent;color:var(--text);text-align:right}.user-item:hover,.user-item.active{background:#1b2920}.avatar{width:46px;height:46px;flex:none;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#28553a,#14271a);color:var(--green);font-weight:900;font-size:17px}.user-info{min-width:0;flex:1}.user-name{font-size:14px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.user-preview{font-size:11px;color:var(--muted);margin-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.side-bottom{border-top:1px solid var(--line);padding:12px;display:flex;align-items:center;gap:10px}.side-bottom .user-info{flex:1}.logout{font-size:11px;padding:8px 10px}.main{display:flex;flex-direction:column;min-width:0;background:radial-gradient(ellipse at 50% 50%,#101b14,#0b100d 70%)}.chat-head{height:78px;display:flex;align-items:center;gap:13px;padding:14px 22px;border-bottom:1px solid var(--line);background:#101612e8}.chat-head .user-info{flex:1}.chat-title{font-weight:800;font-size:15px}.online{color:var(--green);font-size:11px;margin-top:6px}.head-actions{display:flex;gap:8px}.chat-messages{flex:1;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:24px clamp(14px,4vw,50px);background-image:radial-gradient(#25402d25 1px,transparent 1px);background-size:22px 22px}.welcome{margin:auto;max-width:360px;text-align:center;color:var(--muted);line-height:2;font-size:13px;background:#101712dc;padding:26px;border:1px solid #233329;border-radius:22px}.welcome .big{font-size:34px;margin-bottom:10px}.bubble{max-width:min(76%,600px);align-self:flex-start;background:#1a251e;border:1px solid #29382e;padding:11px 14px;border-radius:16px 5px 16px 16px;overflow-wrap:anywhere;box-shadow:0 5px 18px #0002}.bubble.mine{align-self:flex-end;background:#183b27;border-color:#24633e;border-radius:5px 16px 16px 16px}.bubble-name{font-size:11px;color:var(--green);font-weight:700;margin-bottom:6px}.bubble-body{white-space:pre-wrap;line-height:1.85;font-size:14px}.bubble-time{text-align:left;font-size:10px;color:#94ab9a;margin-top:7px}.composer-wrap{padding:14px 20px 18px;border-top:1px solid var(--line);background:#101612}.composer{display:flex;align-items:center;gap:10px;background:#0c120e;border:1px solid #2a3b30;border-radius:17px;padding:7px}.composer input{border:0;background:transparent;outline:none;color:var(--text);padding:10px;min-width:0;flex:1}.send{width:44px;height:44px;border-radius:13px;padding:0;font-size:18px}.notice{font-size:11px;color:var(--muted);padding:7px 6px 0;min-height:18px}.mobile-top{display:none}.modal-back{position:fixed;inset:0;background:#0009;display:grid;place-items:center;padding:20px;z-index:20}.modal{width:min(420px,100%);padding:22px;background:var(--side);border:1px solid var(--line);border-radius:20px}.modal h3{margin-top:0}.modal textarea{min-height:120px;resize:vertical}.modal-actions{display:flex;gap:10px;margin-top:12px}.modal-actions button{flex:1}.story-view{white-space:pre-wrap;line-height:1.9;background:#14251a;border:1px solid #2a5137;padding:20px;border-radius:16px;margin:15px 0}.pill{display:inline-flex;padding:5px 8px;background:#183a26;color:var(--green);border-radius:20px;font-size:10px}
@media(max-width:760px){.shell{grid-template-columns:1fr}.sidebar{height:100%;}.main{display:none;height:100dvh}.shell.chat-open .sidebar{display:none}.shell.chat-open .main{display:flex}.mobile-top{display:inline-grid}.chat-head{padding:12px 14px;height:70px}.chat-messages{padding:16px 12px}.composer-wrap{padding:10px}.bubble{max-width:90%}.side-head{padding:14px}.stories{padding:12px}.side-bottom{padding:10px}}
</style></head><body>
<div class="auth-wrap" id="authWrap"><section class="auth"><div class="brand"><div class="logo">PM</div><div>PM Chat<div class="muted">پیام‌رسان تو؛ ساده، سریع و امن</div></div></div><h1 id="authTitle">ورود به PM Chat</h1><div class="muted">با حساب خودت وارد شو یا یک حساب تازه بساز.</div><form class="form" id="authForm"><input class="field" id="username" placeholder="نام کاربری انگلیسی" minlength="3" maxlength="24" autocomplete="username" required><input class="field" id="password" type="password" placeholder="رمز عبور (حداقل ۱۲ نویسه برای ثبت‌نام)" autocomplete="current-password" required><button class="btn" id="authSubmit">ورود</button></form><div class="auth-switch"><button class="btn ghost" id="loginMode" type="button">ورود</button><button class="btn ghost" id="registerMode" type="button">ساخت حساب</button></div><div class="error" id="authError"></div><div class="muted">ورود گوگل بعد از تنظیم OAuth در Google Cloud فعال می‌شود.</div></section></div>
<div class="shell hidden" id="shell"><aside class="sidebar"><div class="side-head"><div class="head-row"><div class="brand brand-sm"><div class="logo">PM</div><div>PM Chat<div class="muted">پیام‌رسان شخصی</div></div></div><button class="icon-btn" id="newStoryBtn" title="افزودن استوری">＋</button></div><div class="search"><input class="field" id="searchUsers" placeholder="جست‌وجوی کاربران..."></div></div><div class="stories"><div class="section-title">استوری‌ها · ۲۴ ساعت</div><div class="story-row" id="stories"><button class="story add" id="addStory"><span class="story-ring"><span class="story-avatar">＋</span></span><span>استوری من</span></button></div></div><div class="tabs"><button class="tab active" data-tab="all">همه</button><button class="tab" data-tab="users">کاربران</button><button class="tab" data-tab="public">گفت‌وگوی عمومی</button></div><div class="list-head" id="listLabel">گفت‌وگوها</div><div class="user-list" id="userList"></div><div class="side-bottom"><div class="avatar" id="meAvatar">P</div><div class="user-info"><div class="user-name" id="meName">حساب من</div><div class="user-preview">آنلاین در PM Chat</div></div><button class="btn ghost logout" id="logout">خروج</button></div></aside>
<main class="main"><header class="chat-head"><button class="icon-btn mobile-top" id="backBtn">‹</button><div class="avatar" id="chatAvatar">🌿</div><div class="user-info"><div class="chat-title" id="chatTitle">گفت‌وگوی عمومی</div><div class="online" id="chatSubtitle">● آمادهٔ گفت‌وگو</div></div><div class="head-actions"><button class="icon-btn" id="refreshBtn" title="تازه‌سازی">↻</button></div></header><div class="chat-messages" id="messages"><div class="welcome"><div class="big">✳</div><strong>به PM Chat خوش آمدی</strong><br>از فهرست سمت راست یک کاربر انتخاب کن یا وارد گفت‌وگوی عمومی شو.</div></div><div class="composer-wrap"><form class="composer" id="sendForm"><input id="message" maxlength="1000" placeholder="پیام بنویس..." autocomplete="off" required><button class="btn send" id="sendBtn" title="ارسال">➤</button></form><div class="notice" id="notice">پیام‌ها به سرور ارسال می‌شوند.</div></div></main></div>
<div class="modal-back hidden" id="storyModal"><section class="modal"><h3>استوری متنی جدید</h3><textarea class="field" id="storyText" maxlength="1000" placeholder="الان چه خبر؟"></textarea><div class="modal-actions"><button class="btn" id="publishStory">انتشار استوری</button><button class="btn ghost" id="cancelStory">لغو</button></div><div class="error" id="storyError"></div></section></div><div class="modal-back hidden" id="storyView"><section class="modal"><div class="head-row"><h3 id="storyAuthor">استوری</h3><button class="icon-btn" id="closeStory">×</button></div><div class="story-view" id="storyBody"></div><div class="muted" id="storyExpiry">استوری پس از ۲۴ ساعت حذف می‌شود.</div></section></div>
<script>
let token=localStorage.getItem('pm_token')||'', username=localStorage.getItem('pm_user')||'', registering=false, mode='public', otherId=null, otherName='', lastId=0, polling=false, activeTab='all';const $=id=>document.getElementById(id);
function authMode(reg){registering=reg;$('authTitle').textContent=reg?'ساخت حساب PM Chat':'ورود به PM Chat';$('authSubmit').textContent=reg?'ثبت‌نام':'ورود';$('password').autocomplete=reg?'new-password':'current-password';$('authError').textContent=''}$('loginMode').onclick=()=>authMode(false);$('registerMode').onclick=()=>authMode(true);
async function api(url,opts={}){opts.headers={...(opts.headers||{}),...(token?{Authorization:'Bearer '+token}:{})};if(opts.body)opts.headers['Content-Type']='application/json';let r=await fetch(url,opts);let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.detail||'خطا در ارتباط با سرور');return d}
function showApp(){ $('authWrap').classList.add('hidden');$('shell').classList.remove('hidden');$('meName').textContent='@'+username;$('meAvatar').textContent=(username[0]||'P').toUpperCase();loadUsers();loadStories();setMode('public');}
function showAuth(){ $('shell').classList.add('hidden');$('authWrap').classList.remove('hidden');}
$('authForm').onsubmit=async e=>{e.preventDefault();$('authSubmit').disabled=true;$('authError').textContent='';try{const u=$('username').value.trim(),p=$('password').value;if(registering){await api('/api/register',{method:'POST',body:JSON.stringify({username:u,password:p})});$('username').value=u;$('password').value='';authMode(false);$('authError').textContent='حساب ساخته شد؛ حالا وارد شو.'}else{let d=await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});token=d.access_token;username=d.username;localStorage.setItem('pm_token',token);localStorage.setItem('pm_user',username);try{let me=await api('/api/me');window.pmMyId=me.id}catch{}showApp()}}catch(err){$('authError').textContent=err.message}finally{$('authSubmit').disabled=false}};
function setMode(m,id=null,name=''){mode=m;otherId=id;otherName=name;lastId=0;$('shell').classList.toggle('chat-open',window.innerWidth<=760);$('chatTitle').textContent=m==='public'?'گفت‌وگوی عمومی':name;$('chatSubtitle').textContent=m==='public'?'● اتاق عمومی PM Chat':'● گفت‌وگوی خصوصی';$('chatAvatar').textContent=m==='public'?'✳':(name[0]||'U').toUpperCase();$('messages').innerHTML='<div class="welcome"><div class="big">✳</div><strong>'+ (m==='public'?'گفت‌وگوی عمومی':'گفت‌وگو با @'+name) +'</strong><br>در حال بارگذاری پیام‌ها...</div>';loadMessages(true);renderUserList();}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function loadUsers(){try{let q=$('searchUsers').value.trim();let users=await api('/api/users?q='+encodeURIComponent(q));window.pmUsers=users;renderUserList()}catch(e){$('notice').textContent=e.message}}
function renderUserList(){let box=$('userList');box.innerHTML='';if(activeTab==='public'){let b=document.createElement('button');b.className='user-item'+(mode==='public'?' active':'');b.innerHTML='<div class="avatar">✳</div><div class="user-info"><div class="user-name">گفت‌وگوی عمومی</div><div class="user-preview">پیام‌های همهٔ کاربران</div></div>';b.onclick=()=>setMode('public');box.append(b);$('listLabel').textContent='اتاق عمومی';return}let users=window.pmUsers||[];if(!users.length){box.innerHTML='<div class="muted" style="padding:20px">کاربری پیدا نشد. یک حساب دیگر بساز یا نامی جست‌وجو کن.</div>';return}$('listLabel').textContent=activeTab==='users'?'کاربران':'کاربران';users.forEach(u=>{let b=document.createElement('button');b.className='user-item'+(mode==='private'&&otherId===u.id?' active':'');b.innerHTML='<div class="avatar">'+esc((u.username[0]||'U').toUpperCase())+'</div><div class="user-info"><div class="user-name">@'+esc(u.username)+'</div><div class="user-preview">برای شروع گفت‌وگو کلیک کن</div></div>';b.onclick=()=>setMode('private',u.id,u.username);box.append(b)})}
$('searchUsers').oninput=()=>loadUsers();document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));activeTab=b.dataset.tab;renderUserList()});
function addMessage(m,priv=false){let empty=$('messages').querySelector('.welcome');if(empty)empty.remove();let mine=priv?m.sender_id===Number(window.pmMyId):m.username===username;let wrap=document.createElement('div');wrap.className='bubble'+(mine?' mine':'');let name=document.createElement('div');name.className='bubble-name';name.textContent=priv?(mine?'شما':'@'+(m.sender_username||otherName)):'@'+m.username;let body=document.createElement('div');body.className='bubble-body';body.textContent=m.body;let time=document.createElement('div');time.className='bubble-time';try{time.textContent=new Date(m.created_at).toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit'})}catch{}wrap.append(name,body,time);$('messages').append(wrap);$('messages').scrollTop=$('messages').scrollHeight;lastId=Math.max(lastId,m.id)}
async function loadMessages(initial=false){if(polling||!token)return;polling=true;try{if(initial){$('messages').innerHTML='';lastId=0}let list=mode==='public'?await api('/api/messages?after='+(initial?0:lastId)):await api('/api/private/'+otherId+'?after='+(initial?0:lastId));if(initial&&list.length===0)$('messages').innerHTML='<div class="welcome"><div class="big">✳</div><strong>شروع یک گفت‌وگوی تازه</strong><br>اولین پیام را بفرست.</div>';list.forEach(m=>addMessage(m,mode==='private'));$('notice').textContent=''}catch(e){$('notice').textContent=e.message}finally{polling=false}}
$('sendForm').onsubmit=async e=>{e.preventDefault();let body=$('message').value.trim();if(!body)return;$('sendBtn').disabled=true;try{let url=mode==='public'?'/api/messages':'/api/private/'+otherId;let m=await api(url,{method:'POST',body:JSON.stringify({body})});$('message').value='';if(mode==='private')m.sender_id=Number(window.pmMyId);addMessage(m,mode==='private')}catch(err){$('notice').textContent=err.message}finally{$('sendBtn').disabled=false;$('message').focus()}};
async function loadStories(){try{let stories=await api('/api/stories');let row=$('stories');row.innerHTML='';let add=document.createElement('button');add.className='story add';add.innerHTML='<span class="story-ring"><span class="story-avatar">＋</span></span><span>استوری من</span>';add.onclick=openStory;row.append(add);stories.forEach(s=>{let b=document.createElement('button');b.className='story';b.innerHTML='<span class="story-ring"><span class="story-avatar">'+esc((s.username[0]||'U').toUpperCase())+'</span></span><span>'+esc(s.username)+'</span>';b.onclick=()=>viewStory(s);row.append(b)})}catch(e){}}
function openStory(){$('storyText').value='';$('storyError').textContent='';$('storyModal').classList.remove('hidden')}$('addStory').onclick=openStory;$('newStoryBtn').onclick=openStory;$('cancelStory').onclick=()=>$('storyModal').classList.add('hidden');$('publishStory').onclick=async()=>{try{let body=$('storyText').value.trim();if(!body)throw Error('متن استوری را بنویس');await api('/api/stories',{method:'POST',body:JSON.stringify({body})});$('storyModal').classList.add('hidden');loadStories()}catch(e){$('storyError').textContent=e.message}};function viewStory(s){$('storyAuthor').textContent='@'+s.username;$('storyBody').textContent=s.body;$('storyExpiry').textContent='انتشار: '+new Date(s.created_at).toLocaleString('fa-IR')+' · انقضا پس از ۲۴ ساعت';$('storyView').classList.remove('hidden')}$('closeStory').onclick=()=>$('storyView').classList.add('hidden');$('storyView').onclick=e=>{if(e.target===$('storyView'))$('storyView').classList.add('hidden')};
function logout(){token='';username='';localStorage.removeItem('pm_token');localStorage.removeItem('pm_user');showAuth()}$('logout').onclick=logout;$('refreshBtn').onclick=()=>{loadMessages(true);loadUsers();loadStories()};$('backBtn').onclick=()=>$('shell').classList.remove('chat-open');window.addEventListener('resize',()=>{if(window.innerWidth>760)$('shell').classList.remove('chat-open')});
(async()=>{if(token&&username){try{let me=await api('/api/me');window.pmMyId=me.id;showApp()}catch(e){logout()}}else showAuth()})();setInterval(()=>{if(token&&!$('shell').classList.contains('hidden'))loadMessages(false)},2200);setInterval(()=>{if(token&&!$('shell').classList.contains('hidden'))loadStories()},30000);
</script></body></html>"""
