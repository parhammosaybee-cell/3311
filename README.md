# PM Chat — Telegram-inspired black & green starter

This is a real FastAPI project intended as the next incremental version of the existing Render deployment. It keeps the current `/api/register`, `/api/login`, `/api/me`, and public-message APIs, and adds user search, private text conversations, and text stories that expire after 24 hours. The interface is responsive and styled in black/neon green with a Telegram-like two-pane layout.

## Included in this phase
- Account registration/login with Argon2 password hashing, JWT tokens, and rate limits.
- Public text chat with polling.
- Private text messages between registered accounts.
- Search registered users.
- Text stories that expire after 24 hours.
- Responsive black/green desktop/mobile interface.

## Not included yet
Google OAuth is not wired into this phase; it requires a callback route and real Google Cloud credentials. Media uploads, recorded voice messages, group chats/channels, email password recovery, message delivery/read states, and full 14-language translation are later phases. Do not advertise these as complete yet.

## Deploy on Render
1. Extract this ZIP on your computer.
2. Upload the **contents** of `pm_chat_project` to the root of your GitHub repository (so `main.py`, `requirements.txt`, and `render.yaml` are at the repository root).
3. Render settings: Runtime Python 3; Build Command `pip install -r requirements.txt`; Start Command `uvicorn main:app --host 0.0.0.0 --port $PORT`.
4. In Render Environment, set `JWT_SECRET_KEY` to a unique random secret of at least 32 characters. Do not commit secrets to GitHub or send them in chat.
5. Commit changes to GitHub; Render should redeploy automatically.

## Important data note
This starter uses SQLite in `chat.db`. On Render without a persistent disk, database contents may be lost when the service restarts or redeploys. Before public use, attach persistent storage or move to managed PostgreSQL. This is a functional starter, not a security-audited production messenger.

## Run locally
Python 3.11+ recommended.
```bash
pip install -r requirements.txt
# Set JWT_SECRET_KEY in your shell to a unique random string of 32+ characters
uvicorn main:app --reload
```
