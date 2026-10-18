# Village Trading Hub — CTF lab (reference implementation)

A single Minecraft-themed web app (Flask) that hosts the LOC Camp 9 hackday Mini-CTF:
**14 challenges** across JavaScript recon (×4), Web Low-Hanging-Fruit (×5), reflected XSS (×4),
and a final crafting "extra" that chains web_lhf + crypto + a stored-XSS session hijack. Students
attack this app over the network and submit flags in CTFd.

> **No flags or solutions in this repo.** Flags, the mayor credential, and the enchant seal are
> **not** committed — they live in `_secrets.py` (gitignored) or environment variables, and the
> encoded challenge files are generated from them at deploy time. Challenge walkthroughs are kept
> out of this repo on purpose.

## Layout
```
app.py                     the whole web app (routes + challenge logic)
_secrets.example.py        template for flags/creds -> copy to _secrets.py (gitignored)
tools/gen_crypto.py        builds the encoded challenge assets from _secrets.py
scripts/gen_token.py       prints the JS-4 token (reference utility)
templates/  static/        pages + assets (CSS, images, challenge JS)
bot/                       Admin Bot (headless Playwright, logs in as the mayor)
Dockerfile  docker-compose.yml   Hub + Admin Bot + CTFd
attachments/common-dirs.txt      wordlist handed to players for one challenge
```

## Configure (set your flags — required)
```bash
cp _secrets.example.py _secrets.py     # then edit _secrets.py with THIS deployment's flags/creds
```
Every flag can also be supplied via an environment variable of the same name (overrides the file).
Keep real values out of git.

## Run (local)
```bash
cd hub
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 tools/gen_crypto.py      # builds dev-backup/, launch.flag, codex.recipe from _secrets.py — run once after editing secrets
python app.py                    # http://127.0.0.1:8000   (or PORT=5000 python app.py)
```
In production put a reverse proxy / `docker -p 80:8000` in front of it.

## Run (full stack: Hub + Admin Bot + CTFd)
```bash
cd hub
docker compose up --build        # Hub, the mayor Admin Bot (sweeps pages ~every 30s), and CTFd
```
The Admin Bot is the "victim" for the EXTRA challenge's stored-XSS step (steal the mayor cookie via
the /profile avatar sink to read the Enchant Seal on /admin); its mayor session cookie is
intentionally non-HttpOnly (that is the lesson). Configure its credentials via the same secrets.

## CTFd
Create the categories (JS / Web-LHF / XSS / Extra), add the 14 challenges with their
point values, hints, attachments, and prerequisites (the Extra unlocks after all 13 others), and
point every challenge's connection info at this app's public host. The flag for each challenge is
whatever you set in `_secrets.py`.

## Arena — classroom PvP "cookie heist" (separate activity, beginner-friendly)
A self-contained stored-XSS game at **`/arena`** — NOT one of the 14 challenges and not in CTFd; meant
for a live class that hasn't learned XSS yet. It has its **own menu and landing page** (the
14-challenge hub nav no longer links to it), so it reads as a separate mini-site while sharing this
app's process, port, and theme. Students self-register a throwaway name+PIN → get a
non-HttpOnly `arena_session` cookie + a private flag at `/arena/me`, then steal each other's cookies by
planting a **ready-made guestbook payload** (pre-filled on each classmate's `/arena/u/<name>` board — one
click). A built-in catcher (`/arena/steal`) collects stolen cookies on the attacker's **`/arena/loot`**
page, so **no webhook.site or DevTools is needed**; "use a ticket" to read the victim's flag and Claim it
on `/arena/scoreboard`. Teacher reset: `POST /arena/reset` with `pin=ARENA_ADMIN_PIN` (from `_secrets.py`).
Closed lab network only; use throwaway accounts.

## Notes
- `tools/gen_crypto.py` is the single source of truth for the encoded assets — re-run it whenever
  you change a flag in `_secrets.py`.
- The app binds `$PORT` (default 8000). Serve `.map`/`.flag`/`.recipe` files as text; the app sets
  the right content types itself.
