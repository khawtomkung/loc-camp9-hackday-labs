#!/usr/bin/env python3
# tools/gen_crypto.py  — run from the hub/ dir:  python3 -I tools/gen_crypto.py
# Single source of truth for all ENCODED challenge assets. Reads the real flags from
# _secrets.py (or env) so no flag is stored in this script, and (re)builds:
#   dev-backup/notes.txt              (WEB-3, base64)
#   dev-backup/config.bak.enc         (WEB-4, base64 + XOR 0x5c)   + attachments/ copy
#   static/assets/vip/launch.flag     (JS-2,  base64 + XOR 0x17)
#   static/forge-recipes/codex.recipe (EXTRA, base64 + XOR 0x3b)
# Re-run this after editing _secrets.py. These outputs are gitignored.
import base64
import os
import pathlib
import shutil
import sys

HUB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # hub/ (works under python3 -I)
sys.path.insert(0, HUB)
try:
    from _secrets import SECRETS
except Exception:
    SECRETS = {}


def sec(key, default):
    return os.environ.get(key) or SECRETS.get(key, default)


def xor_b64(data: bytes, key: int) -> str:
    return base64.b64encode(bytes(b ^ key for b in data)).decode()


# JS-4: localStorage token = base64( XOR(flag, 0x2a) ) — app injects this per-render now;
# printed here only as a reference for whoever wants to verify it.
js4_token = xor_b64(sec("JS4_FLAG", "LOC9{SET_ME}").encode(), 0x2a)

# JS-2: /assets/vip/launch.flag = base64( XOR(flag, 0x17) )
js2_launch = xor_b64(sec("JS2_FLAG", "LOC9{SET_ME}").encode(), 0x17)

# WEB-4: config.bak.enc = base64( XOR(config_plaintext, 0x5c) )
WEB4_CONFIG = (
    "# Village Trading Hub - legacy config backup\n"
    "db_host=127.0.0.1\n"
    "db_user=villager\n"
    "db_pass=redstone_dust_2026\n"
    "mayor_user=mayor\n"
    "flag=%s\n" % sec("WEB4_FLAG", "LOC9{SET_ME}")
)
web4_enc = xor_b64(WEB4_CONFIG.encode(), 0x5c)

# WEB-3: notes.txt = base64 of two lines (flag + pointer to WEB-4)
WEB3_LINES = (
    "flag: %s\n" % sec("WEB3_FLAG", "LOC9{SET_ME}")
    + "note: config.bak.enc in this folder = base64 then single-byte XOR\n"
)
web3_notes = base64.b64encode(WEB3_LINES.encode()).decode()

# EXTRA: codex.recipe = base64( XOR(recipe_scroll, 0x3b) ). Built from the 3x3 recipe in _secrets,
# so the arrangement is not stored in this script either.
_NAMES = {
    "diamond": "Diamond", "emerald": "Emerald", "ender_pearl": "Ender Pearl",
    "golden_apple": "Enchanted Golden Apple", "apple": "Apple", "bread": "Bread",
    "feather": "Feather", "bone": "Bone",
}
recipe = SECRETS.get("CRAFT_RECIPE", ["diamond"] * 9)
rows = [recipe[0:3], recipe[3:6], recipe[6:9]]
scroll = "=== ENCHANTER'S CODEX RECIPE (lost scroll) ===\n"
scroll += "Set the Crafting Table 3x3 grid exactly like this (row by row, left to right):\n"
for i, r in enumerate(rows, 1):
    scroll += "  row%d: %s\n" % (i, ", ".join(_NAMES.get(x, x) for x in r))
scroll += ("\nYou ALSO need the Mayor's Enchant Seal -- it is shown only on the /admin\n"
           "dashboard (reachable with the stolen mayor cookie from the Stored-XSS challenge).\n"
           "Then press Craft to forge the Enchanted Book (the flag is inside it).\n")
codex = xor_b64(scroll.encode(), 0x3b)

# write assets (relative to hub/)
os.chdir(HUB)
pathlib.Path("dev-backup").mkdir(exist_ok=True)
pathlib.Path("attachments").mkdir(exist_ok=True)
pathlib.Path("static/assets/vip").mkdir(parents=True, exist_ok=True)
pathlib.Path("static/forge-recipes").mkdir(parents=True, exist_ok=True)
pathlib.Path("dev-backup/notes.txt").write_text(web3_notes + "\n")
pathlib.Path("dev-backup/config.bak.enc").write_text(web4_enc + "\n")
shutil.copyfile("dev-backup/config.bak.enc", "attachments/config.bak.enc")  # CTFd attachment copy
pathlib.Path("static/assets/vip/launch.flag").write_text(js2_launch + "\n")
pathlib.Path("static/forge-recipes/codex.recipe").write_text(codex + "\n")

print("JS-2  launch.flag        =", js2_launch)
print("JS-4  cleric_vault_token =", js4_token, "(app injects this via window.__ct)")
print("WEB-3 notes.txt          =", web3_notes)
print("WEB-4 config.bak.enc     =", web4_enc)
print("EXTRA codex.recipe       =", codex)
if not SECRETS:
    print("\n[!] _secrets.py not found — used SET_ME placeholders. Copy _secrets.example.py -> _secrets.py.")
