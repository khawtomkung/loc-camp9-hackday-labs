#!/usr/bin/env python3
# gen_token.py — print the JS-4 Local Storage token for the current JS4_FLAG.
# The app now injects this token at render time (window.__ct in vault.html), reading
# JS4_FLAG from _secrets.py / env — so you normally don't need to paste it anywhere.
# Usage: python3 scripts/gen_token.py            (uses _secrets.py / env)
#        python3 scripts/gen_token.py 'LOC9{...}' (override explicitly)
import base64, os, sys

HUB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HUB)
try:
    from _secrets import SECRETS
except Exception:
    SECRETS = {}

flag = (sys.argv[1] if len(sys.argv) > 1
        else os.environ.get("JS4_FLAG") or SECRETS.get("JS4_FLAG", "LOC9{SET_ME}")).encode()
KEY = 0x2a
enc = base64.b64encode(bytes(b ^ KEY for b in flag)).decode()
print("flag :", flag.decode())
print("token:", enc)
