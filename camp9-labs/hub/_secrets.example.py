# === Lab secrets TEMPLATE ===
# 1) copy this file to  _secrets.py  (which is gitignored)
# 2) replace every value below with the real flags / credentials for your deployment
# 3) run  python3 tools/gen_crypto.py   to (re)build the encoded challenge assets
#        (dev-backup/notes.txt, dev-backup/config.bak.enc, static/assets/vip/launch.flag,
#         static/forge-recipes/codex.recipe)  from these values
#
# You can also provide any flag via an environment variable of the same name
# (e.g. JS1_FLAG=...), which overrides this file. Keep real values OUT of git.
SECRETS = {
    "MAYOR_PASSWORD": "change_me_mayor_password",
    "ENCHANT_SEAL":   "SET-ME-ENCHANT-SEAL",

    "JS1_FLAG":  "LOC9{SET_ME_js1}",
    "JS2_FLAG":  "LOC9{SET_ME_js2}",
    "JS3_FLAG":  "LOC9{SET_ME_js3}",
    "JS4_FLAG":  "LOC9{SET_ME_js4}",
    "WEB1_FLAG": "LOC9{SET_ME_web1}",
    "WEB2_FLAG": "LOC9{SET_ME_web2}",
    "WEB3_FLAG": "LOC9{SET_ME_web3}",
    "WEB4_FLAG": "LOC9{SET_ME_web4}",
    "WEB5_FLAG": "LOC9{SET_ME_web5}",
    "XSS1_FLAG": "LOC9{SET_ME_xss1}",
    "XSS2_FLAG": "LOC9{SET_ME_xss2}",
    "XSS3_FLAG": "LOC9{SET_ME_xss3}",
    "XSS4_FLAG": "LOC9{SET_ME_xss4}",
    "XSS5_FLAG": "LOC9{SET_ME_xss5}",
    "XSS6_FLAG": "LOC9{SET_ME_xss6}",
    "SQLI_FLAG": "LOC9{SET_ME_sqli}",
    "CRAFT_FLAG": "LOC9{SET_ME_craft}",

    # EXTRA crafting recipe: the 3x3 grid (row by row) of item ids.
    # Valid ids (match the palette in templates/craft.html):
    #   diamond, emerald, ender_pearl, golden_apple, apple, bread, feather, bone
    # Pick your own 9-cell arrangement; the same value feeds both the validator
    # and the generated codex.recipe scroll.
    "CRAFT_RECIPE": ["diamond", "emerald", "diamond",
                     "emerald", "golden_apple", "emerald",
                     "diamond", "emerald", "diamond"],
}
