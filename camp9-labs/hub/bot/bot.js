// bot/bot.js  — run:  HUB=http://hub:8080 node bot.js
// Admin Bot (the victim). Logs in as mayor (non-HttpOnly session cookie), sweeps /reviews,
// follows every same-origin link (incl. each review author's /profile/<username>), re-visits
// its own /profile, waits, loops every ~30s. Visiting a student's /profile fires the stored
// avatar payload (XSS-5); loading a review's <script src> fires the JSONP bypass (XSS-6).
const { chromium } = require("playwright");

const HUB = process.env.HUB || "http://hub:8080";
const MAYOR_USER = process.env.MAYOR_USER || "mayor";
const MAYOR_PASS = process.env.MAYOR_PASS || "change_me_mayor_password";
const INTERVAL_MS = 30000;

async function loginAsMayor(ctx) {
  const page = await ctx.newPage();
  await page.goto(`${HUB}/login`);
  await page.fill('input[name="username"]', MAYOR_USER);
  await page.fill('input[name="password"]', MAYOR_PASS);
  await page.click('button[type="submit"]');
  await page.waitForLoadState("networkidle");
  // Sanity check: the session cookie must be readable by JS (non-HttpOnly).
  const c = await page.evaluate(() => document.cookie);
  console.log("[bot] logged in; document.cookie =", c || "(EMPTY — check httponly=False in set_cookie!)");
  await page.close();
}

async function sweep(ctx) {
  const seeds = [`${HUB}/reviews`, `${HUB}/profile`, `${HUB}/`];
  const page = await ctx.newPage();
  try {
    for (const url of seeds) {
      await page.goto(url, { waitUntil: "networkidle" }).catch(() => {});
      // Collect same-origin links on this page (review author -> /profile/<username>, etc.)
      const hrefs = await page.$$eval("a[href]", as => as.map(a => a.getAttribute("href")));
      for (const h of hrefs) {
        if (!h || h.startsWith("#") || /^javascript:/i.test(h)) continue;   // do NOT eval javascript: (out of scope)
        let abs;
        try { abs = new URL(h, url).toString(); } catch { continue; }
        if (!abs.startsWith(HUB)) continue;                                  // same-origin only
        await page.goto(abs, { waitUntil: "networkidle" }).catch(() => {});  // visiting /profile/<student> fires the avatar payload
        await page.waitForTimeout(1200);                                     // let onerror / injected <script src> fire & exfil
        await page.goto(url, { waitUntil: "networkidle" }).catch(() => {});  // back to the seed page
      }
      await page.waitForTimeout(1500);
    }
  } finally { await page.close(); }
}

(async () => {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const ctx = await browser.newContext();   // one context = one persistent mayor session
  await loginAsMayor(ctx);
  while (true) {
    const t = Date.now();
    try { await sweep(ctx); } catch (e) { console.error("[bot] sweep error", e.message); }
    const wait = Math.max(0, INTERVAL_MS - (Date.now() - t));
    console.log(`[bot] sweep done; sleeping ${Math.round(wait / 1000)}s`);
    await new Promise(r => setTimeout(r, wait));
  }
})();
