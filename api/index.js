import axios from "axios";
import * as cheerio from "cheerio";

// ═══════════════════════════════════════════════════════════════════════════
//  IN-MEMORY RATE LIMITER  (no Redis / no MongoDB)
//  50 requests / 24h per IP. Repeat abusers get a 1h hard block.
// ═══════════════════════════════════════════════════════════════════════════

const rlStore = new Map();
const RL = {
  WINDOW_MS:   24 * 60 * 60 * 1000,
  MAX_REQ:     50,
  VIOL_LIMIT:  5,
  BLOCK_MS:    60 * 60 * 1000,
  CLEANUP_MS:  30 * 60 * 1000,
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, d] of rlStore.entries())
    if (now > d.resetAt && now > (d.blockedUntil || 0)) rlStore.delete(ip);
}, RL.CLEANUP_MS).unref?.();

function checkRL(ip) {
  const now = Date.now();
  let r = rlStore.get(ip);
  if (!r || now > r.resetAt)
    r = { count: 0, resetAt: now + RL.WINDOW_MS, violations: r?.violations || 0, blockedUntil: r?.blockedUntil || 0 };

  if (r.blockedUntil && now < r.blockedUntil) {
    rlStore.set(ip, r);
    return { ok: false, remaining: 0, limit: RL.MAX_REQ, resetAt: r.resetAt, retryAfter: Math.ceil((r.blockedUntil - now) / 1000), reason: "hard_block" };
  }
  if (r.count >= RL.MAX_REQ) {
    r.violations++;
    if (r.violations >= RL.VIOL_LIMIT) r.blockedUntil = now + RL.BLOCK_MS;
    rlStore.set(ip, r);
    return { ok: false, remaining: 0, limit: RL.MAX_REQ, resetAt: r.resetAt, retryAfter: Math.ceil((r.resetAt - now) / 1000), reason: r.blockedUntil ? "hard_block" : "daily_limit" };
  }
  r.count++;
  rlStore.set(ip, r);
  return { ok: true, remaining: RL.MAX_REQ - r.count, limit: RL.MAX_REQ, resetAt: r.resetAt, retryAfter: null, reason: null };
}

function rlPayload(rl) {
  return {
    limit:     rl.limit     ?? RL.MAX_REQ,
    remaining: rl.remaining ?? 0,
    resetAt:   rl.resetAt   ? new Date(rl.resetAt).toISOString() : new Date(Date.now() + RL.WINDOW_MS).toISOString(),
    window:    "24h",
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  IN-MEMORY CACHE  (rateLimit NEVER stored — always injected fresh)
// ═══════════════════════════════════════════════════════════════════════════

const cache = new Map();
const CACHE = { TTL: 10 * 60 * 1000, MAX: 500, CLEAN: 5 * 60 * 1000 };

setInterval(() => {
  const now = Date.now();
  for (const [k, e] of cache.entries()) if (now > e.exp) cache.delete(k);
}, CACHE.CLEAN).unref?.();

function cGet(key) {
  const e = cache.get(key);
  if (!e) return null;
  if (Date.now() > e.exp) { cache.delete(key); return null; }
  return e.v;
}

function cSet(key, value, ttl = CACHE.TTL) {
  if (cache.size >= CACHE.MAX) cache.delete(cache.keys().next().value);
  const { rateLimit: _drop, ...clean } = value; // strip rateLimit before storing
  cache.set(key, { v: clean, exp: Date.now() + ttl });
}

// ═══════════════════════════════════════════════════════════════════════════
//  CLIENT IP  (Vercel-safe)
// ═══════════════════════════════════════════════════════════════════════════

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const first = xff.split(",")[0].trim();
    if (first && first !== "::1" && first !== "127.0.0.1") return first;
  }
  for (const h of ["x-real-ip","cf-connecting-ip","fastly-client-ip","true-client-ip","x-client-ip"]) {
    const v = req.headers[h];
    if (v && v !== "::1" && v !== "127.0.0.1" && v !== "::ffff:127.0.0.1") return v;
  }
  const sock = req.socket?.remoteAddress || req.connection?.remoteAddress;
  if (sock && sock !== "::1" && sock !== "127.0.0.1") return sock;
  return "global-fallback";
}

// ═══════════════════════════════════════════════════════════════════════════
//  URL SECURITY
// ═══════════════════════════════════════════════════════════════════════════

const BLOCKED_HOSTS = new Set(["localhost","127.0.0.1","0.0.0.0","::1","metadata.google.internal","169.254.169.254"]);
const PRIV_RE = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^fc00:/, /^fe80:/];

function isPrivate(h) { return BLOCKED_HOSTS.has(h) || PRIV_RE.some((r) => r.test(h)); }

function validateUrl(raw) {
  if (!raw) return { err: "Missing URL" };
  let p;
  try { p = new URL(String(raw).trim()); } catch { return { err: "Invalid URL format" }; }
  if (!["http:","https:"].includes(p.protocol)) return { err: "Only HTTP/HTTPS allowed" };
  if (isPrivate(p.hostname))                    return { err: "Private/local URLs are blocked" };
  return { parsed: p };
}

// ═══════════════════════════════════════════════════════════════════════════
//  USER-AGENT ROTATION
//  WhatsApp / social sites only return proper OG tags to crawler bots
// ═══════════════════════════════════════════════════════════════════════════

const UA_BROWSER = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
];
const UA_CRAWLERS = [
  "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
  "Twitterbot/1.0",
  "LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/3.1 +http://www.linkedin.com)",
  "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
  "WhatsApp/2.23.24.0 A",
];
const SOCIAL_DOMAINS = ["wa.me","whatsapp.com","t.me","telegram.org","instagram.com","twitter.com","x.com","tiktok.com","linkedin.com","fb.com","facebook.com","pinterest.com","reddit.com"];

function pickUA(hostname) {
  return SOCIAL_DOMAINS.some((d) => hostname.toLowerCase().includes(d))
    ? UA_CRAWLERS[Math.floor(Math.random() * UA_CRAWLERS.length)]
    : UA_BROWSER[Math.floor(Math.random() * UA_BROWSER.length)];
}

// ═══════════════════════════════════════════════════════════════════════════
//  FETCH  (auto-retry with Facebook crawler UA on network failure)
// ═══════════════════════════════════════════════════════════════════════════

async function fetchHtml(url, hostname) {
  const makeOpts = (ua) => ({
    timeout: 10_000,
    maxContentLength: 6 * 1024 * 1024,
    maxRedirects: 8,
    decompress: true,
    validateStatus: (s) => s < 500,
    headers: {
      "User-Agent":      ua,
      "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Cache-Control":   "no-cache",
      "Upgrade-Insecure-Requests": "1",
    },
  });
  try {
    return await axios.get(url, makeOpts(pickUA(hostname)));
  } catch (err) {
    if (err.code && !err.response) {
      // Retry once with the Facebook crawler UA
      return await axios.get(url, makeOpts("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"));
    }
    throw err;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function resolveUrl(base, rel) {
  if (!rel || typeof rel !== "string") return null;
  rel = rel.trim();
  if (!rel || rel.startsWith("data:")) return null;
  try { return new URL(rel, base).href; } catch { return rel.startsWith("http") ? rel : null; }
}

function first(...vals) {
  for (const v of vals) { const s = (v ?? "").toString().trim(); if (s) return s; }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
//  CORE SCRAPER
//  Returns EXACTLY the same JSON shape the original handler returned.
//  Your Android code reading json.optString("title"), json.optJSONObject("images")
//  .optString("primary"), etc. will work with zero changes.
// ═══════════════════════════════════════════════════════════════════════════

async function scrape(url) {
  const parsedUrl = new URL(url);
  const response  = await fetchHtml(url, parsedUrl.hostname);

  if (response.status >= 400)
    throw Object.assign(new Error(`HTTP ${response.status}`), { httpStatus: response.status });

  const $ = cheerio.load(response.data);

  // ── Title ─────────────────────────────────────────────────────────────────
  // Same priority as original
  const title = first(
    $('meta[property="og:title"]').attr("content"),
    $('meta[name="twitter:title"]').attr("content"),
    $("title").text(),
    $("h1").first().text(),
  );

  // ── Description ───────────────────────────────────────────────────────────
  const description = first(
    $('meta[property="og:description"]').attr("content"),
    $('meta[name="twitter:description"]').attr("content"),
    $('meta[name="description"]').attr("content"),
  );

  // ── Images ────────────────────────────────────────────────────────────────
  // Builds the same { primary, count, samples } the original returned.
  // Also collects extras (WhatsApp image_src, itemprop, JSON-LD) for better coverage.
  const imgList = [];
  const imgSeen = new Set();

  const addImg = (raw, meta) => {
    const r = resolveUrl(url, raw);
    if (r && !imgSeen.has(r)) { imgSeen.add(r); imgList.push({ url: r, ...meta }); }
  };

  // OG (includes og:image:secure_url used by WhatsApp channels)
  $('meta[property="og:image"], meta[property="og:image:url"], meta[property="og:image:secure_url"]').each((_, el) => {
    addImg($(el).attr("content"), {
      type:   "og",
      width:  $('meta[property="og:image:width"]').first().attr("content")  || null,
      height: $('meta[property="og:image:height"]').first().attr("content") || null,
    });
  });

  // Twitter
  $('meta[name="twitter:image"], meta[name="twitter:image:src"]').each((_, el) => {
    addImg($(el).attr("content"), {
      type: "twitter",
      card: $('meta[name="twitter:card"]').attr("content") || null,
    });
  });

  // link[rel="image_src"] — used by WhatsApp group/channel pages
  $('link[rel="image_src"]').each((_, el) => addImg($(el).attr("href"), { type: "image_src" }));

  // itemprop
  $('[itemprop="image"]').each((_, el) => {
    addImg($(el).attr("content") || $(el).attr("src"), { type: "itemprop" });
  });

  // JSON-LD
  $('script[type="application/ld+json"]').each((_, el) => {
    try {
      const j = JSON.parse($(el).html() || "{}");
      [j?.image?.url, j?.image, j?.logo?.url, j?.logo]
        .flat().filter((i) => typeof i === "string")
        .forEach((i) => addImg(i, { type: "schema" }));
    } catch {}
  });

  // Apple touch icon
  $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
    addImg($(el).attr("href"), { type: "apple-touch-icon", sizes: $(el).attr("sizes") || "180x180" });
  });

  // First large in-page image (original logic preserved)
  let contentImage = null;
  $("img[src]").each((_, el) => {
    if (contentImage) return;
    const src   = $(el).attr("src");
    const width = parseInt($(el).attr("width") || "0");
    const alt   = $(el).attr("alt") || "";
    if (src && !src.startsWith("data:") && width > 300) {
      contentImage = {
        url:    resolveUrl(url, src),
        type:   "content",
        width,
        height: parseInt($(el).attr("height") || "0"),
        alt:    alt.substring(0, 100),
      };
    }
  });

  const primaryImage =
    imgList.find((i) => i.type === "og")?.url       ||
    imgList.find((i) => i.type === "twitter")?.url  ||
    imgList.find((i) => i.type === "image_src")?.url||
    imgList.find((i) => i.type === "itemprop")?.url  ||
    imgList[0]?.url || contentImage?.url || null;

  // ── Icons ─────────────────────────────────────────────────────────────────
  const iconList = [];
  const iconSeen = new Set();

  const addIcon = (raw, meta) => {
    const r = resolveUrl(url, raw);
    if (r && !iconSeen.has(r)) { iconSeen.add(r); iconList.push({ url: r, ...meta }); }
  };

  $('link[rel="icon"], link[rel="shortcut icon"]').each((_, el) => {
    const href = $(el).attr("href");
    if (href) addIcon(href, { sizes: $(el).attr("sizes") || "16x16", type: $(el).attr("type") || "icon" });
  });
  $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
    const href = $(el).attr("href");
    if (href) addIcon(href, { sizes: $(el).attr("sizes") || "180x180", type: "apple-touch-icon" });
  });
  $('meta[name="msapplication-TileImage"]').each((_, el) => {
    const c = $(el).attr("content");
    if (c) addIcon(c, { sizes: "144x144", type: "ms-tile" });
  });

  const manifestHref = $('link[rel="manifest"]').attr("href");

  iconList.sort((a, b) => {
    const sz = (i) => { const m = (i.sizes || "").match(/(\d+)x(\d+)/); return m ? parseInt(m[1]) * parseInt(m[2]) : 0; };
    return sz(b) - sz(a);
  });

  // ── Additional meta ───────────────────────────────────────────────────────
  const siteName     = first($('meta[property="og:site_name"]').attr("content"))
                       || parsedUrl.hostname.replace(/^www\./, "").split(".")[0]
                       || parsedUrl.hostname;
  const keywords     = $('meta[name="keywords"]').attr("content")?.split(",").map((k) => k.trim()).filter(Boolean) || [];
  const author       = first($('meta[name="author"]').attr("content"), $('meta[property="article:author"]').attr("content"));
  const themeColor   = first($('meta[name="theme-color"]').attr("content"), $('meta[name="msapplication-TileColor"]').attr("content"));
  const twitterCard  = $('meta[name="twitter:card"]').attr("content") || null;
  const twitterSite  = $('meta[name="twitter:site"]').attr("content") || null;
  const twitterCreator = $('meta[name="twitter:creator"]').attr("content") || null;
  const contentType  = $('meta[property="og:type"]').attr("content") || "website";

  // ═════════════════════════════════════════════════════════════════════════
  //  RESPONSE — original shape EXACTLY preserved
  //
  //  Your Android code reads:
  //    json.optBoolean("success")          ✅
  //    json.optString("title")             ✅
  //    json.optString("description")       ✅
  //    json.optJSONObject("images")
  //      .optString("primary")             ✅
  //      .optString("thumbnail")           ✅  (added as alias)
  //
  //  Everything else is additive — won't break existing consumers.
  // ═════════════════════════════════════════════════════════════════════════
  return {
    // ── Fields your Android code reads directly ───────────────────────────
    success:     true,
    url:         parsedUrl.href,
    title,
    description,
    siteName,
    hostname:    parsedUrl.hostname,
    domain:      parsedUrl.hostname.replace(/^www\./, ""),

    // ── metadata — original structure unchanged ───────────────────────────
    metadata: {
      basic: {
        title,
        description,
        keywords:    keywords.length > 0 ? keywords : undefined,
        author,
        contentType,
        language:    $("html").attr("lang") || "en",
      },
      social: {
        twitter: { card: twitterCard, site: twitterSite, creator: twitterCreator },
      },
      appearance: { themeColor },
    },

    // ── images — original keys kept, thumbnail alias added ────────────────
    //   Android reads: images.primary  ✅ (untouched)
    //   Android reads: images.thumbnail ✅ (new alias = same value as primary)
    images: {
      primary:      primaryImage,                   // ← your Android code reads this
      thumbnail:    primaryImage,                   // ← alias so both keys work
      count:        imgList.length,
      samples:      imgList.slice(0, 3),            // original: first 3
      allSamples:   imgList.slice(0, 8),            // bonus: up to 8
      contentImage: contentImage || null,
    },

    // ── icons — original keys kept ────────────────────────────────────────
    icons: {
      primary:     iconList[0]?.url || new URL("/favicon.ico", url).href,
      count:       iconList.length,
      all:         iconList.slice(0, 5),            // original: first 5
      allIcons:    iconList.slice(0, 10),           // bonus
      hasManifest: !!manifestHref,
    },

    // ── responseInfo — original structure unchanged ───────────────────────
    responseInfo: {
      status:      response.status,
      contentType: response.headers["content-type"]?.split(";")[0] || null,
      server:      response.headers["server"] || null,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  ERROR MAPPER  (same codes the original handler used)
// ═══════════════════════════════════════════════════════════════════════════

function mapErr(err) {
  if (err.httpStatus)                                             return { status: err.httpStatus, error: `HTTP ${err.httpStatus}`,  message: `Website returned ${err.httpStatus}` };
  if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT")   return { status: 408, error: "Request Timeout",    message: "Website took too long to respond" };
  if (err.code === "ENOTFOUND")                                  return { status: 404, error: "Domain Not Found",   message: "Could not resolve domain name" };
  if (err.code === "ECONNREFUSED")                               return { status: 502, error: "Connection Refused", message: "Website refused the connection" };
  if (err.code?.startsWith("ERR_TLS") || err.code === "CERT_HAS_EXPIRED") return { status: 502, error: "SSL Error", message: "Invalid or expired SSL certificate" };
  if (err.message?.includes("Invalid URL"))                      return { status: 400, error: "Invalid URL",        message: "The provided URL is not valid" };
  return { status: 500, error: "Internal Server Error", message: "Failed to fetch website metadata" };
}

// ═══════════════════════════════════════════════════════════════════════════
//  ROUTE: GET /api  or  GET /api/meta  or  GET /
//
//  This is the endpoint your Android code already calls:
//    https://counter-azure-nine.vercel.app/api?url=<encoded>
//
//  Unchanged behaviour for single ?url=.
//  Also now supports:
//    ?url=a&url=b          (multi, repeated param)
//    ?urls=a,b,c           (multi, comma-separated)
//    ?nocache=1            (bypass cache)
// ═══════════════════════════════════════════════════════════════════════════

async function handleMeta(req, res) {
  const ip = clientIp(req);

  // Collect URLs — backwards-compatible: single ?url still works exactly as before
  let rawUrls = [];
  const q = req.query.urls || req.query.url;
  if (Array.isArray(q))           rawUrls = q;
  else if (typeof q === "string") rawUrls = q.includes(",") ? q.split(",").map((u) => u.trim()) : [q];
  rawUrls = rawUrls.filter(Boolean).slice(0, 10);

  if (!rawUrls.length)
    return res.status(400).json({ success: false, error: "Missing ?url= parameter" });

  // Consume one RL slot per URL
  let lastRl;
  for (let i = 0; i < rawUrls.length; i++) {
    const rl = checkRL(ip);
    lastRl = rl;
    if (!rl.ok) {
      res.setHeader("Retry-After", String(rl.retryAfter ?? 3600));
      res.setHeader("X-RateLimit-Remaining", "0");
      return res.status(429).json({
        success:    false,
        error:      "Rate Limit Exceeded",
        message:    rl.reason === "hard_block"
          ? "Too many violations — temporarily blocked for 1 hour."
          : "You have used all 50 daily requests. Resets in 24 hours.",
        retryAfter: rl.retryAfter,
        rateLimit:  rlPayload(rl),
      });
    }
  }

  res.setHeader("X-RateLimit-Limit",     String(lastRl.limit));
  res.setHeader("X-RateLimit-Remaining", String(lastRl.remaining));
  res.setHeader("X-RateLimit-Reset",     String(Math.floor(lastRl.resetAt / 1000)));

  const nocache = req.query.nocache === "1";

  // ── SINGLE URL — identical response to original handler ──────────────────
  if (rawUrls.length === 1) {
    const { err: urlErr, parsed } = validateUrl(rawUrls[0]);
    if (urlErr) return res.status(400).json({ success: false, error: urlErr });

    const key = `meta:${parsed.href}`;

    if (!nocache) {
      const hit = cGet(key);
      if (hit) {
        res.setHeader("X-Cache", "HIT");
        // Inject rateLimit fresh — never read from cache
        return res.status(200).json({ ...hit, rateLimit: rlPayload(lastRl) });
      }
    }
    res.setHeader("X-Cache", "MISS");

    try {
      const result = await scrape(parsed.href);
      cSet(key, result);
      // rateLimit appended — your Android code ignores unknown keys so this is safe
      return res.status(200).json({ ...result, rateLimit: rlPayload(lastRl) });
    } catch (err) {
      const { status, error, message } = mapErr(err);
      return res.status(status).json({
        success: false, error, message,
        details: process.env.NODE_ENV === "development" ? err.message : undefined,
      });
    }
  }

  // ── MULTIPLE URLS — returns { success, count, results[], rateLimit } ─────
  res.setHeader("X-Cache", "MULTI");

  const settled = await Promise.allSettled(
    rawUrls.map(async (raw) => {
      const { err: urlErr, parsed } = validateUrl(raw);
      if (urlErr) return { success: false, url: raw, error: urlErr };
      if (!nocache) { const hit = cGet(`meta:${parsed.href}`); if (hit) return { ...hit, _fromCache: true }; }
      try {
        const result = await scrape(parsed.href);
        cSet(`meta:${parsed.href}`, result);
        return result;
      } catch (err) {
        const { error, message } = mapErr(err);
        return { success: false, url: raw, error, message };
      }
    })
  );

  return res.status(200).json({
    success:   true,
    count:     settled.length,
    results:   settled.map((r) => r.status === "fulfilled" ? r.value : { success: false, error: r.reason?.message }),
    rateLimit: rlPayload(lastRl),
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  ROUTE: POST /api/batch  { urls: [...] }  max 10
//         ?full=1 → full metadata per URL (default = lite)
// ═══════════════════════════════════════════════════════════════════════════

async function handleBatch(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ success: false, error: "Use POST for /api/batch" });

  const ip   = clientIp(req);
  const urls = req.body?.urls;

  if (!Array.isArray(urls) || !urls.length)
    return res.status(400).json({ success: false, error: "Body must include { urls: string[] }" });
  if (urls.length > 10)
    return res.status(400).json({ success: false, error: "Max 10 URLs per batch" });

  let lastRl;
  for (let i = 0; i < urls.length; i++) {
    const rl = checkRL(ip);
    lastRl = rl;
    if (!rl.ok) {
      res.setHeader("Retry-After", String(rl.retryAfter ?? 3600));
      return res.status(429).json({ success: false, error: "Rate Limit Exceeded", message: `Hit limit at URL ${i + 1}.`, retryAfter: rl.retryAfter, rateLimit: rlPayload(rl) });
    }
  }

  res.setHeader("X-RateLimit-Limit",     String(lastRl.limit));
  res.setHeader("X-RateLimit-Remaining", String(lastRl.remaining));
  res.setHeader("X-RateLimit-Reset",     String(Math.floor(lastRl.resetAt / 1000)));

  const full = req.query.full === "1";

  const settled = await Promise.allSettled(
    urls.map(async (raw) => {
      const { err: urlErr, parsed } = validateUrl(raw);
      if (urlErr) return { success: false, url: raw, error: urlErr };

      const hit = cGet(`meta:${parsed.href}`);
      if (hit) return full ? { ...hit, _fromCache: true } : lite(hit);

      try {
        const result = await scrape(parsed.href);
        cSet(`meta:${parsed.href}`, result);
        return full ? result : lite(result);
      } catch (err) {
        const { error, message } = mapErr(err);
        return { success: false, url: raw, error, message };
      }
    })
  );

  return res.status(200).json({
    success:   true,
    count:     settled.length,
    results:   settled.map((r) => r.status === "fulfilled" ? r.value : { success: false, error: r.reason?.message }),
    rateLimit: rlPayload(lastRl),
  });
}

// Lite response for batch — just the essentials
function lite(r) {
  return {
    success:     r.success,
    url:         r.url,
    title:       r.title,
    description: r.description,
    siteName:    r.siteName,
    domain:      r.domain,
    image:       r.images?.primary  || null,    // flat convenience key
    thumbnail:   r.images?.primary  || null,    // alias
    favicon:     r.icons?.primary   || null,
    themeColor:  r.metadata?.appearance?.themeColor || null,
    responseInfo: r.responseInfo,
    _fromCache:  r._fromCache,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  ROUTE: GET /api/health
//  Original shape preserved. Bonus fields added.
// ═══════════════════════════════════════════════════════════════════════════

function handleHealth(req, res) {
  const up  = process.uptime();
  const mem = process.memoryUsage();
  const fmtUp = (s) => [
    Math.floor(s / 86400)          && `${Math.floor(s / 86400)}d`,
    Math.floor((s % 86400) / 3600) && `${Math.floor((s % 86400) / 3600)}h`,
    Math.floor((s % 3600)  / 60)   && `${Math.floor((s % 3600)  / 60)}m`,
    `${Math.floor(s % 60)}s`,
  ].filter(Boolean).join(" ");
  const fmtB = (b) => `${(b / 1024 / 1024).toFixed(1)} MB`;

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

  return res.status(200).json({
    // ── Original health fields — unchanged ──────────────────────────────
    status:      "online",
    service:     "Meta Fetcher API",
    madeBy:      "Cyber Coder",
    timestamp:   new Date().toISOString(),
    uptime:      process.uptime(),     // original was a plain number
    version:     "2.1.0",
    environment: process.env.NODE_ENV || "development",
    // ── Bonus fields ─────────────────────────────────────────────────────
    uptimeHuman: fmtUp(up),
    memory:      { heapUsed: fmtB(mem.heapUsed), heapTotal: fmtB(mem.heapTotal), rss: fmtB(mem.rss) },
    rateLimit:   { trackedIPs: rlStore.size, maxRequests: RL.MAX_REQ, windowHours: 24 },
    cache:       (() => {
      const now = Date.now(); let exp = 0;
      for (const e of cache.values()) if (now > e.exp) exp++;
      return { total: cache.size, active: cache.size - exp, expired: exp, maxEntries: CACHE.MAX };
    })(),
    endpoints: {
      // ← same path your Android code calls
      api:       "GET  /api?url=<url>                    (original endpoint)",
      meta:      "GET  /api/meta?url=<url>               (alias)",
      multiGet:  "GET  /api?url=a&url=b  OR  ?urls=a,b   (multi, max 10)",
      batch:     "POST /api/batch  { urls:[] }            (lite, max 10)",
      batchFull: "POST /api/batch?full=1  { urls:[] }     (full metadata)",
      health:    "GET  /api/health",
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN ROUTER
// ═══════════════════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  // CORS — same as original
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method === "OPTIONS") return res.status(200).end();

  const path = (req.url?.split("?")[0] || "/").replace(/\/+$/, "") || "/";

  // Health
  if (path === "/api/health" || path === "/health")
    return handleHealth(req, res);

  // Batch (new)
  if (path === "/api/batch" || path === "/batch")
    return handleBatch(req, res);

  // ↓ Original endpoint — /api  is what your Android code calls
  //   /api/meta is an alias for convenience
  if (path === "/api" || path === "/api/meta" || path === "/meta" || path === "/" || path === "")
    return handleMeta(req, res);

  return res.status(404).json({
    success: false,
    error:   "Not Found",
    endpoints: {
      api:    "GET  /api?url=<url>",
      batch:  "POST /api/batch",
      health: "GET  /api/health",
    },
  });
}
