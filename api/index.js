import axios from "axios";
import * as cheerio from "cheerio";

// ═══════════════════════════════════════════════════════════════
//  IN-MEMORY RATE LIMITER  (no Redis, no MongoDB)
//  Sliding window — 50 req / 24h per IP
//  Violation escalation → 1h hard block after 5 violations
// ═══════════════════════════════════════════════════════════════

const rlStore = new Map();

const RL_CONFIG = {
  WINDOW_MS:        24 * 60 * 60 * 1000, // 24 hours
  MAX_REQUESTS:     50,
  BLOCK_THRESHOLD:  5,                    // violations before hard block
  BLOCK_DURATION:   60 * 60 * 1000,       // 1 hour hard block
  CLEANUP_INTERVAL: 30 * 60 * 1000,       // clean stale IPs every 30 min
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, d] of rlStore.entries()) {
    if (now > d.resetAt && now > (d.blockedUntil || 0)) rlStore.delete(ip);
  }
}, RL_CONFIG.CLEANUP_INTERVAL);

function checkRateLimit(ip) {
  const now = Date.now();
  let r = rlStore.get(ip);

  if (!r || now > r.resetAt) {
    r = {
      count:       0,
      resetAt:     now + RL_CONFIG.WINDOW_MS,
      violations:  r?.violations  || 0,
      blockedUntil: r?.blockedUntil || 0,
    };
  }

  // Hard blocked
  if (r.blockedUntil && now < r.blockedUntil) {
    return {
      allowed: false, remaining: 0, resetAt: r.resetAt,
      retryAfter: Math.ceil((r.blockedUntil - now) / 1000),
      reason: "hard_block",
    };
  }

  // Daily limit hit
  if (r.count >= RL_CONFIG.MAX_REQUESTS) {
    r.violations++;
    if (r.violations >= RL_CONFIG.BLOCK_THRESHOLD) {
      r.blockedUntil = now + RL_CONFIG.BLOCK_DURATION;
    }
    rlStore.set(ip, r);
    return {
      allowed: false, remaining: 0, resetAt: r.resetAt,
      retryAfter: Math.ceil((r.resetAt - now) / 1000),
      reason: r.blockedUntil ? "hard_block" : "daily_limit",
    };
  }

  r.count++;
  rlStore.set(ip, r);
  return {
    allowed: true,
    remaining: RL_CONFIG.MAX_REQUESTS - r.count,
    resetAt:   r.resetAt,
    limit:     RL_CONFIG.MAX_REQUESTS,
  };
}

// ═══════════════════════════════════════════════════════════════
//  IN-MEMORY CACHE  (LRU-ish + TTL)
//  10 min TTL, max 500 entries, auto-evicts oldest
// ═══════════════════════════════════════════════════════════════

const cacheStore = new Map();

const CACHE_CONFIG = {
  DEFAULT_TTL: 10 * 60 * 1000, // 10 minutes
  MAX_ENTRIES: 500,
  CLEANUP_INTERVAL: 5 * 60 * 1000,
};

setInterval(() => {
  const now = Date.now();
  for (const [k, e] of cacheStore.entries()) {
    if (now > e.expiresAt) cacheStore.delete(k);
  }
}, CACHE_CONFIG.CLEANUP_INTERVAL);

function cacheGet(key) {
  const e = cacheStore.get(key);
  if (!e) return null;
  if (Date.now() > e.expiresAt) { cacheStore.delete(key); return null; }
  e.hits = (e.hits || 0) + 1;
  return e.value;
}

function cacheSet(key, value, ttl = CACHE_CONFIG.DEFAULT_TTL) {
  if (cacheStore.size >= CACHE_CONFIG.MAX_ENTRIES) {
    cacheStore.delete(cacheStore.keys().next().value);
  }
  cacheStore.set(key, { value, expiresAt: Date.now() + ttl, cachedAt: Date.now(), hits: 0 });
}

function getCacheStats() {
  const now = Date.now();
  let expired = 0;
  for (const e of cacheStore.values()) if (now > e.expiresAt) expired++;
  return { total: cacheStore.size, active: cacheStore.size - expired, expired, maxEntries: CACHE_CONFIG.MAX_ENTRIES };
}

function getRlStats() {
  return { trackedIPs: rlStore.size, maxRequests: RL_CONFIG.MAX_REQUESTS, windowHours: 24 };
}

// ═══════════════════════════════════════════════════════════════
//  SECURITY HELPERS
// ═══════════════════════════════════════════════════════════════

const BLOCKED_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal", "169.254.169.254"]);
const PRIVATE_IP_RE = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^fc00:/, /^fe80:/];

function isPrivateHost(h) {
  return BLOCKED_HOSTS.has(h) || PRIVATE_IP_RE.some((r) => r.test(h));
}

function getClientIp(req) {
  return (
    req.headers["x-real-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

// ═══════════════════════════════════════════════════════════════
//  METADATA EXTRACTORS
// ═══════════════════════════════════════════════════════════════

function resolveUrl(base, rel) {
  if (!rel) return null;
  try { return new URL(rel, base).href; } catch { return rel.startsWith("http") ? rel : null; }
}

function extractTitle($) {
  return (
    $('meta[property="og:title"]').attr("content")?.trim() ||
    $('meta[name="twitter:title"]').attr("content")?.trim() ||
    $('meta[name="title"]').attr("content")?.trim() ||
    $("title").text()?.trim() ||
    $("h1").first().text()?.trim() ||
    null
  );
}

function extractDescription($) {
  return (
    $('meta[property="og:description"]').attr("content")?.trim() ||
    $('meta[name="twitter:description"]').attr("content")?.trim() ||
    $('meta[name="description"]').attr("content")?.trim() ||
    $('meta[itemprop="description"]').attr("content")?.trim() ||
    null
  );
}

function extractImages($, baseUrl) {
  const seen = new Set();
  const images = [];

  const add = (url, meta = {}) => {
    const r = resolveUrl(baseUrl, url);
    if (r && !seen.has(r) && !r.startsWith("data:")) { seen.add(r); images.push({ url: r, ...meta }); }
  };

  $('meta[property="og:image"], meta[property="og:image:url"]').each((_, el) => {
    add($(el).attr("content"), {
      type: "og",
      width:  $('meta[property="og:image:width"]').attr("content")  || null,
      height: $('meta[property="og:image:height"]').attr("content") || null,
      alt:    $('meta[property="og:image:alt"]').attr("content")    || null,
    });
  });

  $('meta[name="twitter:image"], meta[name="twitter:image:src"]').each((_, el) => {
    add($(el).attr("content"), { type: "twitter" });
  });

  // JSON-LD image
  $('script[type="application/ld+json"]').each((_, el) => {
    try {
      const j = JSON.parse($(el).html());
      const img = j?.image?.url || j?.image || j?.logo?.url;
      if (typeof img === "string") add(img, { type: "schema" });
    } catch {}
  });

  $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
    add($(el).attr("href"), { type: "apple-touch-icon", sizes: $(el).attr("sizes") || "180x180" });
  });

  $("img[src]").each((_, el) => {
    const src = $(el).attr("src");
    const w = parseInt($(el).attr("width") || "0");
    const h = parseInt($(el).attr("height") || "0");
    if (w > 300 || h > 300) {
      add(src, { type: "content", width: w || null, height: h || null, alt: ($(el).attr("alt") || "").substring(0, 100) || null });
    }
  });

  const primary =
    images.find((i) => i.type === "og")?.url     ||
    images.find((i) => i.type === "twitter")?.url ||
    images[0]?.url || null;

  return { primary, all: images, count: images.length };
}

function extractIcons($, baseUrl) {
  const seen = new Set();
  const icons = [];

  const add = (href, meta = {}) => {
    const r = resolveUrl(baseUrl, href);
    if (r && !seen.has(r)) { seen.add(r); icons.push({ url: r, ...meta }); }
  };

  $('link[rel~="icon"], link[rel="shortcut icon"]').each((_, el) => {
    add($(el).attr("href"), { type: "favicon", sizes: $(el).attr("sizes") || null, mimeType: $(el).attr("type") || null });
  });

  $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
    add($(el).attr("href"), { type: "apple-touch-icon", sizes: $(el).attr("sizes") || "180x180" });
  });

  $('meta[name="msapplication-TileImage"]').each((_, el) => {
    add($(el).attr("content"), { type: "ms-tile" });
  });

  icons.sort((a, b) => {
    const sz = (s) => { const m = s?.match(/(\d+)x(\d+)/i); return m ? parseInt(m[1]) * parseInt(m[2]) : 0; };
    return sz(b.sizes) - sz(a.sizes);
  });

  return {
    primary: icons[0]?.url || resolveUrl(baseUrl, "/favicon.ico"),
    all: icons.slice(0, 8),
    count: icons.length,
    manifestPresent: !!$('link[rel="manifest"]').attr("href"),
  };
}

function extractOpenGraph($) {
  const og = {};
  $("meta[property^='og:']").each((_, el) => {
    const k = $(el).attr("property")?.replace("og:", "");
    if (k && !og[k]) og[k] = $(el).attr("content")?.trim();
  });
  return og;
}

function extractTwitterCard($) {
  const tc = {};
  $("meta[name^='twitter:']").each((_, el) => {
    const k = $(el).attr("name")?.replace("twitter:", "");
    if (k && !tc[k]) tc[k] = $(el).attr("content")?.trim();
  });
  return tc;
}

function extractLinks($, baseUrl) {
  const canonical = $('link[rel="canonical"]').attr("href") || $('meta[property="og:url"]').attr("content") || null;
  const alternates = [];
  $('link[rel="alternate"]').each((_, el) => {
    const href = $(el).attr("href");
    if (href) alternates.push({ href: resolveUrl(baseUrl, href), hreflang: $(el).attr("hreflang") || null, type: $(el).attr("type") || null });
  });
  return { canonical: canonical ? resolveUrl(baseUrl, canonical) : null, alternates: alternates.slice(0, 5) };
}

function extractReadability($) {
  const bodyText = $("body").text().replace(/\s+/g, " ").trim();
  const wordCount = bodyText.split(/\s+/).filter(Boolean).length;
  const headings = { h1: $("h1").length, h2: $("h2").length, h3: $("h3").length };
  return { wordCount, readingTimeMin: Math.ceil(wordCount / 200), headings };
}

function extractStructuredData($) {
  const out = [];
  $('script[type="application/ld+json"]').each((_, el) => {
    try { out.push(JSON.parse($(el).html())); } catch {}
  });
  return out.slice(0, 3);
}

// ═══════════════════════════════════════════════════════════════
//  FETCH HELPER  (shared by /meta and /batch)
// ═══════════════════════════════════════════════════════════════

async function fetchPageMeta(url, lite = false) {
  const cacheKey = `meta:${url}`;
  const cached = cacheGet(cacheKey);
  if (cached) return { ...cached, _fromCache: true };

  const response = await axios.get(url, {
    timeout: 10_000,
    maxContentLength: 5 * 1024 * 1024,
    maxRedirects: 5,
    decompress: true,
    validateStatus: (s) => s < 500,
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Cache-Control": "no-cache",
    },
  });

  if (response.status >= 400) {
    throw Object.assign(new Error(`HTTP ${response.status}`), { httpStatus: response.status });
  }

  const $ = cheerio.load(response.data);
  const parsedUrl = new URL(url);
  const base = parsedUrl.href;

  // Lite mode = fast minimal payload (used by /batch)
  if (lite) {
    const result = {
      success: true,
      url,
      title: extractTitle($),
      description: extractDescription($),
      image: resolveUrl(base, $('meta[property="og:image"]').attr("content")) ||
             resolveUrl(base, $('meta[name="twitter:image"]').attr("content")) || null,
      favicon: resolveUrl(base, $('link[rel="icon"]').first().attr("href")) ||
               resolveUrl(base, $('link[rel="shortcut icon"]').attr("href")) ||
               `${parsedUrl.origin}/favicon.ico`,
      themeColor: $('meta[name="theme-color"]').attr("content") || null,
      domain: parsedUrl.hostname.replace(/^www\./, ""),
      responseStatus: response.status,
      fetchedAt: new Date().toISOString(),
    };
    cacheSet(cacheKey, result);
    return result;
  }

  // Full mode
  const og     = extractOpenGraph($);
  const tc     = extractTwitterCard($);
  const images = extractImages($, base);
  const icons  = extractIcons($, base);
  const links  = extractLinks($, base);

  const result = {
    success: true,
    url: parsedUrl.href,
    domain: parsedUrl.hostname.replace(/^www\./, ""),
    hostname: parsedUrl.hostname,
    title: extractTitle($),
    description: extractDescription($),
    siteName: og?.site_name?.trim() || parsedUrl.hostname.replace(/^www\./, "").split(".")[0],
    themeColor: $('meta[name="theme-color"]').attr("content")?.trim() || $('meta[name="msapplication-TileColor"]').attr("content")?.trim() || null,
    images: { primary: images.primary, count: images.count, samples: images.all.slice(0, 5) },
    icons: { primary: icons.primary, count: icons.count, all: icons.all, manifestPresent: icons.manifestPresent },
    metadata: {
      basic: {
        title:       extractTitle($),
        description: extractDescription($),
        keywords:    $('meta[name="keywords"]').attr("content")?.split(",").map((k) => k.trim()).filter(Boolean) || [],
        author:      $('meta[name="author"]').attr("content")?.trim() || $('meta[property="article:author"]').attr("content")?.trim() || tc?.creator || null,
        language:    $("html").attr("lang")?.trim() || null,
        robots:      $('meta[name="robots"]').attr("content")?.trim() || null,
        viewport:    $('meta[name="viewport"]').attr("content")?.trim() || null,
        charset:     $("meta[charset]").attr("charset") || null,
      },
      openGraph: og,
      twitterCard: tc,
      links,
      publication: {
        publishedTime: $('meta[property="article:published_time"]').attr("content") || $('meta[name="date"]').attr("content") || null,
        modifiedTime:  $('meta[property="article:modified_time"]').attr("content") || null,
        section:       $('meta[property="article:section"]').attr("content") || null,
        tags:          $('meta[property="article:tag"]').map((_, el) => $(el).attr("content")).get(),
        type:          og?.type || "website",
      },
      appearance: {
        themeColor:  $('meta[name="theme-color"]').attr("content")?.trim() || null,
        colorScheme: $('meta[name="color-scheme"]').attr("content") || null,
      },
      readability: extractReadability($),
      structuredData: extractStructuredData($),
    },
    response: {
      status: response.status,
      contentType: response.headers["content-type"]?.split(";")[0]?.trim() || null,
      server: response.headers["server"] || null,
      fetchedAt: new Date().toISOString(),
    },
  };

  cacheSet(cacheKey, result);
  return result;
}

function handleFetchError(err) {
  if (err.httpStatus)               return { status: err.httpStatus, error: `HTTP ${err.httpStatus}`,   message: `Target returned status ${err.httpStatus}` };
  if (err.code === "ECONNABORTED" ||
      err.code === "ETIMEDOUT")     return { status: 408, error: "Request Timeout",     message: "Website took too long to respond" };
  if (err.code === "ENOTFOUND")     return { status: 404, error: "Domain Not Found",    message: "Could not resolve the domain" };
  if (err.code === "ECONNREFUSED")  return { status: 502, error: "Connection Refused",  message: "Website refused the connection" };
  if (err.code?.startsWith("ERR_TLS") ||
      err.code === "CERT_HAS_EXPIRED") return { status: 502, error: "SSL Error",        message: "Invalid or expired SSL certificate" };
  return { status: 500, error: "Internal Server Error", message: "Failed to fetch metadata" };
}

// ═══════════════════════════════════════════════════════════════
//  CORS + RATE-LIMIT HEADERS  (applied to every handler)
// ═══════════════════════════════════════════════════════════════

function applyBaseHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
}

function applyRlHeaders(res, rl) {
  res.setHeader("X-RateLimit-Limit",     String(RL_CONFIG.MAX_REQUESTS));
  res.setHeader("X-RateLimit-Remaining", String(rl.remaining ?? 0));
  res.setHeader("X-RateLimit-Reset",     String(Math.floor((rl.resetAt ?? Date.now()) / 1000)));
}

// ═══════════════════════════════════════════════════════════════
//  ROUTE HANDLERS
// ═══════════════════════════════════════════════════════════════

// GET /api/meta?url=<url>&nocache=1
async function handleMeta(req, res) {
  const clientIp = getClientIp(req);
  const rl = checkRateLimit(clientIp);
  applyRlHeaders(res, rl);

  if (!rl.allowed) {
    res.setHeader("Retry-After", String(rl.retryAfter ?? 3600));
    return res.status(429).json({
      success: false,
      error: "Rate Limit Exceeded",
      message: rl.reason === "hard_block"
        ? "Too many violations — you are temporarily blocked for 1 hour."
        : "You have used all 50 daily requests. Resets in 24 hours.",
      retryAfter: rl.retryAfter,
      resetAt: new Date(rl.resetAt).toISOString(),
      limit: { requests: 50, window: "24h" },
    });
  }

  const { url, nocache } = req.query;

  if (!url) return res.status(400).json({ success: false, error: "Missing ?url= parameter" });

  let parsedUrl;
  try { parsedUrl = new URL(url); } catch {
    return res.status(400).json({ success: false, error: "Invalid URL format" });
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol))
    return res.status(400).json({ success: false, error: "Only HTTP/HTTPS allowed" });

  if (isPrivateHost(parsedUrl.hostname))
    return res.status(403).json({ success: false, error: "Private/local URLs are blocked" });

  // Cache check
  const cacheKey = `meta:${parsedUrl.href}`;
  if (nocache !== "1") {
    const cached = cacheGet(cacheKey);
    if (cached) {
      res.setHeader("X-Cache", "HIT");
      return res.status(200).json({ ...cached, rateLimit: { remaining: rl.remaining, resetAt: new Date(rl.resetAt).toISOString(), limit: 50 } });
    }
  }
  res.setHeader("X-Cache", "MISS");

  try {
    const result = await fetchPageMeta(parsedUrl.href, false);
    return res.status(200).json({
      ...result,
      rateLimit: { remaining: rl.remaining, resetAt: new Date(rl.resetAt).toISOString(), limit: 50 },
    });
  } catch (err) {
    const { status, error, message } = handleFetchError(err);
    return res.status(status).json({ success: false, error, message });
  }
}

// POST /api/batch  { urls: ["url1", ...] }  max 5
async function handleBatch(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ success: false, error: "Use POST for /api/batch" });

  const clientIp = getClientIp(req);
  const urls = req.body?.urls;

  if (!Array.isArray(urls) || urls.length === 0)
    return res.status(400).json({ success: false, error: "Body must include { urls: string[] }" });

  if (urls.length > 5)
    return res.status(400).json({ success: false, error: "Max 5 URLs per batch request" });

  // Consume one RL slot per URL
  let lastRl;
  for (let i = 0; i < urls.length; i++) {
    const rl = checkRateLimit(clientIp);
    lastRl = rl;
    if (!rl.allowed) {
      res.setHeader("Retry-After", String(rl.retryAfter ?? 3600));
      return res.status(429).json({
        success: false,
        error: "Rate Limit Exceeded",
        message: `Hit rate limit after consuming ${i} slots in this batch.`,
        retryAfter: rl.retryAfter,
        resetAt: new Date(rl.resetAt).toISOString(),
      });
    }
  }

  applyRlHeaders(res, lastRl);

  const results = await Promise.allSettled(
    urls.map(async (u) => {
      try {
        new URL(u);
        return await fetchPageMeta(u, true /* lite */);
      } catch (err) {
        const { error, message } = handleFetchError(err);
        return { success: false, url: u, error, message };
      }
    })
  );

  return res.status(200).json({
    success: true,
    count: results.length,
    results: results.map((r) => (r.status === "fulfilled" ? r.value : { success: false, error: r.reason?.message })),
    rateLimit: { remaining: lastRl?.remaining, resetAt: new Date(lastRl?.resetAt ?? Date.now()).toISOString(), limit: 50 },
  });
}

// GET /api/health
function handleHealth(req, res) {
  const uptime = process.uptime();
  const fmt = (s) => [Math.floor(s / 86400) && `${Math.floor(s / 86400)}d`, Math.floor((s % 86400) / 3600) && `${Math.floor((s % 86400) / 3600)}h`, Math.floor((s % 3600) / 60) && `${Math.floor((s % 3600) / 60)}m`, `${Math.floor(s % 60)}s`].filter(Boolean).join(" ");
  const fmtB = (b) => `${(b / 1024 / 1024).toFixed(1)} MB`;
  const mem = process.memoryUsage();

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({
    status: "online",
    service: "Meta Fetcher API",
    version: "2.0.0",
    madeBy: "Cyber Coder",
    timestamp: new Date().toISOString(),
    uptime: { seconds: Math.floor(uptime), human: fmt(uptime) },
    memory: { heapUsed: fmtB(mem.heapUsed), heapTotal: fmtB(mem.heapTotal), rss: fmtB(mem.rss) },
    rateLimit: getRlStats(),
    cache: getCacheStats(),
    environment: process.env.NODE_ENV || "development",
    endpoints: {
      meta:   "GET  /api/meta?url=<url>          (full metadata, 1 RL slot)",
      batch:  "POST /api/batch { urls: string[] } (up to 5 URLs, 1 slot each)",
      health: "GET  /api/health                  (this endpoint)",
    },
  });
}

// ═══════════════════════════════════════════════════════════════
//  MAIN ROUTER  — single export, routes by path
// ═══════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  applyBaseHeaders(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  const path = req.url?.split("?")[0] || "";

  if (path === "/api/health" || path === "/health") {
    return handleHealth(req, res);
  }

  if (path === "/api/batch" || path === "/batch") {
    return handleBatch(req, res);
  }

  if (path === "/api/meta" || path === "/meta" || path === "/" || path === "") {
    return handleMeta(req, res);
  }

  return res.status(404).json({
    success: false,
    error: "Not Found",
    message: "Unknown endpoint",
    endpoints: {
      meta:   "GET  /api/meta?url=<url>",
      batch:  "POST /api/batch",
      health: "GET  /api/health",
    },
  });
}
