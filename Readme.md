# 🌐 Meta Fetcher API

A high-performance, serverless Node.js metadata scraper designed to reliably extract Open Graph data, titles, descriptions, and high-quality images from any URL. 

Built specifically to power Android applications (Sketchware/Java), automated bots (WhatsApp/Termux), and web apps without breaking existing client-side parsing.

Created by **Cyber Coder** 💻

---

## 🚀 Everything This API Does (Core Features)

This API is much more than just a basic HTML fetcher. Under the hood, it performs several advanced tasks to guarantee high-quality data extraction, security, and performance:

### 🕵️‍♂️ Advanced Scraping & Crawler Evasion
- **Smart User-Agent Spoofing:** Detects social links (`wa.me`, `t.me`, `twitter.com`, `instagram.com`, `facebook.com`, etc.) and automatically routes them through specialized crawler User-Agents (like Twitterbot or WhatsApp/2.23) to bypass bot-walls and extract hidden metadata.
- **Auto-Retry on Failure:** If a website rejects the initial request, the API automatically retries the connection using a `facebookexternalhit` User-Agent to force the site to yield its Open Graph tags.
- **Deep Image Extraction:** Doesn't just look for `og:image`. It hunts down images from Twitter cards, JSON-LD schema, Apple touch icons, `itemprop`, and raw HTML `<img>` tags if metadata is missing.

### 🛡️ Security & Stability
- **SSRF Protection:** Strict URL validation instantly blocks requests to private/local networks (e.g., `localhost`, `192.168.x.x`, AWS metadata IPs).
- **Client IP Detection:** Safely extracts the real user IP behind proxies, Cloudflare, Fastly, and Vercel using fallback headers (`x-forwarded-for`, `cf-connecting-ip`, etc.).
- **Smart Error Mapping:** Intercepts raw Node.js network errors (Timeouts, DNS failures, Expired SSLs) and translates them into clean, friendly JSON responses so your Android app never crashes.

### ⚡ Performance & Traffic Control
- **In-Memory Rate Limiting:** Limits users to 50 requests per 24 hours per IP. Repeat abusers (5+ violations) get automatically slapped with a 1-hour hard block.
- **Blazing Fast Cache:** Features an internal memory cache with a 10-minute TTL. Popular URLs are served instantly without making external network calls.
- **Batch Processing:** Can process up to 10 URLs in parallel in a single request.

### 🔄 100% Backward Compatibility
- Ensures that fields like `images.primary` and `images.thumbnail` are always present, meaning legacy Android Java/Sketchware code can consume this API with absolutely zero modifications.

---

## 📡 ALL Available Endpoints

### 1. The Scraper (GET)
*Scrape one or multiple URLs via query parameters.*

**Available Paths:**
- `GET /`
- `GET /api`
- `GET /meta`
- `GET /api/meta`

**Parameters:**
- `?url=<url>` : Fetch a single URL.
- `?url=<url1>&url=<url2>` : Fetch multiple URLs (up to 10).
- `?urls=<url1>,<url2>` : Fetch multiple URLs via comma-separated list.
- `?nocache=1` : Bypass the internal cache and force a fresh fetch from the target website.

**Example Usage:**
```http
GET /api?url=[https://t.me/telegram](https://t.me/telegram)
