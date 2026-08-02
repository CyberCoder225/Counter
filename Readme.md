# 🌐 Meta Fetcher API

A high-performance, serverless-ready metadata scraper designed to reliably extract Open Graph data, titles, descriptions, and high-quality images from any URL. 

Built with smart User-Agent rotation to bypass bot protections on social platforms like WhatsApp, Telegram, Twitter/X, and Facebook. Perfect as a robust backend utility for Android applications and automated bots.

Created by **Cyber Coder**

---

## ✨ Features

- **Smart Social Scraping:** Automatically swaps to crawler User-Agents (Twitterbot, WhatsApp crawler, etc.) for social domains to guarantee metadata extraction.
- **100% Backward Compatible:** Preserves legacy Android app JSON structures (`json.optJSONObject("images").optString("primary")`) so client-side code doesn't break.
- **In-Memory Rate Limiting:** Built-in protection (50 requests/24h per IP) with 1-hour hard blocks for repeat abusers. No Redis required.
- **Fast Caching:** 10-minute TTL cache to reduce external network requests and speed up response times for popular links.
- **Batch Processing:** Fetch metadata for up to 10 URLs in a single API call to save bandwidth.
- **Vercel & Termux Ready:** Runs flawlessly in serverless environments (Vercel) or local Termux Node.js deployments.

---

## 🚀 Endpoints

### 1. Scrape Single URL (GET)
The primary endpoint for fetching metadata.

**Request:**
`GET /api?url=https://t.me/telegram`

**Response (Legacy-Compatible):**
```json
{
  "success": true,
  "url": "[https://t.me/telegram](https://t.me/telegram)",
  "title": "Telegram Messenger",
  "description": "A new era of messaging.",
  "images": {
    "primary": "[https://telegram.org/img/t_logo.png](https://telegram.org/img/t_logo.png)",
    "thumbnail": "[https://telegram.org/img/t_logo.png](https://telegram.org/img/t_logo.png)"
  },
  "rateLimit": {
    "limit": 50,
    "remaining": 49,
    "window": "24h"
  }
}
