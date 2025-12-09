import axios from "axios";
import * as cheerio from "cheerio";

export default async function handler(req, res) {
  // Set CORS headers for Vercel
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Only allow GET requests
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({ 
        success: false,
        error: "Missing ?url= parameter" 
      });
    }

    // Validate URL format
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
      
      // Security: Prevent SSRF attacks by blocking internal/private URLs
      const privateIPs = [
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^::1$/,
        /^fc00:/,
        /^fe80:/,
        /^::/
      ];
      
      const hostname = parsedUrl.hostname;
      if (privateIPs.some(regex => regex.test(hostname))) {
        return res.status(400).json({
          success: false,
          error: "Private/internal URLs are not allowed"
        });
      }
      
      // Only allow HTTP/HTTPS protocols
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(400).json({
          success: false,
          error: "Only HTTP and HTTPS protocols are allowed"
        });
      }
    } catch (err) {
      return res.status(400).json({
        success: false,
        error: "Invalid URL format"
      });
    }

    // Set timeout to avoid Vercel's 10s limit (recommend 8s max)
    const timeout = 8000;
    
    // Fetch HTML with better headers to avoid blocking
    const response = await axios.get(url, {
      timeout,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Cache-Control": "max-age=0"
      },
      maxRedirects: 5,
      validateStatus: function (status) {
        return status >= 200 && status < 400; // Accept 2xx and 3xx status codes
      },
      decompress: true
    });

    const $ = cheerio.load(response.data);

    // Extract metadata with fallbacks
    const title = $('meta[property="og:title"]').attr("content") ||
                  $('meta[name="twitter:title"]').attr("content") ||
                  $("title").text()?.trim() ||
                  $('h1').first().text()?.trim() ||
                  null;

    const description = $('meta[property="og:description"]').attr("content") ||
                       $('meta[name="twitter:description"]').attr("content") ||
                       $('meta[name="description"]').attr("content") ||
                       null;

    // Find favicon with multiple strategies
    let icon = null;
    
    // Try Apple touch icon first (often higher resolution)
    icon = $('link[rel="apple-touch-icon"]').attr("href") ||
           $('link[rel="apple-touch-icon-precomposed"]').attr("href");
    
    // Try standard favicon
    if (!icon) {
      icon = $('link[rel="icon"][sizes="32x32"], link[rel="icon"][sizes="16x16"]').attr("href") ||
             $('link[rel="shortcut icon"]').attr("href") ||
             $('link[rel="icon"]').attr("href");
    }
    
    // Default favicon location
    if (!icon) {
      icon = '/favicon.ico';
    }

    // Resolve relative URLs
    let fullIconUrl = null;
    try {
      fullIconUrl = new URL(icon, url).href;
    } catch (err) {
      // If URL construction fails, return as-is or null
      fullIconUrl = icon.startsWith('http') ? icon : null;
    }

    // Try to extract site name
    const siteName = $('meta[property="og:site_name"]').attr("content") || 
                     parsedUrl.hostname?.replace(/^www\./, '');

    return res.status(200).json({
      success: true,
      url: parsedUrl.href,
      title,
      description,
      icon: fullIconUrl,
      siteName,
      hostname: parsedUrl.hostname
    });

  } catch (err) {
    console.error("Vercel Function Error:", err.message);
    
    // Handle specific axios errors
    if (err.code === 'ECONNABORTED') {
      return res.status(408).json({
        success: false,
        error: "Request timeout",
        message: "The website took too long to respond"
      });
    }
    
    if (err.response) {
      return res.status(err.response.status).json({
        success: false,
        error: `Website returned ${err.response.status}`,
        message: "Failed to fetch the website"
      });
    }
    
    if (err.code === 'ENOTFOUND') {
      return res.status(404).json({
        success: false,
        error: "Website not found",
        message: "The domain could not be resolved"
      });
    }

    return res.status(500).json({
      success: false,
      error: "Failed to process request",
      message: err.message
    });
  }
        }
