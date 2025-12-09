import axios from "axios";
import * as cheerio from "cheerio";

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ 
      success: false,
      error: 'Method not allowed' 
    });
  }

  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({ 
        success: false,
        error: "Missing ?url= parameter" 
      });
    }

    // Basic URL validation
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
      
      // Block private/localhost URLs
      const hostname = parsedUrl.hostname;
      if (hostname.includes('localhost') || 
          hostname.includes('127.0.0.1') || 
          hostname.includes('192.168.') ||
          hostname.includes('10.') ||
          hostname.startsWith('172.')) {
        return res.status(403).json({
          success: false,
          error: "Local/private URLs are not allowed"
        });
      }

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

    // Fetch the page with timeout
    const response = await axios.get(url, {
      timeout: 8000,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br"
      },
      maxRedirects: 5,
      validateStatus: (status) => status < 500,
      decompress: true
    });

    const $ = cheerio.load(response.data);

    // 1. TITLE
    const title = $('meta[property="og:title"]').attr("content")?.trim() ||
                  $('meta[name="twitter:title"]').attr("content")?.trim() ||
                  $("title").text()?.trim() ||
                  $('h1').first().text()?.trim() ||
                  null;

    // 2. DESCRIPTION
    const description = $('meta[property="og:description"]').attr("content")?.trim() ||
                       $('meta[name="twitter:description"]').attr("content")?.trim() ||
                       $('meta[name="description"]').attr("content")?.trim() ||
                       null;

    // 3. IMAGES - Simplified and robust
    const extractImages = () => {
      const images = [];
      
      // Open Graph Images
      $('meta[property="og:image"], meta[property="og:image:url"]').each((_, el) => {
        const imgUrl = $(el).attr("content");
        if (imgUrl && !imgUrl.startsWith('data:')) {
          images.push({
            url: imgUrl,
            type: 'og',
            width: $(el).siblings('meta[property="og:image:width"]').attr("content") || null,
            height: $(el).siblings('meta[property="og:image:height"]').attr("content") || null
          });
        }
      });
      
      // Twitter Images
      $('meta[name="twitter:image"], meta[name="twitter:image:src"]').each((_, el) => {
        const imgUrl = $(el).attr("content");
        if (imgUrl && !imgUrl.startsWith('data:')) {
          images.push({
            url: imgUrl,
            type: 'twitter',
            card: $(el).closest('meta[name="twitter:card"]').attr("content") || null
          });
        }
      });
      
      // Apple Touch Icons (often high quality)
      $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
        const imgUrl = $(el).attr("href");
        if (imgUrl) {
          images.push({
            url: imgUrl,
            type: 'apple-touch-icon',
            sizes: $(el).attr("sizes") || '180x180'
          });
        }
      });
      
      // First large content image
      let contentImage = null;
      $('img[src]').each((_, el) => {
        if (!contentImage) {
          const src = $(el).attr("src");
          const width = parseInt($(el).attr("width") || "0");
          const alt = $(el).attr("alt") || "";
          
          if (src && !src.startsWith('data:') && width > 300) {
            contentImage = {
              url: src,
              type: 'content',
              width: width,
              height: parseInt($(el).attr("height") || "0"),
              alt: alt.substring(0, 100)
            };
          }
        }
      });
      
      // Resolve URLs
      const resolveUrl = (imgUrl) => {
        if (!imgUrl) return null;
        try {
          return new URL(imgUrl, url).href;
        } catch {
          return imgUrl.startsWith('http') ? imgUrl : null;
        }
      };
      
      const resolvedImages = images
        .map(img => ({
          ...img,
          url: resolveUrl(img.url)
        }))
        .filter(img => img.url);
      
      // Find primary image (largest OG or first available)
      let primaryImage = null;
      if (resolvedImages.length > 0) {
        // Prefer OG images
        const ogImages = resolvedImages.filter(img => img.type === 'og');
        if (ogImages.length > 0) {
          primaryImage = ogImages[0].url;
        } else {
          primaryImage = resolvedImages[0].url;
        }
      } else if (contentImage) {
        primaryImage = resolveUrl(contentImage.url);
      }
      
      return {
        primary: primaryImage,
        all: resolvedImages,
        contentImage: contentImage ? {
          ...contentImage,
          url: resolveUrl(contentImage.url)
        } : null
      };
    };

    // 4. ICONS - Simplified
    const extractIcons = () => {
      const icons = [];
      
      // Standard icons
      $('link[rel="icon"], link[rel="shortcut icon"]').each((_, el) => {
        const href = $(el).attr("href");
        if (href) {
          icons.push({
            url: href,
            sizes: $(el).attr("sizes") || '16x16',
            type: $(el).attr("type") || 'icon'
          });
        }
      });
      
      // Apple icons
      $('link[rel="apple-touch-icon"]').each((_, el) => {
        const href = $(el).attr("href");
        if (href) {
          icons.push({
            url: href,
            sizes: $(el).attr("sizes") || '180x180',
            type: 'apple-touch-icon'
          });
        }
      });
      
      // Manifest icons (without fetching manifest to avoid crashes)
      const manifestHref = $('link[rel="manifest"]').attr("href");
      
      // Resolve URLs and sort by size
      const resolveUrl = (iconUrl) => {
        if (!iconUrl) return null;
        try {
          return new URL(iconUrl, url).href;
        } catch {
          return iconUrl.startsWith('http') ? iconUrl : null;
        }
      };
      
      const resolvedIcons = icons
        .map(icon => ({
          ...icon,
          url: resolveUrl(icon.url)
        }))
        .filter(icon => icon.url)
        .sort((a, b) => {
          // Sort by estimated size (largest first)
          const getSize = (icon) => {
            if (!icon.sizes) return 0;
            const match = icon.sizes.match(/(\d+)x(\d+)/);
            return match ? parseInt(match[1]) * parseInt(match[2]) : 0;
          };
          return getSize(b) - getSize(a);
        });
      
      return {
        primary: resolvedIcons[0]?.url || new URL('/favicon.ico', url).href,
        all: resolvedIcons,
        hasManifest: !!manifestHref
      };
    };

    // 5. ADDITIONAL METADATA
    const siteName = $('meta[property="og:site_name"]').attr("content")?.trim() ||
                    parsedUrl.hostname.replace(/^www\./, '').split('.')[0] ||
                    parsedUrl.hostname;
    
    const keywords = $('meta[name="keywords"]').attr("content")?.split(',').map(k => k.trim()).filter(k => k) || [];
    
    const author = $('meta[name="author"]').attr("content") ||
                   $('meta[property="article:author"]').attr("content") ||
                   null;
    
    const themeColor = $('meta[name="theme-color"]').attr("content") ||
                      $('meta[name="msapplication-TileColor"]').attr("content") ||
                      null;
    
    const twitterCard = $('meta[name="twitter:card"]').attr("content");
    const twitterSite = $('meta[name="twitter:site"]').attr("content");
    const twitterCreator = $('meta[name="twitter:creator"]').attr("content");
    
    const contentType = $('meta[property="og:type"]').attr("content") || 'website';
    
    // 6. Extract images and icons
    const images = extractImages();
    const icons = extractIcons();

    // 7. RESPONSE
    const result = {
      success: true,
      url: parsedUrl.href,
      title,
      description,
      siteName,
      hostname: parsedUrl.hostname,
      domain: parsedUrl.hostname.replace(/^www\./, ''),
      metadata: {
        basic: {
          title,
          description,
          keywords: keywords.length > 0 ? keywords : undefined,
          author,
          contentType,
          language: $('html').attr('lang') || 'en'
        },
        social: {
          twitter: {
            card: twitterCard,
            site: twitterSite,
            creator: twitterCreator
          }
        },
        appearance: {
          themeColor
        }
      },
      images: {
        primary: images.primary,
        count: images.all.length,
        samples: images.all.slice(0, 3) // Return first 3 images
      },
      icons: {
        primary: icons.primary,
        count: icons.all.length,
        all: icons.all.slice(0, 5) // Return first 5 icons
      },
      responseInfo: {
        status: response.status,
        contentType: response.headers['content-type']?.split(';')[0],
        server: response.headers['server']
      }
    };

    return res.status(200).json(result);

  } catch (err) {
    console.error("API Error:", err.message);
    
    // Better error responses
    let status = 500;
    let error = "Internal Server Error";
    let message = "Failed to fetch website metadata";
    
    if (err.code === 'ECONNABORTED') {
      status = 408;
      error = "Request Timeout";
      message = "Website took too long to respond";
    } else if (err.code === 'ENOTFOUND') {
      status = 404;
      error = "Domain Not Found";
      message = "Could not resolve domain name";
    } else if (err.response) {
      status = err.response.status;
      error = `HTTP ${status}`;
      message = `Website returned ${status}`;
    } else if (err.message.includes('Invalid URL')) {
      status = 400;
      error = "Invalid URL";
      message = "The provided URL is not valid";
    }
    
    return res.status(status).json({
      success: false,
      error,
      message,
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
        }
