import axios from "axios";
import * as cheerio from "cheerio";

export default async function handler(req, res) {
  // Enhanced CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ 
      success: false,
      error: 'Method not allowed. Use GET.' 
    });
  }

  try {
    const { url, timeout = 8000, extended = false } = req.query;

    if (!url) {
      return res.status(400).json({ 
        success: false,
        error: "Missing ?url= parameter" 
      });
    }

    // Validate URL
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
      
      // Enhanced security checks
      const blockedHosts = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '[::1]',
        'internal',
        'private'
      ];
      
      const hostname = parsedUrl.hostname.toLowerCase();
      if (blockedHosts.includes(hostname)) {
        return res.status(403).json({
          success: false,
          error: "Access to local/internal resources is blocked"
        });
      }

      // IP address validation
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(hostname)) {
        const parts = hostname.split('.').map(Number);
        const isPrivate = (
          parts[0] === 10 ||
          (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
          (parts[0] === 192 && parts[1] === 168)
        );
        if (isPrivate) {
          return res.status(403).json({
            success: false,
            error: "Private IP addresses are not allowed"
          });
        }
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
        error: "Invalid URL format",
        details: err.message
      });
    }

    // Enhanced headers for better compatibility
    const headers = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "Connection": "keep-alive",
      "Upgrade-Insecure-Requests": "1",
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none",
      "Sec-Fetch-User": "?1",
      "Cache-Control": "max-age=0",
      "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
      "Sec-Ch-Ua-Mobile": "?0",
      "Sec-Ch-Ua-Platform": '"Windows"'
    };

    const response = await axios.get(url, {
      timeout: Math.min(parseInt(timeout), 15000),
      headers,
      maxRedirects: 10,
      maxContentLength: 10 * 1024 * 1024, // 10MB
      validateStatus: (status) => status >= 200 && status < 500,
      decompress: true,
      responseType: 'text',
      responseEncoding: 'utf-8'
    });

    const $ = cheerio.load(response.data);

    // 1. TITLE EXTRACTION (with multiple fallbacks)
    const title = $('meta[property="og:title"]').attr("content")?.trim() ||
                  $('meta[name="twitter:title"]').attr("content")?.trim() ||
                  $('meta[name="title"]').attr("content")?.trim() ||
                  $("title").text()?.trim() ||
                  $('h1').first().text()?.trim() ||
                  $('h2').first().text()?.trim() ||
                  $('meta[property="og:site_name"]').attr("content")?.trim() ||
                  null;

    // 2. DESCRIPTION EXTRACTION
    const description = $('meta[property="og:description"]').attr("content")?.trim() ||
                       $('meta[name="twitter:description"]').attr("content")?.trim() ||
                       $('meta[name="description"]').attr("content")?.trim() ||
                       null;

    // 3. COMPREHENSIVE IMAGE EXTRACTION
    const extractImages = () => {
      const images = new Set();
      
      // Open Graph Images (highest priority)
      $('meta[property="og:image"]').each((_, el) => {
        const img = $(el).attr("content");
        if (img) images.add(img);
      });
      
      $('meta[property="og:image:url"]').each((_, el) => {
        const img = $(el).attr("content");
        if (img) images.add(img);
      });
      
      // Twitter Images
      $('meta[name="twitter:image"]').each((_, el) => {
        const img = $(el).attr("content");
        if (img) images.add(img);
      });
      
      $('meta[name="twitter:image:src"]').each((_, el) => {
        const img = $(el).attr("content");
        if (img) images.add(img);
      });
      
      // Apple touch icons (often high quality)
      $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
        const href = $(el).attr("href");
        const sizes = $(el).attr("sizes");
        if (href) {
          images.add({
            url: href,
            type: 'apple-touch-icon',
            sizes: sizes || 'unknown'
          });
        }
      });
      
      // Largest image from meta (by dimensions)
      const metaImages = [];
      $('meta[property="og:image:width"], meta[property="og:image:height"]').each((_, el) => {
        const width = $(el).attr("content");
        const parent = $(el).parent();
        const url = parent.find('meta[property="og:image"]').attr("content");
        if (url && width) {
          metaImages.push({
            url,
            width: parseInt(width),
            height: parseInt(parent.find('meta[property="og:image:height"]').attr("content")) || 0
          });
        }
      });
      
      // Icon images
      const icons = [];
      $('link[rel*="icon"]').each((_, el) => {
        const href = $(el).attr("href");
        const sizes = $(el).attr("sizes");
        const type = $(el).attr("type") || $(el).attr("rel");
        if (href) {
          icons.push({
            url: href,
            sizes: sizes || 'unknown',
            type: type || 'icon'
          });
        }
      });
      
      // First large image from content
      let contentImage = null;
      $('img').each((_, el) => {
        if (!contentImage) {
          const src = $(el).attr("src");
          const width = $(el).attr("width");
          const alt = $(el).attr("alt");
          if (src && width && parseInt(width) > 100) {
            contentImage = {
              url: src,
              width: parseInt(width),
              alt: alt || ''
            };
          }
        }
      });
      
      // Convert Set to array and resolve URLs
      const imageArray = Array.from(images).map(img => {
        try {
          return typeof img === 'object' ? img : { url: new URL(img, url).href, type: 'meta' };
        } catch {
          return typeof img === 'object' ? img : { url: img, type: 'meta' };
        }
      });
      
      return {
        all: imageArray,
        metaImages: metaImages.sort((a, b) => (b.width * b.height) - (a.width * a.height)),
        icons: icons,
        contentImage: contentImage,
        primary: imageArray[0]?.url || metaImages[0]?.url || contentImage?.url || null
      };
    };

    // 4. FAVICON EXTRACTION (Advanced)
    const extractFavicon = () => {
      const icons = [];
      
      // Modern approach: icons with sizes
      $('link[rel="icon"], link[rel="shortcut icon"]').each((_, el) => {
        const href = $(el).attr("href");
        const sizes = $(el).attr("sizes");
        const type = $(el).attr("type");
        if (href) {
          icons.push({
            url: href,
            sizes: sizes || '16x16',
            type: type || 'icon/x-icon',
            priority: sizes ? parseInt(sizes.split('x')[0]) : 16
          });
        }
      });
      
      // Apple touch icons (high res)
      $('link[rel="apple-touch-icon"], link[rel="apple-touch-icon-precomposed"]').each((_, el) => {
        const href = $(el).attr("href");
        const sizes = $(el).attr("sizes") || '180x180';
        if (href) {
          icons.push({
            url: href,
            sizes,
            type: 'apple-touch-icon',
            priority: 1000 // High priority
          });
        }
      });
      
      // Manifest icons (PWA)
      $('link[rel="manifest"]').each(async (_, el) => {
        const manifestUrl = $(el).attr("href");
        if (manifestUrl) {
          try {
            const manifestResponse = await axios.get(new URL(manifestUrl, url).href, { timeout: 3000 });
            const manifest = manifestResponse.data;
            if (manifest.icons && Array.isArray(manifest.icons)) {
              manifest.icons.forEach(icon => {
                icons.push({
                  url: icon.src,
                  sizes: icon.sizes || '192x192',
                  type: icon.type || 'image/png',
                  purpose: icon.purpose || 'any',
                  priority: 900
                });
              });
            }
          } catch (err) {
            // Silent fail for manifest
          }
        }
      });
      
      // Sort by priority/size and resolve URLs
      const sortedIcons = icons.sort((a, b) => b.priority - a.priority);
      
      const resolvedIcons = sortedIcons.map(icon => {
        try {
          return {
            ...icon,
            url: new URL(icon.url, url).href
          };
        } catch {
          return icon;
        }
      });
      
      return {
        all: resolvedIcons,
        primary: resolvedIcons[0]?.url || new URL('/favicon.ico', url).href
      };
    };

    // 5. ADDITIONAL METADATA
    const keywords = $('meta[name="keywords"]').attr("content")?.split(',').map(k => k.trim()) || [];
    const author = $('meta[name="author"]').attr("content") ||
                   $('meta[property="article:author"]').attr("content") ||
                   $('meta[name="twitter:creator"]').attr("content")?.replace('@', '') ||
                   null;
    
    const publisher = $('meta[property="article:publisher"]').attr("content") ||
                      $('meta[name="publisher"]').attr("content") ||
                      null;
    
    const publishedTime = $('meta[property="article:published_time"]').attr("content") ||
                         $('meta[name="published"]').attr("content") ||
                         null;
    
    const modifiedTime = $('meta[property="article:modified_time"]').attr("content") ||
                        $('meta[name="modified"]').attr("content") ||
                        null;
    
    const contentType = $('meta[property="og:type"]').attr("content") ||
                       response.headers['content-type']?.split(';')[0] ||
                       'website';
    
    const locale = $('meta[property="og:locale"]').attr("content") ||
                  $('html').attr('lang') ||
                  'en_US';
    
    // 6. THEME & COLORS
    const themeColor = $('meta[name="theme-color"]').attr("content") ||
                      $('meta[name="msapplication-TileColor"]').attr("content") ||
                      $('meta[name="apple-mobile-web-app-status-bar-style"]').attr("content") ||
                      null;
    
    // 7. SCRIPT & STRUCTURE DETECTION
    const hasJavascript = $('script[src], script:not([src])').length > 0;
    const hasForms = $('form').length > 0;
    const hasVideo = $('video, [data-video], iframe[src*="youtube"], iframe[src*="vimeo"]').length > 0;
    
    // 8. PERFORMANCE METRICS
    const pageSize = Buffer.byteLength(response.data, 'utf8');
    const domElements = $('*').length;
    const imageCount = $('img').length;
    
    // 9. SOCIAL MEDIA SPECIFIC
    const twitterCard = $('meta[name="twitter:card"]').attr("content");
    const twitterSite = $('meta[name="twitter:site"]').attr("content');
    const twitterCreator = $('meta[name="twitter:creator"]').attr("content');
    
    const fbAppId = $('meta[property="fb:app_id"]').attr("content");
    const fbAdmins = $('meta[property="fb:admins"]').attr("content');
    
    // 10. EXTRACT IMAGES & ICONS
    const images = extractImages();
    const favicon = extractFavicon();
    
    // 11. RESOLVE ALL URLs
    const resolveUrl = (relativeUrl) => {
      if (!relativeUrl) return null;
      try {
        return new URL(relativeUrl, url).href;
      } catch {
        return relativeUrl.startsWith('http') ? relativeUrl : null;
      }
    };
    
    // 12. SITE NAME WITH BETTER EXTRACTION
    const siteName = $('meta[property="og:site_name"]').attr("content")?.trim() ||
                    $('meta[name="application-name"]').attr("content")?.trim() ||
                    parsedUrl.hostname.replace(/^www\./, '').split('.')[0] ||
                    parsedUrl.hostname;

    // 13. PREPARE RESPONSE
    const baseResponse = {
      success: true,
      url: parsedUrl.href,
      canonical: $('link[rel="canonical"]').attr("href") || parsedUrl.href,
      title,
      description,
      siteName,
      hostname: parsedUrl.hostname,
      domain: parsedUrl.hostname.replace(/^www\./, ''),
      protocol: parsedUrl.protocol.replace(':', ''),
      metadata: {
        basic: {
          title,
          description,
          keywords: keywords.length > 0 ? keywords : undefined,
          author,
          publisher,
          contentType,
          locale
        },
        dates: {
          published: publishedTime,
          modified: modifiedTime,
          fetched: new Date().toISOString()
        },
        social: {
          twitter: {
            card: twitterCard,
            site: twitterSite,
            creator: twitterCreator
          },
          facebook: {
            appId: fbAppId,
            admins: fbAdmins
          }
        },
        appearance: {
          themeColor,
          hasDarkMode: $('meta[name="color-scheme"][content*="dark"], meta[name="theme-color"][media*="dark"]').length > 0
        },
        structure: {
          hasJavascript,
          hasForms,
          hasVideo,
          domElements,
          imageCount,
          pageSize: `${(pageSize / 1024).toFixed(2)} KB`
        }
      },
      images: {
        primary: resolveUrl(images.primary),
        all: images.all.map(img => ({
          ...img,
          url: resolveUrl(img.url)
        })).filter(img => img.url),
        metaImages: images.metaImages.map(img => ({
          ...img,
          url: resolveUrl(img.url)
        })).filter(img => img.url),
        contentImage: images.contentImage ? {
          ...images.contentImage,
          url: resolveUrl(images.contentImage.url)
        } : null
      },
      icons: {
        primary: favicon.primary,
        all: favicon.all.map(icon => ({
          ...icon,
          url: resolveUrl(icon.url)
        })).filter(icon => icon.url)
      },
      responseInfo: {
        status: response.status,
        statusText: response.statusText,
        contentType: response.headers['content-type'],
        server: response.headers['server'],
        poweredBy: response.headers['x-powered-by']
      }
    };

    // Extended mode with additional analysis
    if (extended === 'true' || extended === '1') {
      // Extract first paragraph
      const firstParagraph = $('p').first().text()?.trim().substring(0, 200) + '...';
      
      // Extract headings structure
      const headings = {
        h1: $('h1').map((_, el) => $(el).text()?.trim()).get(),
        h2: $('h2').map((_, el) => $(el).text()?.trim()).get(),
        h3: $('h3').map((_, el) => $(el).text()?.trim()).get()
      };
      
      // Detect framework/technology
      const technologies = {
        react: $('div[id="root"], div[id="app"]').length > 0 || response.data.includes('react'),
        nextjs: response.headers['x-powered-by'] === 'Next.js' || response.data.includes('__NEXT_DATA__'),
        vue: $('div[id="app"]').length > 0 || response.data.includes('vue'),
        angular: $('[ng-app], [ng-controller]').length > 0,
        wordpress: $('meta[name="generator"][content*="WordPress"]').length > 0 || 
                   response.data.includes('wp-content') ||
                   response.data.includes('wp-includes')
      };
      
      baseResponse.extended = {
        firstParagraph,
        headings,
        technologies,
        language: $('html').attr('lang'),
        charset: $('meta[charset]').attr('charset') || 
                $('meta[http-equiv="Content-Type"]').attr('content')?.split('charset=')[1],
        viewport: $('meta[name="viewport"]').attr('content'),
        robots: $('meta[name="robots"]').attr('content')
      };
    }

    return res.status(200).json(baseResponse);

  } catch (err) {
    console.error("Vercel Function Error:", {
      message: err.message,
      code: err.code,
      url: req.query?.url,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
    
    // Enhanced error responses
    const errorMap = {
      ECONNABORTED: {
        status: 408,
        error: "Request Timeout",
        message: "The website took too long to respond"
      },
      ECONNREFUSED: {
        status: 502,
        error: "Connection Refused",
        message: "Unable to connect to the website"
      },
      ENOTFOUND: {
        status: 404,
        error: "Domain Not Found",
        message: "The domain could not be resolved"
      },
      ERR_BAD_REQUEST: {
        status: 400,
        error: "Bad Request",
        message: "Invalid request to the target website"
      },
      ERR_BAD_RESPONSE: {
        status: 502,
        error: "Bad Gateway",
        message: "The website returned an invalid response"
      }
    };
    
    const errorInfo = errorMap[err.code] || {
      status: 500,
      error: "Internal Server Error",
      message: err.message || "Failed to process request"
    };
    
    if (err.response) {
      errorInfo.status = err.response.status;
      errorInfo.error = `HTTP ${err.response.status}`;
      errorInfo.message = `Website returned ${err.response.status} ${err.response.statusText}`;
    }
    
    return res.status(errorInfo.status).json({
      success: false,
      ...errorInfo,
      timestamp: new Date().toISOString()
    });
  }
        }
