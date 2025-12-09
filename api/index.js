import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

// -----------------------------------------
// 1️⃣ METADATA SCRAPER ENDPOINT
// -----------------------------------------
app.get("/meta", async (req, res) => {
    try {
        const url = req.query.url;
        if (!url) return res.json({ error: "Missing URL" });

        const html = await fetch(url).then(r => r.text());

        const titleMatch = html.match(/<title>(.*?)<\/title>/i);
        const descMatch =
            html.match(/<meta name="description" content="(.*?)"/i) ||
            html.match(/<meta property="og:description" content="(.*?)"/i);

        const imageMatch =
            html.match(/<meta property="og:image" content="(.*?)"/i) ||
            html.match(/<link rel="icon" href="(.*?)"/i);

        res.json({
            title: titleMatch ? titleMatch[1] : "",
            description: descMatch ? descMatch[1] : "",
            image: imageMatch ? imageMatch[1] : "",
            provider: url.includes("t.me")
                ? "Telegram"
                : url.includes("youtube.com")
                ? "YouTube"
                : url.includes("discord.com")
                ? "Discord"
                : "Website"
        });
    } catch (e) {
        res.json({ error: "Failed to fetch metadata" });
    }
});

// -----------------------------------------
// 2️⃣ LINK VALIDATOR
// -----------------------------------------
app.post("/validate", async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.json({ error: "URL required" });

        // Check if URL is reachable
        const check = await fetch(url).catch(() => null);
        if (!check) return res.json({ valid: false, reason: "dead_link" });

        // Optional: integrate Firebase duplicate-check later
        res.json({ valid: true, reason: "ok" });
    } catch {
        res.json({ valid: false, reason: "unknown_error" });
    }
});

// -----------------------------------------
// 3️⃣ SEARCH (dummy, expandable)
// -----------------------------------------
app.get("/search", (req, res) => {
    const q = req.query.q ?? "";
    res.json({
        groups: [],
        channels: [],
        tools: [],
        websites: [],
        query: q
    });
});

// -----------------------------------------
// 4️⃣ TRENDING (for future use)
// -----------------------------------------
app.get("/trending", (req, res) => {
    res.json({
        groups: [],
        channels: [],
        tools: [],
        websites: []
    });
});

// -----------------------------------------
// 5️⃣ ROOT
// -----------------------------------------
app.get("/", (req, res) => {
    res.send("🔥 Your API is working!");
});

export default app;
