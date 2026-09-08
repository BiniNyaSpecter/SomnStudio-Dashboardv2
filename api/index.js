"use strict";

/**
 * SOMN Studio OS — dashboard (Vercel serverless version)
 * -------------------------------------------------------
 * Every request (any path, any method) is routed here via the catch-all
 * rewrite in vercel.json. This mirrors the standalone server.js version
 * almost exactly — the routing/auth logic is unchanged — with two
 * adjustments for a serverless environment:
 *
 *   1. There's no persistent disk to store a session-signing secret, so it
 *      comes from the SESSION_SECRET environment variable. If you don't
 *      set one, a secret is derived from your password instead (works out
 *      of the box, but a real random SESSION_SECRET is more secure — see
 *      README.md).
 *   2. Rate limiting is still in-memory, but on Vercel that memory is
 *      per-instance, not global — Vercel may run several instances of
 *      this function concurrently, each with its own counter. It still
 *      slows down casual guessing, just not as strictly as on a
 *      single-process deployment (Render, a VPS, etc).
 *
 * /app.js and /login.js are served directly by Vercel from /public
 * (static files take precedence over rewrites), so this function never
 * needs to handle them.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Vercel's build tracer resolves fs paths built from process.cwd() more
// reliably than __dirname-relative paths — process.cwd() is the project
// root at runtime, same as it is locally when you run `node` from there.
const VIEWS_DIR = path.join(process.cwd(), "api", "views");
const CONFIG_FILE = path.join(process.cwd(), "config.json");

const DEFAULT_PASSWORD = "change-me-now";

function loadConfig() {
  let fileConfig = {};
  try {
    fileConfig = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
  } catch (err) {
    // config.json is optional on Vercel — env vars are the primary path.
  }

  const password = process.env.DASHBOARD_PASSWORD || fileConfig.password || DEFAULT_PASSWORD;
  const sessionTtlHours = parseInt(
    process.env.SESSION_TTL_HOURS || fileConfig.sessionTtlHours || "168",
    10
  );

  return { password, sessionTtlHours };
}

const CONFIG = loadConfig();

// ---------------------------------------------------------------------------
// Password hashing + session secret
// ---------------------------------------------------------------------------

const PASSWORD_SALT = crypto.randomBytes(16);
const PASSWORD_HASH = crypto.scryptSync(CONFIG.password, PASSWORD_SALT, 64);

function resolveSessionSecret() {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16) {
    return process.env.SESSION_SECRET;
  }
  // No SESSION_SECRET set: derive a stable one from the password so
  // sessions still work consistently across cold starts and instances.
  // Setting a real SESSION_SECRET env var is stronger — see README.md.
  return crypto.createHash("sha256").update("somn-studio-fallback:" + CONFIG.password).digest("hex");
}

const SESSION_SECRET = resolveSessionSecret();

// Signing key derives from BOTH the session secret and the current password
// hash, so changing the password invalidates every previously issued
// session automatically (takes effect on the next cold start).
const SIGNING_KEY = crypto
  .createHmac("sha256", SESSION_SECRET)
  .update(PASSWORD_HASH)
  .digest();

const SESSION_COOKIE_NAME = "somn_session";
const SESSION_TTL_MS = CONFIG.sessionTtlHours * 60 * 60 * 1000;

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBuffer(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

function createSessionToken() {
  const payload = JSON.stringify({ iat: Date.now(), exp: Date.now() + SESSION_TTL_MS });
  const payloadB64 = base64url(Buffer.from(payload, "utf8"));
  const sig = crypto.createHmac("sha256", SIGNING_KEY).update(payloadB64).digest();
  return payloadB64 + "." + base64url(sig);
}

function verifySessionToken(token) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payloadB64, sigB64] = parts;

  let expectedSig;
  try {
    expectedSig = crypto.createHmac("sha256", SIGNING_KEY).update(payloadB64).digest();
  } catch (err) {
    return false;
  }

  let providedSig;
  try {
    providedSig = base64urlToBuffer(sigB64);
  } catch (err) {
    return false;
  }

  if (providedSig.length !== expectedSig.length) return false;
  if (!crypto.timingSafeEqual(providedSig, expectedSig)) return false;

  let payload;
  try {
    payload = JSON.parse(base64urlToBuffer(payloadB64).toString("utf8"));
  } catch (err) {
    return false;
  }

  if (typeof payload.exp !== "number" || Date.now() > payload.exp) return false;
  return true;
}

function verifyPassword(candidate) {
  if (typeof candidate !== "string" || candidate.length === 0) return false;
  const candidateHash = crypto.scryptSync(candidate, PASSWORD_SALT, 64);
  return crypto.timingSafeEqual(candidateHash, PASSWORD_HASH);
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  });
  return out;
}

function isRequestSecure(req) {
  if (req.socket && req.socket.encrypted) return true;
  const proto = req.headers["x-forwarded-proto"];
  return typeof proto === "string" && proto.split(",")[0].trim() === "https";
}

function buildSessionCookie(req, token, maxAgeSeconds) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (isRequestSecure(req)) parts.push("Secure");
  return parts.join("; ");
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  return verifySessionToken(cookies[SESSION_COOKIE_NAME]);
}

// ---------------------------------------------------------------------------
// Per-IP login rate limiting (best-effort — see note at top of file)
// ---------------------------------------------------------------------------

const MAX_ATTEMPTS = 10;
const WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;

const attempts = new Map();

function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length > 0) {
    return fwd.split(",")[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry) return { blocked: false };
  if (entry.lockedUntil && now < entry.lockedUntil) {
    return { blocked: true, retryAfterMs: entry.lockedUntil - now };
  }
  if (entry.lockedUntil && now >= entry.lockedUntil) {
    attempts.delete(ip);
    return { blocked: false };
  }
  if (now - entry.windowStart > WINDOW_MS) {
    attempts.delete(ip);
    return { blocked: false };
  }
  return { blocked: false };
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  let entry = attempts.get(ip);
  if (!entry || now - entry.windowStart > WINDOW_MS) {
    entry = { count: 0, windowStart: now, lockedUntil: 0 };
  }
  entry.count += 1;
  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = now + LOCK_MS;
  }
  attempts.set(ip, entry);
}

function clearAttempts(ip) {
  attempts.delete(ip);
}

if (typeof setInterval === "function") {
  setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of attempts.entries()) {
      const windowExpired = now - entry.windowStart > WINDOW_MS;
      const lockExpired = !entry.lockedUntil || now > entry.lockedUntil;
      if (windowExpired && lockExpired) attempts.delete(ip);
    }
  }, 10 * 60 * 1000).unref();
}

// ---------------------------------------------------------------------------
// View loading + page rendering (done once per cold start, then cached)
// ---------------------------------------------------------------------------

function readView(relPath) {
  return fs.readFileSync(path.join(VIEWS_DIR, relPath), "utf8");
}

const HEAD_RAW = readView("head.html");
const HEADER_HTML = readView("header.html");
const LOGO_BLOCK_HTML = readView("logo_block.html");
const PROFILE_BLOCK_HTML = readView("profile_block.html");
const LOGIN_BODY_HTML = readView("login.html");
const ERROR_BODY_RAW = readView("error.html");
const COMING_SOON_RAW = readView(path.join("pages", "coming-soon.html"));

const NAV_STRUCTURE = JSON.parse(readView("nav_structure.json"));

const HEAD_WITH_TITLE = HEAD_RAW.replace("</head>", "<title>%%TITLE%%</title></head>");

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHead(title) {
  return HEAD_WITH_TITLE.replace("%%TITLE%%", escapeHtml(title));
}

const NAV_LINK_ACTIVE_CLASSES =
  "flex items-center gap-md px-sm py-xs rounded transition-colors group bg-surface-interface text-text-primary border-l-2 border-primary";
const NAV_LINK_INACTIVE_CLASSES =
  "flex items-center gap-md px-sm py-xs rounded hover:bg-surface-interface text-on-surface-variant transition-colors group";

function renderNavItem(item, activePath) {
  const isActive = item.path === activePath;
  const cls = isActive ? NAV_LINK_ACTIVE_CLASSES : NAV_LINK_INACTIVE_CLASSES;
  const ariaCurrent = isActive ? ' aria-current="page"' : "";
  return (
    `<a${ariaCurrent} class="${cls}" data-path="${item.path}" href="/${item.path}">` +
    `<span class="material-symbols-outlined text-[20px]">${item.icon}</span>` +
    `<span class="text-body-md">${item.label}</span></a>`
  );
}

function renderSidebar(activePath) {
  const sectionsHtml = NAV_STRUCTURE.map((section, idx) => {
    const itemsHtml = section.items.map((item) => renderNavItem(item, activePath)).join("");
    const spacer = idx > 0 ? '<div class="h-md"></div>' : "";
    return (
      `${spacer}<div class="text-label-caps font-label-caps text-text-secondary opacity-50 px-sm py-xs uppercase mb-unit">${section.section}</div>` +
      itemsHtml
    );
  }).join("");

  return (
    `<aside class="fixed left-0 top-0 h-full w-[260px] bg-surface-base border-r border-border-subtle z-50 flex flex-col">` +
    LOGO_BLOCK_HTML +
    `<nav class="flex-1 overflow-y-auto px-md space-y-unit" data-active-classes="bg-surface-interface text-text-primary border-l-2 border-primary">${sectionsHtml}</nav>` +
    PROFILE_BLOCK_HTML +
    `</aside>`
  );
}

const PAGE_TAIL = `</main></div><script src="/app.js"></script></body></html>`;

function renderShellPage(title, activePath, contentHtml) {
  return (
    renderHead(title) +
    `<body class="bg-surface-base font-body-md text-on-surface">` +
    renderSidebar(activePath) +
    `<div class="pl-[260px]">` +
    HEADER_HTML +
    `<main class="pt-14 min-h-screen bg-surface">` +
    contentHtml +
    PAGE_TAIL
  );
}

const DESIGNED_PAGES = {
  overview: { title: "Overview", file: "overview.html" },
  projects: { title: "Projects", file: "projects.html" },
  feedback: { title: "Feedback", file: "feedback.html" },
  workload: { title: "Workload", file: "workload.html" },
  reports: { title: "Reports", file: "reports.html" },
};

const COMING_SOON_COPY = {
  "my-tasks": "A focused view of everything assigned to you.",
  calendar: "Deadlines and milestones in one shared calendar.",
  team: "Directory of everyone working across the studio.",
  clients: "Client profiles, contacts, and shared history.",
  assets: "Centralized brand and production asset library.",
  files: "Shared drive for briefs, exports, and deliverables.",
  deadlines: "A rolled-up timeline of every upcoming due date.",
  announcements: "Studio-wide updates and pinned announcements.",
  "team-chat": "Real-time messaging with your project teams.",
};

const PAGE_CACHE = new Map();
const ALL_NAV_ITEMS = NAV_STRUCTURE.reduce((acc, section) => acc.concat(section.items), []);

for (const item of ALL_NAV_ITEMS) {
  const designed = DESIGNED_PAGES[item.path];
  let contentHtml;
  let title;

  if (designed) {
    contentHtml = readView(path.join("pages", designed.file));
    title = `SOMN Studio \u2014 ${designed.title}`;
  } else {
    const desc = COMING_SOON_COPY[item.path] || "This section is on its way.";
    contentHtml = COMING_SOON_RAW.replace(/%%TITLE%%/g, escapeHtml(item.label))
      .replace(/%%DESC%%/g, escapeHtml(desc))
      .replace(/%%ICON%%/g, item.icon);
    title = `SOMN Studio \u2014 ${item.label}`;
  }

  PAGE_CACHE.set(`/${item.path}`, renderShellPage(title, item.path, contentHtml));
}

const DEFAULT_ROUTE = "/overview";
const LOGIN_PAGE_HTML = renderHead("SOMN Studio \u2014 Sign In") + LOGIN_BODY_HTML;

function renderErrorPage(code, message, linkHref, linkLabel, icon) {
  const body = ERROR_BODY_RAW.replace("%%CODE%%", escapeHtml(code))
    .replace("%%MESSAGE%%", escapeHtml(message))
    .replace("%%LINK_HREF%%", escapeHtml(linkHref))
    .replace("%%LINK_LABEL%%", escapeHtml(linkLabel))
    .replace("%%ICON%%", icon);
  return renderHead(`SOMN Studio \u2014 ${code}`) + body;
}

const NOT_FOUND_HTML = renderErrorPage(
  "404",
  "That page doesn't exist.",
  "/overview",
  "Back to Overview",
  "search_off"
);

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function sendHtml(res, status, html, extraHeaders) {
  const headers = Object.assign(
    {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": Buffer.byteLength(html),
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    },
    extraHeaders || {}
  );
  res.writeHead(status, headers);
  res.end(html);
}

function sendJson(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  const headers = Object.assign(
    {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(body),
      "X-Content-Type-Options": "nosniff",
    },
    extraHeaders || {}
  );
  res.writeHead(status, headers);
  res.end(body);
}

function sendRedirect(res, location) {
  res.writeHead(302, { Location: location, "Content-Length": 0 });
  res.end();
}

function readJsonBody(req, maxBytes, cb) {
  let received = 0;
  let chunks = [];
  let done = false;

  req.on("data", (chunk) => {
    if (done) return;
    received += chunk.length;
    if (received > maxBytes) {
      done = true;
      cb(new Error("payload_too_large"));
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on("end", () => {
    if (done) return;
    done = true;
    const raw = Buffer.concat(chunks).toString("utf8");
    if (!raw) return cb(null, {});
    try {
      cb(null, JSON.parse(raw));
    } catch (err) {
      cb(new Error("invalid_json"));
    }
  });

  req.on("error", (err) => {
    if (done) return;
    done = true;
    cb(err);
  });
}

function safeNextParam(rawNext) {
  if (typeof rawNext !== "string") return DEFAULT_ROUTE;
  if (PAGE_CACHE.has(rawNext)) return rawNext;
  return DEFAULT_ROUTE;
}

// ---------------------------------------------------------------------------
// Request routing (identical logic to the standalone server.js version)
// ---------------------------------------------------------------------------

function handleRequest(req, res) {
  let url;
  try {
    url = new URL(req.url, "http://localhost");
  } catch (err) {
    return sendHtml(res, 400, "Bad request");
  }

  let pathname = decodeURIComponent(url.pathname);
  if (pathname.length > 1 && pathname.endsWith("/")) {
    pathname = pathname.slice(0, -1);
  }

  if (pathname === "/api/login" && req.method === "POST") {
    const ip = getClientIp(req);
    const rl = checkRateLimit(ip);
    if (rl.blocked) {
      const minutes = Math.ceil(rl.retryAfterMs / 60000);
      return sendJson(
        res,
        429,
        { ok: false, error: `Too many attempts. Try again in about ${minutes} minute${minutes === 1 ? "" : "s"}.` },
        { "Retry-After": String(Math.ceil(rl.retryAfterMs / 1000)) }
      );
    }

    return readJsonBody(req, 2048, (err, body) => {
      if (err) return sendJson(res, 400, { ok: false, error: "Malformed request." });

      const password = body && body.password;
      if (verifyPassword(password)) {
        clearAttempts(ip);
        const token = createSessionToken();
        const cookie = buildSessionCookie(req, token, Math.floor(SESSION_TTL_MS / 1000));
        return sendJson(res, 200, { ok: true }, { "Set-Cookie": cookie });
      }

      recordFailedAttempt(ip);
      return sendJson(res, 401, { ok: false, error: "Incorrect password." });
    });
  }

  if (pathname === "/api/logout" && req.method === "POST") {
    const cookie = `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
    return sendJson(res, 200, { ok: true }, { "Set-Cookie": cookie });
  }

  if (pathname === "/logout" && req.method === "GET") {
    const cookie = `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
    res.setHeader("Set-Cookie", cookie);
    return sendRedirect(res, "/login");
  }

  if (pathname === "/login") {
    if (req.method !== "GET") return sendHtml(res, 405, "Method not allowed");
    if (isAuthenticated(req)) {
      return sendRedirect(res, safeNextParam(url.searchParams.get("next")));
    }
    return sendHtml(res, 200, LOGIN_PAGE_HTML);
  }

  if (pathname === "" || pathname === "/") {
    return sendRedirect(res, isAuthenticated(req) ? DEFAULT_ROUTE : "/login");
  }

  if (PAGE_CACHE.has(pathname)) {
    if (req.method !== "GET") return sendHtml(res, 405, "Method not allowed");
    if (!isAuthenticated(req)) {
      const next = encodeURIComponent(pathname);
      return sendRedirect(res, `/login?next=${next}`);
    }
    return sendHtml(res, 200, PAGE_CACHE.get(pathname));
  }

  return sendHtml(res, 404, NOT_FOUND_HTML);
}

// ---------------------------------------------------------------------------
// Vercel entry point
// ---------------------------------------------------------------------------

module.exports = function handler(req, res) {
  try {
    handleRequest(req, res);
  } catch (err) {
    console.error("[request error]", err);
    if (!res.headersSent) {
      sendHtml(res, 500, "Something went wrong. Please try again.");
    } else {
      res.end();
    }
  }
};
