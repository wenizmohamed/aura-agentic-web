// AURA Agentic Web - stateless BYOK + optional server-demo inference relay.
// Most OpenAI-compatible endpoints do NOT send browser CORS headers, so a
// direct in-browser fetch to them is blocked. This same-origin serverless
// function forwards the request server-side (no CORS between server and
// provider), letting the browser runtime reach any provider while staying
// bring-your-own-key. When DEMO_API_KEY and DEMO_BASE_URL are configured on
// the deployment, it also supports zero-setup demo routing via x-use-demo: "1"
// without exposing server credentials to the browser. MIT.

export const maxDuration = 60;

const UPSTREAM_TIMEOUT_MS = 55_000;
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function cleanEnv(val) {
  let s = String(val || "").trim();
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

function getDemoConfig() {
  const apiKey = cleanEnv(process.env.DEMO_API_KEY);
  const baseUrl = cleanEnv(process.env.DEMO_BASE_URL);
  const model = cleanEnv(process.env.DEMO_MODEL) || null;
  return {
    available: Boolean(apiKey && baseUrl),
    apiKey,
    baseUrl,
    model,
  };
}

function isAllowedDemoHost(hostname) {
  const h = String(hostname || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  if (!h) return false;
  if (
    h === "aura-agentic-web.vercel.app" ||
    h === "localhost" ||
    h === "127.0.0.1" ||
    h === "::1"
  ) {
    return true;
  }
  if (/^aura-agentic-web-[a-z0-9-]+\.vercel\.app$/.test(h)) {
    return true;
  }
  const runtimeVercelHosts = [
    cleanEnv(process.env.VERCEL_URL),
    cleanEnv(process.env.VERCEL_BRANCH_URL),
    cleanEnv(process.env.VERCEL_PROJECT_PRODUCTION_URL),
  ]
    .filter(Boolean)
    .map((v) => v.toLowerCase().replace(/^https?:\/\//, "").split("/")[0]);
  return runtimeVercelHosts.includes(h);
}

function isAllowedDemoCaller(req) {
  const origin = String(req.headers["origin"] || "").trim();
  if (origin) {
    try {
      const parsed = new URL(origin);
      return isAllowedDemoHost(parsed.hostname);
    } catch {
      return false;
    }
  }
  const referer = String(req.headers["referer"] || "").trim();
  if (referer) {
    try {
      const parsed = new URL(referer);
      return isAllowedDemoHost(parsed.hostname);
    } catch {
      return false;
    }
  }
  return false;
}

function isBlockedHost(hostname) {
  const h = String(hostname || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (
    h === "localhost" ||
    h === "0.0.0.0" ||
    h === "::1" ||
    h.endsWith(".localhost")
  ) {
    return true;
  }
  if (
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^169\.254\./.test(h)
  ) {
    return true;
  }
  const m172 = h.match(/^172\.(\d+)\./);
  if (m172) {
    const second = Number(m172[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

function buildChatCompletionsUrl(rawBase) {
  const trimmed = cleanEnv(rawBase).replace(/\/+$/, "");
  if (!trimmed) return "";
  const parsed = new URL(trimmed);
  if (parsed.protocol !== "https:" || isBlockedHost(parsed.hostname)) {
    throw new Error("Invalid upstream base URL.");
  }
  if (/\/chat\/completions$/i.test(parsed.pathname)) {
    return parsed.href;
  }
  parsed.pathname =
    !parsed.pathname || parsed.pathname === "/"
      ? "/v1/chat/completions"
      : parsed.pathname.replace(/\/+$/, "") + "/chat/completions";
  return parsed.href;
}

function validateByokTargetUrl(rawTarget) {
  const trimmed = String(rawTarget || "").trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") return null;
    if (isBlockedHost(parsed.hostname)) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

async function parseJsonBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) {
      const str = req.body.toString("utf8").trim();
      return str ? JSON.parse(str) : {};
    }
    if (typeof req.body === "string") {
      const str = req.body.trim();
      return str ? JSON.parse(str) : {};
    }
    if (typeof req.body === "object") {
      return req.body;
    }
  }

  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    totalBytes += buf.length;
    if (totalBytes > MAX_BODY_BYTES) {
      const err = new Error("Request body exceeds 4MB limit.");
      err.statusCode = 413;
      throw err;
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  return raw ? JSON.parse(raw) : {};
}

function sendJson(res, statusCode, data) {
  res.statusCode = statusCode;
  if (typeof res.status === "function") res.status(statusCode);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (typeof res.json === "function") {
    res.json(data);
  } else {
    res.end(JSON.stringify(data));
  }
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-target-url, x-use-demo"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    if (typeof res.status === "function") res.status(204);
    res.end();
    return;
  }

  if (req.method === "GET") {
    const demo = getDemoConfig();
    sendJson(res, 200, {
      ok: true,
      demoAvailable: demo.available,
      demoModel: demo.available ? demo.model : null,
    });
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 405, {
      error: { message: "Method not allowed. Use GET or POST." },
    });
    return;
  }

  let bodyObj;
  try {
    bodyObj = await parseJsonBody(req);
  } catch (err) {
    const code = err && err.statusCode ? err.statusCode : 400;
    sendJson(res, code, {
      error: {
        message:
          code === 413
            ? "Request payload too large."
            : "Invalid JSON body in relay request.",
      },
    });
    return;
  }

  if (!bodyObj || typeof bodyObj !== "object" || Array.isArray(bodyObj)) {
    sendJson(res, 400, {
      error: { message: "Relay request body must be a JSON object." },
    });
    return;
  }

  const useDemo = String(req.headers["x-use-demo"] || "").trim() === "1";
  let targetUrl = "";
  let authHeader = "";
  let outBody = bodyObj;

  if (useDemo) {
    if (!isAllowedDemoCaller(req)) {
      sendJson(res, 403, {
        error: {
          message:
            "Demo router is only available from the AURA web app; supply BYOK headers for external callers.",
        },
      });
      return;
    }
    const demo = getDemoConfig();
    if (!demo.available) {
      sendJson(res, 503, {
        error: {
          message:
            "Built-in demo router is not configured on this server. Activate your own OpenAI-compatible Base URL and API key in the router panel.",
        },
      });
      return;
    }
    try {
      targetUrl = buildChatCompletionsUrl(demo.baseUrl);
    } catch {
      sendJson(res, 500, {
        error: { message: "Server demo router base URL is misconfigured." },
      });
      return;
    }
    authHeader = /^Bearer\s+/i.test(demo.apiKey)
      ? demo.apiKey
      : `Bearer ${demo.apiKey}`;
    outBody = { ...bodyObj };
    if (demo.model) {
      outBody.model = demo.model;
    } else if (!outBody.model || outBody.model === "default") {
      outBody.model = "gpt-4o-mini";
    }
  } else {
    const validTarget = validateByokTargetUrl(req.headers["x-target-url"]);
    if (!validTarget) {
      sendJson(res, 400, {
        error: { message: "Missing or non-HTTPS x-target-url header." },
      });
      return;
    }
    targetUrl = validTarget;
    authHeader = String(req.headers["authorization"] || "").trim();
  }

  const payload = JSON.stringify(outBody);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstream = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": "aura-agentic-web-relay/0.2",
        ...(authHeader ? { Authorization: authHeader } : {}),
      },
      body: payload,
      signal: controller.signal,
    });

    const text = await upstream.text();
    const contentType =
      upstream.headers.get("content-type") || "application/json; charset=utf-8";

    res.statusCode = upstream.status;
    if (typeof res.status === "function") res.status(upstream.status);
    res.setHeader("Content-Type", contentType);
    if (typeof res.send === "function") {
      res.send(text);
    } else {
      res.end(text);
    }
  } catch (err) {
    if (controller.signal.aborted || (err && err.name === "AbortError")) {
      sendJson(res, 504, {
        error: {
          message:
            "Upstream LLM provider timed out after 55 seconds via /api/relay.",
          code: "relay_timeout",
        },
      });
      return;
    }
    const rawMsg = err instanceof Error ? err.message : String(err);
    const safeDetail = useDemo
      ? "Upstream connection failed"
      : rawMsg.slice(0, 200);
    sendJson(res, 502, {
      error: {
        message: `Relay upstream request failed: ${safeDetail}`,
        code: "relay_failed",
      },
    });
  } finally {
    clearTimeout(timeoutId);
  }
}
