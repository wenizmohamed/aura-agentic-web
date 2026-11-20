// AURA Agentic Web - stateless BYOK + optional server-demo Edge inference relay.
// Runs on Vercel Edge Runtime (Web Standard Request/Response + ReadableStream)
// so SSE completions (stream: true -> text/event-stream) pipe directly to the
// browser with zero buffering and up to 300s streaming duration (eliminating
// 55s/60s buffered serverless 504 timeouts on deep reasoning models such as
// deepseek-v4-pro). When DEMO_API_KEY and DEMO_BASE_URL are configured on the
// deployment, it also supports zero-setup demo routing via x-use-demo: "1"
// without exposing server credentials to the browser. MIT.

export const config = {
  runtime: "edge",
};

const DEFAULT_INITIAL_HEADERS_TIMEOUT_MS = 24_000;
const MAX_BODY_BYTES = 4 * 1024 * 1024;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Content-Type, Accept, Authorization, x-target-url, x-use-demo",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Expose-Headers": "x-upstream-content-type",
  "Cache-Control": "no-store",
};

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

function readEnv(key) {
  if (typeof process !== "undefined" && process && process.env) {
    return cleanEnv(process.env[key]);
  }
  return "";
}

function getInitialTimeoutMs() {
  const raw = readEnv("RELAY_INITIAL_TIMEOUT_MS");
  if (raw) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 50 && parsed <= 24_500) {
      return Math.floor(parsed);
    }
  }
  return DEFAULT_INITIAL_HEADERS_TIMEOUT_MS;
}

function getHeader(req, name) {
  if (!req || !req.headers) return "";
  if (typeof req.headers.get === "function") {
    return String(req.headers.get(name) || "").trim();
  }
  const lower = name.toLowerCase();
  return String(req.headers[lower] ?? req.headers[name] ?? "").trim();
}

function getDemoConfig() {
  const apiKey = readEnv("DEMO_API_KEY");
  const baseUrl = readEnv("DEMO_BASE_URL");
  const model = readEnv("DEMO_MODEL") || null;
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
  if (/^aura-agentic(?:-web)?-[a-z0-9-]+\.vercel\.app$/.test(h)) {
    return true;
  }
  const runtimeVercelHosts = [
    readEnv("VERCEL_URL"),
    readEnv("VERCEL_BRANCH_URL"),
    readEnv("VERCEL_PROJECT_PRODUCTION_URL"),
  ]
    .filter(Boolean)
    .map((v) => v.toLowerCase().replace(/^https?:\/\//, "").split("/")[0]);
  return runtimeVercelHosts.includes(h);
}

function isAllowedDemoCaller(req) {
  const origin = getHeader(req, "origin");
  if (origin) {
    try {
      const parsed = new URL(origin);
      return isAllowedDemoHost(parsed.hostname);
    } catch {
      return false;
    }
  }
  const referer = getHeader(req, "referer");
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
    h === "::" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local")
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
  if (
    /^(fc|fd)[0-9a-f]{2}:/i.test(h) ||
    /^fe[89ab][0-9a-f]:/i.test(h) ||
    /^::ffff:/i.test(h)
  ) {
    return true;
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
  if (!trimmed || /\s/.test(trimmed)) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") return null;
    if (parsed.username || parsed.password) return null;
    if (isBlockedHost(parsed.hostname)) return null;
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    if (!host.includes(".") && !host.includes(":")) return null;
    if (host.startsWith(".") || host.endsWith(".") || host.includes("..")) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}

function describeUpstreamFetchError(err) {
  const cause = err && typeof err === "object" ? err.cause : null;
  const nestedFirst =
    cause && Array.isArray(cause.errors) && cause.errors.length
      ? cause.errors[0]
      : null;
  const code = String(
    (cause && cause.code) ||
      (nestedFirst && nestedFirst.code) ||
      (err && err.code) ||
      ""
  ).trim();
  const causeMsg = String(
    (cause && cause.message) ||
      (nestedFirst && nestedFirst.message) ||
      ""
  ).trim();
  const topMsg = String(
    err instanceof Error ? err.message : err || ""
  ).trim();

  let detail = "";
  if (
    code === "ENOTFOUND" ||
    code === "EAI_AGAIN" ||
    code === "ENODATA" ||
    code === "EBADNAME"
  ) {
    detail = `DNS lookup failed (${code})`;
  } else if (code === "ECONNREFUSED") {
    detail = "connection refused (ECONNREFUSED)";
  } else if (
    code === "ECONNRESET" ||
    code === "EPIPE" ||
    code === "UND_ERR_SOCKET"
  ) {
    detail = `connection reset (${code})`;
  } else if (
    code === "ETIMEDOUT" ||
    code === "EHOSTUNREACH" ||
    code === "ENETUNREACH" ||
    code === "UND_ERR_CONNECT_TIMEOUT" ||
    code === "UND_ERR_HEADERS_TIMEOUT"
  ) {
    detail = `connection unreachable or timed out (${code})`;
  } else if (
    code.startsWith("ERR_TLS_") ||
    code.startsWith("ERR_SSL_") ||
    code.includes("CERT") ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "EPROTO"
  ) {
    detail = causeMsg
      ? `TLS handshake failed (${code}: ${causeMsg})`
      : `TLS handshake failed (${code})`;
  } else if (code) {
    detail =
      causeMsg && !causeMsg.includes(code)
        ? `${code}: ${causeMsg}`
        : causeMsg || code;
  } else if (causeMsg && causeMsg.toLowerCase() !== "fetch failed") {
    detail = causeMsg;
  } else {
    detail = topMsg || "network connection failed";
  }

  return detail.replace(/\s+/g, " ").slice(0, 200);
}

async function parseJsonBody(req) {
  const rawLen = getHeader(req, "content-length");
  if (rawLen) {
    const contentLength = Number(rawLen);
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
      const err = new Error("Request body exceeds 4MB limit.");
      err.statusCode = 413;
      throw err;
    }
  }

  if (!req.body) {
    if (typeof req.text === "function") {
      const text = await req.text();
      if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) {
        const err = new Error("Request body exceeds 4MB limit.");
        err.statusCode = 413;
        throw err;
      }
      const trimmed = text.trim();
      return trimmed ? JSON.parse(trimmed) : {};
    }
    return {};
  }

  const reader = req.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const bytes =
        value instanceof Uint8Array ? value : new Uint8Array(value);
      totalBytes += bytes.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {}
        const err = new Error("Request body exceeds 4MB limit.");
        err.statusCode = 413;
        throw err;
      }
      chunks.push(bytes);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {}
  }

  if (totalBytes === 0) return {};
  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const raw = new TextDecoder("utf-8").decode(merged).trim();
  return raw ? JSON.parse(raw) : {};
}

function jsonResponse(statusCode, data) {
  return new Response(JSON.stringify(data), {
    status: statusCode,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function buildRelayedHeaders(contentType) {
  const headers = new Headers(CORS_HEADERS);
  headers.set("Content-Type", contentType);
  headers.set("x-upstream-content-type", contentType);
  if (contentType.toLowerCase().includes("text/event-stream")) {
    headers.set("X-Accel-Buffering", "no");
  }
  return headers;
}

export default async function handler(req) {
  const method = String((req && req.method) || "GET").toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS,
    });
  }

  if (method === "GET" || method === "HEAD") {
    const demo = getDemoConfig();
    if (method === "HEAD") {
      return new Response(null, {
        status: 200,
        headers: {
          ...CORS_HEADERS,
          "Content-Type": "application/json; charset=utf-8",
        },
      });
    }
    return jsonResponse(200, {
      ok: true,
      demoAvailable: demo.available,
      demoModel: demo.available ? demo.model : null,
    });
  }

  if (method !== "POST") {
    return jsonResponse(405, {
      error: { message: "Method not allowed. Use GET or POST." },
    });
  }

  let bodyObj;
  try {
    bodyObj = await parseJsonBody(req);
  } catch (err) {
    const code = err && err.statusCode ? err.statusCode : 400;
    return jsonResponse(code, {
      error: {
        message:
          code === 413
            ? "Request payload too large."
            : "Invalid JSON body in relay request.",
      },
    });
  }

  if (!bodyObj || typeof bodyObj !== "object" || Array.isArray(bodyObj)) {
    return jsonResponse(400, {
      error: { message: "Relay request body must be a JSON object." },
    });
  }

  const useDemo = getHeader(req, "x-use-demo") === "1";
  let targetUrl = "";
  let authHeader = "";
  let outBody = bodyObj;

  if (useDemo) {
    if (!isAllowedDemoCaller(req)) {
      return jsonResponse(403, {
        error: {
          message:
            "Demo router is only available from the AURA web app; supply BYOK headers for external callers.",
        },
      });
    }
    const demo = getDemoConfig();
    if (!demo.available) {
      return jsonResponse(503, {
        error: {
          message:
            "Built-in demo router is not configured on this server. Activate your own OpenAI-compatible Base URL and API key in the router panel.",
        },
      });
    }
    try {
      targetUrl = buildChatCompletionsUrl(demo.baseUrl);
    } catch {
      return jsonResponse(500, {
        error: { message: "Server demo router base URL is misconfigured." },
      });
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
    const validTarget = validateByokTargetUrl(getHeader(req, "x-target-url"));
    if (!validTarget) {
      return jsonResponse(400, {
        error: {
          message:
            "Invalid Base URL: must be a public HTTPS OpenAI-compatible endpoint.",
          code: "invalid_base_url",
          field: "baseUrl",
        },
      });
    }
    targetUrl = validTarget;
    authHeader = getHeader(req, "authorization");
    if (
      authHeader &&
      (/[\0\r\n]/.test(authHeader) || /[^\x20-\x7e\t]/.test(authHeader))
    ) {
      return jsonResponse(401, {
        error: {
          message:
            "Invalid API key: contains illegal non-ASCII or control characters.",
          code: "invalid_api_key",
          field: "apiKey",
        },
      });
    }
  }

  const payload = JSON.stringify(outBody);
  const wantsStream = Boolean(outBody && outBody.stream === true);
  const initialTimeoutMs = getInitialTimeoutMs();
  const controller = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, initialTimeoutMs);

  try {
    const upstream = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: wantsStream
          ? "text/event-stream, application/json"
          : "application/json",
        "User-Agent": "aura-agentic-web-relay/0.3-edge",
        ...(authHeader ? { Authorization: authHeader } : {}),
      },
      body: payload,
      signal: controller.signal,
    });

    const isNullBodyStatus =
      upstream.status === 101 ||
      upstream.status === 204 ||
      upstream.status === 205 ||
      upstream.status === 304;

    const rawContentType =
      upstream.headers && typeof upstream.headers.get === "function"
        ? String(upstream.headers.get("content-type") || "").trim()
        : "";

    if (rawContentType || isNullBodyStatus || !upstream.body) {
      // Clear initial-headers timeout IMMEDIATELY so SSE ReadableStreams
      // continue flowing freely for up to 300s without being aborted!
      clearTimeout(timeoutId);
      const contentType = rawContentType || "application/json; charset=utf-8";
      return new Response(isNullBodyStatus ? null : upstream.body, {
        status: upstream.status,
        headers: buildRelayedHeaders(contentType),
      });
    }

    // Fallback only when upstream omitted Content-Type completely:
    // peek the very first chunk to sniff HTML/SSE/JSON without buffering the stream.
    const reader = upstream.body.getReader();
    const first = await reader.read();
    clearTimeout(timeoutId);

    if (first.done) {
      try {
        reader.releaseLock();
      } catch {}
      return new Response("", {
        status: upstream.status,
        headers: buildRelayedHeaders("application/json; charset=utf-8"),
      });
    }

    const firstBytes =
      first.value instanceof Uint8Array
        ? first.value
        : new Uint8Array(first.value);
    const sample = new TextDecoder("utf-8", { fatal: false }).decode(
      firstBytes.subarray(0, 512)
    );
    const contentType = /^\s*<(?:!doctype\s+html|html)\b/i.test(sample)
      ? "text/html; charset=utf-8"
      : /^\s*(?:data:|event:|id:|retry:|:)/i.test(sample)
      ? "text/event-stream; charset=utf-8"
      : "application/json; charset=utf-8";

    const replayStream = new ReadableStream({
      start(ctrl) {
        ctrl.enqueue(firstBytes);
      },
      async pull(ctrl) {
        const { done, value } = await reader.read();
        if (done) {
          ctrl.close();
        } else {
          ctrl.enqueue(
            value instanceof Uint8Array ? value : new Uint8Array(value)
          );
        }
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    });

    return new Response(replayStream, {
      status: upstream.status,
      headers: buildRelayedHeaders(contentType),
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (
      timedOut ||
      controller.signal.aborted ||
      (err && (err.name === "AbortError" || err.name === "TimeoutError"))
    ) {
      const secs = Math.max(1, Math.round(initialTimeoutMs / 1000));
      return jsonResponse(504, {
        error: {
          message: `Upstream LLM provider timed out after ${secs} seconds waiting for initial response via /api/relay.`,
          code: "relay_timeout",
        },
      });
    }
    if (useDemo) {
      return jsonResponse(502, {
        error: {
          message: "Relay upstream request failed: Upstream connection failed",
          code: "relay_failed",
        },
      });
    }
    let host = "upstream";
    try {
      host = new URL(targetUrl).host || "upstream";
    } catch {}
    const safeDetail = describeUpstreamFetchError(err);
    return jsonResponse(502, {
      error: {
        message: "Unreachable Base URL (" + host + "): " + safeDetail,
        code: "unreachable_base_url",
        field: "baseUrl",
      },
    });
  }
}
