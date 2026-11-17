// AURA Agentic Web - browser runtime (reference-conforming, MVP Profile 0.2)
// Parses a Neuro SAN-profile agent network, validates it, and runs the front
// agent loop in the browser against an OpenAI-compatible router. Supports
// agent-to-agent delegation, bounded execution, peer-site loading with consent,
// stateless CORS relay caching, live router verification/flagging, and optional
// built-in demo relay routing.
// No build step. Pure ES module. MIT.

function isLocalHostName(hostname) {
  const h = String(hostname || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

function isLocalEndpointUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return isLocalHostName(u.hostname);
  } catch {
    return false;
  }
}

export function normalizeChatUrl(baseUrl) {
  let raw = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!raw) throw new Error("Router Base URL is empty.");
  if (!/^https?:\/\//i.test(raw) && !raw.startsWith("/")) {
    raw = "https://" + raw;
  }
  try {
    const u = new URL(raw);
    const cleanPath = u.pathname.replace(/\/+$/, "");
    if (/\/chat\/completions$/i.test(cleanPath)) {
      return u.origin + cleanPath + u.search;
    }
    if (!cleanPath || cleanPath === "/") {
      return u.origin + "/v1/chat/completions" + u.search;
    }
    return u.origin + cleanPath + "/chat/completions" + u.search;
  } catch {
    if (/\/chat\/completions$/i.test(raw)) return raw;
    return raw + "/chat/completions";
  }
}

function extractRouterError(data, rawText) {
  const obj = Array.isArray(data) ? data[0] : data;
  if (obj && typeof obj === "object") {
    if (obj.error) {
      if (typeof obj.error === "string") {
        return obj.detail ? `${obj.error} (${obj.detail})` : obj.error;
      }
      if (typeof obj.error.message === "string" && obj.error.message.trim()) {
        return obj.error.message.trim();
      }
      return JSON.stringify(obj.error).slice(0, 300);
    }
    if (typeof obj.message === "string" && obj.message.trim()) {
      return obj.message.trim();
    }
    if (typeof obj.detail === "string" && obj.detail.trim()) {
      return obj.detail.trim();
    }
  }
  const trimmed = String(rawText || "").trim();
  if (/^\s*(?:<!doctype\s+html|<html[\s>])/i.test(trimmed)) {
    const titleMatch = trimmed.match(/<title[^>]*>([^<]{1,120})<\/title>/i);
    return titleMatch && titleMatch[1]
      ? `HTML page returned ("${titleMatch[1].trim()}")`
      : "HTML webpage returned instead of JSON API";
  }
  return (trimmed || "Empty response from router").slice(0, 300);
}

export function validateRouterInputs({ baseUrl, apiKey, model } = {}) {
  const rawBase = typeof baseUrl === "string" ? baseUrl.trim() : "";
  const rawKey = typeof apiKey === "string" ? apiKey.trim() : "";
  const rawModel = typeof model === "string" ? model.trim() : "";

  // 1. Detect API key accidentally pasted into Base URL
  if (
    rawBase &&
    !/^https?:\/\//i.test(rawBase) &&
    /^(sk-|xai-|gsk_|rk-|AIza|nvapi-|pplx-|Bearer\s)/i.test(rawBase)
  ) {
    return {
      ok: false,
      field: "baseUrl",
      code: "swapped_key_in_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: that looks like an API key, not an endpoint URL."
    };
  }

  // 2. Empty Base URL (check if URL was pasted into API key box first)
  if (!rawBase) {
    if (/^https?:\/\//i.test(rawKey)) {
      return {
        ok: false,
        field: "apiKey",
        code: "swapped_url_in_key",
        badge: "INVALID API KEY",
        message: "Invalid API key: that looks like a URL, not an API key."
      };
    }
    return {
      ok: false,
      field: "baseUrl",
      code: "empty_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: enter an OpenAI-compatible https:// endpoint URL (e.g. https://api.openai.com/v1)."
    };
  }

  // 3. Strict Base URL syntax, protocol, whitespace, and hostname validation
  if (/\s/.test(rawBase) || /[\x00-\x1f\x7f]/.test(rawBase)) {
    return {
      ok: false,
      field: "baseUrl",
      code: "invalid_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: URL must not contain spaces or control characters."
    };
  }

  if (!/^https?:\/\//i.test(rawBase)) {
    return {
      ok: false,
      field: "baseUrl",
      code: "invalid_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: must start with https:// (or http://localhost for local servers)."
    };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawBase);
  } catch {
    return {
      ok: false,
      field: "baseUrl",
      code: "invalid_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: malformed endpoint URL."
    };
  }

  if (parsedUrl.username || parsedUrl.password) {
    return {
      ok: false,
      field: "baseUrl",
      code: "invalid_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: do not embed credentials in the URL."
    };
  }

  const proto = parsedUrl.protocol.toLowerCase();
  const host = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const isLocal = isLocalHostName(host);

  if (proto === "http:" && !isLocal) {
    return {
      ok: false,
      field: "baseUrl",
      code: "insecure_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: must use https:// (http:// is only allowed for localhost or 127.0.0.1)."
    };
  }

  if (proto !== "https:" && proto !== "http:") {
    return {
      ok: false,
      field: "baseUrl",
      code: "invalid_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: protocol must be https://."
    };
  }

  const isIpv4 =
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) &&
    host.split(".").every((part) => Number(part) <= 255);
  const isValidDomain =
    isLocal ||
    isIpv4 ||
    (host.includes(".") &&
      !/^\.|\.$|\.\./.test(host) &&
      /^[a-z0-9.-]+$/i.test(host) &&
      /\.[a-z0-9-]{2,}$/i.test(host));

  if (!isValidDomain) {
    return {
      ok: false,
      field: "baseUrl",
      code: "invalid_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: hostname '" + (parsedUrl.hostname || rawBase) + "' is not a valid domain."
    };
  }

  if (
    !isLocal &&
    (/^(?:0\.|10\.|127\.|169\.254\.|192\.168\.)/.test(host) ||
      /^172\.(?:1[6-9]|2\d|3[01])\./.test(host))
  ) {
    return {
      ok: false,
      field: "baseUrl",
      code: "private_ip_base_url",
      badge: "INVALID BASE URL",
      message: "Invalid Base URL: private network IPs are blocked on HTTPS relay (use localhost or a public HTTPS endpoint)."
    };
  }

  // 4. API key validation
  if (!rawKey) {
    return {
      ok: false,
      field: "apiKey",
      code: "empty_api_key",
      badge: "INVALID API KEY",
      message: "Invalid API key: API key cannot be empty."
    };
  }

  if (/^https?:\/\//i.test(rawKey)) {
    return {
      ok: false,
      field: "apiKey",
      code: "swapped_url_in_key",
      badge: "INVALID API KEY",
      message: "Invalid API key: that looks like a URL, not an API key."
    };
  }

  const tokenPart = /^bearer$/i.test(rawKey)
    ? ""
    : rawKey.replace(/^Bearer\s+/i, "").trim();
  if (!tokenPart) {
    return {
      ok: false,
      field: "apiKey",
      code: "empty_api_key",
      badge: "INVALID API KEY",
      message: "Invalid API key: Bearer token is empty."
    };
  }

  if (/\s/.test(tokenPart) || !/^[\x21-\x7E]+$/.test(tokenPart)) {
    return {
      ok: false,
      field: "apiKey",
      code: "malformed_api_key",
      badge: "INVALID API KEY",
      message: "Invalid API key: contains whitespace or invalid non-ASCII characters."
    };
  }

  // 5. Model validation (defaults to gpt-4o-mini when omitted)
  if (rawModel) {
    if (/^https?:\/\//i.test(rawModel)) {
      return {
        ok: false,
        field: "model",
        code: "invalid_model",
        badge: "INVALID MODEL",
        message: "Invalid Model: that looks like a URL, not a model ID."
      };
    }
    if (/\s/.test(rawModel) || !/^[\x21-\x7E]+$/.test(rawModel)) {
      return {
        ok: false,
        field: "model",
        code: "invalid_model",
        badge: "INVALID MODEL",
        message: "Invalid Model: model ID must not contain spaces or non-ASCII characters."
      };
    }
  }

  return {
    ok: true,
    baseUrl: rawBase,
    normalizedUrl: normalizeChatUrl(rawBase),
    apiKey: rawKey,
    model: rawModel || "gpt-4o-mini",
    isLocal,
    isLocalHttp: isLocal && proto === "http:"
  };
}

const API_KEY_ERR_RE =
  /invalid[_ -]?api[_ -]?key|incorrect[_ -]?api[_ -]?key|api[_ -]?key[_ -]?not[_ -]?valid|invalid[_ -]?key|missing[_ -]?api[_ -]?key|api[_ -]?key[^\n]{0,40}(?:invalid|incorrect|revoked|expired|disabled|missing|required|not\s+valid)|unauthorized|unauthenticated|not[_ -]?authenticated|authentication[_ -]?(?:failed|error|required)|invalid[_ -]?(?:token|bearer|credentials|auth)|token[_ -]?(?:expired|invalid|revoked)|permission[_ -]?denied|insufficient[_ -]?quota|exceeded\s+your\s+current\s+quota|billing[^\n]{0,40}(?:disabled|not[_ -]?active|hard[_ -]?limit)|account[^\n]{0,30}(?:deactivated|suspended|disabled)/i;

const MODEL_ERR_RE =
  /model[_ -]?not[_ -]?(?:found|exist|supported|available)|models?[\/:\s`'"]+[^\s`'"]*\s*(?:does\s+not\s+exist|not\s+exist|not\s+found|is\s+not\s+(?:found|valid|supported|available))|(?:does\s+not\s+exist|not\s+found|not\s+supported)[^\n]{0,40}model|unknown\s+model|invalid\s+model|not\s+a\s+valid\s+model|unrecognized\s+model|no\s+endpoints?\s+found\s+for|not\s+a\s+chat\s+model|not\s+supported\s+(?:for|in)\s+(?:the\s+)?(?:v1\/)?chat/i;

export function classifyRouterError(errOrInfo) {
  if (!errOrInfo) return null;
  if (
    typeof errOrInfo === "object" &&
    errOrInfo.routerFlag &&
    typeof errOrInfo.routerFlag === "object" &&
    errOrInfo.routerFlag.field
  ) {
    return errOrInfo.routerFlag;
  }

  let info = errOrInfo;
  if (errOrInfo instanceof Error || typeof errOrInfo === "string") {
    const rawMsg = typeof errOrInfo === "string" ? errOrInfo : errOrInfo.message || String(errOrInfo);
    const httpMatch = rawMsg.match(/\bHTTP\s+(\d{3})\b/i);
    const isNetTypeErr =
      (typeof TypeError !== "undefined" && errOrInfo instanceof TypeError) ||
      /failed to fetch|networkerror|load failed|fetch failed|econnrefused|enotfound/i.test(rawMsg);
    info = {
      status: httpMatch ? Number(httpMatch[1]) : 0,
      message: rawMsg,
      rawText: rawMsg,
      networkError: isNetTypeErr
    };
  }

  const status = typeof info.status === "number" ? info.status : 0;
  const rawText = typeof info.rawText === "string" ? info.rawText : "";
  let data = info.data !== undefined ? info.data : null;
  if (!data && rawText) {
    try {
      data = JSON.parse(rawText);
    } catch {
      data = null;
    }
  }

  const obj = Array.isArray(data) ? data[0] : data;
  const errObj =
    obj && typeof obj === "object" && obj.error && typeof obj.error === "object"
      ? obj.error
      : null;
  const errCode = String(
    (errObj && (errObj.code || errObj.type || errObj.status)) ||
      (obj && typeof obj === "object" && obj.code) ||
      info.code ||
      ""
  ).trim();
  const errField = String(
    (errObj && (errObj.field || errObj.param)) ||
      (obj && typeof obj === "object" && obj.field) ||
      info.field ||
      ""
  ).trim();

  const codeLower = errCode.toLowerCase();
  const fieldLower = errField.toLowerCase();
  const ct = String(info.upstreamContentType || info.contentType || "").toLowerCase();
  const detailMsg =
    (typeof info.message === "string" && info.message.trim() && !data && !rawText
      ? info.message.trim()
      : extractRouterError(data, rawText || info.message || "")) || "";
  const haystack = [errCode, errField, detailMsg, rawText.slice(0, 600)].join(" ");
  const looksLikeHtml =
    ct.includes("text/html") ||
    ct.includes("application/xhtml") ||
    /^\s*(?:<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>])/i.test(rawText);

  // 1. Explicit relay or validator Base URL codes
  if (
    fieldLower === "baseurl" ||
    codeLower === "invalid_base_url" ||
    codeLower === "unreachable_base_url" ||
    codeLower === "relay_failed" ||
    codeLower === "swapped_key_in_url" ||
    codeLower === "insecure_base_url" ||
    codeLower === "private_ip_base_url" ||
    codeLower === "empty_base_url"
  ) {
    return {
      field: "baseUrl",
      code: codeLower || "invalid_base_url",
      badge: "INVALID BASE URL",
      message: detailMsg || "Invalid or unreachable Base URL."
    };
  }

  // 2. Network TypeError / unreachable endpoint
  if (info.networkError) {
    const local = Boolean(info.isLocal || info.isLocalHttp || isLocalEndpointUrl(info.url));
    return {
      field: "baseUrl",
      code: local ? "local_cors_or_unreachable" : "unreachable_base_url",
      badge: "INVALID BASE URL",
      message: local
        ? "Unreachable local Base URL: connection failed or blocked by browser CORS. Ensure your local server (e.g. Ollama / LM Studio) is running and allows CORS."
        : "Unreachable Base URL: could not connect to endpoint (check domain and HTTPS URL)."
    };
  }

  // 3. Timeout on verification probe
  if (info.probeTimeout || codeLower === "probe_timeout") {
    return {
      field: "baseUrl",
      code: "probe_timeout",
      badge: "INVALID BASE URL",
      message: detailMsg || "Unreachable Base URL: verification probe timed out."
    };
  }

  // 4. HTML webpage returned instead of JSON API (unless literal HTTP 401 auth challenge)
  if (looksLikeHtml && status !== 401) {
    return {
      field: "baseUrl",
      code: "html_not_api",
      badge: "INVALID BASE URL",
      message:
        "Invalid Base URL: endpoint returned an HTML webpage instead of an OpenAI JSON API (check path, e.g. /v1 or /api/v1)."
    };
  }

  // 5. API Key / Auth / Permission / Quota errors
  if (
    fieldLower === "apikey" ||
    codeLower === "invalid_api_key" ||
    codeLower === "swapped_url_in_key" ||
    codeLower === "empty_api_key" ||
    codeLower === "malformed_api_key" ||
    status === 401 ||
    status === 402 ||
    (!looksLikeHtml && API_KEY_ERR_RE.test(haystack)) ||
    (status === 403 && !looksLikeHtml)
  ) {
    return {
      field: "apiKey",
      code:
        codeLower && codeLower !== "client specified an invalid argument"
          ? codeLower.replace(/\s+/g, "_")
          : status === 403
          ? "forbidden_api_key"
          : "invalid_api_key",
      badge: "INVALID API KEY",
      message:
        "Invalid API key" +
        (status ? " (HTTP " + status + ")" : "") +
        (detailMsg ? ": " + detailMsg : ".")
    };
  }

  // 6. Invalid / Unknown / Unsupported Model errors
  if (
    !looksLikeHtml &&
    (fieldLower === "model" ||
      codeLower === "model_not_found" ||
      codeLower === "model_not_exist" ||
      codeLower === "invalid_model" ||
      ((status === 400 || status === 404 || status === 422 || !status || (obj && obj.error)) &&
        MODEL_ERR_RE.test(haystack)))
  ) {
    return {
      field: "model",
      code: "model_not_found",
      badge: "INVALID MODEL",
      message:
        "Invalid Model" +
        (status ? " (HTTP " + status + ")" : "") +
        (detailMsg ? ": " + detailMsg : ".")
    };
  }

  // 7. HTTP 404 or 405 without an OpenAI model error -> wrong endpoint path / Base URL
  if (status === 404 || status === 405) {
    return {
      field: "baseUrl",
      code: status === 405 ? "method_not_allowed_url" : "endpoint_not_found",
      badge: "INVALID BASE URL",
      message:
        "Invalid Base URL: HTTP " +
        status +
        " at chat completions path" +
        (detailMsg ? " (" + detailMsg + ")" : ".")
    };
  }

  // 8. 2xx response that is non-JSON or missing choices[0].message (without data.error)
  if (status >= 200 && status < 300) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return {
        field: "baseUrl",
        code: "non_json_base_url",
        badge: "INVALID BASE URL",
        message: "Invalid Base URL: endpoint returned non-JSON payload instead of OpenAI chat completions."
      };
    }
    if (!data.error) {
      const msg = data.choices && data.choices[0] && data.choices[0].message;
      if (!msg || typeof msg !== "object") {
        return {
          field: "baseUrl",
          code: "unexpected_payload_url",
          badge: "INVALID BASE URL",
          message: "Invalid Base URL: endpoint returned HTTP " + status + " without choices[0].message."
        };
      }
    }
  }

  return null;
}

function attachRouterFlag(err, flagInfo) {
  const flag = classifyRouterError(flagInfo);
  if (flag) {
    err.routerFlag = flag;
  }
  return err;
}

export class AuraRuntime {
  constructor({ router, onEvent } = {}) {
    this.router = router || null; // { baseUrl, apiKey, model } or { demo: true, model }
    this.onEvent = onEvent || (() => {});
    this.network = null;
    this.agents = new Map();
    this.limits = {
      max_composition_depth: 4,
      max_agent_invocations: 40,
      max_remote_calls: 40,
      max_elapsed_seconds: 300
    };
    this._invocations = 0;
    this._remoteCalls = 0;
    this._startedAt = 0;
    this._preferRelayFor = null;
  }

  setRouter(router) {
    let prevUrl = null;
    let nextUrl = null;
    try { if (this.router && this.router.baseUrl) prevUrl = normalizeChatUrl(this.router.baseUrl); } catch {}
    try { if (router && router.baseUrl) nextUrl = normalizeChatUrl(router.baseUrl); } catch {}
    if (prevUrl !== nextUrl || !nextUrl) {
      this._preferRelayFor = null;
    }
    this.router = router || null;
  }

  hasActiveRouter() {
    if (!this.router) return false;
    if (this.router.demo === true) return true;
    return Boolean(
      typeof this.router.baseUrl === "string" &&
      this.router.baseUrl.trim() &&
      typeof this.router.apiKey === "string" &&
      this.router.apiKey.trim()
    );
  }

  // --- Lightweight handshake validation without mutating active router or counters ---
  async validateRouter(candidateRouter, { timeoutMs = 15000, throwOnError = false } = {}) {
    const emitFail = (flag) => {
      const payload = {
        ok: false,
        field: flag.field,
        code: flag.code,
        badge: flag.badge,
        message: flag.message
      };
      this.onEvent({
        type: "router_flagged",
        field: flag.field,
        code: flag.code,
        badge: flag.badge,
        message: flag.message
      });
      if (throwOnError) {
        const err = new Error(flag.message);
        err.routerFlag = flag;
        throw err;
      }
      return payload;
    };

    const inputCheck = validateRouterInputs(candidateRouter);
    if (!inputCheck.ok) {
      return emitFail(inputCheck);
    }

    const url = inputCheck.normalizedUrl;
    const auth = /^Bearer\s+/i.test(inputCheck.apiKey)
      ? inputCheck.apiKey
      : "Bearer " + inputCheck.apiKey;
    const model = inputCheck.model;
    const isLocal = inputCheck.isLocal;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const executeProbe = async (probeBody) => {
      const payload = JSON.stringify(probeBody);
      let res = null;
      let rawText = "";
      let viaRelay = false;

      const callRelay = () =>
        fetch("/api/relay", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": auth,
            "x-target-url": url
          },
          body: payload,
          signal: controller.signal
        });

      if (!isLocal && this._preferRelayFor === url) {
        viaRelay = true;
        res = await callRelay();
        rawText = await res.text();
      } else {
        try {
          res = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": auth
            },
            body: payload,
            signal: controller.signal
          });
          rawText = await res.text();
        } catch (directErr) {
          if (controller.signal.aborted || (directErr && directErr.name === "AbortError")) {
            throw directErr;
          }
          if (isLocal) {
            const localErr = new TypeError("Local endpoint unreachable or blocked by CORS");
            localErr._isLocal = true;
            throw localErr;
          }
          viaRelay = true;
          res = await callRelay();
          rawText = await res.text();
        }

        if (
          !viaRelay &&
          !isLocal &&
          res &&
          (res.status === 403 || res.status === 405) &&
          /^https:\/\//i.test(url)
        ) {
          let probeJson = null;
          try { probeJson = rawText ? JSON.parse(rawText) : null; } catch { probeJson = null; }
          const hasCompletion = Boolean(
            probeJson && probeJson.choices && probeJson.choices[0] && probeJson.choices[0].message
          );
          if (!hasCompletion) {
            viaRelay = true;
            res = await callRelay();
            rawText = await res.text();
          }
        }
      }

      return { res, rawText, viaRelay };
    };

    try {
      let attempt = await executeProbe({
        model,
        messages: [{ role: "user", content: "ping" }],
        max_tokens: 1,
        stream: false
      });

      let data = null;
      try {
        data = attempt.rawText ? JSON.parse(attempt.rawText) : null;
      } catch {
        data = null;
      }

      // Automatic retry without max_tokens for strict reasoning models requiring max_completion_tokens
      if (attempt.res && attempt.res.status === 400) {
        const errText = extractRouterError(data, attempt.rawText);
        if (/max_completion_tokens|unsupported\s+parameter[^\n]*max_tokens|max_tokens[^\n]*not\s+supported/i.test(errText)) {
          attempt = await executeProbe({
            model,
            messages: [{ role: "user", content: "ping" }],
            stream: false
          });
          try {
            data = attempt.rawText ? JSON.parse(attempt.rawText) : null;
          } catch {
            data = null;
          }
        }
      }

      const { res, rawText, viaRelay } = attempt;
      const contentType = res.headers ? res.headers.get("content-type") || "" : "";
      const upstreamContentType = res.headers ? res.headers.get("x-upstream-content-type") || "" : "";

      if (
        res.ok &&
        data &&
        typeof data === "object" &&
        !Array.isArray(data) &&
        !data.error &&
        data.choices &&
        data.choices[0] &&
        data.choices[0].message &&
        typeof data.choices[0].message === "object"
      ) {
        this.onEvent({ type: "router_verified", model, viaRelay });
        return { ok: true, model, viaRelay };
      }

      const flag =
        classifyRouterError({
          status: res.status,
          data,
          rawText,
          contentType,
          upstreamContentType,
          isLocal,
          isLocalHttp: inputCheck.isLocalHttp,
          url
        }) || {
          field: "baseUrl",
          code: "router_http_" + res.status,
          badge: "INVALID BASE URL",
          message: "Router HTTP " + res.status + ": " + extractRouterError(data, rawText)
        };

      return emitFail(flag);
    } catch (err) {
      if (err && err.routerFlag && throwOnError) throw err;
      const aborted = controller.signal.aborted || Boolean(err && err.name === "AbortError");
      const flag = aborted
        ? classifyRouterError({
            probeTimeout: true,
            message:
              "Invalid Base URL: verification probe timed out after " +
              Math.max(1, Math.round(timeoutMs / 1000)) +
              "s."
          })
        : classifyRouterError({
            networkError: true,
            isLocal: isLocal || Boolean(err && err._isLocal),
            isLocalHttp: inputCheck.isLocalHttp,
            url,
            message: err && err.message ? err.message : String(err)
          });
      return emitFail(flag);
    } finally {
      clearTimeout(timer);
    }
  }

  // --- Load + validate a network definition (Tenet One / section 3.1 parse+validate) ---
  loadNetwork(def) {
    if (!def || typeof def !== "object") throw new Error("Network definition must be an object.");
    const meta = def.metadata || {};
    const front = meta.front_agent || def.front_agent;
    if (!front) throw new Error("Network has no front_agent.");
    const tools = Array.isArray(def.tools) ? def.tools : [];
    if (!tools.length) throw new Error("Network has no agents/tools.");
    const names = new Set();
    for (const t of tools) {
      if (!t.name) throw new Error("An agent is missing a name.");
      if (names.has(t.name)) throw new Error("Duplicate agent name: " + t.name);
      names.add(t.name);
    }
    // Validate every referenced internal tool exists (external URLs allowed)
    for (const t of tools) {
      for (const ref of (t.tools || [])) {
        if (typeof ref === "string" && !/^https?:\/\//.test(ref) && !names.has(ref)) {
          throw new Error("Agent '" + t.name + "' references unknown agent '" + ref + "'.");
        }
      }
    }
    if (!names.has(front)) throw new Error("Front agent '" + front + "' is not defined.");
    this.network = def;
    this.agents = new Map(tools.map((t) => [t.name, t]));
    if (def.execution_limits) this.limits = { ...this.limits, ...def.execution_limits };
    this.onEvent({ type: "network_loaded", name: meta.name || "network", front, agents: [...names] });
    return { front, agents: [...names] };
  }

  async loadNetworkFromUrl(url) {
    const res = await fetch(url, { mode: "cors" });
    if (!res.ok) throw new Error("Failed to fetch network (" + res.status + "): " + url);
    const def = await res.json();
    return this.loadNetwork(def);
  }

  // --- Peer-site loading (section 3.2): URL's final path component is the network name ---
  async loadPeerNetwork(peerUrl, confirmFn) {
    const u = new URL(peerUrl);
    const parts = u.pathname.split("/").filter(Boolean);
    const networkName = parts.pop();
    if (!networkName) throw new Error("Peer URL must end with a network name.");
    const base = u.origin + "/" + parts.join("/") + (parts.length ? "/" : "");
    // Consent before contacting a third-party origin
    const ok = confirmFn
      ? await confirmFn({ origin: u.origin, purpose: "load peer agent network '" + networkName + "'" })
      : false;
    if (!ok) {
      this.onEvent({ type: "peer_denied", origin: u.origin });
      return null;
    }
    this._remoteCalls++;
    const mRes = await fetch(base + "agent-manifest.json", { mode: "cors" });
    if (!mRes.ok) throw new Error("Peer manifest HTTP " + mRes.status + " from " + u.origin);
    const manifest = await mRes.json();
    const entry = (manifest.networks || []).find((n) => n.name === networkName);
    if (!entry) throw new Error("Peer manifest has no exact-match network '" + networkName + "' (fail closed per spec).");
    const hoconUrl = new URL(entry.hocon, base).href;
    const hRes = await fetch(hoconUrl, { mode: "cors" });
    if (!hRes.ok) throw new Error("Peer network definition HTTP " + hRes.status);
    const def = await hRes.json();
    this.onEvent({ type: "peer_loaded", origin: u.origin, network: networkName });
    return this.loadNetwork(def);
  }

  // --- OpenAI-compatible model call ---
  async _model(messages, functions) {
    if (!this.hasActiveRouter()) {
      throw new Error("No active LLM router. Use the BYOK panel to set a base URL, key, and model.");
    }
    const isDemo = this.router.demo === true;
    if (!isDemo) {
      const inputCheck = validateRouterInputs(this.router);
      if (!inputCheck.ok) {
        const err = new Error(inputCheck.message);
        err.routerFlag = {
          field: inputCheck.field,
          code: inputCheck.code,
          badge: inputCheck.badge,
          message: inputCheck.message
        };
        throw err;
      }
    }
    if (this._startedAt && (Date.now() - this._startedAt) / 1000 > this.limits.max_elapsed_seconds) {
      throw new Error("Elapsed-time limit reached.");
    }
    this._remoteCalls++;
    if (this._remoteCalls > this.limits.max_remote_calls) {
      throw new Error("Remote-call limit reached (" + this.limits.max_remote_calls + ").");
    }

    const requestedModel = typeof this.router.model === "string" ? this.router.model.trim() : "";
    const body = {
      ...(isDemo
        ? (requestedModel && requestedModel !== "default" ? { model: requestedModel } : {})
        : { model: requestedModel || "gpt-4o-mini" }),
      messages,
      stream: false,
      ...(functions && functions.length ? { tools: functions, tool_choice: "auto" } : {})
    };
    const payload = JSON.stringify(body);

    let res = null;
    let rawText = "";
    let targetUrl = "";

    if (isDemo) {
      res = await fetch("/api/relay", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-use-demo": "1"
        },
        body: payload
      });
      rawText = await res.text();
    } else {
      const url = normalizeChatUrl(this.router.baseUrl);
      targetUrl = url;
      const isLocal = isLocalEndpointUrl(url);
      const rawKey = String(this.router.apiKey || "").trim();
      const auth = /^Bearer\s+/i.test(rawKey) ? rawKey : "Bearer " + rawKey;
      const callRelay = () =>
        fetch("/api/relay", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": auth,
            "x-target-url": url
          },
          body: payload
        });

      try {
        if (!isLocal && this._preferRelayFor === url) {
          res = await callRelay();
          rawText = await res.text();
        } else {
          let usedRelay = false;
          try {
            // Try provider directly first (browser-to-provider when CORS is supported).
            res = await fetch(url, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Authorization": auth
              },
              body: payload
            });
            rawText = await res.text();
          } catch (directErr) {
            if (isLocal) {
              throw directErr;
            }
            // Direct call blocked by browser CORS / network TypeError -> cache relay for this URL.
            this._preferRelayFor = url;
            res = await callRelay();
            rawText = await res.text();
            usedRelay = true;
          }

          // Also catch browser Origin WAF / CORS gateway rejections (403/405 without valid JSON completion).
          if (!usedRelay && !isLocal && res && (res.status === 403 || res.status === 405) && /^https:\/\//i.test(url)) {
            let probe = null;
            try { probe = rawText ? JSON.parse(rawText) : null; } catch { probe = null; }
            const hasCompletion = Boolean(probe && probe.choices && probe.choices[0] && probe.choices[0].message);
            if (!hasCompletion) {
              this._preferRelayFor = url;
              res = await callRelay();
              rawText = await res.text();
            }
          }
        }
      } catch (netErr) {
        const err = new Error(
          isLocal
            ? "Unreachable local Base URL: connection failed or blocked by browser CORS."
            : "Unreachable Base URL: network request failed."
        );
        throw attachRouterFlag(err, {
          networkError: true,
          isLocal,
          url
        });
      }
    }

    let data = null;
    try {
      data = rawText ? JSON.parse(rawText) : null;
    } catch {
      data = null;
    }

    const contentType = res.headers ? res.headers.get("content-type") || "" : "";
    const upstreamContentType = res.headers ? res.headers.get("x-upstream-content-type") || "" : "";
    const flagContext = {
      status: res.status,
      data,
      rawText,
      contentType,
      upstreamContentType,
      url: targetUrl
    };

    if (!res.ok) {
      const err = new Error("Router HTTP " + res.status + ": " + extractRouterError(data, rawText));
      if (!isDemo) attachRouterFlag(err, flagContext);
      throw err;
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      const err = new Error("Router returned non-JSON or malformed payload: " + extractRouterError(data, rawText));
      if (!isDemo) attachRouterFlag(err, flagContext);
      throw err;
    }
    if (data.error) {
      const err = new Error("Router error: " + extractRouterError(data, rawText));
      if (!isDemo) attachRouterFlag(err, flagContext);
      throw err;
    }
    const msg = data.choices && data.choices[0] && data.choices[0].message;
    if (!msg || typeof msg !== "object") {
      const err = new Error("Router response missing choices[0].message: " + extractRouterError(data, rawText));
      if (!isDemo) attachRouterFlag(err, flagContext);
      throw err;
    }
    return msg;
  }

  _agentAsFunction(agent) {
    const params = (agent.function && agent.function.parameters) || { type: "object", properties: {} };
    return {
      type: "function",
      function: {
        name: agent.name,
        description: (agent.function && agent.function.description) || agent.name,
        parameters: params
      }
    };
  }

  // --- Run one agent (with delegation) ---
  async _runAgent(name, input, depth) {
    if (depth > this.limits.max_composition_depth) throw new Error("Composition depth limit reached.");
    if (++this._invocations > this.limits.max_agent_invocations) throw new Error("Agent-invocation limit reached.");
    if ((Date.now() - this._startedAt) / 1000 > this.limits.max_elapsed_seconds) throw new Error("Elapsed-time limit reached.");
    const agent = this.agents.get(name);
    if (!agent) throw new Error("Unknown agent: " + name);
    this.onEvent({ type: "agent_start", agent: name, depth, input });

    const callable = (agent.tools || [])
      .filter((t) => typeof t === "string" && this.agents.has(t))
      .map((t) => this._agentAsFunction(this.agents.get(t)));
    const messages = [
      { role: "system", content: agent.instructions || ("You are the " + name + " agent.") },
      { role: "user", content: typeof input === "string" ? input : JSON.stringify(input) }
    ];

    let hops = 0;
    while (hops++ < 16) {
      const msg = await this._model(messages, callable);
      if (msg.tool_calls && msg.tool_calls.length) {
        const normalizedCalls = msg.tool_calls.map((tc, i) => ({
          ...tc,
          id: tc.id || ("call_" + hops + "_" + i),
          type: tc.type || "function"
        }));
        const assistantMsg = {
          role: "assistant",
          content: typeof msg.content === "string" ? msg.content : "",
          tool_calls: normalizedCalls,
          ...(typeof msg.reasoning_content === "string" ? { reasoning_content: msg.reasoning_content } : {})
        };
        messages.push(assistantMsg);

        for (const tc of normalizedCalls) {
          const childName = tc.function && tc.function.name ? String(tc.function.name).trim() : "";
          let args = {};
          const rawArgs = tc.function ? tc.function.arguments : "{}";
          if (typeof rawArgs === "string") {
            try { args = JSON.parse(rawArgs || "{}"); } catch { args = { input: rawArgs }; }
          } else if (rawArgs && typeof rawArgs === "object") {
            args = rawArgs;
          }

          this.onEvent({ type: "agent_delegate", from: name, to: childName, depth: depth + 1, input: args });

          let toolContent = "";
          if (!this.agents.has(childName)) {
            toolContent = "Error: unknown agent '" + childName + "'. Available agents: " + [...this.agents.keys()].join(", ");
          } else {
            const childOut = await this._runAgent(childName, args, depth + 1);
            toolContent = typeof childOut === "string" ? (childOut || "(empty)") : JSON.stringify(childOut);
          }
          messages.push({ role: "tool", tool_call_id: tc.id, content: toolContent });
        }
        continue;
      }

      const textOut = Array.isArray(msg.content)
        ? msg.content.map((p) => (typeof p === "string" ? p : (p && p.text) || "")).join("")
        : (typeof msg.content === "string" ? msg.content : "");
      this.onEvent({ type: "agent_done", agent: name, depth, output: textOut });
      return textOut;
    }

    const limitOut = "(agent hop limit reached)";
    this.onEvent({ type: "agent_done", agent: name, depth, output: limitOut, hopLimitReached: true });
    return limitOut;
  }

  // --- Public entry: run the front agent ---
  async run(request) {
    if (!this.network) throw new Error("No network loaded.");
    this._invocations = 0;
    this._remoteCalls = 0;
    this._startedAt = Date.now();
    const front = (this.network.metadata && this.network.metadata.front_agent) || this.network.front_agent;
    this.onEvent({ type: "run_start", request, front });
    try {
      const out = await this._runAgent(front, { request }, 0);
      this.onEvent({
        type: "run_done",
        output: out,
        invocations: this._invocations,
        remoteCalls: this._remoteCalls,
        elapsedMs: Date.now() - this._startedAt
      });
      return out;
    } catch (err) {
      if (err && err.routerFlag) {
        this.onEvent({
          type: "router_flagged",
          field: err.routerFlag.field,
          code: err.routerFlag.code,
          badge: err.routerFlag.badge,
          message: err.routerFlag.message
        });
      }
      this.onEvent({
        type: "run_error",
        error: err && err.message ? err.message : String(err),
        elapsedMs: Date.now() - this._startedAt
      });
      throw err;
    }
  }
}
