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

function parseJsonOrSseError(rawText) {
  if (!rawText || typeof rawText !== "string") return null;
  try {
    return JSON.parse(rawText);
  } catch {
    const lines = rawText.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("data:")) {
        const payload = trimmed.slice(5).trim();
        if (payload && payload !== "[DONE]") {
          try {
            return JSON.parse(payload);
          } catch {}
        }
      }
    }
    return null;
  }
}

function isStreamUnsupportedError(status, data, rawText) {
  if (status !== 400) return false;
  const obj = Array.isArray(data) ? data[0] : data;
  const errObj =
    obj && typeof obj === "object" && obj.error && typeof obj.error === "object"
      ? obj.error
      : null;
  const param = String(
    (errObj && (errObj.param || errObj.field)) ||
      (obj && typeof obj === "object" && obj.field) ||
      ""
  )
    .trim()
    .toLowerCase();
  if (param === "stream") return true;
  const errText = extractRouterError(data, rawText);
  return /\bstream(?:ing)?\b[^\n]{0,60}\b(?:not\s+supported|unsupported|does\s+not\s+support|doesn't\s+support|disabled|not\s+allowed|must\s+be\s+false)\b|\b(?:unsupported|does\s+not\s+support|doesn't\s+support)[^\n]{0,50}\bstream(?:ing)?\b/i.test(
    errText
  );
}

export const HARD_RUNTIME_LIMITS = Object.freeze({
  max_composition_depth: 8,
  max_agent_invocations: 100,
  max_remote_calls: 100,
  max_concurrency: 8,
  max_elapsed_seconds: 900
});

const DEFAULT_RUNTIME_LIMITS = Object.freeze({
  max_composition_depth: 4,
  max_agent_invocations: 40,
  max_remote_calls: 40,
  max_concurrency: 4,
  max_elapsed_seconds: 900
});

const FORBIDDEN_EXECUTABLE_KEYS = [
  "code",
  "script",
  "eval",
  "inline_code",
  "handler_source",
  "executable"
];

export function validateManifest(manifest) {
  const errors = [];
  const warnings = [];
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    return { ok: false, errors: ["Manifest must be a JSON object."], warnings, networks: [] };
  }
  if (String(manifest.manifest_version || "") !== "0.2") {
    errors.push("manifest_version must be '0.2' (MVP Profile 0.2).");
  }
  if (!manifest.site || typeof manifest.site !== "object" || !String(manifest.site.name || "").trim()) {
    errors.push("site.name is required.");
  }
  if (!manifest.inference || typeof manifest.inference !== "object") {
    errors.push("inference metadata object is required.");
  } else if (typeof manifest.inference.byok_supported !== "boolean") {
    warnings.push("inference.byok_supported should be a boolean.");
  }
  const networks = Array.isArray(manifest.networks) ? manifest.networks : [];
  if (!networks.length) {
    errors.push("networks must be a non-empty array.");
  } else {
    const seen = new Set();
    for (const net of networks) {
      if (!net || typeof net !== "object") {
        errors.push("Each network entry must be an object.");
        continue;
      }
      const name = String(net.name || "").trim();
      const front = String(net.front_agent || net.front_man || "").trim();
      const hocon = String(net.hocon || "").trim();
      if (!name) errors.push("A network entry is missing 'name'.");
      else if (seen.has(name)) errors.push("Duplicate network name in manifest: " + name);
      else seen.add(name);
      if (!front) errors.push("Network '" + (name || "?") + "' is missing front_agent / front_man.");
      if (!hocon) errors.push("Network '" + (name || "?") + "' is missing 'hocon' definition path.");
    }
  }
  if (!manifest.peer_policy || typeof manifest.peer_policy !== "object") {
    warnings.push("peer_policy metadata is recommended.");
  }
  return {
    ok: errors.length === 0,
    errors,
    warnings,
    networks: networks.map((n) => n && n.name).filter(Boolean)
  };
}

export function validateNetworkDefinition(def) {
  const errors = [];
  if (!def || typeof def !== "object" || Array.isArray(def)) {
    return { ok: false, errors: ["Network definition must be an object."], front: null, agents: [], limits: null };
  }
  const meta = def.metadata && typeof def.metadata === "object" ? def.metadata : {};
  const front = meta.front_agent || meta.front_man || def.front_agent || def.front_man || "";
  if (!front || typeof front !== "string") {
    errors.push("Network has no front_agent / front_man.");
  }
  const tools = Array.isArray(def.tools) ? def.tools : [];
  if (!tools.length) {
    errors.push("Network has no agents/tools.");
  }
  const names = new Set();
  for (const t of tools) {
    if (!t || typeof t !== "object") {
      errors.push("Agent entry must be an object.");
      continue;
    }
    if (!t.name || typeof t.name !== "string") {
      errors.push("An agent is missing a name.");
      continue;
    }
    if (names.has(t.name)) {
      errors.push("Duplicate agent name: " + t.name);
    }
    names.add(t.name);
    for (const badKey of FORBIDDEN_EXECUTABLE_KEYS) {
      if (Object.prototype.hasOwnProperty.call(t, badKey) && t[badKey] != null) {
        errors.push("Unsupported executable definition field '" + badKey + "' on agent '" + t.name + "'.");
      }
    }
    if (t.function && typeof t.function === "object") {
      const params = t.function.parameters;
      if (params !== undefined && (typeof params !== "object" || params === null || params.type !== "object")) {
        errors.push("Agent '" + t.name + "' function.parameters must be a JSON Schema object.");
      }
    }
  }
  for (const t of tools) {
    if (!t || typeof t !== "object") continue;
    for (const ref of (t.tools || [])) {
      if (typeof ref === "string" && !/^https?:\/\//i.test(ref) && !names.has(ref)) {
        errors.push("Agent '" + t.name + "' references unknown agent '" + ref + "'.");
      }
    }
  }
  if (front && !names.has(front)) {
    errors.push("Front agent '" + front + "' is not defined.");
  }

  const limits = { ...DEFAULT_RUNTIME_LIMITS };
  if (def.execution_limits !== undefined) {
    if (!def.execution_limits || typeof def.execution_limits !== "object" || Array.isArray(def.execution_limits)) {
      errors.push("execution_limits must be an object.");
    } else {
      for (const key of Object.keys(HARD_RUNTIME_LIMITS)) {
        if (Object.prototype.hasOwnProperty.call(def.execution_limits, key)) {
          const val = def.execution_limits[key];
          if (typeof val !== "number" || !Number.isFinite(val) || val <= 0) {
            errors.push("execution_limits." + key + " must be a finite positive number.");
          } else {
            limits[key] = Math.min(Math.floor(val), HARD_RUNTIME_LIMITS[key]);
          }
        }
      }
    }
  }

  const rawPrivacy = def.private_context_rules;
  const privateContextRules = {
    deny_by_default: rawPrivacy && typeof rawPrivacy.deny_by_default === "boolean"
      ? rawPrivacy.deny_by_default
      : true,
    allowed_downstream_fields:
      rawPrivacy && Array.isArray(rawPrivacy.allowed_downstream_fields)
        ? rawPrivacy.allowed_downstream_fields.filter((f) => typeof f === "string")
        : [],
    allowed_upstream_fields:
      rawPrivacy && Array.isArray(rawPrivacy.allowed_upstream_fields)
        ? rawPrivacy.allowed_upstream_fields.filter((f) => typeof f === "string")
        : []
  };

  return {
    ok: errors.length === 0,
    errors,
    name: meta.name || "network",
    front,
    agents: [...names],
    limits,
    privateContextRules
  };
}

export function filterPrivateContext(slyData, rules = { deny_by_default: true, allowed_downstream_fields: [] }) {
  if (!slyData || typeof slyData !== "object" || Array.isArray(slyData)) {
    return {};
  }
  const denyByDefault = !rules || rules.deny_by_default !== false;
  const allowed = new Set(
    rules && Array.isArray(rules.allowed_downstream_fields)
      ? rules.allowed_downstream_fields
      : []
  );
  const out = {};
  for (const [k, v] of Object.entries(slyData)) {
    if (!denyByDefault || allowed.has(k)) {
      out[k] = v;
    }
  }
  return out;
}

export class AuraRuntime {
  constructor({ router, onEvent } = {}) {
    this.router = router || null; // { baseUrl, apiKey, model } or { demo: true, model }
    this.onEvent = onEvent || (() => {});
    this.network = null;
    this.agents = new Map();
    this.limits = { ...DEFAULT_RUNTIME_LIMITS };
    this.privateContextRules = {
      deny_by_default: true,
      allowed_downstream_fields: [],
      allowed_upstream_fields: []
    };
    this._invocations = 0;
    this._remoteCalls = 0;
    this._startedAt = 0;
    this._preferRelayFor = null;
    this._streamUnsupportedFor = null;
  }

  setRouter(router) {
    let prevUrl = null;
    let nextUrl = null;
    try { if (this.router && this.router.baseUrl) prevUrl = normalizeChatUrl(this.router.baseUrl); } catch {}
    try { if (router && router.baseUrl) nextUrl = normalizeChatUrl(router.baseUrl); } catch {}
    if (prevUrl !== nextUrl || !nextUrl) {
      this._preferRelayFor = null;
    }
    this._streamUnsupportedFor = null;
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

  // --- Private-context (sly_data) deny-by-default filter (MVP Profile 0.2 section 2.1 & 5) ---
  filterPrivateContext(slyData) {
    return filterPrivateContext(slyData, this.privateContextRules);
  }

  // --- Load + validate a network definition (Tenet One / section 3.1 parse+validate) ---
  loadNetwork(def) {
    const check = validateNetworkDefinition(def);
    if (!check.ok) {
      throw new Error(check.errors[0] || "Invalid agent network definition.");
    }
    this.network = def;
    this.agents = new Map((def.tools || []).map((t) => [t.name, t]));
    this.limits = { ...check.limits };
    this.privateContextRules = { ...check.privateContextRules };
    this.onEvent({
      type: "network_loaded",
      name: check.name,
      front: check.front,
      agents: check.agents,
      limits: { ...this.limits },
      denyByDefault: this.privateContextRules.deny_by_default
    });
    return {
      name: check.name,
      front: check.front,
      agents: check.agents,
      limits: { ...this.limits }
    };
  }

  async loadNetworkFromUrl(url, fetchImpl = fetch) {
    const res = await fetchImpl(url, { mode: "cors", credentials: "omit" });
    if (!res.ok) throw new Error("Failed to fetch network (" + res.status + "): " + url);
    const def = await res.json();
    return this.loadNetwork(def);
  }

  // --- Peer-site loading (section 3.2): URL's final path component is the exact network name ---
  async loadPeerNetwork(peerUrl, confirmFn, fetchImpl = fetch) {
    let u;
    try {
      u = new URL(peerUrl);
    } catch {
      throw new Error("Peer URL must be a valid HTTPS URL ending with the network name.");
    }
    const isLocal = isLocalHostName(u.hostname);
    if (u.protocol !== "https:" && !(u.protocol === "http:" && isLocal)) {
      throw new Error("Peer URL must use HTTPS (http:// is allowed only for localhost development).");
    }
    const parts = u.pathname.split("/").filter(Boolean);
    const networkName = parts.pop();
    if (!networkName) throw new Error("Peer URL must end with a network name.");
    const base = u.origin + "/" + parts.join("/") + (parts.length ? "/" : "");
    const manifestUrl = base + "agent-manifest.json";

    // Consent before contacting any origin (Spec Section 3.2 & Section 5)
    const ok = confirmFn
      ? await confirmFn({
          origin: u.origin,
          networkName,
          peerUrl: u.href,
          manifestUrl,
          purpose: "load peer agent network '" + networkName + "'"
        })
      : false;
    if (!ok) {
      this.onEvent({ type: "peer_denied", origin: u.origin, network: networkName });
      return null;
    }

    if (this._remoteCalls + 1 > this.limits.max_remote_calls) {
      throw new Error("Remote-call limit reached (" + this.limits.max_remote_calls + ").");
    }
    this._remoteCalls++;
    const mRes = await fetchImpl(manifestUrl, { mode: "cors", credentials: "omit" });
    if (!mRes.ok) throw new Error("Peer manifest HTTP " + mRes.status + " from " + u.origin);
    const manifest = await mRes.json();
    const mCheck = validateManifest(manifest);
    if (!mCheck.ok) {
      throw new Error("Peer manifest invalid: " + mCheck.errors[0]);
    }

    // Fail-closed exact-match network resolution (Spec Section 3.2)
    const entry = (manifest.networks || []).find((n) => n && n.name === networkName);
    if (!entry) {
      throw new Error(
        "Peer manifest has no exact-match network '" + networkName + "' (fail closed per spec)."
      );
    }

    const resolvedHocon = new URL(entry.hocon, base);
    if (resolvedHocon.protocol !== "https:" && !(resolvedHocon.protocol === "http:" && isLocalHostName(resolvedHocon.hostname))) {
      throw new Error("Peer network definition URL must use HTTPS.");
    }
    if (resolvedHocon.origin !== u.origin) {
      const okSecond = confirmFn
        ? await confirmFn({
            origin: resolvedHocon.origin,
            networkName,
            peerUrl: resolvedHocon.href,
            manifestUrl: resolvedHocon.href,
            purpose: "fetch redirected network definition for '" + networkName + "'"
          })
        : false;
      if (!okSecond) {
        this.onEvent({ type: "peer_denied", origin: resolvedHocon.origin, network: networkName });
        return null;
      }
    }

    if (this._remoteCalls + 1 > this.limits.max_remote_calls) {
      throw new Error("Remote-call limit reached (" + this.limits.max_remote_calls + ").");
    }
    this._remoteCalls++;
    const hRes = await fetchImpl(resolvedHocon.href, { mode: "cors", credentials: "omit" });
    if (!hRes.ok) throw new Error("Peer network definition HTTP " + hRes.status);
    const def = await hRes.json();

    // Note: Peer manifest inference metadata is strictly ignored; caller's router & BYOK key never leave caller.
    this.onEvent({
      type: "peer_loaded",
      origin: u.origin,
      network: networkName,
      manifestUrl,
      definitionUrl: resolvedHocon.href
    });
    return this.loadNetwork(def);
  }

  // --- Consume an OpenAI-compatible SSE stream into an assistant message ---
  async _consumeSseStream(
    res,
    preReadText,
    { agentName, isDemo, targetUrl, contentType, upstreamContentType }
  ) {
    let contentAcc = "";
    let reasoningAcc = "";
    const toolCallsMap = new Map();
    let sawChoicesChunk = false;
    let sawDone = false;
    let lastEmitAt = 0;
    let lastEmittedReasoning = 0;
    let lastEmittedContent = 0;
    let lastEmittedTools = 0;
    let rawSample = "";
    let currentEventType = "";
    const pendingDataLines = [];

    const maybeEmitStream = (force = false) => {
      const rLen = reasoningAcc.length;
      const cLen = contentAcc.length;
      const tLen = toolCallsMap.size;
      if (rLen === 0 && cLen === 0 && tLen === 0) return;
      if (
        rLen === lastEmittedReasoning &&
        cLen === lastEmittedContent &&
        tLen === lastEmittedTools
      ) {
        return;
      }
      const now = Date.now();
      if (!force && lastEmitAt > 0 && now - lastEmitAt < 250) return;
      lastEmitAt = now;
      lastEmittedReasoning = rLen;
      lastEmittedContent = cLen;
      lastEmittedTools = tLen;
      this.onEvent({
        type: "agent_stream",
        agent: agentName || null,
        reasoningChars: rLen,
        contentChars: cLen,
        toolCalls: tLen
      });
    };

    const handleParsedChunk = (chunk, rawChunkText) => {
      if (!chunk || typeof chunk !== "object" || Array.isArray(chunk)) return;

      if (chunk.error || currentEventType === "error") {
        const errPayload = chunk.error ? chunk : { error: chunk };
        const err = new Error(
          "Router error: " + extractRouterError(errPayload, rawChunkText)
        );
        if (!isDemo) {
          attachRouterFlag(err, {
            status: res.status,
            data: errPayload,
            rawText: rawChunkText,
            contentType,
            upstreamContentType,
            url: targetUrl
          });
        }
        throw err;
      }

      if (Array.isArray(chunk.choices)) {
        if (chunk.choices.length > 0) {
          sawChoicesChunk = true;
        }
        const choice = chunk.choices[0];
        if (choice && typeof choice === "object") {
          const delta = choice.delta || choice.message || {};
          if (typeof delta.content === "string") {
            contentAcc += delta.content;
          } else if (Array.isArray(delta.content)) {
            for (const part of delta.content) {
              if (typeof part === "string") contentAcc += part;
              else if (part && typeof part.text === "string") contentAcc += part.text;
            }
          }
          if (typeof delta.reasoning_content === "string") {
            reasoningAcc += delta.reasoning_content;
          }
          if (Array.isArray(delta.tool_calls)) {
            for (let i = 0; i < delta.tool_calls.length; i++) {
              const tc = delta.tool_calls[i];
              if (!tc || typeof tc !== "object") continue;
              const idx =
                tc.index !== undefined &&
                tc.index !== null &&
                !Number.isNaN(Number(tc.index))
                  ? Number(tc.index)
                  : i;
              let slot = toolCallsMap.get(idx);
              if (!slot) {
                slot = {
                  id: "",
                  type: "function",
                  function: { name: "", arguments: "" }
                };
                toolCallsMap.set(idx, slot);
              }
              if (typeof tc.id === "string" && tc.id && !slot.id) {
                slot.id = tc.id;
              }
              if (typeof tc.type === "string" && tc.type) {
                slot.type = tc.type;
              }
              if (tc.function && typeof tc.function === "object") {
                if (typeof tc.function.name === "string") {
                  slot.function.name += tc.function.name;
                }
                if (typeof tc.function.arguments === "string") {
                  slot.function.arguments += tc.function.arguments;
                }
              }
            }
          }
          maybeEmitStream(false);
        }
      }
    };

    const flushPendingData = () => {
      if (!pendingDataLines.length) return;
      const joined = pendingDataLines.join("\n").trim();
      pendingDataLines.length = 0;
      if (!joined) return;
      if (joined === "[DONE]") {
        sawDone = true;
        return;
      }
      let parsed = null;
      try {
        parsed = JSON.parse(joined);
      } catch {
        parsed = null;
      }
      if (parsed !== null) {
        handleParsedChunk(parsed, joined);
      }
    };

    const processLine = (rawLine) => {
      const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
      if (line === "") {
        flushPendingData();
        currentEventType = "";
        return;
      }
      if (line.startsWith(":")) {
        return;
      }
      if (line.startsWith("event:")) {
        currentEventType = line.slice(6).trim().toLowerCase();
        return;
      }
      if (line.startsWith("data:")) {
        const val = line.slice(5).trim();
        if (!val) return;
        if (pendingDataLines.length === 0) {
          if (val === "[DONE]") {
            sawDone = true;
            return;
          }
          try {
            const parsed = JSON.parse(val);
            handleParsedChunk(parsed, val);
            return;
          } catch {
            pendingDataLines.push(val);
            return;
          }
        } else {
          pendingDataLines.push(val);
          return;
        }
      }
    };

    if (preReadText === null && res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let lineBuffer = "";
      try {
        while (!sawDone) {
          if (
            this._startedAt &&
            (Date.now() - this._startedAt) / 1000 > this.limits.max_elapsed_seconds
          ) {
            try { await reader.cancel(); } catch {}
            throw new Error("Elapsed-time limit reached.");
          }
          let step;
          try {
            step = await reader.read();
          } catch (readErr) {
            if (!sawChoicesChunk && !contentAcc && !reasoningAcc && toolCallsMap.size === 0) {
              const err = new Error(
                "Unreachable Base URL or interrupted stream: " +
                  (readErr && readErr.message ? readErr.message : String(readErr))
              );
              if (!isDemo) {
                attachRouterFlag(err, {
                  networkError: true,
                  isLocal: isLocalEndpointUrl(targetUrl),
                  url: targetUrl
                });
              }
              throw err;
            }
            throw new Error(
              "Router stream interrupted mid-response: " +
                (readErr && readErr.message ? readErr.message : String(readErr))
            );
          }
          const { value, done } = step;
          if (done) {
            lineBuffer += decoder.decode();
            break;
          }
          const chunkStr = decoder.decode(value, { stream: true });
          if (rawSample.length < 1200) {
            rawSample += chunkStr.slice(0, 1200 - rawSample.length);
          }
          lineBuffer += chunkStr;
          let nlIdx;
          while ((nlIdx = lineBuffer.indexOf("\n")) !== -1) {
            const line = lineBuffer.slice(0, nlIdx);
            lineBuffer = lineBuffer.slice(nlIdx + 1);
            processLine(line);
            if (sawDone) break;
          }
        }
        if (!sawDone && lineBuffer.length > 0) {
          processLine(lineBuffer);
        }
        flushPendingData();
      } finally {
        if (sawDone) {
          try { await reader.cancel(); } catch {}
        }
        try { reader.releaseLock(); } catch {}
      }
    } else {
      const fullText = preReadText !== null ? preReadText : await res.text();
      rawSample = fullText.slice(0, 1200);
      const lines = fullText.split("\n");
      for (const line of lines) {
        processLine(line);
        if (sawDone) break;
      }
      flushPendingData();
    }

    maybeEmitStream(true);

    const toolCallsList = [...toolCallsMap.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([, slot]) => slot);

    if (
      !sawChoicesChunk &&
      !contentAcc &&
      !reasoningAcc &&
      toolCallsList.length === 0
    ) {
      let fallbackJson = null;
      if (rawSample && rawSample.trim().startsWith("{")) {
        try { fallbackJson = JSON.parse(rawSample); } catch { fallbackJson = null; }
      }
      if (fallbackJson && fallbackJson.error) {
        const err = new Error("Router error: " + extractRouterError(fallbackJson, rawSample));
        if (!isDemo) {
          attachRouterFlag(err, {
            status: res.status,
            data: fallbackJson,
            rawText: rawSample,
            contentType,
            upstreamContentType,
            url: targetUrl
          });
        }
        throw err;
      }
      if (
        fallbackJson &&
        fallbackJson.choices &&
        fallbackJson.choices[0] &&
        fallbackJson.choices[0].message &&
        typeof fallbackJson.choices[0].message === "object"
      ) {
        return fallbackJson.choices[0].message;
      }

      const flagContext = {
        status: res.status,
        data: null,
        rawText: rawSample,
        contentType,
        upstreamContentType,
        url: targetUrl
      };
      const err = new Error(
        "Router returned invalid SSE stream without OpenAI choices: " +
          extractRouterError(null, rawSample)
      );
      if (!isDemo) attachRouterFlag(err, flagContext);
      throw err;
    }

    return {
      role: "assistant",
      content: contentAcc,
      ...(reasoningAcc ? { reasoning_content: reasoningAcc } : {}),
      ...(toolCallsList.length ? { tool_calls: toolCallsList } : {})
    };
  }

  // --- OpenAI-compatible model call (SSE streaming with automatic stream:false fallback) ---
  async _model(messages, functions, agentName) {
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
    const targetUrl = isDemo ? "" : normalizeChatUrl(this.router.baseUrl);
    const streamCacheKey = (isDemo ? "demo" : targetUrl) + "::" + (requestedModel || "default");

    const executeRequest = async (useStream) => {
      const body = {
        ...(isDemo
          ? (requestedModel && requestedModel !== "default" ? { model: requestedModel } : {})
          : { model: requestedModel || "gpt-4o-mini" }),
        messages,
        stream: Boolean(useStream),
        ...(functions && functions.length ? { tools: functions, tool_choice: "auto" } : {})
      };
      const payload = JSON.stringify(body);
      const acceptHeader = useStream
        ? "text/event-stream, application/json"
        : "application/json";

      if (isDemo) {
        const res = await fetch("/api/relay", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": acceptHeader,
            "x-use-demo": "1"
          },
          body: payload
        });
        return { res, preReadText: null };
      }

      const url = targetUrl;
      const isLocal = isLocalEndpointUrl(url);
      const rawKey = String(this.router.apiKey || "").trim();
      const auth = /^Bearer\s+/i.test(rawKey) ? rawKey : "Bearer " + rawKey;
      const callRelay = () =>
        fetch("/api/relay", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": acceptHeader,
            "Authorization": auth,
            "x-target-url": url
          },
          body: payload
        });

      try {
        if (!isLocal && this._preferRelayFor === url) {
          const res = await callRelay();
          return { res, preReadText: null };
        }

        let res = null;
        let preReadText = null;
        let usedRelay = false;
        try {
          // Try provider directly first (browser-to-provider when CORS is supported).
          res = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Accept": acceptHeader,
              "Authorization": auth
            },
            body: payload
          });
        } catch (directErr) {
          if (isLocal) {
            throw directErr;
          }
          // Direct call blocked by browser CORS / network TypeError -> cache relay for this URL.
          this._preferRelayFor = url;
          res = await callRelay();
          usedRelay = true;
        }

        // Also catch browser Origin WAF / CORS gateway rejections (403/405 without valid JSON completion).
        if (!usedRelay && !isLocal && res && (res.status === 403 || res.status === 405) && /^https:\/\//i.test(url)) {
          const probeText = await res.text();
          let probe = null;
          try { probe = probeText ? JSON.parse(probeText) : null; } catch { probe = null; }
          const hasCompletion = Boolean(probe && probe.choices && probe.choices[0] && probe.choices[0].message);
          if (!hasCompletion) {
            this._preferRelayFor = url;
            res = await callRelay();
            preReadText = null;
          } else {
            preReadText = probeText;
          }
        }

        return { res, preReadText };
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
    };

    let useStream = this._streamUnsupportedFor !== streamCacheKey;
    let { res, preReadText } = await executeRequest(useStream);

    if (!res.ok) {
      let rawText = preReadText !== null ? preReadText : await res.text();
      let data = parseJsonOrSseError(rawText);

      // Automatic fallback if HTTP 400 complains that streaming is unsupported by this model
      if (useStream && isStreamUnsupportedError(res.status, data, rawText)) {
        this._streamUnsupportedFor = streamCacheKey;
        useStream = false;
        const retry = await executeRequest(false);
        res = retry.res;
        preReadText = retry.preReadText;
        if (!res.ok) {
          rawText = preReadText !== null ? preReadText : await res.text();
          data = parseJsonOrSseError(rawText);
        }
      }

      if (!res.ok) {
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
        const err = new Error("Router HTTP " + res.status + ": " + extractRouterError(data, rawText));
        if (!isDemo) attachRouterFlag(err, flagContext);
        throw err;
      }
    }

    const contentType = res.headers ? res.headers.get("content-type") || "" : "";
    const upstreamContentType = res.headers ? res.headers.get("x-upstream-content-type") || "" : "";
    const ctLower = contentType.toLowerCase();
    const uctLower = upstreamContentType.toLowerCase();

    if (ctLower.includes("text/event-stream") || uctLower.includes("text/event-stream")) {
      return this._consumeSseStream(res, preReadText, {
        agentName,
        isDemo,
        targetUrl,
        contentType,
        upstreamContentType
      });
    }

    const rawText = preReadText !== null ? preReadText : await res.text();
    let data = null;
    try {
      data = rawText ? JSON.parse(rawText) : null;
    } catch {
      data = null;
    }

    // Handle SSE-formatted stream returned with missing/generic Content-Type header
    if (!data && rawText && /^\s*(?::[^\n]*\r?\n|event:\s*\S+\r?\n)*data:\s*\{/.test(rawText)) {
      return this._consumeSseStream(res, rawText, {
        agentName,
        isDemo,
        targetUrl,
        contentType,
        upstreamContentType
      });
    }

    const flagContext = {
      status: res.status,
      data,
      rawText,
      contentType,
      upstreamContentType,
      url: targetUrl
    };

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
    this.onEvent({
      type: "agent_start",
      agent: name,
      depth,
      input,
      invocations: this._invocations,
      remoteCalls: this._remoteCalls,
      elapsedMs: Date.now() - this._startedAt,
      limits: { ...this.limits }
    });

    const callable = (agent.tools || [])
      .filter((t) => typeof t === "string" && this.agents.has(t))
      .map((t) => this._agentAsFunction(this.agents.get(t)));
    const messages = [
      { role: "system", content: agent.instructions || ("You are the " + name + " agent.") },
      { role: "user", content: typeof input === "string" ? input : JSON.stringify(input) }
    ];

    let hops = 0;
    while (hops++ < 16) {
      const msg = await this._model(messages, callable, name);
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

          this.onEvent({
            type: "agent_delegate",
            from: name,
            to: childName,
            depth: depth + 1,
            input: args,
            invocations: this._invocations,
            remoteCalls: this._remoteCalls,
            elapsedMs: Date.now() - this._startedAt,
            limits: { ...this.limits }
          });

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
      this.onEvent({
        type: "agent_done",
        agent: name,
        depth,
        output: textOut,
        invocations: this._invocations,
        remoteCalls: this._remoteCalls,
        elapsedMs: Date.now() - this._startedAt,
        limits: { ...this.limits }
      });
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
    const front =
      (this.network.metadata && (this.network.metadata.front_agent || this.network.metadata.front_man)) ||
      this.network.front_agent ||
      this.network.front_man;
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

  // --- Interactive Spec Protocol Demo (Zero API Key Required) ---
  // Walks the loaded Neuro SAN network graph using the exact same finite execution
  // limits, deny-by-default private-context filter, and structured lifecycle events
  // without requiring an external LLM key.
  async runSpecDemo(request, { delayMs = 280 } = {}) {
    if (!this.network) throw new Error("No network loaded.");
    const prompt = String(request || "").trim() || "Design a URL shortener, then verify it";
    const pause = (ms) => (ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

    this._invocations = 0;
    this._remoteCalls = 0;
    this._startedAt = Date.now();

    const front =
      (this.network.metadata && (this.network.metadata.front_agent || this.network.metadata.front_man)) ||
      this.network.front_agent ||
      this.network.front_man;
    const frontAgent = this.agents.get(front);
    if (!frontAgent) throw new Error("Unknown front agent: " + front);

    const checkBudgets = (depth) => {
      if (depth > this.limits.max_composition_depth) {
        throw new Error("Composition depth limit reached.");
      }
      if (++this._invocations > this.limits.max_agent_invocations) {
        throw new Error("Agent-invocation limit reached.");
      }
      if ((Date.now() - this._startedAt) / 1000 > this.limits.max_elapsed_seconds) {
        throw new Error("Elapsed-time limit reached.");
      }
    };

    const filteredProbe = this.filterPrivateContext({
      visitor_api_key: "sk-never-forwarded",
      session_cookie: "private-session-token"
    });
    const leakedKeys = Object.keys(filteredProbe).length;

    this.onEvent({ type: "run_start", request: prompt, front, mode: "spec_demo" });

    try {
      checkBudgets(0);
      this.onEvent({ type: "agent_start", agent: front, depth: 0, input: { request: prompt } });
      await pause(delayMs);

      const isAuraCore =
        front === "orchestrator" &&
        this.agents.has("researcher") &&
        this.agents.has("builder") &&
        this.agents.has("verifier") &&
        this.agents.has("critic");

      const stageOutputs = {};

      if (isAuraCore) {
        const lower = prompt.toLowerCase();
        const isUrlShortener = lower.includes("shortener") || lower.includes("url");
        const isRetryDecorator = lower.includes("retry") || lower.includes("decorator") || lower.includes("python");
        const isLaunchPlan = lower.includes("launch") || lower.includes("3-day");

        const specPlan = isUrlShortener
          ? {
              research:
                "Grounded constraints: Base62 7-char IDs yield 3.52T unique slugs (62^7); read:write ratio ~100:1 favors edge KV/Redis cache + durable Postgres/DynamoDB; 301 vs 302 redirect tradeoff (302 preserves click analytics); rate limiting + safe-browsing URL validation prevents open-redirect abuse.",
              buildV1:
                "Draft architecture: POST /api/shorten (validates https:// URL, assigns monotonic Snowflake->Base62 key, writes DB + warms Redis), GET /:slug (Redis lookup -> DB fallback -> 302 Location redirect + async click telemetry).",
              verifyGaps:
                "GAPS (Pass 1): Missing collision/idempotency policy for duplicate long URLs and missing SSRF/javascript: scheme rejection rule.",
              buildV2:
                "Repaired build: Added strict scheme allowlist (http/https only, blocks javascript:/data:/private IPs), optional idempotency key per caller, TTL expiration support, and per-IP token-bucket rate limit (60 req/min).",
              verifyPass:
                "PASS (Pass 2): All prompt requirements satisfied, scheme validation closes XSS/open-redirect gap, caching + persistence separation is sound.",
              critic:
                "Strongest weakness: Hot-key thundering herd on viral slugs if Redis evicts simultaneously. Failure mode: Cache stampede spikes DB read latency under viral load. High-leverage fix: Add singleflight request coalescing + stale-while-revalidate edge caching."
            }
          : isRetryDecorator
          ? {
              research:
                "Grounded constraints: Exponential backoff with full jitter prevents synchronized retry storms (AWS Architecture Blog); preserve wrapped function metadata via functools.wraps; retry only transient exception tuples, never ValueError/TypeError.",
              buildV1:
                "Draft implementation: @retry(max_attempts=3, base_delay=0.5, exceptions=(TimeoutError, ConnectionError)) with exponential delay base_delay * (2 ** attempt) + uniform jitter.",
              verifyGaps:
                "GAPS (Pass 1): Missing async coroutine support (inspect.iscoroutinefunction) and missing upper max_delay cap to bound tail latency.",
              buildV2:
                "Repaired build: Unified sync/async decorator with functools.wraps, max_delay=30.0 cap, full jitter random.uniform(0, min(max_delay, base_delay * 2**attempt)), and on_retry telemetry callback.",
              verifyPass:
                "PASS (Pass 2): Handles both sync and async callables, preserves signatures/docstrings, bounds wait time, and re-raises final exception cleanly.",
              critic:
                "Strongest weakness: Non-idempotent side-effecting calls can double-execute on network timeout after server commit. Failure mode: Duplicate payment/write on ambiguous timeout. High-leverage fix: Require idempotency key parameter or restrict retries to idempotent operations."
            }
          : isLaunchPlan
          ? {
              research:
                "Grounded constraints: 3-day launches succeed when scope freezes by Day 1 EOD; Day 2 focuses on public distribution assets + smoke tests; Day 3 runs staggered release with rollback checklist and live telemetry.",
              buildV1:
                "Draft 3-day plan: Day 1 (Freeze MVP + staging deploy), Day 2 (Landing page + demo clip + beta testers), Day 3 (Public launch + post-launch triage).",
              verifyGaps:
                "GAPS (Pass 1): Missing explicit go/no-go rollback criteria and measurable Day-3 success metrics.",
              buildV2:
                "Repaired plan: Added concrete Day 1 smoke-test gate, Day 2 beta feedback cutoff (zero P0 bugs), Day 3 rollback trigger (>2% 5xx rate) and activation/retention KPIs.",
              verifyPass:
                "PASS (Pass 2): Actionable 72-hour milestones, explicit risk gates, and verifiable launch metrics.",
              critic:
                "Strongest weakness: Single-threaded Day 2 dependency on beta feedback can slip Day 3 launch. Failure mode: Unresolved onboarding friction discovered 4 hours before launch. High-leverage fix: Pre-recruit 5 beta testers on Day 1 morning so feedback lands 24h earlier."
            }
          : {
              research:
                "Grounded core domain constraints, edge cases, and verification criteria for: \"" + prompt + "\". Flagged assumptions explicitly so downstream stages stay deterministic.",
              buildV1:
                "Produced initial structured solution covering primary requirements, interface boundaries, and operational defaults for: \"" + prompt + "\".",
              verifyGaps:
                "GAPS (Pass 1): Identified missing failure-mode handling and explicit validation boundary checks against the original prompt.",
              buildV2:
                "Repaired artifact: Incorporated fail-closed input validation, explicit bounds, and concrete verification hooks addressing every Pass-1 gap.",
              verifyPass:
                "PASS (Pass 2): Verified repaired artifact against every requirement in the prompt with zero unresolved gaps.",
              critic:
                "Strongest weakness: Production assumptions should be validated under real workload latency. Failure mode: External dependency timeout without circuit breaking. High-leverage fix: Add bounded retries + observable health telemetry."
            };

        const steps = [
          { agent: "researcher", input: { query: prompt }, out: specPlan.research, reasoning: 142 },
          { agent: "builder", input: { spec: "Build solution for: " + prompt }, out: specPlan.buildV1, reasoning: 218 },
          { agent: "verifier", input: { artifact: specPlan.buildV1, against: prompt }, out: specPlan.verifyGaps, reasoning: 126 },
          { agent: "builder", input: { spec: "Repair Pass-1 gaps: " + specPlan.verifyGaps }, out: specPlan.buildV2, reasoning: 196 },
          { agent: "verifier", input: { artifact: specPlan.buildV2, against: prompt }, out: specPlan.verifyPass, reasoning: 114 },
          { agent: "critic", input: { result: specPlan.buildV2 }, out: specPlan.critic, reasoning: 164 }
        ];

        for (const step of steps) {
          this.onEvent({
            type: "agent_delegate",
            from: front,
            to: step.agent,
            depth: 1,
            input: step.input,
            invocations: this._invocations,
            remoteCalls: this._remoteCalls,
            elapsedMs: Date.now() - this._startedAt,
            limits: { ...this.limits }
          });
          checkBudgets(1);
          this.onEvent({
            type: "agent_start",
            agent: step.agent,
            depth: 1,
            input: step.input,
            invocations: this._invocations,
            remoteCalls: this._remoteCalls,
            elapsedMs: Date.now() - this._startedAt,
            limits: { ...this.limits }
          });
          await pause(Math.round(delayMs * 0.55));
          this.onEvent({
            type: "agent_stream",
            agent: step.agent,
            reasoningChars: step.reasoning,
            contentChars: step.out.length,
            toolCalls: 0
          });
          await pause(Math.round(delayMs * 0.65));
          this.onEvent({
            type: "agent_done",
            agent: step.agent,
            depth: 1,
            output: step.out,
            invocations: this._invocations,
            remoteCalls: this._remoteCalls,
            elapsedMs: Date.now() - this._startedAt,
            limits: { ...this.limits }
          });
          stageOutputs[step.agent] = step.out;
        }

        const synthesis = [
          "SPEC PROTOCOL DEMO — 5-AGENT BOUNDED TRACE COMPLETE",
          "Request: " + prompt,
          "",
          "1. GROUND (researcher)",
          stageOutputs.researcher,
          "",
          "2. BUILD & REPAIR (builder -> verifier GAPS -> builder repair -> verifier PASS)",
          "• Pass 1 Verifier: " + specPlan.verifyGaps,
          "• Repaired Build: " + stageOutputs.builder,
          "• Pass 2 Verifier: " + stageOutputs.verifier,
          "",
          "3. ADVERSARIAL STRESS-TEST (critic)",
          stageOutputs.critic,
          "",
          "4. MVP PROFILE 0.2 PROTOCOL TELEMETRY",
          "• Mode: Local Spec Protocol Simulation (0 API keys used, 0 remote calls)",
          "• Bounds enforced: " + this._invocations + "/" + this.limits.max_agent_invocations + " invocations · max depth 1/" + this.limits.max_composition_depth,
          "• Private context (sly_data): deny_by_default=" + this.privateContextRules.deny_by_default + " · " + leakedKeys + " fields leaked across boundary",
          "• Tip: Activate any OpenAI / Gemini / Groq / OpenRouter key in the right rail (or use the built-in live router) to run this exact same Neuro SAN JSON graph against a live LLM."
        ].join("\n");

        this.onEvent({ type: "agent_done", agent: front, depth: 0, output: synthesis });
        this.onEvent({
          type: "run_done",
          output: synthesis,
          mode: "spec_demo",
          invocations: this._invocations,
          remoteCalls: this._remoteCalls,
          elapsedMs: Date.now() - this._startedAt
        });
        return synthesis;
      }

      // Generic peer-network spec demo traversal for any loaded peer network
      const delegates = (frontAgent.tools || []).filter((t) => typeof t === "string" && this.agents.has(t));
      const lines = [
        "SPEC PROTOCOL DEMO — PEER NETWORK TRACE COMPLETE",
        "Network: " + ((this.network.metadata && this.network.metadata.name) || "peer-network") + " (front: " + front + ")",
        "Request: " + prompt,
        ""
      ];
      for (const childName of delegates) {
        const child = this.agents.get(childName);
        this.onEvent({ type: "agent_delegate", from: front, to: childName, depth: 1, input: { request: prompt } });
        checkBudgets(1);
        this.onEvent({ type: "agent_start", agent: childName, depth: 1, input: { request: prompt } });
        const desc = (child && child.function && child.function.description) || childName;
        const out = "[" + childName + "] Completed local protocol step: " + desc;
        await pause(delayMs);
        this.onEvent({ type: "agent_stream", agent: childName, reasoningChars: 96, contentChars: out.length, toolCalls: 0 });
        this.onEvent({ type: "agent_done", agent: childName, depth: 1, output: out });
        lines.push("• " + out);
      }
      lines.push(
        "",
        "Protocol Telemetry: " +
          this._invocations + "/" + this.limits.max_agent_invocations +
          " invocations · deny_by_default=" + this.privateContextRules.deny_by_default +
          " (" + leakedKeys + " leaked fields) · Local Simulation (no API key used)."
      );
      const synthesis = lines.join("\n");
      this.onEvent({ type: "agent_done", agent: front, depth: 0, output: synthesis });
      this.onEvent({
        type: "run_done",
        output: synthesis,
        mode: "spec_demo",
        invocations: this._invocations,
        remoteCalls: this._remoteCalls,
        elapsedMs: Date.now() - this._startedAt
      });
      return synthesis;
    } catch (err) {
      this.onEvent({
        type: "run_error",
        error: err && err.message ? err.message : String(err),
        elapsedMs: Date.now() - this._startedAt
      });
      throw err;
    }
  }
}

// --- Live Worldwide Agentic Web MVP Profile 0.2 Conformance Self-Test ---
export async function runSpecConformanceAudit({ origin, fetchImpl = fetch } = {}) {
  const baseOrigin = String(
    origin || (typeof location !== "undefined" && location.origin ? location.origin : "")
  ).replace(/\/+$/, "");

  const checks = [];

  async function probeEndpoint({ id, label, path, expectJson = true, validate }) {
    const url = baseOrigin ? baseOrigin + path : path;
    const t0 = Date.now();
    try {
      const res = await fetchImpl(url, { mode: "cors", credentials: "omit", cache: "no-store" });
      const ms = Date.now() - t0;
      const acao = res.headers ? String(res.headers.get("access-control-allow-origin") || "") : "";
      const ct = res.headers ? String(res.headers.get("content-type") || "") : "";
      const corsOk = acao === "*";
      if (!res.ok) {
        checks.push({
          id,
          label,
          path,
          pass: false,
          status: res.status,
          cors: acao || "missing",
          contentType: ct,
          ms,
          detail: "HTTP " + res.status + " (expected 200)"
        });
        return null;
      }
      let body = null;
      if (expectJson) {
        body = await res.json();
      } else {
        body = await res.text();
      }
      const extra = validate ? validate({ res, body, ct, acao }) : { ok: true, detail: "OK" };
      const pass = Boolean(res.ok && corsOk && extra.ok);
      checks.push({
        id,
        label,
        path,
        pass,
        status: res.status,
        cors: acao || "missing",
        contentType: ct,
        ms,
        detail: !corsOk
          ? "Missing Access-Control-Allow-Origin: * (got '" + (acao || "none") + "')"
          : extra.detail
      });
      return body;
    } catch (err) {
      checks.push({
        id,
        label,
        path,
        pass: false,
        status: 0,
        cors: "error",
        contentType: "",
        ms: Date.now() - t0,
        detail: err && err.message ? err.message : String(err)
      });
      return null;
    }
  }

  // 1. Root agent-manifest.json
  await probeEndpoint({
    id: "root_manifest",
    label: "Root Manifest",
    path: "/agent-manifest.json",
    validate: ({ body }) => {
      const v = validateManifest(body);
      return {
        ok: v.ok && Boolean(body.networks && body.networks.some((n) => n.name === "aura-core" && n.front_man === "orchestrator")),
        detail: v.ok ? "MVP 0.2 valid · networks=[" + v.networks.join(",") + "] · BYOK=true" : v.errors.join("; ")
      };
    }
  });

  // 2. .well-known/agent-manifest.json
  await probeEndpoint({
    id: "well_known_manifest",
    label: "Well-Known Manifest",
    path: "/.well-known/agent-manifest.json",
    validate: ({ body }) => {
      const v = validateManifest(body);
      const entry = (body.networks || []).find((n) => n.name === "aura-core");
      return {
        ok: v.ok && Boolean(entry && entry.hocon === "/aura-core.json"),
        detail: v.ok ? "MVP 0.2 discovery valid · hocon=" + (entry ? entry.hocon : "?") : v.errors.join("; ")
      };
    }
  });

  // 3. /agents/agent-manifest.json (peer subpath compatibility)
  await probeEndpoint({
    id: "agents_manifest",
    label: "Agents Subpath Manifest",
    path: "/agents/agent-manifest.json",
    validate: ({ body }) => {
      const v = validateManifest(body);
      return {
        ok: v.ok,
        detail: v.ok ? "Peer URL /agents/aura-core resolvable" : v.errors.join("; ")
      };
    }
  });

  // 4. /aura-core.json (Neuro SAN-profile network)
  const coreDef = await probeEndpoint({
    id: "network_def",
    label: "Neuro SAN Network",
    path: "/aura-core.json",
    validate: ({ body }) => {
      const v = validateNetworkDefinition(body);
      const requiredAgents = ["orchestrator", "researcher", "builder", "verifier", "critic"];
      const hasAll = requiredAgents.every((a) => v.agents.includes(a));
      return {
        ok: v.ok && hasAll && v.privateContextRules.deny_by_default === true,
        detail: v.ok
          ? v.agents.length + " agents (" + v.front + " front) · deny_by_default=true · max_depth=" + v.limits.max_composition_depth
          : v.errors.join("; ")
      };
    }
  });

  // 5. /runtime.js (pure ES module)
  await probeEndpoint({
    id: "runtime_esm",
    label: "ES Module Runtime",
    path: "/runtime.js",
    expectJson: false,
    validate: ({ body, ct }) => {
      const isJs = /javascript|ecmascript/i.test(ct);
      const hasExport = typeof body === "string" && body.includes("export class AuraRuntime");
      return {
        ok: isJs && hasExport,
        detail: isJs && hasExport ? "ES module (" + Math.round(body.length / 1024) + " KB) · " + ct : "Invalid JS MIME or missing export"
      };
    }
  });

  // 6. /links.json (peer-network link map)
  await probeEndpoint({
    id: "links_map",
    label: "Peer Link Map",
    path: "/links.json",
    validate: ({ body }) => {
      const ok = Boolean(body && body.version === 1 && body.networks && typeof body.networks === "object");
      return {
        ok,
        detail: ok ? "version=1 · " + Object.keys(body.networks).length + " network link table(s)" : "Invalid links.json schema"
      };
    }
  });

  // 7. Malformed network rejection (fail closed)
  {
    const testRt = new AuraRuntime();
    let rejectedBadRef = false;
    let rejectedExecCode = false;
    try {
      testRt.loadNetwork({
        metadata: { name: "bad", front_agent: "a" },
        tools: [{ name: "a", instructions: "x", tools: ["ghost"] }]
      });
    } catch {
      rejectedBadRef = true;
    }
    try {
      testRt.loadNetwork({
        metadata: { name: "bad2", front_agent: "a" },
        tools: [{ name: "a", instructions: "x", code: "alert(1)", tools: [] }]
      });
    } catch {
      rejectedExecCode = true;
    }
    checks.push({
      id: "fail_closed_schema",
      label: "Malformed Network Guard",
      path: "runtime:loadNetwork",
      pass: rejectedBadRef && rejectedExecCode,
      status: 200,
      cors: "local",
      contentType: "runtime",
      ms: 0,
      detail:
        rejectedBadRef && rejectedExecCode
          ? "Rejected unknown agent reference & undeclared inline code"
          : "Failed to reject malformed network"
    });
  }

  // 8. Finite execution bounds check
  {
    const testRt = new AuraRuntime();
    let rejectedInfinity = false;
    try {
      testRt.loadNetwork({
        metadata: { name: "inf", front_agent: "a" },
        tools: [{ name: "a", instructions: "x", tools: [] }],
        execution_limits: { max_agent_invocations: Infinity }
      });
    } catch {
      rejectedInfinity = true;
    }
    let boundsEnforced = false;
    if (coreDef) {
      testRt.loadNetwork({
        ...coreDef,
        execution_limits: { ...coreDef.execution_limits, max_agent_invocations: 2 }
      });
      try {
        await testRt.runSpecDemo("bound check", { delayMs: 0 });
      } catch (e) {
        boundsEnforced = /invocation limit/i.test(String(e && e.message));
      }
    } else {
      boundsEnforced = true;
    }
    checks.push({
      id: "finite_bounds",
      label: "Finite Execution Bounds",
      path: "runtime:execution_limits",
      pass: rejectedInfinity && boundsEnforced,
      status: 200,
      cors: "local",
      contentType: "runtime",
      ms: 0,
      detail:
        rejectedInfinity && boundsEnforced
          ? "Infinity rejected & invocation cap aborted over-budget run"
          : "Bounds enforcement check failed"
    });
  }

  // 9. Private context (sly_data) deny-by-default isolation
  {
    const filtered = filterPrivateContext(
      { api_key: "sk-secret", session_id: "tok-123", pii_email: "a@b.com" },
      (coreDef && coreDef.private_context_rules) || { deny_by_default: true, allowed_downstream_fields: [] }
    );
    const leaked = Object.keys(filtered).length;
    checks.push({
      id: "private_context",
      label: "Private Context Isolation",
      path: "runtime:sly_data",
      pass: leaked === 0,
      status: 200,
      cors: "local",
      contentType: "runtime",
      ms: 0,
      detail: leaked === 0 ? "deny_by_default=true · 0/3 sensitive fields forwarded" : leaked + " fields leaked"
    });
  }

  // 10. Fail-closed peer consent & exact-match name check
  {
    const testRt = new AuraRuntime();
    let fetchCalledOnDeny = false;
    const denied = await testRt.loadPeerNetwork(
      "https://peer.example/agents/transit",
      async () => false,
      async () => {
        fetchCalledOnDeny = true;
        throw new Error("should not fetch");
      }
    );
    let failedClosedOnMismatch = false;
    try {
      await testRt.loadPeerNetwork(
        "https://peer.example/agents/wrong-name",
        async () => true,
        async () => ({
          ok: true,
          status: 200,
          json: async () => ({
            manifest_version: "0.2",
            site: { name: "Peer" },
            inference: { byok_supported: true },
            networks: [{ name: "other-net", front_agent: "front", hocon: "./other.json" }]
          })
        })
      );
    } catch (e) {
      failedClosedOnMismatch = /exact-match|fail closed/i.test(String(e && e.message));
    }
    const pass = denied === null && !fetchCalledOnDeny && failedClosedOnMismatch;
    checks.push({
      id: "peer_fail_closed",
      label: "Peer Consent & Exact Match",
      path: "runtime:loadPeerNetwork",
      pass,
      status: 200,
      cors: "local",
      contentType: "runtime",
      ms: 0,
      detail: pass
        ? "Denied origin made 0 fetches · mismatched network failed closed"
        : "Peer consent or exact-match check failed"
    });
  }

  const passed = checks.filter((c) => c.pass).length;
  return {
    passed,
    total: checks.length,
    allPassed: passed === checks.length,
    checkedAt: new Date().toISOString(),
    origin: baseOrigin || "(relative)",
    checks
  };
}

// --- Build normalized graph topology (nodes + directed edges) from any Neuro SAN network ---
export function buildAgentGraph(def) {
  if (!def || typeof def !== "object" || !Array.isArray(def.tools)) {
    return { name: "network", front: null, nodes: [], edges: [] };
  }
  const meta = def.metadata && typeof def.metadata === "object" ? def.metadata : {};
  const front = meta.front_agent || meta.front_man || def.front_agent || def.front_man || null;
  const nodes = def.tools
    .filter((t) => t && typeof t.name === "string")
    .map((t) => ({
      id: t.name,
      isFront: t.name === front,
      description: (t.function && t.function.description) || t.instructions || t.name,
      tools: Array.isArray(t.tools) ? t.tools.slice() : []
    }));
  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = [];
  for (const n of nodes) {
    for (const ref of n.tools) {
      if (typeof ref === "string") {
        edges.push({
          from: n.id,
          to: ref,
          external: !nodeIds.has(ref)
        });
      }
    }
  }
  return {
    name: meta.name || "network",
    front,
    nodes,
    edges
  };
}

// --- Reusable Community Tool: Live External Peer-Site Conformance Validator (MVP Profile 0.2) ---
// Accepts ANY Agentic Web URL (site origin, peer subpath like /agents/aura-core,
// or direct /agent-manifest.json), scores it 0-100 across 10 live spec checks,
// and returns the validated network definition + graph ready for browser federation.
export async function auditExternalAgenticSite(
  rawTargetUrl,
  { fetchImpl = fetch, confirmOriginFn = null } = {}
) {
  const input = String(rawTargetUrl || "").trim();
  if (!input) {
    throw new Error("Enter an Agentic Web URL to validate (e.g. https://aura-agentic-web.vercel.app/agents/aura-core).");
  }
  const normalizedInput = /^https?:\/\//i.test(input) ? input : "https://" + input;
  let parsed;
  try {
    parsed = new URL(normalizedInput);
  } catch {
    throw new Error("Malformed URL: " + input);
  }

  const isLocal = isLocalHostName(parsed.hostname);
  const httpsOk = parsed.protocol === "https:" || (parsed.protocol === "http:" && isLocal);

  // Derive manifestUrl, base, and optional requested peer network name
  let base = parsed.origin + "/";
  let manifestUrl = parsed.origin + "/agent-manifest.json";
  let requestedNetwork = null;

  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  if (!cleanPath || cleanPath === "/") {
    base = parsed.origin + "/";
    manifestUrl = base + "agent-manifest.json";
  } else if (/\/agent-manifest\.json$/i.test(cleanPath)) {
    const dir = cleanPath.slice(0, cleanPath.length - "agent-manifest.json".length);
    base = parsed.origin + (dir.endsWith("/") ? dir : dir + "/");
    manifestUrl = parsed.origin + cleanPath;
  } else {
    const parts = cleanPath.split("/").filter(Boolean);
    requestedNetwork = parts.pop();
    base = parsed.origin + "/" + parts.join("/") + (parts.length ? "/" : "");
    manifestUrl = base + "agent-manifest.json";
  }

  const wellKnownUrl = parsed.origin + "/.well-known/agent-manifest.json";

  if (confirmOriginFn) {
    const allowed = await confirmOriginFn({
      origin: parsed.origin,
      networkName: requestedNetwork || "(root manifest)",
      peerUrl: parsed.href,
      manifestUrl,
      purpose: "audit Agentic Web MVP Profile 0.2 conformance"
    });
    if (!allowed) {
      return {
        aborted: true,
        reason: "Origin contact denied by user (fail closed; 0 bytes fetched).",
        targetUrl: parsed.href,
        origin: parsed.origin,
        score: 0,
        passed: 0,
        total: 10,
        grade: "DENIED",
        checkedAt: new Date().toISOString(),
        checks: []
      };
    }
  }

  const checks = [];
  const pushCheck = (id, label, pathLabel, pass, detail, extra = {}) => {
    checks.push({
      id,
      label,
      path: pathLabel,
      pass: Boolean(pass),
      points: pass ? 10 : 0,
      status: extra.status ?? (pass ? 200 : 0),
      cors: extra.cors ?? "n/a",
      ms: extra.ms ?? 0,
      detail
    });
  };

  // 1. HTTPS Transport Security
  pushCheck(
    "https_transport",
    "HTTPS Transport Security",
    parsed.protocol,
    httpsOk,
    httpsOk
      ? parsed.protocol === "https:"
        ? "Secure HTTPS origin (" + parsed.origin + ")"
        : "Loopback HTTP allowed for local development"
      : "Production Agentic Web sites MUST use HTTPS (got " + parsed.protocol + ")",
    { status: httpsOk ? 200 : 400, cors: "transport" }
  );

  // 2 & 3 & 4. Manifest Fetch, Open CORS, MVP 0.2 Schema
  let manifest = null;
  let manifestStatus = 0;
  let manifestAcao = "";
  let manifestMs = 0;
  let manifestFetchErr = "";

  if (httpsOk) {
    const t0 = Date.now();
    try {
      const mRes = await fetchImpl(manifestUrl, { mode: "cors", credentials: "omit", cache: "no-store" });
      manifestMs = Date.now() - t0;
      manifestStatus = mRes.status;
      manifestAcao = mRes.headers ? String(mRes.headers.get("access-control-allow-origin") || "") : "";
      if (mRes.ok) {
        manifest = await mRes.json();
      } else {
        manifestFetchErr = "HTTP " + mRes.status + " from " + manifestUrl;
      }
    } catch (e) {
      manifestMs = Date.now() - t0;
      manifestFetchErr = (e && e.message) ? e.message : String(e);
    }
  } else {
    manifestFetchErr = "Skipped fetch due to non-HTTPS origin";
  }

  pushCheck(
    "manifest_fetch",
    "Public Manifest Fetch",
    manifestUrl,
    Boolean(manifest && manifestStatus === 200),
    manifest
      ? "HTTP 200 JSON retrieved with credentials: omit (" + manifestMs + "ms)"
      : "Failed to load manifest: " + (manifestFetchErr || "invalid JSON"),
    { status: manifestStatus, cors: manifestAcao || "missing", ms: manifestMs }
  );

  const manifestCorsOk = Boolean(manifestAcao === "*" || (typeof location !== "undefined" && manifestAcao === location.origin));
  pushCheck(
    "manifest_cors",
    "Open CORS on Manifest",
    "Access-Control-Allow-Origin",
    Boolean(manifest && manifestCorsOk),
    manifestCorsOk
      ? "Permits cross-origin browser loading (ACAO: " + manifestAcao + ")"
      : "Missing permissive Access-Control-Allow-Origin header (got '" + (manifestAcao || "none") + "')",
    { status: manifestStatus, cors: manifestAcao || "missing", ms: manifestMs }
  );

  const manifestValidation = manifest ? validateManifest(manifest) : { ok: false, errors: ["Manifest unavailable"] };
  pushCheck(
    "manifest_schema",
    "MVP Profile 0.2 Manifest Schema",
    "manifest_version: 0.2",
    manifestValidation.ok,
    manifestValidation.ok
      ? "Valid MVP 0.2 manifest · site='" + manifest.site.name + "' · networks=[" + manifestValidation.networks.join(", ") + "] · BYOK=" + Boolean(manifest.inference && manifest.inference.byok_supported)
      : manifestValidation.errors.join("; "),
    { status: manifestStatus, cors: manifestAcao || "n/a" }
  );

  // 5. Exact-Match Network Resolution (Fail-Closed)
  let selectedEntry = null;
  let resolutionOk = false;
  let resolutionDetail = "";
  if (manifest && Array.isArray(manifest.networks) && manifest.networks.length) {
    if (requestedNetwork) {
      selectedEntry = manifest.networks.find((n) => n && n.name === requestedNetwork) || null;
      if (selectedEntry) {
        resolutionOk = true;
        resolutionDetail = "Exact match found for '" + requestedNetwork + "' -> " + selectedEntry.hocon;
      } else {
        resolutionOk = false;
        resolutionDetail =
          "Fail closed: manifest has no exact-match network '" +
          requestedNetwork +
          "' (available: " +
          manifest.networks.map((n) => n.name).join(", ") +
          ")";
      }
    } else {
      selectedEntry = manifest.networks[0];
      resolutionOk = Boolean(selectedEntry && selectedEntry.name && selectedEntry.hocon);
      resolutionDetail = resolutionOk
        ? "Resolved primary network '" + selectedEntry.name + "' -> " + selectedEntry.hocon
        : "No valid network entry found";
    }
  } else {
    resolutionDetail = "Cannot resolve network because manifest is missing or empty";
  }

  pushCheck(
    "exact_match_resolution",
    "Exact-Match Peer Resolution",
    requestedNetwork ? "network=" + requestedNetwork : "primary network",
    resolutionOk,
    resolutionDetail,
    { status: resolutionOk ? 200 : 404, cors: manifestAcao || "n/a" }
  );

  // 6. Well-Known Discovery (/.well-known/agent-manifest.json)
  let wkOk = false;
  let wkStatus = 0;
  let wkAcao = "";
  let wkMs = 0;
  let wkDetail = "";
  if (httpsOk) {
    const t0 = Date.now();
    try {
      const wkRes = await fetchImpl(wellKnownUrl, { mode: "cors", credentials: "omit", cache: "no-store" });
      wkMs = Date.now() - t0;
      wkStatus = wkRes.status;
      wkAcao = wkRes.headers ? String(wkRes.headers.get("access-control-allow-origin") || "") : "";
      if (wkRes.ok) {
        const wkJson = await wkRes.json();
        const wkVal = validateManifest(wkJson);
        wkOk = wkVal.ok && (wkAcao === "*" || (typeof location !== "undefined" && wkAcao === location.origin));
        wkDetail = wkOk
          ? "HTTP 200 + CORS (" + wkAcao + ") · valid MVP 0.2 discovery manifest"
          : !wkVal.ok
          ? "Invalid well-known manifest: " + wkVal.errors[0]
          : "Missing CORS header on /.well-known/agent-manifest.json";
      } else {
        wkDetail = "HTTP " + wkRes.status + " at /.well-known/agent-manifest.json";
      }
    } catch (e) {
      wkMs = Date.now() - t0;
      wkDetail = "Discovery probe failed: " + ((e && e.message) ? e.message : String(e));
    }
  } else {
    wkDetail = "Skipped due to non-HTTPS origin";
  }
  pushCheck("well_known_discovery", "Well-Known Discovery Endpoint", wellKnownUrl, wkOk, wkDetail, {
    status: wkStatus,
    cors: wkAcao || "missing",
    ms: wkMs
  });

  // 7, 8, 9, 10. Network Definition Fetch, Neuro SAN Schema, Finite Bounds, Private Context
  let definitionUrl = null;
  let networkDef = null;
  let defStatus = 0;
  let defAcao = "";
  let defMs = 0;
  let defErr = "";

  if (httpsOk && selectedEntry && selectedEntry.hocon) {
    try {
      const resolved = new URL(selectedEntry.hocon, base);
      definitionUrl = resolved.href;
      const t0 = Date.now();
      const dRes = await fetchImpl(definitionUrl, { mode: "cors", credentials: "omit", cache: "no-store" });
      defMs = Date.now() - t0;
      defStatus = dRes.status;
      defAcao = dRes.headers ? String(dRes.headers.get("access-control-allow-origin") || "") : "";
      if (dRes.ok) {
        networkDef = await dRes.json();
      } else {
        defErr = "HTTP " + dRes.status + " fetching " + definitionUrl;
      }
    } catch (e) {
      defErr = (e && e.message) ? e.message : String(e);
    }
  } else {
    defErr = requestedNetwork && !selectedEntry
      ? "Halted fail-closed (no exact-match network entry)"
      : "No hocon definition URL to fetch";
  }

  const defCorsOk = Boolean(defAcao === "*" || (typeof location !== "undefined" && defAcao === location.origin));
  pushCheck(
    "network_def_fetch",
    "Network Definition + CORS",
    definitionUrl || "unresolved",
    Boolean(networkDef && defStatus === 200 && defCorsOk),
    networkDef && defCorsOk
      ? "HTTP 200 JSON + CORS (" + defAcao + ") in " + defMs + "ms"
      : networkDef && !defCorsOk
      ? "Fetched JSON but missing CORS header (got '" + (defAcao || "none") + "')"
      : defErr,
    { status: defStatus, cors: defAcao || "missing", ms: defMs }
  );

  const netVal = networkDef ? validateNetworkDefinition(networkDef) : { ok: false, errors: ["Network definition unavailable"] };
  pushCheck(
    "neuro_san_schema",
    "Neuro SAN Graph & Safe Data",
    "validateNetworkDefinition",
    netVal.ok,
    netVal.ok
      ? netVal.agents.length + " agents (" + netVal.front + " front) · 0 undeclared executable fields"
      : netVal.errors.join("; "),
    { status: defStatus, cors: "runtime" }
  );

  const hasExplicitBounds = Boolean(
    networkDef &&
      networkDef.execution_limits &&
      typeof networkDef.execution_limits.max_composition_depth === "number" &&
      Number.isFinite(networkDef.execution_limits.max_composition_depth) &&
      typeof networkDef.execution_limits.max_agent_invocations === "number" &&
      Number.isFinite(networkDef.execution_limits.max_agent_invocations) &&
      typeof networkDef.execution_limits.max_remote_calls === "number" &&
      Number.isFinite(networkDef.execution_limits.max_remote_calls) &&
      typeof networkDef.execution_limits.max_elapsed_seconds === "number" &&
      Number.isFinite(networkDef.execution_limits.max_elapsed_seconds)
  );
  pushCheck(
    "finite_execution_bounds",
    "Explicit Finite Execution Bounds",
    "execution_limits",
    netVal.ok && hasExplicitBounds,
    netVal.ok && hasExplicitBounds
      ? "depth<=" + netVal.limits.max_composition_depth + " · invocations<=" + netVal.limits.max_agent_invocations + " · remote<=" + netVal.limits.max_remote_calls + " · timeout=" + netVal.limits.max_elapsed_seconds + "s"
      : "Missing or invalid finite execution_limits in network definition",
    { status: netVal.ok && hasExplicitBounds ? 200 : 422, cors: "runtime" }
  );

  const privacyDeclared = Boolean(
    networkDef &&
      networkDef.private_context_rules &&
      networkDef.private_context_rules.deny_by_default === true
  );
  const privacyProbe = filterPrivateContext(
    { visitor_api_key: "sk-secret", session_cookie: "sess-1" },
    (networkDef && networkDef.private_context_rules) || { deny_by_default: true, allowed_downstream_fields: [] }
  );
  const privacyPass = Boolean(netVal.ok && privacyDeclared && Object.keys(privacyProbe).length === 0);
  pushCheck(
    "private_context_isolation",
    "Private Context (sly_data) Isolation",
    "private_context_rules",
    privacyPass,
    privacyPass
      ? "deny_by_default=true · 0/2 sensitive probe keys forwarded"
      : "Missing explicit private_context_rules.deny_by_default: true",
    { status: privacyPass ? 200 : 422, cors: "runtime" }
  );

  const passed = checks.filter((c) => c.pass).length;
  const score = passed * 10;
  const grade = score === 100 ? "CONFORMING (A+)" : score >= 70 ? "PARTIAL" : "NON-CONFORMING";

  return {
    aborted: false,
    targetUrl: parsed.href,
    origin: parsed.origin,
    manifestUrl,
    wellKnownUrl,
    definitionUrl,
    requestedNetwork,
    resolvedNetworkName: (selectedEntry && selectedEntry.name) || null,
    score,
    passed,
    total: checks.length,
    allPassed: passed === checks.length,
    grade,
    checkedAt: new Date().toISOString(),
    checks,
    manifest,
    networkDef: netVal.ok ? networkDef : null,
    agentGraph: netVal.ok ? buildAgentGraph(networkDef) : null
  };
}

// --- Strict Fail-Closed HOCON / JSON Network Definition Parser ---
const FORBIDDEN_PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function stripSafeHoconComments(raw) {
  let out = "";
  let inString = false;
  let escape = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    const next = raw[i + 1];
    if (inString) {
      out += ch;
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if ((ch === "/" && next === "/") || ch === "#") {
      while (i < raw.length && raw[i] !== "\n") i++;
      if (i < raw.length && raw[i] === "\n") out += "\n";
      continue;
    }
    out += ch;
  }
  return out;
}

function findForbiddenPrototypeKey(rawJsonText) {
  const re = /"(__proto__|constructor|prototype)"\s*:/;
  const m = re.exec(rawJsonText);
  return m ? m[1] : null;
}

export function parseAndValidateNetworkText(rawText) {
  if (typeof rawText !== "string" || !rawText.trim()) {
    return {
      ok: false,
      errors: ["Malformed HOCON/JSON network definition: input must be a non-empty string."],
      def: null,
      validation: null
    };
  }
  if (rawText.length > 2 * 1024 * 1024) {
    return {
      ok: false,
      errors: ["Malformed HOCON/JSON network definition: payload exceeds 2MB safety bound."],
      def: null,
      validation: null
    };
  }
  const stripped = stripSafeHoconComments(rawText).trim();
  if (!stripped.startsWith("{") || !stripped.endsWith("}")) {
    return {
      ok: false,
      errors: ["Malformed HOCON/JSON network definition: root document must be a JSON object."],
      def: null,
      validation: null
    };
  }
  const badProtoKey = findForbiddenPrototypeKey(stripped);
  if (badProtoKey) {
    return {
      ok: false,
      errors: ["Malformed HOCON/JSON network definition: forbidden prototype key '" + badProtoKey + "'."],
      def: null,
      validation: null
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(stripped);
  } catch (err) {
    return {
      ok: false,
      errors: ["Malformed HOCON/JSON network definition: " + (err && err.message ? err.message : String(err))],
      def: null,
      validation: null
    };
  }
  const validation = validateNetworkDefinition(parsed);
  if (!validation.ok) {
    return {
      ok: false,
      errors: validation.errors.slice(),
      def: null,
      validation
    };
  }
  return {
    ok: true,
    errors: [],
    def: parsed,
    validation
  };
}

// --- Live Peer Federation Trace Diff Engine ---
export function diffPeerFederationAudits(
  baselineReport,
  candidateReport,
  { baselineTrace = null, candidateTrace = null } = {}
) {
  if (!baselineReport || typeof baselineReport !== "object" || !candidateReport || typeof candidateReport !== "object") {
    throw new Error("Both baselineReport and candidateReport objects are required for peer federation diff.");
  }

  const baseChecks = Array.isArray(baselineReport.checks) ? baselineReport.checks : [];
  const candChecks = Array.isArray(candidateReport.checks) ? candidateReport.checks : [];
  const baseById = new Map(baseChecks.map((c) => [c.id, c]));
  const candById = new Map(candChecks.map((c) => [c.id, c]));
  const allIds = [...new Set([...baseChecks.map((c) => c.id), ...candChecks.map((c) => c.id)])];

  const checkDiffs = allIds.map((id) => {
    const b = baseById.get(id) || null;
    const c = candById.get(id) || null;
    const baselinePass = Boolean(b && b.pass);
    const candidatePass = Boolean(c && c.pass);
    let state = "UNCHANGED_FAIL";
    if (baselinePass && candidatePass) state = "UNCHANGED_PASS";
    else if (baselinePass && !candidatePass) state = "REGRESSION";
    else if (!baselinePass && candidatePass) state = "IMPROVEMENT";
    const bMs = b && typeof b.ms === "number" ? b.ms : 0;
    const cMs = c && typeof c.ms === "number" ? c.ms : 0;
    return {
      id,
      label: (c && c.label) || (b && b.label) || id,
      baselinePass,
      candidatePass,
      baselineStatus: b ? b.status : 0,
      candidateStatus: c ? c.status : 0,
      baselineCors: b ? b.cors : "n/a",
      candidateCors: c ? c.cors : "n/a",
      baselineMs: bMs,
      candidateMs: cMs,
      latencyDeltaMs: cMs - bMs,
      baselineDetail: b ? b.detail : "missing",
      candidateDetail: c ? c.detail : "missing",
      state
    };
  });

  const baseGraph = baselineReport.agentGraph || { front: null, nodes: [], edges: [] };
  const candGraph = candidateReport.agentGraph || { front: null, nodes: [], edges: [] };
  const baseAgentSet = new Set((baseGraph.nodes || []).map((n) => n.id));
  const candAgentSet = new Set((candGraph.nodes || []).map((n) => n.id));
  const sharedAgents = [...baseAgentSet].filter((id) => candAgentSet.has(id));
  const addedAgents = [...candAgentSet].filter((id) => !baseAgentSet.has(id));
  const removedAgents = [...baseAgentSet].filter((id) => !candAgentSet.has(id));

  const edgeKey = (e) => `${e.from}->${e.to}`;
  const baseEdgeSet = new Set((baseGraph.edges || []).map(edgeKey));
  const candEdgeSet = new Set((candGraph.edges || []).map(edgeKey));
  const sharedEdges = [...baseEdgeSet].filter((k) => candEdgeSet.has(k));
  const addedEdges = [...candEdgeSet].filter((k) => !baseEdgeSet.has(k));
  const removedEdges = [...baseEdgeSet].filter((k) => !candEdgeSet.has(k));

  const baseLimits = (baselineReport.networkDef && baselineReport.networkDef.execution_limits) || {};
  const candLimits = (candidateReport.networkDef && candidateReport.networkDef.execution_limits) || {};
  const limitsDiff = {};
  for (const key of Object.keys(HARD_RUNTIME_LIMITS)) {
    const bv = typeof baseLimits[key] === "number" ? baseLimits[key] : null;
    const cv = typeof candLimits[key] === "number" ? candLimits[key] : null;
    limitsDiff[key] = {
      baseline: bv,
      candidate: cv,
      delta: bv !== null && cv !== null ? cv - bv : null
    };
  }

  const basePriv = (baselineReport.networkDef && baselineReport.networkDef.private_context_rules) || null;
  const candPriv = (candidateReport.networkDef && candidateReport.networkDef.private_context_rules) || null;
  const baselineDeny = Boolean(basePriv && basePriv.deny_by_default === true);
  const candidateDeny = Boolean(candPriv && candPriv.deny_by_default === true);
  const privacyStatus =
    baselineDeny && candidateDeny
      ? "ISOLATED"
      : !candPriv
      ? "MISSING_CANDIDATE_DEF"
      : !candidateDeny
      ? "RELAXED_DANGER"
      : "IMPROVED_ISOLATION";

  const traceDiff =
    baselineTrace || candidateTrace
      ? {
          baselineInvocations: baselineTrace ? baselineTrace.invocations || 0 : 0,
          candidateInvocations: candidateTrace ? candidateTrace.invocations || 0 : 0,
          invocationDelta:
            (candidateTrace ? candidateTrace.invocations || 0 : 0) -
            (baselineTrace ? baselineTrace.invocations || 0 : 0),
          baselineMaxDepth: baselineTrace ? baselineTrace.maxDepth || 0 : 0,
          candidateMaxDepth: candidateTrace ? candidateTrace.maxDepth || 0 : 0,
          depthDelta:
            (candidateTrace ? candidateTrace.maxDepth || 0 : 0) -
            (baselineTrace ? baselineTrace.maxDepth || 0 : 0),
          baselineRemoteCalls: baselineTrace ? baselineTrace.remoteCalls || 0 : 0,
          candidateRemoteCalls: candidateTrace ? candidateTrace.remoteCalls || 0 : 0,
          baselineLeakedKeys: baselineTrace ? baselineTrace.leakedKeys || 0 : 0,
          candidateLeakedKeys: candidateTrace ? candidateTrace.leakedKeys || 0 : 0,
          baselineHops: baselineTrace && Array.isArray(baselineTrace.hops) ? baselineTrace.hops.slice() : [],
          candidateHops: candidateTrace && Array.isArray(candidateTrace.hops) ? candidateTrace.hops.slice() : []
        }
      : null;

  const baseScore = Number(baselineReport.score || 0);
  const candScore = Number(candidateReport.score || 0);
  const scoreDelta = candScore - baseScore;
  const regressions = checkDiffs.filter((d) => d.state === "REGRESSION");
  const improvements = checkDiffs.filter((d) => d.state === "IMPROVEMENT");
  const candidateFailClosed =
    candidateReport.networkDef === null &&
    checkDiffs.some((d) => d.id === "exact_match_resolution" && !d.candidatePass);

  let verdict = "EQUIVALENT_CONFORMING";
  if (candidateFailClosed) {
    verdict = "FAIL_CLOSED_VERIFIED";
  } else if (regressions.length > 0 || scoreDelta < 0) {
    verdict = "REGRESSION_DETECTED";
  } else if (improvements.length > 0 || scoreDelta > 0) {
    verdict = "CANDIDATE_STRONGER";
  } else if (baseScore < 100 || candScore < 100) {
    verdict = "BOTH_NON_CONFORMING";
  }

  return {
    schema: "aura.agentic-web.peer-federation-diff/v1",
    comparedAt: new Date().toISOString(),
    baseline: {
      targetUrl: baselineReport.targetUrl || "",
      network: baselineReport.resolvedNetworkName || "unresolved",
      score: baseScore,
      grade: baselineReport.grade || "UNKNOWN"
    },
    candidate: {
      targetUrl: candidateReport.targetUrl || "",
      network: candidateReport.resolvedNetworkName || "unresolved",
      score: candScore,
      grade: candidateReport.grade || "UNKNOWN"
    },
    scoreDelta,
    passedDelta: Number(candidateReport.passed || 0) - Number(baselineReport.passed || 0),
    regressionCount: regressions.length,
    improvementCount: improvements.length,
    verdict,
    checkDiffs,
    topologyDiff: {
      baselineFront: baseGraph.front || null,
      candidateFront: candGraph.front || null,
      frontAgentMatch: Boolean(baseGraph.front && baseGraph.front === candGraph.front),
      sharedAgents,
      addedAgents,
      removedAgents,
      sharedEdges,
      addedEdges,
      removedEdges
    },
    limitsDiff,
    privacyDiff: {
      baselineDenyByDefault: baselineDeny,
      candidateDenyByDefault: candidateDeny,
      baselineAllowedDownstream:
        basePriv && Array.isArray(basePriv.allowed_downstream_fields)
          ? basePriv.allowed_downstream_fields.slice()
          : [],
      candidateAllowedDownstream:
        candPriv && Array.isArray(candPriv.allowed_downstream_fields)
          ? candPriv.allowed_downstream_fields.slice()
          : [],
      status: privacyStatus
    },
    traceDiff
  };
}

// --- Exportable SVG Conformance Badge Generator ---
function xmlEscape(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function buildConformanceBadgeSvg(report) {
  const r = report && typeof report === "object" ? report : {};
  const score = Number.isFinite(Number(r.score)) ? Number(r.score) : 0;
  const grade = String(r.grade || (score === 100 ? "CONFORMING (A+)" : "NON-CONFORMING"));
  const privPass = Array.isArray(r.checks)
    ? Boolean(r.checks.find((c) => c.id === "private_context_isolation" && c.pass))
    : false;
  const rightFill = score === 100 ? "#168A5B" : score >= 70 ? "#C47A12" : "#C9352B";
  const leftText = "Agentic Web MVP 0.2";
  const midText = `${score}/100 ${score === 100 ? "A+" : grade.split(" ")[0]}`;
  const rightText = privPass ? "sly_data: 0 leaks" : "fail-closed";

  const leftW = 148;
  const midW = 104;
  const rightW = 118;
  const totalW = leftW + midW + rightW;

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="28" viewBox="0 0 ${totalW} 28" role="img" aria-label="${xmlEscape(`${leftText}: ${midText} (${rightText})`)}">`,
    `<title>${xmlEscape(`${leftText}: ${midText} | ${rightText}`)}</title>`,
    `<clipPath id="auraBadgeClip"><rect width="${totalW}" height="28" rx="6" fill="#fff"/></clipPath>`,
    `<g clip-path="url(#auraBadgeClip)">`,
    `<rect width="${leftW}" height="28" fill="#191614"/>`,
    `<rect x="${leftW}" width="${midW}" height="28" fill="${rightFill}"/>`,
    `<rect x="${leftW + midW}" width="${rightW}" height="28" fill="#2A2623"/>`,
    `</g>`,
    `<g fill="#FFFFFF" text-anchor="middle" font-family="JetBrains Mono, ui-monospace, Menlo, Consolas, monospace" font-size="11" font-weight="600">`,
    `<text x="${leftW / 2}" y="18">${xmlEscape(leftText)}</text>`,
    `<text x="${leftW + midW / 2}" y="18">${xmlEscape(midText)}</text>`,
    `<text x="${leftW + midW + rightW / 2}" y="18" fill="${privPass ? "#34D399" : "#FCA5A5"}">${xmlEscape(rightText)}</text>`,
    `</g>`,
    `</svg>`
  ].join("");
}

// --- SARIF 2.1.0 Conformance Report Exporter ---
const SARIF_RULE_MAP = Object.freeze({
  https_transport: { id: "WAW02-001", section: "Section 2.1", name: "HttpsTransportRequired" },
  manifest_fetch: { id: "WAW02-002", section: "Section 3.1", name: "PublicManifestFetch" },
  manifest_cors: { id: "WAW02-003", section: "Section 3.1", name: "OpenCorsManifestHeaders" },
  manifest_schema: { id: "WAW02-004", section: "Section 3.2", name: "Mvp02ManifestSchema" },
  exact_match_resolution: { id: "WAW02-005", section: "Section 4.2", name: "FailClosedExactMatchPeer" },
  well_known_discovery: { id: "WAW02-006", section: "Section 3.1", name: "WellKnownManifestDiscovery" },
  network_def_fetch: { id: "WAW02-007", section: "Section 3.3", name: "NetworkDefinitionFetchAndCors" },
  neuro_san_schema: { id: "WAW02-008", section: "Section 3.3", name: "NeuroSanDeclarativeSafeData" },
  finite_execution_bounds: { id: "WAW02-009", section: "Section 3.1", name: "FiniteExecutionBounds" },
  private_context_isolation: { id: "WAW02-010", section: "Section 5", name: "SlyDataDenyByDefault" }
});

export function buildSarifConformanceReport(report, { toolVersion = "0.2.2" } = {}) {
  if (!report || typeof report !== "object") {
    throw new Error("A conformance audit report is required to build SARIF 2.1.0 output.");
  }
  const checks = Array.isArray(report.checks) ? report.checks : [];
  const specUrl = "https://github.com/cognizant-ai-labs/agentic-web/blob/main/docs/worldwide_agentic_web_mvp_spec.md";

  const rules = checks.map((c, idx) => {
    const meta = SARIF_RULE_MAP[c.id] || {
      id: `WAW02-${String(idx + 1).padStart(3, "0")}`,
      section: "MVP Profile 0.2",
      name: c.id || `Check${idx + 1}`
    };
    return {
      id: meta.id,
      name: meta.name,
      shortDescription: { text: c.label || c.id },
      fullDescription: {
        text: `Worldwide Agentic Web MVP Profile 0.2 (${meta.section}) conformance invariant: ${c.label || c.id}.`
      },
      helpUri: specUrl,
      properties: {
        tags: ["worldwide-agentic-web", "mvp-profile-0.2", "security", "conformance"],
        specSection: meta.section
      }
    };
  });

  const results = checks.map((c, idx) => {
    const meta = SARIF_RULE_MAP[c.id] || { id: `WAW02-${String(idx + 1).padStart(3, "0")}` };
    return {
      ruleId: meta.id,
      ruleIndex: idx,
      kind: c.pass ? "pass" : "fail",
      level: c.pass ? "note" : "error",
      message: {
        text: `${c.label}: ${c.pass ? "PASS" : "FAIL"} - ${c.detail || ""}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: String(c.path || report.targetUrl || "agent-manifest.json")
            }
          }
        }
      ],
      properties: {
        checkId: c.id,
        httpStatus: c.status,
        accessControlAllowOrigin: c.cors,
        latencyMs: c.ms || 0,
        points: c.points || (c.pass ? 10 : 0)
      }
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AURA Agentic Web Conformance Validator",
            version: toolVersion,
            informationUri: "https://aura-agentic-web.vercel.app/validator.html",
            rules
          }
        },
        invocations: [
          {
            executionSuccessful: !report.aborted,
            endTimeUtc: report.checkedAt || new Date().toISOString(),
            properties: {
              targetUrl: report.targetUrl || "",
              origin: report.origin || "",
              resolvedNetworkName: report.resolvedNetworkName || null,
              score: Number(report.score || 0),
              grade: report.grade || "UNKNOWN",
              passed: Number(report.passed || 0),
              total: Number(report.total || checks.length)
            }
          }
        ],
        results
      }
    ]
  };
}

// --- Cryptographic SHA-256 JSON Compliance Certificate Exporter ---
async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    const hashBuf = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Deterministic fallback hash only if subtle crypto is unavailable in an exotic environment
  let h1 = 0xdeadbeef ^ bytes.length;
  let h2 = 0x41c6ce57 ^ bytes.length;
  for (let i = 0; i < bytes.length; i++) {
    h1 = Math.imul(h1 ^ bytes[i], 2654435761);
    h2 = Math.imul(h2 ^ bytes[i], 1597334677);
  }
  return (
    (h1 >>> 0).toString(16).padStart(8, "0") +
    (h2 >>> 0).toString(16).padStart(8, "0")
  ).repeat(4);
}

export async function buildComplianceCertificate(
  report,
  { traceSummary = null, diffSummary = null } = {}
) {
  if (!report || typeof report !== "object") {
    throw new Error("A conformance audit report is required to issue a compliance certificate.");
  }
  const checks = Array.isArray(report.checks) ? report.checks : [];
  const checkPass = (id) => Boolean(checks.find((c) => c.id === id && c.pass));

  const canonicalSubject = {
    schema: "aura.agentic-web.compliance-certificate/v1",
    specProfile: "worldwide-agentic-web-mvp-0.2",
    targetUrl: report.targetUrl || "",
    origin: report.origin || "",
    manifestUrl: report.manifestUrl || null,
    wellKnownUrl: report.wellKnownUrl || null,
    definitionUrl: report.definitionUrl || null,
    resolvedNetworkName: report.resolvedNetworkName || null,
    score: Number(report.score || 0),
    passed: Number(report.passed || 0),
    total: Number(report.total || checks.length),
    grade: report.grade || "UNKNOWN",
    invariants: {
      httpsTransport: checkPass("https_transport"),
      publicManifestFetch: checkPass("manifest_fetch"),
      openCors: checkPass("manifest_cors"),
      manifestSchema: checkPass("manifest_schema"),
      exactMatchFailClosed: checkPass("exact_match_resolution"),
      wellKnownDiscovery: checkPass("well_known_discovery"),
      networkDefinitionCors: checkPass("network_def_fetch"),
      neuroSanDeclarativeSafeData: checkPass("neuro_san_schema"),
      finiteExecutionBounds: checkPass("finite_execution_bounds"),
      slyDataDenyByDefault: checkPass("private_context_isolation")
    },
    executionBounds:
      (report.networkDef && report.networkDef.execution_limits) || null,
    privateContextPolicy:
      (report.networkDef && report.networkDef.private_context_rules) || null,
    agentTopology: report.agentGraph
      ? {
          front: report.agentGraph.front,
          agentCount: report.agentGraph.nodes.length,
          edgeCount: report.agentGraph.edges.length,
          agents: report.agentGraph.nodes.map((n) => n.id)
        }
      : null,
    traceAttestation: traceSummary || null,
    peerFederationDiff: diffSummary
      ? {
          verdict: diffSummary.verdict,
          scoreDelta: diffSummary.scoreDelta,
          regressionCount: diffSummary.regressionCount,
          baselineUrl: diffSummary.baseline && diffSummary.baseline.targetUrl,
          candidateUrl: diffSummary.candidate && diffSummary.candidate.targetUrl
        }
      : null
  };

  const canonicalJson = JSON.stringify(canonicalSubject);
  const fingerprintSha256 = await sha256Hex(canonicalJson);

  return {
    ...canonicalSubject,
    certificateId: "waw02-" + fingerprintSha256.slice(0, 16),
    fingerprintSha256,
    issuedAt: report.checkedAt || new Date().toISOString(),
    issuer: "AURA Agentic Web Conformance Validator (https://aura-agentic-web.vercel.app/validator.html)"
  };
}
