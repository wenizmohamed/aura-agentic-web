// AURA Agentic Web - browser runtime (reference-conforming, MVP Profile 0.2)
// Parses a Neuro SAN-profile agent network, validates it, and runs the front
// agent loop in the browser against an OpenAI-compatible router. Supports
// agent-to-agent delegation, bounded execution, peer-site loading with consent,
// stateless CORS relay caching, and optional built-in demo relay routing.
// No build step. Pure ES module. MIT.

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
  }
  return (rawText || "Empty response from router").trim().slice(0, 300);
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
    if (this._startedAt && (Date.now() - this._startedAt) / 1000 > this.limits.max_elapsed_seconds) {
      throw new Error("Elapsed-time limit reached.");
    }
    this._remoteCalls++;
    if (this._remoteCalls > this.limits.max_remote_calls) {
      throw new Error("Remote-call limit reached (" + this.limits.max_remote_calls + ").");
    }

    const isDemo = this.router.demo === true;
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

      if (this._preferRelayFor === url) {
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
        } catch {
          // Direct call blocked by browser CORS / network TypeError -> cache relay for this URL.
          this._preferRelayFor = url;
          res = await callRelay();
          rawText = await res.text();
          usedRelay = true;
        }

        // Also catch browser Origin WAF / CORS gateway rejections (403/405 without valid JSON completion).
        if (!usedRelay && res && (res.status === 403 || res.status === 405) && /^https:\/\//i.test(url)) {
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
    }

    let data = null;
    try {
      data = rawText ? JSON.parse(rawText) : null;
    } catch {
      data = null;
    }

    if (!res.ok) {
      throw new Error("Router HTTP " + res.status + ": " + extractRouterError(data, rawText));
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("Router returned non-JSON or malformed payload: " + extractRouterError(data, rawText));
    }
    if (data.error) {
      throw new Error("Router error: " + extractRouterError(data, rawText));
    }
    const msg = data.choices && data.choices[0] && data.choices[0].message;
    if (!msg || typeof msg !== "object") {
      throw new Error("Router response missing choices[0].message: " + extractRouterError(data, rawText));
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
      this.onEvent({
        type: "run_error",
        error: err && err.message ? err.message : String(err),
        elapsedMs: Date.now() - this._startedAt
      });
      throw err;
    }
  }
}
