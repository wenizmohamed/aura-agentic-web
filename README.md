# AURA Agentic Web

**Live deployment:** [https://aura-agentic-web.vercel.app](https://aura-agentic-web.vercel.app)  
**Spec conformance:** [Worldwide Agentic Web MVP Profile 0.2](https://github.com/cognizant-ai-labs/agentic-web/blob/main/docs/worldwide_agentic_web_mvp_spec.md)  
**License:** MIT

![AURA Agentic Web](./devpost-screenshot.png)

AURA Agentic Web publishes a portable 5-agent Neuro SAN network as open static JSON data that loads and executes directly in the browser with no dedicated agent server. Visitors bring their own OpenAI-compatible inference router (BYOK) - or use an optional zero-setup server demo router when configured - to run a multi-stage **plan -> ground -> build -> verify -> stress-critique** loop in real time, inspect the live delegation trace, or load peer agentic websites into the same browser runtime.

---

## Architecture & Agent Network (`aura-core`)

Published at [`/agents/agent-manifest.json`](./public/agents/agent-manifest.json) and [`/agents/aura-core.json`](./public/agents/aura-core.json) with permissive CORS headers (`Access-Control-Allow-Origin: *`) so any conforming runtime can discover and execute the network:

1. **`orchestrator` (Front Agent - Plan & Synthesize):** Decomposes the user request, delegates self-contained tasks across specialist agents via OpenAI-compatible tool calls, drives a repair pass when verification flags gaps, and synthesizes one unified response.
2. **`researcher` (Ground):** Grounds domain facts, constraints, and edge cases, explicitly flagging uncertainty.
3. **`builder` (Produce):** Produces complete, runnable code or structured artifacts from the plan and grounded context.
4. **`verifier` (Check):** Audits the candidate build against every requirement in the prompt and returns `PASS` or an itemized `GAPS` list for repair.
5. **`critic` (Stress):** Performs a final adversarial pass identifying the strongest remaining weakness, a realistic failure mode, and one high-leverage improvement.

---

## Browser Runtime & Stateless Edge SSE `/api/relay`

- **Pure ES Module Streaming Runtime ([`public/runtime.js`](./public/runtime.js)):**
  - Normalizes OpenAI-compatible base URLs automatically (bare origins, `/v1`, custom gateway prefixes, or full `/chat/completions` URLs).
  - **OpenAI-Compatible SSE Streaming (`stream: true`):** Streams `text/event-stream` responses via `ReadableStream`, reassembling `reasoning_content`, `content`, and fragmented `tool_calls` chunks on the fly while surfacing real-time thinking/writing character telemetry (`agent_stream`) in the active chat bubble (with automatic `stream: false` fallback when an endpoint rejects streaming).
  - Multi-provider tool-calling compatibility across OpenAI, xAI Grok, DeepSeek / Moonshot heavy thinking models (preserving `reasoning_content` across tool-call turns, normalizing empty assistant `content` to `""`, and providing a 900s `max_elapsed_seconds` multi-agent reasoning budget), Alibaba DashScope/Bailian, and OpenRouter.
  - **Live BYOK Router Verification & Flagging:** Validates router inputs and performs a lightweight handshake probe (`validateRouterInputs`, `classifyRouterError`, `AuraRuntime.validateRouter`) on **Activate** (and on reload/mid-run errors), immediately flagging swapped or malformed URLs, unreachable/HTML website URLs (`INVALID BASE URL`), invalid/revoked API keys (`INVALID API KEY`), or unknown model IDs (`INVALID MODEL`) in the UI without overwriting working credentials or built-in demo routing.
  - Enforces execution budgets (`max_depth`, `max_agent_invocations`, `max_remote_calls`, `max_elapsed_seconds`) and per-origin user consent before loading external peer agent networks, and surfaces a canonical-domain notice if opened on an immutable Vercel deployment preview URL.
  - Streams structured lifecycle events (`network_loaded`, `peer_loaded`, `router_verified`, `router_flagged`, `run_start`, `agent_start`, `agent_stream`, `agent_delegate`, `agent_done`, `run_done`, `run_error`) to the live UI pipeline and trace log.
- **Stateless Vercel Edge SSE Relay ([`api/relay.js`](./api/relay.js)):**
  - The browser attempts direct `fetch()` calls to the visitor's chosen BYOK endpoint first.
  - Because many LLM gateways omit browser CORS headers (or reject browser `Origin` headers at WAF), `AuraRuntime` automatically falls back to `POST /api/relay` (`x-target-url` + `Authorization`) and caches relay preference for that endpoint for the remainder of the session to avoid repeated preflight failures.
  - Runs on **Vercel Edge Runtime** (`runtime: "edge"`), piping upstream `ReadableStream` SSE responses directly to the browser with **zero buffering and up to 300s streaming duration per call** (eliminating 60s buffered serverless timeouts on deep reasoning models such as `deepseek-v4-pro`). It validates HTTPS targets, blocks private/loopback SSRF ranges, classifies invalid/unreachable Base URLs (`invalid_base_url`, `unreachable_base_url`), exposes `x-upstream-content-type` for HTML-vs-API detection, guards initial upstream response headers with an `AbortController` timeout that clears as soon as streaming starts, stores nothing, and logs no keys or prompts.
  - **Optional Zero-Setup Demo Mode:** `GET /api/relay` reports `{ ok: true, demoAvailable, demoModel }`. When `DEMO_BASE_URL` and `DEMO_API_KEY` (plus optional `DEMO_MODEL`) are configured in Vercel environment variables, cold visitors on the AURA web app can run the network immediately via `x-use-demo: "1"` (protected by an `Origin` / `Referer` allowlist against off-site abuse, while BYOK remains open) without exposing server credentials to the client.

---

## Repository Structure

```text
.
├── api/
│   └── relay.js                  # Stateless Edge Runtime SSE/JSON BYOK & demo relay (zero-buffered)
├── public/
│   ├── index.html                # Editorial console UI, live 5-stage pipeline, router & peer loader
│   ├── runtime.js                # Portable browser Neuro SAN streaming runtime (ES module, MVP Profile 0.2)
│   └── agents/
│       ├── agent-manifest.json   # Site manifest advertising aura-core & BYOK policy
│       └── aura-core.json        # 5-agent Neuro SAN network definition & 900s reasoning budget
├── devpost-screenshot.png        # UI preview screenshot
├── vercel.json                   # Static output & CORS headers for /agents/* and /runtime.js
└── LICENSE                       # MIT License
```

---

## Local Development & Deployment

Serve statically or run with Vercel CLI (which also serves `/api/relay` locally):

```bash
# Run locally with Vercel dev server
npx vercel dev

# Deploy to Vercel production
npx vercel deploy --prod
```

To enable optional zero-setup demo routing on your deployment (while keeping BYOK available in the UI), set `DEMO_BASE_URL`, `DEMO_API_KEY`, and optionally `DEMO_MODEL` in your Vercel project environment variables.
