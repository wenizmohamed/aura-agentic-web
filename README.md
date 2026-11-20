# AURA Agentic Web

[![Devpost Submission](https://img.shields.io/badge/Devpost-Open%20Agentic%20Web%20Challenge-003E54?style=for-the-badge&logo=devpost&logoColor=white)](https://devpost.com/software/aura-agentic-web)
[![Live Agentic Site](https://img.shields.io/badge/Live%20Site-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://aura-agentic-web.vercel.app)
[![Free Validator](https://img.shields.io/badge/MVP%200.2%20Validator-Test%20Your%20Site-2ea44f?style=for-the-badge)](https://aura-agentic-web.vercel.app/validator.html)
[![Demo Video](https://img.shields.io/badge/Demo%20Video-YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=8C0mwlOgszw)

**Devpost project:** [https://devpost.com/software/aura-agentic-web](https://devpost.com/software/aura-agentic-web)  
**Live deployment:** [https://aura-agentic-web.vercel.app](https://aura-agentic-web.vercel.app)  
**Standalone MVP 0.2 Conformance Validator:** [https://aura-agentic-web.vercel.app/validator.html](https://aura-agentic-web.vercel.app/validator.html)  
**Spec conformance:** [Worldwide Agentic Web MVP Profile 0.2](https://github.com/cognizant-ai-labs/agentic-web/blob/main/docs/worldwide_agentic_web_mvp_spec.md)  
**License:** MIT

![AURA Agentic Web](./devpost-screenshot.png)

AURA Agentic Web publishes a portable 5-agent Neuro SAN network as open static JSON data that loads and executes directly in the browser with no dedicated agent server. Visitors can:

1. **Run the 1-Click Live Spec Demo (No Key Required)** to watch the full 5-agent bounded delegation loop (`orchestrator -> researcher -> builder -> verifier (GAPS) -> builder (repair) -> verifier (PASS) -> critic -> synthesis`) animate live in under 4 seconds with zero setup.
2. **Inspect the Live Spec Conformance Self-Test Panel** embedded right in the page, which performs 10 live HTTP/CORS, JSON schema, finite-bound, private-context (`sly_data`), and fail-closed peer checks against its own endpoints.
3. **Use the Standalone Open Conformance Validator & Federation Diff Workbench (`/validator.html`)** to audit ANY Agentic Website on a 100-point MVP Profile 0.2 rubric, run a side-by-side **Live Peer Federation Trace Diff** (comparing conformance score, Neuro SAN topology, execution bounds, `sly_data` privacy, and zero-key hop traces), and export an inline **SVG Conformance Badge**, **SARIF 2.1.0 CI Report**, and **SHA-256 JSON Compliance Certificate**.
4. **Bring Their Own Key (BYOK)** using 1-click provider presets (**OpenAI**, **Gemini**, **Groq**, **OpenRouter**) or any OpenAI-compatible endpoint (plus an optional zero-setup server demo router via `/api/relay`).
5. **Load Peer Agentic Sites** with an accessible in-page **Explicit Origin Consent Modal** and strict fail-closed exact-match network name resolution.

---

## Published MVP Profile 0.2 Endpoints (All HTTP 200 + `Access-Control-Allow-Origin: *`)

| Path | Content-Type | Purpose |
| --- | --- | --- |
| [`/agent-manifest.json`](./public/agent-manifest.json) | `application/json; charset=utf-8` | Canonical root Worldwide Agentic Web MVP Profile 0.2 site manifest |
| [`/.well-known/agent-manifest.json`](./public/.well-known/agent-manifest.json) | `application/json; charset=utf-8` | Standard well-known discovery manifest (`hocon: "/aura-core.json"`) |
| [`/aura-core.json`](./public/aura-core.json) | `application/json; charset=utf-8` | Resolved 5-agent Neuro SAN-profile network definition (finite bounds + `deny_by_default` private context) |
| [`/links.json`](./public/links.json) | `application/json; charset=utf-8` | Publisher-owned peer-network link map (MVP Profile 0.2 Section 3.3) |
| [`/agents/agent-manifest.json`](./public/agents/agent-manifest.json) | `application/json; charset=utf-8` | Backward-compatible subpath manifest for peer URL `https://aura-agentic-web.vercel.app/agents/aura-core` |
| [`/agents/aura-core.json`](./public/agents/aura-core.json) | `application/json; charset=utf-8` | Subpath mirror of `aura-core.json` |
| [`/runtime.js`](./public/runtime.js) | `text/javascript; charset=utf-8` | Pure ES-module browser Neuro SAN runtime + conformance audit engine |

---

## Architecture & Agent Network (`aura-core`)

1. **`orchestrator` (Front Agent / `front_man` - Plan & Synthesize):** Decomposes the user request, delegates self-contained tasks across specialist agents via OpenAI-compatible tool calls, drives a repair pass when verification flags gaps, and synthesizes one unified response.
2. **`researcher` (Ground):** Grounds domain facts, constraints, and edge cases, explicitly flagging uncertainty.
3. **`builder` (Produce):** Produces complete, runnable code or structured artifacts from the plan and grounded context.
4. **`verifier` (Check):** Audits the candidate build against every requirement in the prompt and returns `PASS` or an itemized `GAPS` list for repair.
5. **`critic` (Stress):** Performs a final adversarial pass identifying the strongest remaining weakness, a realistic failure mode, and one high-leverage improvement.

---

## Browser Runtime & Stateless Edge SSE `/api/relay`

- **Pure ES Module Streaming Runtime ([`public/runtime.js`](./public/runtime.js)):**
  - Strict MVP Profile 0.2 validators (`validateManifest`, `validateNetworkDefinition`, `filterPrivateContext`, `runSpecConformanceAudit`) rejecting malformed graphs, unknown references, undeclared inline executable code, and non-finite execution limits.
  - Enforces finite execution budgets (`max_composition_depth`, `max_agent_invocations`, `max_remote_calls`, `max_concurrency`, `max_elapsed_seconds`) clamped to hard runtime ceilings (`HARD_RUNTIME_LIMITS`).
  - Hardened peer-site loading (`loadPeerNetwork`) requiring HTTPS (or localhost dev), explicit user consent before contacting any origin (including cross-origin `hocon` redirects), `credentials: "omit"`, fail-closed exact-match network name lookup, and strict BYOK non-disclosure.
  - Built-in **Spec Protocol Demo (`runSpecDemo`)** traversing the loaded Neuro SAN graph locally with zero API key required.
  - Full BYOK OpenAI-compatible SSE streaming (`stream: true` via `ReadableStream`, preserving `reasoning_content` across tool-call turns) with live handshake validation and field-level error flagging (`INVALID BASE URL`, `INVALID API KEY`, `INVALID MODEL`).
- **Stateless Vercel Edge SSE Relay ([`api/relay.js`](./api/relay.js)):**
  - Browser attempts direct `fetch()` to the visitor's BYOK endpoint first and transparently falls back to `POST /api/relay` only if CORS blocks direct access.
  - Runs on Vercel Edge Runtime (`runtime: "edge"`) with zero buffering, SSRF protection, zero credential storage/logging, and optional zero-setup server demo mode (`DEMO_BASE_URL`, `DEMO_API_KEY`, `DEMO_MODEL`).

---

## Automated Verification & Local Development

```bash
# Run 27 deterministic MVP Profile 0.2 conformance, security invariant (sly_data, recursion bounds,
# prototype pollution, malformed HOCON/JSON, CORS/SSRF relay), diff, SARIF 2.1.0 & SHA-256 certificate tests
npm test

# Run locally with Vercel dev server
npx vercel dev

# Deploy to Vercel production
npx vercel deploy --prod
```
