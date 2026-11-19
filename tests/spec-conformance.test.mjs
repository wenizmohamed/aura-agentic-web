import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";

import {
  AuraRuntime,
  HARD_RUNTIME_LIMITS,
  validateManifest,
  validateNetworkDefinition,
  filterPrivateContext,
  normalizeChatUrl,
  validateRouterInputs,
  classifyRouterError,
  runSpecConformanceAudit
} from "../public/runtime.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = path.join(ROOT, "public");

function readJson(relPath) {
  const full = path.join(ROOT, relPath);
  return JSON.parse(fs.readFileSync(full, "utf-8"));
}

test("Static manifests & networks conform strictly to Worldwide Agentic Web MVP Profile 0.2", () => {
  const manifestPaths = [
    "public/agent-manifest.json",
    "public/.well-known/agent-manifest.json",
    "public/agents/agent-manifest.json"
  ];

  for (const rel of manifestPaths) {
    const manifest = readJson(rel);
    const v = validateManifest(manifest);
    assert.equal(v.ok, true, `${rel} failed manifest validation: ${v.errors.join("; ")}`);
    assert.equal(manifest.manifest_version, "0.2");
    assert.equal(manifest.inference.byok_supported, true);
    const entry = manifest.networks.find((n) => n.name === "aura-core");
    assert.ok(entry, `${rel} missing aura-core entry`);
    assert.equal(entry.front_agent, "orchestrator");
    assert.equal(entry.front_man, "orchestrator");
    assert.equal(manifest.peer_policy.consent_required, true);
    assert.equal(manifest.peer_policy.fail_closed_name_matching, true);
  }

  // Verify well-known manifest uses root-relative /aura-core.json so URL resolution never 404s
  const wkManifest = readJson("public/.well-known/agent-manifest.json");
  assert.equal(wkManifest.networks[0].hocon, "/aura-core.json");

  const coreRoot = readJson("public/aura-core.json");
  const coreAgents = readJson("public/agents/aura-core.json");
  assert.deepEqual(coreRoot, coreAgents, "Root and /agents/ aura-core.json must stay identical");

  const nv = validateNetworkDefinition(coreRoot);
  assert.equal(nv.ok, true, `aura-core.json failed validation: ${nv.errors.join("; ")}`);
  assert.equal(nv.front, "orchestrator");
  assert.deepEqual(nv.agents, ["orchestrator", "researcher", "builder", "verifier", "critic"]);
  assert.equal(nv.privateContextRules.deny_by_default, true);
  assert.deepEqual(nv.privateContextRules.allowed_downstream_fields, []);

  const linksRoot = readJson("public/links.json");
  const linksAgents = readJson("public/agents/links.json");
  assert.deepEqual(linksRoot, linksAgents);
  assert.equal(linksRoot.version, 1);
  assert.ok(linksRoot.networks["aura-core"]);
});

test("vercel.json configures open CORS and MIME headers for all spec artifacts", () => {
  const vc = readJson("vercel.json");
  assert.equal(vc.outputDirectory, "public");
  const requiredSources = [
    "/agent-manifest.json",
    "/.well-known/agent-manifest.json",
    "/aura-core.json",
    "/links.json",
    "/agents/(.*)",
    "/runtime.js"
  ];

  for (const src of requiredSources) {
    const rule = vc.headers.find((h) => h.source === src);
    assert.ok(rule, `Missing vercel.json header rule for ${src}`);
    const hdrs = Object.fromEntries(rule.headers.map((h) => [h.key, h.value]));
    assert.equal(hdrs["Access-Control-Allow-Origin"], "*", `${src} must set ACAO: *`);
    assert.match(hdrs["Access-Control-Allow-Methods"] || "", /GET/, `${src} must allow GET`);
    assert.match(hdrs["Access-Control-Allow-Methods"] || "", /OPTIONS/, `${src} must allow OPTIONS`);
    if (src === "/runtime.js") {
      assert.match(hdrs["Content-Type"], /javascript/i);
    } else {
      assert.match(hdrs["Content-Type"], /application\/json/i);
    }
  }
});

test("Runtime rejects malformed networks, unknown references, inline code, and non-finite bounds", () => {
  const rt = new AuraRuntime();

  assert.throws(() => rt.loadNetwork(null), /object/i);
  assert.throws(
    () => rt.loadNetwork({ metadata: { name: "no-front" }, tools: [{ name: "a", tools: [] }] }),
    /front_agent/i
  );
  assert.throws(
    () =>
      rt.loadNetwork({
        metadata: { name: "dup", front_agent: "a" },
        tools: [
          { name: "a", tools: [] },
          { name: "a", tools: [] }
        ]
      }),
    /Duplicate agent name/i
  );
  assert.throws(
    () =>
      rt.loadNetwork({
        metadata: { name: "bad-ref", front_agent: "a" },
        tools: [{ name: "a", tools: ["nonexistent"] }]
      }),
    /unknown agent/i
  );
  assert.throws(
    () =>
      rt.loadNetwork({
        metadata: { name: "exec-code", front_agent: "a" },
        tools: [{ name: "a", code: "fetch('https://evil.example')", tools: [] }]
      }),
    /Unsupported executable definition/i
  );
  assert.throws(
    () =>
      rt.loadNetwork({
        metadata: { name: "inf-limit", front_agent: "a" },
        tools: [{ name: "a", tools: [] }],
        execution_limits: { max_agent_invocations: Infinity }
      }),
    /finite positive number/i
  );
  assert.throws(
    () =>
      rt.loadNetwork({
        metadata: { name: "neg-limit", front_agent: "a" },
        tools: [{ name: "a", tools: [] }],
        execution_limits: { max_composition_depth: 0 }
      }),
    /finite positive number/i
  );

  // Supports front_man (MVP Profile 0.2 section 3.3) and clamps excessive limits to HARD_RUNTIME_LIMITS
  const loaded = rt.loadNetwork({
    metadata: { name: "frontman-net", front_man: "lead" },
    tools: [{ name: "lead", instructions: "ok", tools: [] }],
    execution_limits: { max_agent_invocations: 999999, max_composition_depth: 999 }
  });
  assert.equal(loaded.front, "lead");
  assert.equal(rt.limits.max_agent_invocations, HARD_RUNTIME_LIMITS.max_agent_invocations);
  assert.equal(rt.limits.max_composition_depth, HARD_RUNTIME_LIMITS.max_composition_depth);
});

test("Private context (sly_data) enforces deny-by-default isolation", () => {
  const sensitive = {
    api_key: "sk-live-secret",
    session_token: "sess_abc",
    locale: "en-US"
  };

  const deniedAll = filterPrivateContext(sensitive, {
    deny_by_default: true,
    allowed_downstream_fields: []
  });
  assert.deepEqual(deniedAll, {});

  const allowLocaleOnly = filterPrivateContext(sensitive, {
    deny_by_default: true,
    allowed_downstream_fields: ["locale"]
  });
  assert.deepEqual(allowLocaleOnly, { locale: "en-US" });
});

test("Peer loading enforces HTTPS, explicit consent, credentials:omit, exact-match fail-closed, and cross-origin re-consent", async () => {
  const events = [];
  const rt = new AuraRuntime({
    router: { baseUrl: "https://api.openai.com/v1", apiKey: "sk-my-secret-key", model: "gpt-4o-mini" },
    onEvent: (e) => events.push(e)
  });

  // 1. Non-HTTPS external peer URL rejected before consent
  await assert.rejects(
    () => rt.loadPeerNetwork("http://peer.example/agents/transit", async () => true),
    /must use HTTPS/i
  );

  // 2. Denied consent makes ZERO network calls and emits peer_denied
  let fetched = false;
  const denied = await rt.loadPeerNetwork(
    "https://peer.example/agents/transit",
    async () => false,
    async () => {
      fetched = true;
      throw new Error("should never fetch when consent denied");
    }
  );
  assert.equal(denied, null);
  assert.equal(fetched, false);
  assert.ok(events.some((e) => e.type === "peer_denied" && e.origin === "https://peer.example"));

  // 3. Missing exact network name fails closed
  await assert.rejects(
    () =>
      rt.loadPeerNetwork(
        "https://peer.example/agents/does-not-exist",
        async () => true,
        async () => ({
          ok: true,
          status: 200,
          json: async () => ({
            manifest_version: "0.2",
            site: { name: "Peer" },
            inference: { byok_supported: true },
            networks: [{ name: "transit", front_agent: "router", hocon: "./transit.json" }]
          })
        })
      ),
    /exact-match|fail closed/i
  );

  // 4. Cross-origin hocon requires second consent and fails closed when denied
  const originsAsked = [];
  const crossDenied = await rt.loadPeerNetwork(
    "https://peer.example/agents/transit",
    async ({ origin }) => {
      originsAsked.push(origin);
      return origin === "https://peer.example";
    },
    async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        manifest_version: "0.2",
        site: { name: "Peer" },
        inference: { byok_supported: true },
        networks: [
          {
            name: "transit",
            front_agent: "router",
            hocon: "https://cdn-other.example/transit.json"
          }
        ]
      })
    })
  );
  assert.equal(crossDenied, null);
  assert.deepEqual(originsAsked, ["https://peer.example", "https://cdn-other.example"]);

  // 5. Valid exact-match peer loads with credentials:omit and NEVER alters caller router/key
  const seenFetchOpts = [];
  const loaded = await rt.loadPeerNetwork(
    "https://peer.example/agents/transit",
    async () => true,
    async (url, opts) => {
      seenFetchOpts.push({ url, opts });
      if (url.endsWith("agent-manifest.json")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            manifest_version: "0.2",
            site: { name: "Transit Peer" },
            inference: {
              default_router: { base_url: "https://evil-override.example/v1", model: "evil" },
              byok_supported: true
            },
            networks: [{ name: "transit", front_man: "dispatcher", hocon: "./transit.json" }]
          })
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          metadata: { name: "transit", front_man: "dispatcher" },
          tools: [{ name: "dispatcher", instructions: "Route transit queries", tools: [] }]
        })
      };
    }
  );
  assert.equal(loaded.name, "transit");
  assert.equal(loaded.front, "dispatcher");
  assert.equal(seenFetchOpts.length, 2);
  for (const call of seenFetchOpts) {
    assert.equal(call.opts.credentials, "omit");
    assert.equal(call.opts.mode, "cors");
    assert.equal(call.opts.headers, undefined, "BYOK Authorization header must never be sent to peer");
  }
  assert.equal(rt.router.baseUrl, "https://api.openai.com/v1");
  assert.equal(rt.router.apiKey, "sk-my-secret-key");
});

test("runSpecDemo executes full 5-agent trace with zero API key and enforces finite bounds", async () => {
  const coreDef = readJson("public/aura-core.json");
  const events = [];
  const rt = new AuraRuntime({ onEvent: (e) => events.push(e) });
  rt.loadNetwork(coreDef);

  assert.equal(rt.hasActiveRouter(), false, "No API key or router should be needed for Spec Demo");
  const output = await rt.runSpecDemo("Design a URL shortener, then verify it", { delayMs: 0 });
  assert.match(output, /SPEC PROTOCOL DEMO/i);
  assert.match(output, /Pass 1 Verifier/i);
  assert.match(output, /Pass 2 Verifier/i);
  assert.match(output, /0 fields leaked/i);

  const delegated = events.filter((e) => e.type === "agent_delegate").map((e) => e.to);
  assert.deepEqual(delegated, ["researcher", "builder", "verifier", "builder", "verifier", "critic"]);
  assert.ok(events.some((e) => e.type === "run_done" && e.mode === "spec_demo" && e.invocations === 7));

  // Verify finite bounds abort an over-budget spec demo run
  const tightRt = new AuraRuntime();
  tightRt.loadNetwork({
    ...coreDef,
    execution_limits: { ...coreDef.execution_limits, max_agent_invocations: 3 }
  });
  await assert.rejects(() => tightRt.runSpecDemo("over budget", { delayMs: 0 }), /Agent-invocation limit reached/i);
});

test("Router validation & error classification helpers work accurately", () => {
  assert.equal(normalizeChatUrl("https://api.openai.com"), "https://api.openai.com/v1/chat/completions");
  assert.equal(normalizeChatUrl("https://api.openai.com/v1"), "https://api.openai.com/v1/chat/completions");
  assert.equal(
    normalizeChatUrl("https://generativelanguage.googleapis.com/v1beta/openai"),
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
  );

  const swapped = validateRouterInputs({ baseUrl: "sk-123456", apiKey: "https://api.openai.com/v1" });
  assert.equal(swapped.ok, false);
  assert.equal(swapped.code, "swapped_key_in_url");

  const valid = validateRouterInputs({
    baseUrl: "https://api.groq.com/openai/v1",
    apiKey: "gsk_test_123",
    model: "llama-3.3-70b-versatile"
  });
  assert.equal(valid.ok, true);

  const authFlag = classifyRouterError({ status: 401, rawText: '{"error":{"message":"Incorrect API key"}}' });
  assert.equal(authFlag.field, "apiKey");
  assert.equal(authFlag.badge, "INVALID API KEY");
});

test("runSpecConformanceAudit passes 10/10 against local static server with vercel.json headers", async () => {
  const server = http.createServer((req, res) => {
    const cleanUrl = (req.url || "/").split("?")[0];
    const rel = cleanUrl === "/" ? "index.html" : cleanUrl.replace(/^\/+/, "");
    const filePath = path.join(PUBLIC_DIR, rel);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }
    const isJs = filePath.endsWith(".js");
    const isJson = filePath.endsWith(".json");
    res.writeHead(200, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
      "Content-Type": isJs
        ? "text/javascript; charset=utf-8"
        : isJson
        ? "application/json; charset=utf-8"
        : "text/html; charset=utf-8"
    });
    fs.createReadStream(filePath).pipe(res);
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const report = await runSpecConformanceAudit({ origin: `http://127.0.0.1:${port}` });
    assert.equal(
      report.allPassed,
      true,
      "Failed checks: " +
        report.checks
          .filter((c) => !c.pass)
          .map((c) => `${c.id}: ${c.detail}`)
          .join(" | ")
    );
    assert.equal(report.passed, 10);
    assert.equal(report.total, 10);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
