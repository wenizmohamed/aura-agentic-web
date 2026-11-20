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
  runSpecConformanceAudit,
  buildAgentGraph,
  auditExternalAgenticSite,
  parseAndValidateNetworkText,
  diffPeerFederationAudits,
  buildConformanceBadgeSvg,
  buildSarifConformanceReport,
  buildComplianceCertificate
} from "../public/runtime.js";
import relayHandler from "../api/relay.js";

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

    // Also verify auditExternalAgenticSite scores 100/100 on root AND /agents/aura-core,
    // and fails closed on /agents/nonexistent-peer!
    const extRoot = await auditExternalAgenticSite(`http://127.0.0.1:${port}`);
    assert.equal(extRoot.score, 100, "Root audit should score 100/100");
    assert.equal(extRoot.grade, "CONFORMING (A+)");
    assert.equal(extRoot.agentGraph.nodes.length, 5);
    assert.equal(extRoot.agentGraph.edges.length, 4);

    const extPeer = await auditExternalAgenticSite(`http://127.0.0.1:${port}/agents/aura-core`);
    assert.equal(extPeer.score, 100, "Peer subpath audit should score 100/100");
    assert.equal(extPeer.resolvedNetworkName, "aura-core");
    assert.ok(extPeer.networkDef);

    const extBad = await auditExternalAgenticSite(`http://127.0.0.1:${port}/agents/nonexistent-peer`);
    assert.equal(extBad.networkDef, null, "Mismatched peer name must fail closed");
    assert.ok(extBad.score < 100);
    const exactCheck = extBad.checks.find((c) => c.id === "exact_match_resolution");
    assert.equal(exactCheck.pass, false);

    // Denied consent aborts cleanly with 0 network calls
    const extDenied = await auditExternalAgenticSite(`http://127.0.0.1:${port}/agents/aura-core`, {
      confirmOriginFn: async () => false
    });
    assert.equal(extDenied.aborted, true);
    assert.equal(extDenied.grade, "DENIED");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("buildAgentGraph & standalone community validator.html are valid and wired to runtime.js", () => {
  const core = readJson("public/aura-core.json");
  const g = buildAgentGraph(core);
  assert.equal(g.front, "orchestrator");
  assert.equal(g.nodes.length, 5);
  assert.deepEqual(
    g.edges.map((e) => `${e.from}->${e.to}`),
    [
      "orchestrator->researcher",
      "orchestrator->builder",
      "orchestrator->verifier",
      "orchestrator->critic"
    ]
  );

  const valHtml = fs.readFileSync(path.join(PUBLIC_DIR, "validator.html"), "utf-8");
  assert.match(valHtml, /auditExternalAgenticSite/);
  assert.match(valHtml, /diffPeerFederationAudits/);
  assert.match(valHtml, /buildConformanceBadgeSvg/);
  assert.match(valHtml, /buildSarifConformanceReport/);
  assert.match(valHtml, /buildComplianceCertificate/);
  assert.match(valHtml, /from "\.\/runtime\.js"/);
  assert.match(valHtml, /delegationSvg/);
  assert.match(valHtml, /id="diffPanel"/);
  assert.match(valHtml, /id="certPanel"/);
});

test("sly_data leak blocking denies secrets by default, handles non-objects, and allows only explicit fields", () => {
  const secrets = {
    api_key: "sk-live-999",
    authorization: "Bearer secret",
    session_cookie: "sid=xyz",
    jwt: "eyJhbGciOiJIUzI1NiJ9.payload.sig",
    password: "hunter2",
    locale: "en-US",
    theme: "warm"
  };

  // Default rules (omitted) MUST deny everything
  assert.deepEqual(filterPrivateContext(secrets), {});
  assert.deepEqual(filterPrivateContext(null), {});
  assert.deepEqual(filterPrivateContext(["sk-secret"]), {});
  assert.deepEqual(filterPrivateContext("sk-secret"), {});

  // Explicit allowlist passes ONLY allowlisted keys and blocks all sensitive keys
  const filtered = filterPrivateContext(secrets, {
    deny_by_default: true,
    allowed_downstream_fields: ["locale"]
  });
  assert.deepEqual(filtered, { locale: "en-US" });
  assert.equal("api_key" in filtered, false);
  assert.equal("authorization" in filtered, false);
  assert.equal("session_cookie" in filtered, false);

  // Runtime instance honors network private_context_rules
  const rt = new AuraRuntime();
  rt.loadNetwork(readJson("public/aura-core.json"));
  assert.deepEqual(rt.filterPrivateContext(secrets), {});
});

test("Infinite self-recursion (a -> a -> a...) is halted strictly at max_composition_depth", async () => {
  const rt = new AuraRuntime({
    router: { baseUrl: "https://api.openai.com/v1", apiKey: "sk-test-123", model: "gpt-4o-mini" }
  });
  rt.loadNetwork({
    metadata: { name: "self-loop", front_agent: "looper" },
    tools: [{ name: "looper", instructions: "call self", tools: ["looper"] }],
    execution_limits: { max_composition_depth: 3, max_agent_invocations: 50, max_remote_calls: 50 }
  });
  let calls = 0;
  rt._model = async () => {
    calls++;
    return {
      role: "assistant",
      content: "",
      tool_calls: [{ id: `tc_${calls}`, type: "function", function: { name: "looper", arguments: '{"step":1}' } }]
    };
  };

  await assert.rejects(() => rt.run("trigger self recursion"), /Composition depth limit reached/i);
  assert.equal(calls, 4, "Depths 0, 1, 2, 3 execute; depth 4 immediately throws");
});

test("Mutual recursion (alpha -> beta -> alpha...) is halted strictly at max_composition_depth", async () => {
  const rt = new AuraRuntime({
    router: { baseUrl: "https://api.openai.com/v1", apiKey: "sk-test-123", model: "gpt-4o-mini" }
  });
  rt.loadNetwork({
    metadata: { name: "mutual-loop", front_agent: "alpha" },
    tools: [
      { name: "alpha", instructions: "call beta", tools: ["beta"] },
      { name: "beta", instructions: "call alpha", tools: ["alpha"] }
    ],
    execution_limits: { max_composition_depth: 2, max_agent_invocations: 40, max_remote_calls: 40 }
  });
  let calls = 0;
  rt._model = async (_msgs, _fns, agentName) => {
    calls++;
    const next = agentName === "alpha" ? "beta" : "alpha";
    return {
      role: "assistant",
      content: "",
      tool_calls: [{ id: `tc_${calls}`, type: "function", function: { name: next, arguments: "{}" } }]
    };
  };

  await assert.rejects(() => rt.run("trigger mutual recursion"), /Composition depth limit reached/i);
  assert.equal(calls, 3, "Depths 0(alpha), 1(beta), 2(alpha) run; depth 3(beta) is blocked");
});

test("Repeated horizontal invocation storm is halted strictly at max_agent_invocations", async () => {
  const rt = new AuraRuntime({
    router: { baseUrl: "https://api.openai.com/v1", apiKey: "sk-test-123", model: "gpt-4o-mini" }
  });
  rt.loadNetwork({
    metadata: { name: "fanout-cap", front_agent: "hub" },
    tools: [
      { name: "hub", instructions: "fanout", tools: ["worker"] },
      { name: "worker", instructions: "work", tools: [] }
    ],
    execution_limits: { max_composition_depth: 4, max_agent_invocations: 3, max_remote_calls: 40 }
  });
  rt._model = async (_msgs, _fns, agentName) => {
    if (agentName === "worker") return { role: "assistant", content: "ok" };
    return {
      role: "assistant",
      content: "",
      tool_calls: [
        { id: "c1", type: "function", function: { name: "worker", arguments: "{}" } },
        { id: "c2", type: "function", function: { name: "worker", arguments: "{}" } },
        { id: "c3", type: "function", function: { name: "worker", arguments: "{}" } }
      ]
    };
  };

  await assert.rejects(() => rt.run("fanout"), /Agent-invocation limit reached/i);
});

test("Remote-call budget halts runaway LLM calls at max_remote_calls", async () => {
  const rt = new AuraRuntime({
    router: { baseUrl: "https://api.openai.com/v1", apiKey: "sk-test-123", model: "gpt-4o-mini" }
  });
  rt.loadNetwork({
    metadata: { name: "remote-cap", front_agent: "solo" },
    tools: [{ name: "solo", instructions: "solo", tools: [] }],
    execution_limits: { max_composition_depth: 4, max_agent_invocations: 20, max_remote_calls: 1 }
  });
  rt._remoteCalls = 1;
  await assert.rejects(() => rt._model([{ role: "user", content: "hi" }], [], "solo"), /Remote-call limit reached/i);
});

test("Elapsed-time budget halts execution once max_elapsed_seconds is exceeded", async () => {
  const rt = new AuraRuntime();
  rt.loadNetwork({
    metadata: { name: "time-cap", front_agent: "solo" },
    tools: [{ name: "solo", instructions: "solo", tools: [] }],
    execution_limits: { max_elapsed_seconds: 1 }
  });
  rt._startedAt = Date.now() - 5000;
  await assert.rejects(() => rt._runAgent("solo", { request: "late" }, 0), /Elapsed-time limit reached/i);
});

test("HARD_RUNTIME_LIMITS strictly clamps malicious peer execution_limits overrides", () => {
  const rt = new AuraRuntime();
  rt.loadNetwork({
    metadata: { name: "clamped", front_agent: "a" },
    tools: [{ name: "a", instructions: "ok", tools: [] }],
    execution_limits: {
      max_composition_depth: 9999,
      max_agent_invocations: 999999,
      max_remote_calls: 500000,
      max_concurrency: 128,
      max_elapsed_seconds: 999999
    }
  });
  assert.deepEqual(rt.limits, { ...HARD_RUNTIME_LIMITS });
});

test("Malformed HOCON/JSON rejection blocks broken syntax, non-objects, and oversized payloads", () => {
  assert.equal(parseAndValidateNetworkText("").ok, false);
  assert.equal(parseAndValidateNetworkText("   ").ok, false);
  assert.equal(parseAndValidateNetworkText(null).ok, false);
  assert.equal(parseAndValidateNetworkText("[1, 2, 3]").ok, false);
  assert.equal(parseAndValidateNetworkText('{"metadata": { unquoted_hocon = true }').ok, false);
  assert.equal(parseAndValidateNetworkText('{"metadata":{"front_agent":"a"},"tools":[]} trailing').ok, false);
  const oversized = "{" + " ".repeat(2 * 1024 * 1024 + 10) + "}";
  const overRes = parseAndValidateNetworkText(oversized);
  assert.equal(overRes.ok, false);
  assert.match(overRes.errors[0], /2MB/i);
});

test("Prototype pollution keys (__proto__, constructor, prototype) in raw HOCON/JSON are rejected", () => {
  const payloads = [
    '{"__proto__":{"polluted":true},"metadata":{"front_agent":"a"},"tools":[{"name":"a","tools":[]}]}',
    '{"metadata":{"front_agent":"a","constructor":{"polluted":1}},"tools":[{"name":"a","tools":[]}]}',
    '{"metadata":{"front_agent":"a"},"tools":[{"name":"a","prototype":{},"tools":[]}]}'
  ];
  for (const raw of payloads) {
    const res = parseAndValidateNetworkText(raw);
    assert.equal(res.ok, false, `Expected rejection for ${raw}`);
    assert.match(res.errors[0], /forbidden prototype key/i);
  }
});

test("All 6 forbidden executable keys and invalid function.parameters schemas are rejected", () => {
  const forbidden = ["code", "script", "eval", "inline_code", "handler_source", "executable"];
  for (const key of forbidden) {
    const v = validateNetworkDefinition({
      metadata: { name: "bad-exec", front_agent: "a" },
      tools: [{ name: "a", [key]: "return 1;", tools: [] }]
    });
    assert.equal(v.ok, false, `Key '${key}' must be rejected`);
    assert.match(v.errors.join(" "), new RegExp(key));
  }

  const badSchema = validateNetworkDefinition({
    metadata: { name: "bad-params", front_agent: "a" },
    tools: [{ name: "a", function: { parameters: { type: "array" } }, tools: [] }]
  });
  assert.equal(badSchema.ok, false);
  assert.match(badSchema.errors[0], /JSON Schema object/i);
});

test("Safe HOCON comment stripping preserves URLs inside strings while parsing valid networks", () => {
  const hoconLike = [
    "// Top-level HOCON comment for AURA peer network",
    "# Secondary hash comment",
    "{",
    '  "metadata": {',
    '    "name": "peer-commented",',
    '    "front_agent": "lead",',
    '    "homepage": "https://aura-agentic-web.vercel.app/#anchor"',
    "  },",
    '  "tools": [',
    '    { "name": "lead", "instructions": "Use https://example.com//path", "tools": [] }',
    "  ]",
    "}"
  ].join("\n");

  const parsed = parseAndValidateNetworkText(hoconLike);
  assert.equal(parsed.ok, true, parsed.errors.join("; "));
  assert.equal(parsed.def.metadata.homepage, "https://aura-agentic-web.vercel.app/#anchor");
  assert.equal(parsed.def.tools[0].instructions, "Use https://example.com//path");
});

test("Manifest validator rejects non-0.2 versions, missing site, duplicate networks, and missing hocon", () => {
  assert.equal(validateManifest(null).ok, false);
  const bad = validateManifest({
    manifest_version: "0.1",
    site: {},
    networks: [
      { name: "dup", front_agent: "a", hocon: "./a.json" },
      { name: "dup", front_agent: "", hocon: "" }
    ]
  });
  assert.equal(bad.ok, false);
  const joined = bad.errors.join(" | ");
  assert.match(joined, /manifest_version/i);
  assert.match(joined, /site\.name/i);
  assert.match(joined, /inference/i);
  assert.match(joined, /Duplicate network name/i);
  assert.match(joined, /missing front_agent/i);
  assert.match(joined, /missing 'hocon'/i);
});

test("Router input validator blocks private IPs, insecure HTTP, embedded credentials, and bad models", () => {
  assert.equal(validateRouterInputs({ baseUrl: "http://api.openai.com/v1", apiKey: "sk-123" }).code, "insecure_base_url");
  assert.equal(validateRouterInputs({ baseUrl: "https://192.168.1.5/v1", apiKey: "sk-123" }).code, "private_ip_base_url");
  assert.equal(validateRouterInputs({ baseUrl: "https://10.0.0.1/v1", apiKey: "sk-123" }).code, "private_ip_base_url");
  assert.equal(validateRouterInputs({ baseUrl: "https://user:pass@api.openai.com/v1", apiKey: "sk-123" }).code, "invalid_base_url");
  assert.equal(validateRouterInputs({ baseUrl: "https://api.openai.com/v1", apiKey: "sk-123", model: "https://bad.model" }).code, "invalid_model");

  const htmlFlag = classifyRouterError({ status: 200, contentType: "text/html", rawText: "<!doctype html><title>Login</title>" });
  assert.equal(htmlFlag.code, "html_not_api");
  const modelFlag = classifyRouterError({ status: 404, rawText: '{"error":{"code":"model_not_found","message":"The model foo does not exist"}}' });
  assert.equal(modelFlag.field, "model");
});

test("Edge /api/relay enforces CORS on OPTIONS/GET/HEAD/POST and blocks SSRF private targets", async () => {
  const optRes = await relayHandler(new Request("https://aura-agentic-web.vercel.app/api/relay", { method: "OPTIONS" }));
  assert.equal(optRes.status, 204);
  assert.equal(optRes.headers.get("access-control-allow-origin"), "*");

  const getRes = await relayHandler(new Request("https://aura-agentic-web.vercel.app/api/relay", { method: "GET" }));
  assert.equal(getRes.status, 200);
  assert.equal(getRes.headers.get("access-control-allow-origin"), "*");

  const headRes = await relayHandler(new Request("https://aura-agentic-web.vercel.app/api/relay", { method: "HEAD" }));
  assert.equal(headRes.status, 200);
  assert.equal(headRes.headers.get("access-control-allow-origin"), "*");

  for (const ssrfUrl of [
    "http://127.0.0.1:8080/v1/chat/completions",
    "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5/v1/chat/completions",
    "https://192.168.0.1/v1/chat/completions"
  ]) {
    const res = await relayHandler(
      new Request("https://aura-agentic-web.vercel.app/api/relay", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-target-url": ssrfUrl },
        body: JSON.stringify({ model: "gpt-4o-mini", messages: [] })
      })
    );
    assert.equal(res.status, 400, `SSRF target ${ssrfUrl} must return 400`);
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
  }

  // Control characters in Authorization header rejected with 401
  const badAuthRes = await relayHandler(
    new Request("https://aura-agentic-web.vercel.app/api/relay", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-target-url": "https://api.openai.com/v1/chat/completions",
        authorization: "Bearer sk-bad-\u007f-key"
      },
      body: JSON.stringify({ model: "gpt-4o-mini", messages: [] })
    })
  );
  assert.equal(badAuthRes.status, 401);
});

test("diffPeerFederationAudits compares conforming peers, fail-closed mismatches, topology, and trace deltas", () => {
  const core = readJson("public/aura-core.json");
  const graph = buildAgentGraph(core);
  const makeChecks = (failIds = []) =>
    [
      "https_transport",
      "manifest_fetch",
      "manifest_cors",
      "manifest_schema",
      "exact_match_resolution",
      "well_known_discovery",
      "network_def_fetch",
      "neuro_san_schema",
      "finite_execution_bounds",
      "private_context_isolation"
    ].map((id) => ({
      id,
      label: id,
      path: "/" + id,
      pass: !failIds.includes(id),
      points: failIds.includes(id) ? 0 : 10,
      status: failIds.includes(id) ? 404 : 200,
      cors: "*",
      ms: 12,
      detail: failIds.includes(id) ? "failed" : "ok"
    }));

  const base = {
    targetUrl: "https://aura-agentic-web.vercel.app",
    resolvedNetworkName: "aura-core",
    score: 100,
    passed: 10,
    total: 10,
    grade: "CONFORMING (A+)",
    checks: makeChecks(),
    networkDef: core,
    agentGraph: graph
  };

  const candPeer = { ...base, targetUrl: "https://aura-agentic-web.vercel.app/agents/aura-core" };
  const eqDiff = diffPeerFederationAudits(base, candPeer, {
    baselineTrace: { invocations: 7, maxDepth: 1, remoteCalls: 0, leakedKeys: 0, hops: ["orchestrator->researcher"] },
    candidateTrace: { invocations: 7, maxDepth: 1, remoteCalls: 0, leakedKeys: 0, hops: ["orchestrator->researcher"] }
  });
  assert.equal(eqDiff.verdict, "EQUIVALENT_CONFORMING");
  assert.equal(eqDiff.scoreDelta, 0);
  assert.equal(eqDiff.topologyDiff.sharedAgents.length, 5);
  assert.equal(eqDiff.topologyDiff.addedAgents.length, 0);
  assert.equal(eqDiff.privacyDiff.status, "ISOLATED");
  assert.equal(eqDiff.traceDiff.invocationDelta, 0);

  const failClosedCand = {
    targetUrl: "https://aura-agentic-web.vercel.app/agents/nonexistent-peer",
    resolvedNetworkName: null,
    score: 50,
    passed: 5,
    total: 10,
    grade: "NON-CONFORMING",
    checks: makeChecks(["exact_match_resolution", "network_def_fetch", "neuro_san_schema", "finite_execution_bounds", "private_context_isolation"]),
    networkDef: null,
    agentGraph: null
  };
  const fcDiff = diffPeerFederationAudits(base, failClosedCand);
  assert.equal(fcDiff.verdict, "FAIL_CLOSED_VERIFIED");
  assert.equal(fcDiff.scoreDelta, -50);
  assert.equal(fcDiff.regressionCount, 5);
  assert.equal(fcDiff.topologyDiff.removedAgents.length, 5);
});

test("buildConformanceBadgeSvg outputs valid XML-escaped SVG badges for A+, partial, and fail states", () => {
  const passSvg = buildConformanceBadgeSvg({
    score: 100,
    grade: "CONFORMING (A+)",
    checks: [{ id: "private_context_isolation", pass: true }]
  });
  assert.match(passSvg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(passSvg, /100\/100 A\+/);
  assert.match(passSvg, /#168A5B/);
  assert.match(passSvg, /sly_data: 0 leaks/);

  const failSvg = buildConformanceBadgeSvg({
    score: 40,
    grade: "NON-CONFORMING",
    checks: [{ id: "private_context_isolation", pass: false }]
  });
  assert.match(failSvg, /#C9352B/);
  assert.match(failSvg, /fail-closed/);
});

test("buildSarifConformanceReport emits schema-valid SARIF 2.1.0 with WAW02 rules and pass/fail results", () => {
  const sarif = buildSarifConformanceReport({
    targetUrl: "https://aura-agentic-web.vercel.app/agents/aura-core",
    origin: "https://aura-agentic-web.vercel.app",
    resolvedNetworkName: "aura-core",
    score: 90,
    passed: 9,
    total: 10,
    grade: "PARTIAL",
    checkedAt: "2026-11-20T21:00:00.000Z",
    checks: [
      { id: "https_transport", label: "HTTPS Transport Security", path: "https:", pass: true, status: 200, cors: "transport", ms: 0, detail: "OK" },
      { id: "private_context_isolation", label: "Private Context (sly_data) Isolation", path: "private_context_rules", pass: false, status: 422, cors: "runtime", ms: 0, detail: "Missing deny_by_default" }
    ]
  });

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 2);
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, "WAW02-001");
  assert.equal(sarif.runs[0].tool.driver.rules[1].id, "WAW02-010");
  assert.equal(sarif.runs[0].results[0].kind, "pass");
  assert.equal(sarif.runs[0].results[0].level, "note");
  assert.equal(sarif.runs[0].results[1].kind, "fail");
  assert.equal(sarif.runs[0].results[1].level, "error");
});

test("buildComplianceCertificate issues deterministic SHA-256 JSON compliance certificates", async () => {
  const core = readJson("public/aura-core.json");
  const report = {
    targetUrl: "https://aura-agentic-web.vercel.app/agents/aura-core",
    origin: "https://aura-agentic-web.vercel.app",
    manifestUrl: "https://aura-agentic-web.vercel.app/agents/agent-manifest.json",
    wellKnownUrl: "https://aura-agentic-web.vercel.app/.well-known/agent-manifest.json",
    definitionUrl: "https://aura-agentic-web.vercel.app/agents/aura-core.json",
    resolvedNetworkName: "aura-core",
    score: 100,
    passed: 10,
    total: 10,
    grade: "CONFORMING (A+)",
    checkedAt: "2026-11-20T21:00:00.000Z",
    checks: [
      "https_transport",
      "manifest_fetch",
      "manifest_cors",
      "manifest_schema",
      "exact_match_resolution",
      "well_known_discovery",
      "network_def_fetch",
      "neuro_san_schema",
      "finite_execution_bounds",
      "private_context_isolation"
    ].map((id) => ({ id, pass: true })),
    networkDef: core,
    agentGraph: buildAgentGraph(core)
  };

  const cert1 = await buildComplianceCertificate(report, {
    traceSummary: { invocations: 7, maxDepth: 1, remoteCalls: 0, leakedKeys: 0 }
  });
  const cert2 = await buildComplianceCertificate(report, {
    traceSummary: { invocations: 7, maxDepth: 1, remoteCalls: 0, leakedKeys: 0 }
  });

  assert.equal(cert1.schema, "aura.agentic-web.compliance-certificate/v1");
  assert.equal(cert1.specProfile, "worldwide-agentic-web-mvp-0.2");
  assert.match(cert1.fingerprintSha256, /^[0-9a-f]{64}$/);
  assert.equal(cert1.fingerprintSha256, cert2.fingerprintSha256, "Canonical SHA-256 must be deterministic");
  assert.equal(cert1.certificateId, "waw02-" + cert1.fingerprintSha256.slice(0, 16));
  assert.equal(cert1.invariants.slyDataDenyByDefault, true);
  assert.equal(cert1.invariants.finiteExecutionBounds, true);
  assert.equal(cert1.agentTopology.agentCount, 5);
});
