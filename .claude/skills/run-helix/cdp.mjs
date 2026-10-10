/**
 * Minimal Chrome DevTools Protocol client — zero dependencies.
 *
 * The repo has no browser driver (no playwright, no chromium-cli), but the
 * devcontainer image ships a Chromium under ~/.cache/ms-playwright. Node 24
 * has a global WebSocket, so speaking CDP directly is ~100 lines and costs no
 * dependency — which matters here, since this repo is deliberately
 * dependency-minimal (AGENTS.md, project plan §6).
 */
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Find the Chromium the devcontainer cached, whatever revision it is. */
export function findChrome() {
  const explicit = process.env.HELIX_SMOKE_CHROME;
  if (explicit) return existsSync(explicit) ? explicit : null;
  const root = join(homedir(), ".cache", "ms-playwright");
  if (!existsSync(root)) return null;
  for (const dir of readdirSync(root)) {
    if (!dir.startsWith("chromium")) continue;
    for (const rel of ["chrome-linux/chrome", "chrome-linux/headless_shell"]) {
      const p = join(root, dir, rel);
      if (existsSync(p)) return p;
    }
  }
  return null;
}

/**
 * Launch headless Chromium and attach one page session.
 * Returns a handle with navigate/evaluate/screenshot plus captured page errors.
 */
export async function launchBrowser({
  port = 9411,
  ignoreCertErrors = false,
  baseDomain,
  hostRules,
} = {}) {
  const bin = findChrome();
  if (!bin) throw new Error("no cached Chromium found (set HELIX_SMOKE_CHROME)");

  const rules = hostRules ?? (baseDomain ? [baseDomain] : []).filter(Boolean);

  const chromeArgs = [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--hide-scrollbars",
    "--window-size=1280,720",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${mkdtempSync(join(tmpdir(), "helix-smoke-"))}`,
    "about:blank",
  ];
  if (ignoreCertErrors) {
    chromeArgs.push("--ignore-certificate-errors");
  }
  if (rules.length) {
    const resolver = rules
      .flatMap((domain) => [`MAP *.${domain} 127.0.0.1`, `MAP ${domain} 127.0.0.1`])
      .join(", ");
    chromeArgs.push(`--host-resolver-rules=${resolver}`);
  }

  const child = spawn(bin, chromeArgs, { stdio: "ignore" });

  let version;
  for (let i = 0; i < 80; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (r.ok) {
        version = await r.json();
        break;
      }
    } catch {
      /* not up yet */
    }
    await sleep(250);
  }
  if (!version) {
    child.kill("SIGKILL");
    throw new Error("Chromium devtools endpoint never came up");
  }

  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", () => rej(new Error("CDP socket failed")), { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const listeners = new Set();
  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
    } else if (msg.method) {
      for (const fn of listeners) fn(msg);
    }
  });

  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`CDP timeout: ${method}`));
      }, 45_000);
    });

  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  await send("Page.enable", {}, sessionId);
  await send("Runtime.enable", {}, sessionId);
  await send("Log.enable", {}, sessionId);
  await send("Network.enable", {}, sessionId);

  // Collected per-navigation; the caller clears between routes.
  const errors = [];
  const failedRequests = [];
  const cspReportPosts = [];
  listeners.add((msg) => {
    if (msg.sessionId !== sessionId) return;
    if (msg.method === "Network.requestWillBeSent") {
      const url = msg.params?.request?.url ?? "";
      if (url.includes("/_csp-report") && msg.params.request.postData) {
        cspReportPosts.push(msg.params.request.postData);
      }
    } else if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      errors.push(d.exception?.description ?? d.text);
    } else if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      errors.push(
        "console.error: " + msg.params.args.map((a) => a.value ?? a.description).join(" "),
      );
    } else if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      errors.push("log: " + msg.params.entry.text);
    } else if (msg.method === "Network.loadingFailed" && !msg.params.canceled) {
      failedRequests.push(msg.params.errorText);
    }
  });

  const waitForLoad = () =>
    new Promise((resolve) => {
      const fn = (msg) => {
        if (msg.sessionId === sessionId && msg.method === "Page.loadEventFired") {
          listeners.delete(fn);
          resolve();
        }
      };
      listeners.add(fn);
      setTimeout(() => {
        listeners.delete(fn);
        resolve();
      }, 30_000);
    });

  return {
    errors,
    failedRequests,
    cspReportPosts,
    reset() {
      errors.length = 0;
      failedRequests.length = 0;
      cspReportPosts.length = 0;
    },
    async navigate(url, settleMs = 2000) {
      const loaded = waitForLoad();
      await send("Page.navigate", { url }, sessionId);
      await loaded;
      await sleep(settleMs); // let TanStack Query settle its first fetches
    },
    async evaluate(expression) {
      const { result, exceptionDetails } = await send(
        "Runtime.evaluate",
        { expression, returnByValue: true, awaitPromise: true },
        sessionId,
      );
      if (exceptionDetails) throw new Error(exceptionDetails.text);
      return result.value;
    },
    async screenshot(path) {
      const { data } = await send("Page.captureScreenshot", { format: "png" }, sessionId);
      const { writeFileSync } = await import("node:fs");
      writeFileSync(path, Buffer.from(data, "base64"));
      return path;
    },
    /** Raw CDP into this page's session — e.g. Input.dispatchMouseEvent to drive :hover. */
    send: (method, params = {}) => send(method, params, sessionId),
    close() {
      try {
        ws.close();
      } catch {
        /* already gone */
      }
      child.kill("SIGKILL");
    },
  };
}
