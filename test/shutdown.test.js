import assert from "node:assert/strict";
import { fork } from "node:child_process";
import http from "node:http";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));

async function start(t) {
  const child = fork(fileURLToPath(new URL("./fixtures/server-child.mjs", import.meta.url)), {
    cwd: root,
    execArgv: ["--experimental-loader", fileURLToPath(new URL("./fixtures/mysql-loader.mjs", import.meta.url))],
    env: { ...process.env, PORT: "0", SESSION_SECRET: "shutdown-test-secret-at-least-32-characters" },
    stdio: ["ignore", "pipe", "pipe", "ipc"]
  });
  let output = "";
  child.stdout.on("data", (data) => { output += data; });
  child.stderr.on("data", (data) => { output += data; });
  const events = [];
  child.on("message", (message) => events.push(message));
  const exited = once(child, "exit");
  t.after(() => { if (child.exitCode === null) child.kill("SIGKILL"); });
  async function waitFor(event) {
    const deadline = Date.now() + 5000;
    while (!events.some((message) => message.event === event)) {
      assert.equal(child.exitCode, null, output);
      assert.ok(Date.now() < deadline, `Missing ${event}: ${output}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    return events.find((message) => message.event === event);
  }
  const { port } = await waitFor("listening");
  return { child, port, events, exited, waitFor, output: () => output };
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  test(`${signal}: drains HTTP, closes pool once despite repeated signals, exits 0`, { timeout: 10000 }, async (t) => {
    const app = await start(t);
    // An incomplete JSON request keeps HTTP active until we finish its body.
    const request = http.request({ host: "127.0.0.1", port: app.port, path: "/login", method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": "2" } });
    t.after(() => request.destroy());
    request.on("error", () => {});
    const response = new Promise((resolve) => request.on("response", (res) => { res.resume(); res.on("end", resolve); }));
    request.write("{");
    await app.waitFor("request");
    app.child.kill(signal);
    await app.waitFor("server-close");
    app.child.kill(signal === "SIGINT" ? "SIGTERM" : "SIGINT");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(app.events.filter((e) => e.event === "pool-end").length, 0);
    // The listener must stop accepting new connections during draining.
    await assert.rejects(new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${app.port}/`, (res) => { res.resume(); resolve(); }).on("error", reject);
    }), { code: "ECONNREFUSED" });
    request.end("}");
    await response;
    await app.waitFor("pool-end");
    app.child.kill(signal);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(app.child.exitCode, null, "must await pool cleanup");
    app.child.send({ action: "resolve-pool" });
    assert.deepEqual(await app.exited, [0, null], app.output());
    assert.equal(app.events.filter((e) => e.event === "server-close").length, 1);
    assert.equal(app.events.filter((e) => e.event === "pool-end").length, 1);
    assert.doesNotMatch(app.output(), /ReferenceError|timeout/);
  });

  test(`${signal}: database cleanup rejection exits 1`, { timeout: 10000 }, async (t) => {
    const app = await start(t);
    app.child.kill(signal);
    await app.waitFor("pool-end");
    app.child.send({ action: "reject-pool" });
    assert.deepEqual(await app.exited, [1, null], app.output());
    assert.match(app.output(), /Error during pool closure:.*test pool failure/);
  });
}

for (const phase of ["HTTP", "database"]) {
  test(`10-second deadline bounds stalled ${phase} cleanup`, { timeout: 15000 }, async (t) => {
    const app = await start(t);
    if (phase === "HTTP") {
      const request = http.request({ host: "127.0.0.1", port: app.port, path: "/login", method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": "2" } });
      request.on("error", () => {});
      t.after(() => request.destroy());
      request.write("{");
      await app.waitFor("request");
    }
    const started = Date.now();
    app.child.kill("SIGTERM");
    await app.waitFor(phase === "HTTP" ? "server-close" : "pool-end");
    app.child.kill("SIGINT");
    assert.deepEqual(await app.exited, [1, null], app.output());
    assert.ok(Date.now() - started >= 9500, "must allow the grace period");
    assert.match(app.output(), /Forcefully shutting down process \(timeout\)/);
    assert.equal(app.events.filter((e) => e.event === "server-close").length, 1);
    assert.equal(app.events.filter((e) => e.event === "pool-end").length, phase === "HTTP" ? 0 : 1);
  });
}
