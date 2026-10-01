import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const mainPath = fileURLToPath(new URL("../dist/main.js", import.meta.url));

function runFakeCodex(mode, timeoutSeconds, targetPath = null) {
  const tempDir = mkdtempSync(path.join(tmpdir(), "codex-action-lifecycle-test-"));
  const runnerTemp = path.join(tempDir, "runner-temp");
  mkdirSync(runnerTemp);
  const fakeCodexPath = path.join(tempDir, "fake-codex.mjs");
  const launcherPath = path.join(tempDir, "codex");
  const outputPath = path.join(tempDir, "output.txt");
  const fakeBody = `import { readdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
const outputIndex = args.indexOf("--output-last-message");
writeFileSync(args[outputIndex + 1], "synthetic final message\\n");
if (${JSON.stringify(mode)} === "replace-trace") {
  const traceName = readdirSync(process.env.RUNNER_TEMP).find((name) => name.startsWith("codex-action-lifecycle-"));
  if (traceName) {
    const tracePath = path.join(process.env.RUNNER_TEMP, traceName);
    unlinkSync(tracePath);
    symlinkSync(process.env.TRACE_TARGET, tracePath);
  }
} else if (${JSON.stringify(mode)} === "timeout") {
  process.on("SIGTERM", () => process.exit(0));
  setInterval(() => {}, 1000);
} else if (${JSON.stringify(mode)} === "ignore-term") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1000);
}
`;
  writeFileSync(fakeCodexPath, fakeBody, "utf8");
  writeFileSync(
    launcherPath,
    `#!/bin/sh\nexec "${process.execPath}" "${fakeCodexPath}" "$@"\n`,
    "utf8"
  );
  chmodSync(launcherPath, 0o755);

  const result = spawnSync(
    process.execPath,
    [
      mainPath,
      "run-codex-exec",
      "--prompt",
      "trace secret prompt",
      "--prompt-file",
      "",
      "--codex-home",
      "",
      "--cd",
      tempDir,
      "--extra-args",
      "",
      "--output-file",
      outputPath,
      "--output-schema-file",
      "",
      "--output-schema",
      "",
      "--sandbox",
      "",
      "--model",
      "trace-secret-model",
      "--effort",
      "",
      "--safety-strategy",
      "unsafe",
      "--codex-user",
      "",
      "--timeout-seconds",
      String(timeoutSeconds),
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: undefined,
        PATH: `${tempDir}${path.delimiter}${process.env.PATH ?? ""}`,
        RUNNER_TEMP: runnerTemp,
        TRACE_TARGET: targetPath ?? undefined,
        TRACE_SECRET_SENTINEL: "trace-secret-environment",
      },
      timeout: 8_000,
      maxBuffer: 1024 * 1024,
    }
  );
  const traceFiles = readdirSync(runnerTemp);
  assert.equal(traceFiles.length, 1, `expected one trace file, got ${traceFiles}`);
  const tracePath = path.join(runnerTemp, traceFiles[0]);
  const traceText = targetPath == null ? readFileSync(tracePath, "utf8") : "";
  const trace = traceText.length
    ? traceText.trim().split("\n").map((line) => JSON.parse(line))
    : [];
  const traceReplacement = targetPath == null
    ? null
    : {
        isSymlink: lstatSync(tracePath).isSymbolicLink(),
        target: readlinkSync(tracePath),
        contents: readFileSync(targetPath, "utf8"),
      };
  rmSync(tempDir, { recursive: true, force: true });
  return { result, trace, traceText, traceReplacement };
}

function assertSafeTrace(trace, traceText) {
  const phases = new Set([
    "run_started",
    "pre_spawn_ready",
    "spawn_requested",
    "spawned",
    "spawn_error",
    "child_error",
    "deadline_armed",
    "deadline_fired",
    "term_attempted",
    "kill_attempted",
    "child_exit",
    "drain_finished",
    "action_returned",
  ]);
  const signals = new Set([
    null,
    "SIGABRT",
    "SIGALRM",
    "SIGBUS",
    "SIGCHLD",
    "SIGCONT",
    "SIGFPE",
    "SIGHUP",
    "SIGILL",
    "SIGINT",
    "SIGIO",
    "SIGKILL",
    "SIGPIPE",
    "SIGPROF",
    "SIGQUIT",
    "SIGSEGV",
    "SIGSTOP",
    "SIGSYS",
    "SIGTERM",
    "SIGTRAP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGUSR1",
    "SIGUSR2",
    "SIGVTALRM",
    "SIGXCPU",
    "SIGXFSZ",
    "other",
  ]);
  for (const item of trace) {
    assert.ok(phases.has(item.phase), `unexpected phase ${item.phase}`);
    assert.ok(Number.isSafeInteger(item.elapsedMs) && item.elapsedMs >= 0);
    assert.deepEqual(
      Object.keys(item).sort(),
      item.phase === "child_exit"
        ? ["elapsedMs", "exitCode", "phase", "signal"]
        : ["elapsedMs", "phase"]
    );
    if (item.phase === "child_exit") {
      assert.ok(item.exitCode === null || Number.isSafeInteger(item.exitCode));
      assert.ok(signals.has(item.signal));
    }
  }
  for (const secret of [
    "trace secret prompt",
    "trace-secret-model",
    "trace-secret-environment",
    process.cwd(),
  ]) {
    assert.equal(traceText.includes(secret), false);
  }
}

function readLiveTrace(stderr) {
  return stderr
    .split("\n")
    .flatMap((line) => {
      try {
        const value = JSON.parse(line);
        return value != null && typeof value === "object" && "phase" in value
          ? [value]
          : [];
      } catch {
        return [];
      }
    });
}

test("built action records a safe trace for a synthetic quick exit", () => {
  const { result, trace, traceText } = runFakeCodex("quick", 5);
  assert.equal(result.status, 0, result.stderr);
  assertSafeTrace(trace, traceText);
  const liveTrace = readLiveTrace(result.stderr);
  assert.deepEqual(liveTrace, trace);
  assertSafeTrace(liveTrace, liveTrace.map((item) => JSON.stringify(item)).join("\n"));
  const phases = trace.map((item) => item.phase);
  assert.ok(phases.indexOf("spawn_requested") < phases.indexOf("spawned"));
  assert.ok(phases.includes("deadline_armed"));
  assert.equal(phases.includes("deadline_fired"), false);
  assert.ok(phases.indexOf("child_exit") < phases.indexOf("drain_finished"));
  assert.equal(phases.at(-1), "action_returned");
  assert.equal(trace.find((item) => item.phase === "child_exit").exitCode, 0);
});

test("built action records its deadline and TERM path for a cooperative synthetic child", () => {
  const { result, trace, traceText } = runFakeCodex("timeout", 1);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Codex execution cancelled: timeout after 1 seconds/);
  assertSafeTrace(trace, traceText);
  const liveTrace = readLiveTrace(result.stderr);
  assert.deepEqual(liveTrace, trace);
  assertSafeTrace(liveTrace, liveTrace.map((item) => JSON.stringify(item)).join("\n"));
  const phases = trace.map((item) => item.phase);
  assert.ok(phases.indexOf("deadline_armed") < phases.indexOf("deadline_fired"));
  assert.ok(phases.indexOf("deadline_fired") < phases.indexOf("term_attempted"));
  assert.ok(phases.includes("child_exit"));
  assert.ok(phases.includes("drain_finished"));
  assert.equal(phases.at(-1), "action_returned");
});

test("built action records KILL and signal outcome for a synthetic TERM-ignoring child", () => {
  const { result, trace, traceText } = runFakeCodex("ignore-term", 1);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Codex execution cancelled: timeout after 1 seconds/);
  assertSafeTrace(trace, traceText);
  const liveTrace = readLiveTrace(result.stderr);
  assert.deepEqual(liveTrace, trace);
  assertSafeTrace(liveTrace, liveTrace.map((item) => JSON.stringify(item)).join("\n"));
  const phases = trace.map((item) => item.phase);
  assert.ok(phases.indexOf("deadline_fired") < phases.indexOf("term_attempted"));
  assert.ok(phases.indexOf("term_attempted") < phases.indexOf("kill_attempted"));
  const childExit = trace.find((item) => item.phase === "child_exit");
  assert.equal(childExit.exitCode, null);
  assert.equal(childExit.signal, "SIGKILL");
  assert.ok(phases.includes("drain_finished"));
  assert.equal(phases.at(-1), "action_returned");
});

test("built action keeps trace writes on the opened file after child replaces its path", {
  skip: process.platform === "win32",
}, () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), "codex-action-trace-target-"));
  const targetPath = path.join(tempDir, "outside-target.txt");
  writeFileSync(targetPath, "target-must-remain-unchanged", "utf8");

  const { result, traceReplacement } = runFakeCodex("replace-trace", 5, targetPath);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(traceReplacement, {
    isSymlink: true,
    target: targetPath,
    contents: "target-must-remain-unchanged",
  });
  rmSync(tempDir, { recursive: true, force: true });
});

test("stderr write failures do not change lifecycle completion or file trace", () => {
  const runnerTemp = mkdtempSync(path.join(tmpdir(), "codex-action-trace-stderr-"));
  const sourceUrl = new URL("../src/lifecycleTrace.ts", import.meta.url).href;
  const result = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--disable-warning=ExperimentalWarning",
      "--input-type=module",
      "-e",
      `import { LifecycleTrace } from ${JSON.stringify(sourceUrl)};
process.stderr.write = () => { throw new Error("closed log"); };
const initialErrorListeners = process.stderr.listenerCount("error");
const trace = new LifecycleTrace();
trace.record("run_started");
process.stderr.write = (_line, callback) => { callback?.(new Error("EPIPE")); return false; };
trace.record("action_returned");
setImmediate(() => {
  if (process.stderr.listenerCount("error") !== initialErrorListeners) process.exitCode = 1;
  console.log("continued");
});`,
    ],
    {
      encoding: "utf8",
      env: { ...process.env, RUNNER_TEMP: runnerTemp },
      timeout: 5_000,
    }
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "continued");
  const traceFiles = readdirSync(runnerTemp);
  assert.equal(traceFiles.length, 1);
  const trace = readFileSync(path.join(runnerTemp, traceFiles[0]), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(trace.map((item) => item.phase), ["run_started", "action_returned"]);
  rmSync(runnerTemp, { recursive: true, force: true });
});

test("a real closed stderr pipe cannot terminate lifecycle completion", { timeout: 5_000 }, async () => {
  const runnerTemp = mkdtempSync(path.join(tmpdir(), "codex-action-trace-epipe-"));
  const sourceUrl = new URL("../src/lifecycleTrace.ts", import.meta.url).href;
  const child = spawn(
    process.execPath,
    [
      "--experimental-strip-types",
      "--disable-warning=ExperimentalWarning",
      "--input-type=module",
      "-e",
      `import { LifecycleTrace } from ${JSON.stringify(sourceUrl)};
const trace = new LifecycleTrace();
process.stdout.write("ready\\n");
process.stdin.once("data", () => {
  trace.record("run_started");
  setTimeout(() => {
    trace.record("action_returned");
    process.stdout.write("continued\\n");
  }, 10);
});`,
    ],
    {
      env: { ...process.env, RUNNER_TEMP: runnerTemp },
      stdio: ["pipe", "pipe", "pipe"],
    }
  );

  let stdout = "";
  let released = false;
  const result = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Timed out waiting for lifecycle subprocess"));
    }, 4_500);
    child.once("error", reject);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (!released && stdout.includes("ready\n")) {
        released = true;
        child.stderr.destroy();
        child.stdin.end("start");
      }
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
  });

  assert.deepEqual(result, { code: 0, signal: null });
  assert.match(stdout, /continued\n/);
  const traceName = readdirSync(runnerTemp).find((name) => name.endsWith(".jsonl"));
  assert.ok(traceName);
  const trace = readFileSync(path.join(runnerTemp, traceName), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(trace.map((item) => item.phase), ["run_started", "action_returned"]);
  rmSync(runnerTemp, { recursive: true, force: true });
});

test("drains high-volume Codex stderr after the workflow log pipe closes", {
  timeout: 10_000,
}, async () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), "codex-action-trace-child-epipe-"));
  const runnerTemp = path.join(tempDir, "runner-temp");
  mkdirSync(runnerTemp);
  const fakeCodexPath = path.join(tempDir, "fake-codex.mjs");
  const launcherPath = path.join(tempDir, "codex");
  const outputPath = path.join(tempDir, "output.txt");
  const triggerPath = path.join(tempDir, "write-stderr-now");
  writeFileSync(
    fakeCodexPath,
    `import { existsSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const outputIndex = args.indexOf("--output-last-message");
writeFileSync(args[outputIndex + 1], "synthetic final message\\n");
process.stdout.write("codex-ready\\n");
const watch = setInterval(() => {
  if (!existsSync(process.env.TRACE_TRIGGER)) return;
  clearInterval(watch);
  const chunk = Buffer.alloc(64 * 1024, "x");
  let written = 0;
  const produce = () => {
    while (written < 128) {
      written += 1;
      if (!process.stderr.write(chunk)) {
        process.stderr.once("drain", produce);
        return;
      }
    }
    process.stdout.write("codex-complete\\n");
    process.exit(0);
  };
  produce();
}, 5);
`,
    "utf8"
  );
  writeFileSync(
    launcherPath,
    `#!/bin/sh\nexec "${process.execPath}" "${fakeCodexPath}" "$@"\n`,
    "utf8"
  );
  chmodSync(launcherPath, 0o755);

  const action = spawn(
    process.execPath,
    [
      mainPath,
      "run-codex-exec",
      "--prompt",
      "trace secret prompt",
      "--prompt-file",
      "",
      "--codex-home",
      "",
      "--cd",
      tempDir,
      "--extra-args",
      "",
      "--output-file",
      outputPath,
      "--output-schema-file",
      "",
      "--output-schema",
      "",
      "--sandbox",
      "",
      "--model",
      "trace-secret-model",
      "--effort",
      "",
      "--safety-strategy",
      "unsafe",
      "--codex-user",
      "",
      "--timeout-seconds",
      "4",
    ],
    {
      env: {
        ...process.env,
        GITHUB_OUTPUT: undefined,
        PATH: `${tempDir}${path.delimiter}${process.env.PATH ?? ""}`,
        RUNNER_TEMP: runnerTemp,
        TRACE_TRIGGER: triggerPath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );

  let stdout = "";
  let sinkClosed = false;
  const result = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      action.kill("SIGKILL");
      reject(new Error("Timed out waiting for the high-volume Codex child"));
    }, 9_000);
    action.once("error", reject);
    action.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (!sinkClosed && stdout.includes("codex-ready\n")) {
        sinkClosed = true;
        action.stderr.destroy();
        writeFileSync(triggerPath, "go", "utf8");
      }
    });
    action.once("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
  });

  assert.equal(sinkClosed, true);
  assert.deepEqual(result, { code: 0, signal: null });
  assert.match(stdout, /codex-complete\n/);
  assert.equal(readFileSync(outputPath, "utf8"), "synthetic final message\n");
  rmSync(tempDir, { recursive: true, force: true });
});
