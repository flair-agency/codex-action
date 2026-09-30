import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';

const canaries = {
  ACTIONS_ID_TOKEN_REQUEST_URL: 'http://127.0.0.1:9/mock-oidc?audience=synthetic-probe',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-github-oidc-request-token-canary',
  SYNTHETIC_GITHUB_OIDC_SUBJECT_TOKEN: 'eyJ.synthetic-github-subject-token.signature',
  OPENAI_API_KEY: 'sk-proj-synthetic-openai-api-key-canary',
  SYNTHETIC_OPENAI_API_ACCESS_TOKEN: 'eyJ.synthetic-openai-api-token.signature',
};
const rootFileCanary = 'synthetic-root-owned-subject-token-file-canary';
const rootProcCanary = 'synthetic-root-process-oidc-token-canary';
const runnerFileCanary = 'synthetic-runner-control-file-canary';
const sandboxEchoMarker = 'WIF_SANDBOX_ECHO_CONTROL_OK';

function sandboxEchoControl(stage) {
  const realCodex = process.env.PROBE_REAL_CODEX;
  if (!realCodex) {
    process.stdout.write(`WIF_SANDBOX_ECHO ${JSON.stringify({ stage, errorCode: 'MISSING_CLI_PATH' })}\n`);
    return false;
  }
  const result = spawnSync(realCodex, [
    'sandbox', '--permission-profile', ':read-only', '--', '/bin/echo', sandboxEchoMarker,
  ], { env: process.env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  const facts = {
    stage,
    status: result.status,
    signal: result.signal,
    errorCode: result.error?.code ?? null,
    markerPresent: result.stdout?.trim() === sandboxEchoMarker,
    stdoutBytes: Buffer.byteLength(result.stdout ?? ''),
    stderrBytes: Buffer.byteLength(result.stderr ?? ''),
  };
  process.stdout.write(`WIF_SANDBOX_ECHO ${JSON.stringify(facts)}\n`);
  return facts.status === 0 && facts.signal == null && facts.errorCode == null &&
    facts.markerPresent && facts.stderrBytes === 0;
}

function procContains(pid, value) {
  if (!pid || !value) return false;
  try {
    return readFileSync(`/proc/${pid}/environ`).includes(Buffer.from(value));
  } catch {
    return false;
  }
}

function fileEquals(file, expected) {
  try {
    return readFileSync(file, 'utf8') === expected;
  } catch {
    return false;
  }
}

function inspect(label, targets) {
  const processEnv = Object.fromEntries(Object.entries(canaries).map(([name, expected]) => [
    name,
    process.env[name] === expected,
  ]));
  const { parentPid, rootPid, rootFile, controlFile } = targets;
  const facts = {
    label,
    processEnv,
    wrapperParentProcEnv: {
      oidcRequestToken: procContains(parentPid, canaries.ACTIONS_ID_TOKEN_REQUEST_TOKEN),
      subjectToken: procContains(parentPid, canaries.SYNTHETIC_GITHUB_OIDC_SUBJECT_TOKEN),
      apiKey: procContains(parentPid, canaries.OPENAI_API_KEY),
      apiAccessToken: procContains(parentPid, canaries.SYNTHETIC_OPENAI_API_ACCESS_TOKEN),
    },
    rootProcessExists: existsSync(`/proc/${rootPid}`),
    rootProcessProcEnv: procContains(rootPid, rootProcCanary),
    rootOwnedFileReadable: fileEquals(rootFile, rootFileCanary),
    runnerControlFileReadable: fileEquals(controlFile, runnerFileCanary),
  };
  process.stdout.write(`WIF_ISOLATION_PROBE ${JSON.stringify(facts)}\n`);
  return facts;
}

const [mode, ...args] = process.argv.slice(2);
if (mode === 'verify-controls') {
  const [rootPid, rootFile, controlFile] = args;
  const stats = statSync(rootFile);
  const valid = process.getuid?.() === 0 && stats.uid === 0 &&
    (stats.mode & 0o777) === 0o600 && fileEquals(rootFile, rootFileCanary) &&
    fileEquals(controlFile, runnerFileCanary) && procContains(rootPid, rootProcCanary);
  process.stdout.write(`WIF_ISOLATION_CONTROLS ${JSON.stringify({ valid })}\n`);
  process.exit(valid ? 0 : 1);
}

if (mode === 'echo-control') {
  sandboxEchoControl(args[0] ?? 'direct');
  process.exit(0);
}

if (mode === 'tool') {
  // Paths and PIDs are explicit arguments: environment filtering is measured,
  // and must not erase the observation targets themselves.
  const facts = inspect('codex-sandbox-command', JSON.parse(args[0]));
  // A PID namespace may hide the host holder; that is a visibility finding,
  // not evidence that host /proc permissions denied access.
  if (!facts.runnerControlFileReadable) {
    process.stderr.write('Probe controls unavailable; observations are incomplete.\n');
    process.exit(1);
  }
  // Allow the pipe to drain before exiting this short-lived command.
  await new Promise(resolve => process.stdout.write('', resolve));
  process.exit(0);
}

if (mode !== 'shim') {
  process.stderr.write('Expected probe mode.\n');
  process.exit(2);
}

const targets = {
  parentPid: process.env.PROBE_WRAPPER_PARENT_PID,
  rootPid: process.env.PROBE_ROOT_PID,
  rootFile: process.env.PROBE_ROOT_FILE,
  controlFile: process.env.PROBE_CONTROL_FILE,
};
if (process.platform !== 'linux' || Object.values(targets).some(value => !value)) {
  process.stderr.write('Disposable Linux probe targets are required.\n');
  process.exit(2);
}
const wrapperFacts = inspect('action-runner-child', targets);
if (!wrapperFacts.rootProcessExists || !wrapperFacts.runnerControlFileReadable) {
  process.stderr.write('Probe controls unavailable; observations are incomplete.\n');
  process.exit(1);
}

const outputIndex = args.indexOf('--output-last-message');
const outputFile = outputIndex >= 0 ? args[outputIndex + 1] : null;
if (!outputFile) {
  process.stderr.write('Action did not provide an output-last-message path.\n');
  process.exit(2);
}

const realCodex = process.env.PROBE_REAL_CODEX;
if (!realCodex) {
  process.stderr.write('Exact Codex CLI path was not recorded.\n');
  process.exit(2);
}

const version = spawnSync(realCodex, ['--version'], { env: process.env, encoding: 'utf8', timeout: 10_000 });
const exactVersion = version.status === 0 && version.stdout.trim() === 'codex-cli 0.159.2';
process.stdout.write(`WIF_ISOLATION_CLI ${JSON.stringify({ exactVersion })}\n`);
if (!exactVersion) process.exit(1);

if (!sandboxEchoControl('action-child')) {
  process.stderr.write('Sandbox echo control failed; actual probe skipped.\n');
  process.exit(1);
}

const child = spawnSync(realCodex, [
  'sandbox',
  '--permission-profile',
  ':read-only',
  '--',
  process.execPath,
  process.env.GITHUB_WORKSPACE + '/probe/linux-isolation/probe.mjs',
  'tool',
  JSON.stringify(targets),
], { env: process.env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 20_000 });
if (child.error) {
  process.stderr.write(`Codex sandbox command failed to start (${child.error.code ?? 'unknown'}).\n`);
  process.exit(1);
}
if (child.signal || child.status !== 0) {
  process.stderr.write(`Codex sandbox command failed (status=${child.status ?? 'none'}, signal=${child.signal ?? 'none'}).\n`);
  process.exit(child.status ?? 1);
}

const sandboxLine = child.stdout.split('\n').find(line => line.startsWith('WIF_ISOLATION_PROBE '));
if (!sandboxLine) {
  process.stderr.write(`WIF_ISOLATION_CAPTURE ${JSON.stringify({ stdoutPresent: Boolean(child.stdout), stderrPresent: Boolean(child.stderr), stderrMentionsSandbox: /sandbox/i.test(child.stderr), stderrMentionsPermission: /permission|denied/i.test(child.stderr) })}\n`);
  process.stderr.write('Real sandbox returned no probe record; observations incomplete.\n');
  process.exit(1);
}
const sandboxFacts = JSON.parse(sandboxLine.slice('WIF_ISOLATION_PROBE '.length));
if (sandboxFacts.label !== 'codex-sandbox-command') {
  process.stderr.write('Unexpected sandbox record.\n');
  process.exit(1);
}
process.stdout.write(`WIF_ISOLATION_PROBE ${JSON.stringify(sandboxFacts)}\n`);

if (!existsSync(`/proc/${targets.rootPid}`)) {
  process.stderr.write('Root holder ended during probe; process findings incomplete.\n');
  process.exit(1);
}

writeFileSync(outputFile, 'Synthetic Linux isolation probe completed.\n', { mode: 0o600 });
