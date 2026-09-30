import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';

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
const stageMarker = 'WIF_NODE_STAGE_CONTROL_OK';

function resultFacts(stage, result, expectedMarker, nodePathMatchesExecPath) {
  const stdout = result.stdout ?? '';
  const markerPresent = expectedMarker.endsWith('_PROBE')
    ? stdout.split('\n').some(line => line.startsWith(`${expectedMarker} `))
    : stdout.trim() === expectedMarker;
  const facts = {
    stage,
    status: result.status,
    signal: result.signal,
    errorCode: result.error?.code ?? null,
    markerPresent,
    stdoutBytes: Buffer.byteLength(stdout),
    stderrBytes: Buffer.byteLength(result.stderr ?? ''),
  };
  facts.passed = facts.status === 0 && facts.signal == null && facts.errorCode == null &&
    facts.markerPresent && facts.stderrBytes === 0;
  if (nodePathMatchesExecPath != null) {
    facts.nodePathMatchesExecPath = nodePathMatchesExecPath;
    facts.nodePathIsAbsolute = isAbsolute(process.env.PROBE_NODE ?? '');
  }
  process.stdout.write(`WIF_NODE_STAGE ${JSON.stringify(facts)}\n`);
  return facts;
}

function sandboxStage(stage, command, expectedMarker) {
  const realCodex = process.env.PROBE_REAL_CODEX;
  const result = spawnSync(realCodex, [
    'sandbox', '--permission-profile', ':read-only', '--', ...command,
  ], { env: process.env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
  return { result, facts: resultFacts(stage, result, expectedMarker,
    process.env.PROBE_NODE === process.execPath) };
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

const shellMarker = 'WIF_NODE_STAGE_SHELL_OK';
const shellStage = sandboxStage('sandbox-shell', [
  '/bin/sh', '-c', 'printf "%s\\n" "$1"', 'wif-probe', shellMarker,
], shellMarker);
if (!shellStage.facts.passed) {
  process.stderr.write('Sandbox shell marker control failed; later stages skipped.\n');
  process.exit(1);
}
const inlineStage = sandboxStage('sandbox-node-inline', [
  process.env.PROBE_NODE, '-e', `process.stdout.write(${JSON.stringify(stageMarker + '\n')})`,
], stageMarker);
process.stdout.write(`WIF_NODE_DIAGNOSTIC ${JSON.stringify({
  stage: 'sandbox-node-inline',
  passed: inlineStage.facts.passed,
  nodePathMatchesExecPath: inlineStage.facts.nodePathMatchesExecPath,
  nodePathIsAbsolute: inlineStage.facts.nodePathIsAbsolute,
})}\n`);

const shellProbePath = process.env.GITHUB_WORKSPACE + '/probe/linux-isolation/observe-shell.sh';
const shellObservation = sandboxStage('sandbox-shell-observation', [
  '/bin/sh', shellProbePath,
  targets.parentPid, targets.rootPid, targets.rootFile, targets.controlFile, 'shell-sandbox-command',
], 'WIF_SHELL_ISOLATION_PROBE');
const child = shellObservation.result;
const shellLine = (child.stdout ?? '').split('\n').find(line => line.startsWith('WIF_SHELL_ISOLATION_PROBE '));
let shellFacts;
try {
  shellFacts = shellLine ? JSON.parse(shellLine.slice('WIF_SHELL_ISOLATION_PROBE '.length)) : null;
} catch {
  shellFacts = null;
}
const hasBooleanKeys = (value, expectedKeys) => value != null &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expectedKeys].sort()) &&
  Object.values(value).every(entry => typeof entry === 'boolean');
const hasExactKeys = (value, expectedKeys) => value != null &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expectedKeys].sort());
const structurallyValidShellFacts = hasExactKeys(shellFacts, [
  'label', 'processEnv', 'wrapperParentProcEnv', 'rootProcessExists',
  'rootProcessProcEnv', 'rootOwnedFileReadable', 'runnerControlFileReadable',
]) && shellFacts.label === 'shell-sandbox-command' &&
  hasBooleanKeys(shellFacts.processEnv, ['oidcRequestUrl', 'oidcRequestToken', 'subjectToken', 'apiKey', 'apiAccessToken']) &&
  hasBooleanKeys(shellFacts.wrapperParentProcEnv, ['oidcRequestToken', 'subjectToken', 'apiKey', 'apiAccessToken']) &&
  typeof shellFacts.rootProcessExists === 'boolean' &&
  typeof shellFacts.rootProcessProcEnv === 'boolean' &&
  typeof shellFacts.rootOwnedFileReadable === 'boolean' &&
  typeof shellFacts.runnerControlFileReadable === 'boolean';
if (structurallyValidShellFacts) process.stdout.write(`WIF_SHELL_ISOLATION_PROBE ${JSON.stringify(shellFacts)}\n`);
const rootPidVisible = structurallyValidShellFacts && shellFacts.rootProcessExists === true;
const runnerControlReadable = structurallyValidShellFacts && shellFacts.runnerControlFileReadable === true;
const completionReasons = [];
if (!structurallyValidShellFacts) completionReasons.push('receipt_invalid');
if (structurallyValidShellFacts && !rootPidVisible) completionReasons.push('root_pid_not_visible');
if (structurallyValidShellFacts && !runnerControlReadable) completionReasons.push('runner_control_unreadable');
if (!shellObservation.facts.passed) completionReasons.push('sandbox_command_incomplete');
const controlsComplete = structurallyValidShellFacts && rootPidVisible && runnerControlReadable;
process.stdout.write(`WIF_SHELL_ISOLATION_COMPLETION ${JSON.stringify({
  structurallyValid: structurallyValidShellFacts,
  controlsComplete,
  rootPidVisible,
  runnerControlReadable,
  commandStatus: child.status,
  commandSignal: child.signal,
  commandErrorCode: child.error?.code ?? null,
  reasons: completionReasons,
})}\n`);
if (!shellObservation.facts.passed || !structurallyValidShellFacts || !controlsComplete) {
  process.stderr.write('Sandboxed shell probe receipt incomplete; observations fail closed.\n');
  process.exit(child.status != null && child.status !== 0 ? child.status : 1);
}

if (!existsSync(`/proc/${targets.rootPid}`)) {
  process.stderr.write('Root holder ended during probe; process findings incomplete.\n');
  process.exit(1);
}

writeFileSync(outputFile, 'Synthetic Linux isolation probe completed.\n', { mode: 0o600 });
