import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, statSync, chmodSync, renameSync } from 'node:fs';
import { basename, dirname, isAbsolute } from 'node:path';

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
const sameUidHolderEnvName = 'SYNTHETIC_SAME_UID_AUTH_HOLDER';
const sameUidHolderCanary = 'synthetic-same-uid-auth-holder-canary';
const sameUidHolderFileCanary = 'synthetic-same-uid-holder-file-canary';
const rootRequestMarker = 'synthetic-root-postcheck-request-v1';
const rootAckMarker = 'synthetic-root-postcheck-ack-v1';
const stageMarker = 'WIF_NODE_STAGE_CONTROL_OK';

function parseProcStat(statText, expectedPid) {
  const open = statText.indexOf('(');
  const close = statText.lastIndexOf(')');
  if (open < 1 || close <= open || statText.slice(0, open).trim() !== String(expectedPid)) return null;
  const fields = statText.slice(close + 1).trim().split(/\s+/);
  const state = fields[0];
  const startTime = fields[19];
  if (!/^[A-Za-z]$/.test(state ?? '') || !/^\d+$/.test(startTime ?? '')) return null;
  return { state, startTime, alive: !['Z', 'X', 'x'].includes(state) };
}

function readProcStat(pid) {
  try {
    return parseProcStat(readFileSync(`/proc/${pid}/stat`, 'utf8'), pid);
  } catch {
    return null;
  }
}

function readProcUids(pid) {
  try {
    const line = readFileSync(`/proc/${pid}/status`, 'utf8').split('\n').find(value => value.startsWith('Uid:'));
    const values = line?.slice(4).trim().split(/\s+/).map(Number);
    return values?.length === 4 && values.every(Number.isInteger) ? values : null;
  } catch {
    return null;
  }
}

function statFixture(pid, command, state, startTime) {
  return `${pid} (${command}) ${[state, ...Array(18).fill('0'), String(startTime)].join(' ')}`;
}

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

function sandboxStage(stage, command, expectedMarker, childEnv = process.env) {
  const realCodex = process.env.PROBE_REAL_CODEX;
  const result = spawnSync(realCodex, [
    'sandbox', '--permission-profile', ':read-only', '--', ...command,
  ], { env: childEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
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

function rootFileFacts(file, initialStats = null) {
  let stats = null;
  try { stats = statSync(file); } catch {}
  return {
    pathExists: existsSync(file),
    metadataReadable: stats !== null,
    ownerIsRoot: stats !== null && stats.uid === 0,
    mode0600: stats !== null && (stats.mode & 0o777) === 0o600,
    contentMatches: fileEquals(file, rootFileCanary),
    identityMatches: initialStats !== null && stats !== null &&
      stats.dev === initialStats.dev && stats.ino === initialStats.ino,
  };
}

function writeBooleanReceipt(file, facts) {
  if (Object.values(facts).some(value => typeof value !== 'boolean')) {
    throw new Error('Invalid synthetic receipt.');
  }
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(facts)}\n`, { mode: 0o600, flag: 'wx' });
  chmodSync(temporary, 0o644);
  renameSync(temporary, file);
}

function readBooleanReceipt(file, expectedKeys) {
  try {
    const value = JSON.parse(readFileSync(file, 'utf8'));
    const keys = Object.keys(value).sort();
    if (JSON.stringify(keys) !== JSON.stringify([...expectedKeys].sort()) ||
        Object.values(value).some(item => typeof item !== 'boolean')) return null;
    const stats = statSync(file);
    return { value, ownerIsRoot: stats.uid === 0, mode0644: (stats.mode & 0o777) === 0o644 };
  } catch {
    return null;
  }
}

const rootReadyKeys = [
  'helperIsRoot', 'helperAlive', 'procCanaryPresent', 'procEnvironmentCanaryPresent', 'filePathExists',
  'fileMetadataReadable', 'fileOwnerIsRoot', 'fileMode0600', 'fileContentMatches', 'valid',
];
const rootPostKeys = [
  'helperIsRoot', 'requestMarkerValid', 'filePathExists', 'fileMetadataReadable',
  'fileOwnerIsRoot', 'fileMode0600', 'fileContentMatches', 'fileIdentityMatches', 'valid',
];

async function runRootHolder(args) {
  const [rootFile, readyFile, requestFile, receiptFile, ackFile, pidFile, startFile] = args;
  const names = [basename(rootFile ?? ''), basename(readyFile ?? ''), basename(requestFile ?? ''),
    basename(receiptFile ?? ''), basename(ackFile ?? ''), basename(pidFile ?? ''), basename(startFile ?? '')];
  const expectedNames = ['wif-root-owned-canary', 'wif-root-ready.json', 'wif-root-post-request',
    'wif-root-post-receipt.json', 'wif-root-post-ack', 'wif-root-process.pid',
    'wif-root-process-starttime'];
  const allPathsFixed = args.length === 7 && args.every(isAbsolute) &&
    JSON.stringify(names) === JSON.stringify(expectedNames) && args.every(file => dirname(file) === dirname(rootFile));
  if (!allPathsFixed || process.env.NODE_OPTIONS) process.exit(2);

  let initialStats = null;
  try { initialStats = statSync(rootFile); } catch {}
  const identity = readProcStat(process.pid);
  const preFile = rootFileFacts(rootFile);
  const helperIsRoot = process.getuid?.() === 0;
  const readyFacts = {
    helperIsRoot,
    helperAlive: identity?.alive === true,
    procCanaryPresent: process.env.PROBE_ROOT_PROC_CANARY === rootProcCanary,
    procEnvironmentCanaryPresent: procContains(process.pid, `PROBE_ROOT_PROC_CANARY=${rootProcCanary}`),
    filePathExists: preFile.pathExists,
    fileMetadataReadable: preFile.metadataReadable,
    fileOwnerIsRoot: preFile.ownerIsRoot,
    fileMode0600: preFile.mode0600,
    fileContentMatches: preFile.contentMatches,
    valid: false,
  };
  readyFacts.valid = Object.entries(readyFacts).every(([key, value]) => key === 'valid' || value === true);
  writeFileSync(pidFile, `${process.pid}\n`, { mode: 0o600 });
  if (identity?.alive) writeFileSync(startFile, `${identity.startTime}\n`, { mode: 0o600 });
  writeBooleanReceipt(readyFile, readyFacts);
  process.stdout.write(`WIF_ROOT_HOLDER_READY ${JSON.stringify(readyFacts)}\n`);
  if (!readyFacts.valid || !initialStats || !identity?.alive) process.exit(1);

  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline && !fileEquals(requestFile, rootRequestMarker)) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const requestMarkerValid = fileEquals(requestFile, rootRequestMarker);
  const postFile = rootFileFacts(rootFile, initialStats);
  const postFacts = {
    helperIsRoot: process.getuid?.() === 0,
    requestMarkerValid,
    filePathExists: postFile.pathExists,
    fileMetadataReadable: postFile.metadataReadable,
    fileOwnerIsRoot: postFile.ownerIsRoot,
    fileMode0600: postFile.mode0600,
    fileContentMatches: postFile.contentMatches,
    fileIdentityMatches: postFile.identityMatches,
    valid: false,
  };
  postFacts.valid = Object.entries(postFacts).every(([key, value]) => key === 'valid' || value === true);
  writeBooleanReceipt(receiptFile, postFacts);
  process.stdout.write(`WIF_ROOT_HOLDER_POST ${JSON.stringify(postFacts)}\n`);

  while (Date.now() < deadline && !fileEquals(ackFile, rootAckMarker)) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  process.exit(fileEquals(ackFile, rootAckMarker) ? 0 : 1);
}

function inspect(label, targets) {
  const processEnv = Object.fromEntries(Object.entries(canaries).map(([name, expected]) => [
    name,
    process.env[name] === expected,
  ]));
  const { parentPid, rootPid, rootFile, controlFile } = targets;
  const sameUid = targets.sameUidHolderPid;
  const holderUids = readProcUids(sameUid);
  const effectiveUid = process.geteuid?.() ?? process.getuid?.();
  const rootPathFacts = rootFileFacts(targets.rootFile);
  let sameUidFileStats;
  try {
    sameUidFileStats = statSync(targets.sameUidHolderFile);
  } catch {
    sameUidFileStats = null;
  }
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
    rootFilePathExists: rootPathFacts.pathExists,
    rootFileMetadataReadable: rootPathFacts.metadataReadable,
    rootFileOwnerIsRoot: rootPathFacts.ownerIsRoot,
    rootFileMode0600: rootPathFacts.mode0600,
    rootOwnedFileReadable: rootPathFacts.contentMatches,
    runnerControlFileReadable: fileEquals(controlFile, runnerFileCanary),
    sameUidHolder: {
      pidVisible: existsSync(`/proc/${sameUid}`),
      authEnvReadable: procContains(sameUid, `${sameUidHolderEnvName}=${sameUidHolderCanary}`),
      uidMatchesProcess: Number.isInteger(effectiveUid) && holderUids?.[1] === effectiveUid,
      fileReadable: fileEquals(targets.sameUidHolderFile, sameUidHolderFileCanary),
      fileMode0600: sameUidFileStats != null && (sameUidFileStats.mode & 0o777) === 0o600,
      fileOwnerMatchesProcess: Number.isInteger(effectiveUid) && sameUidFileStats?.uid === effectiveUid,
    },
  };
  process.stdout.write(`WIF_ISOLATION_PROBE ${JSON.stringify(facts)}\n`);
  return facts;
}

const [mode, ...args] = process.argv.slice(2);
if (mode === 'test-proc-stat-parser') {
  const normal = parseProcStat(statFixture(321, 'holder with spaces (and parens)', 'S', 98765), 321);
  const zombie = parseProcStat(statFixture(322, 'holder (zombie)', 'Z', 98766), 322);
  const dead = parseProcStat(statFixture(323, 'holder (dead)', 'X', 98767), 323);
  const wrongPid = parseProcStat(statFixture(324, 'holder', 'S', 98768), 325);
  const valid = normal?.state === 'S' && normal.startTime === '98765' && normal.alive &&
    zombie?.state === 'Z' && !zombie.alive && dead?.state === 'X' && !dead.alive && wrongPid == null;
  process.stdout.write(`WIF_PROC_STAT_FIXTURES ${JSON.stringify({ valid })}\n`);
  process.exit(valid ? 0 : 1);
}

if (mode === 'root-holder') {
  await runRootHolder(args);
}

if (mode === 'verify-root-ready') {
  const [readyFile] = args;
  const receipt = readBooleanReceipt(readyFile, rootReadyKeys);
  const receiptValid = receipt !== null;
  const receiptOwnerIsRoot = receipt?.ownerIsRoot === true;
  const receiptMode0644 = receipt?.mode0644 === true;
  const controlsPositive = receiptValid && Object.values(receipt.value).every(Boolean);
  const valid = receiptValid && receiptOwnerIsRoot && receiptMode0644 && controlsPositive;
  process.stdout.write(`WIF_ROOT_READY_CHECK ${JSON.stringify({ receiptValid, receiptOwnerIsRoot, receiptMode0644, controlsPositive, valid })}\n`);
  process.exit(valid ? 0 : 1);
}

if (mode === 'verify-root-post') {
  const [rootPid, expectedStartTime, rootFile, receiptFile, ackFile] = args;
  const receipt = readBooleanReceipt(receiptFile, rootPostKeys);
  const receiptValid = receipt !== null;
  const receiptOwnerIsRoot = receipt?.ownerIsRoot === true;
  const receiptMode0644 = receipt?.mode0644 === true;
  const identity = readProcStat(rootPid);
  const holderIdentityReadable = identity !== null;
  const holderAlive = holderIdentityReadable && identity.alive === true;
  const holderIdentityMatches = holderAlive && identity.startTime === expectedStartTime;
  const runnerFile = rootFileFacts(rootFile);
  const ackWritten = Boolean(receiptValid && receiptOwnerIsRoot && receiptMode0644 &&
    receipt.value.requestMarkerValid && receipt.value.helperIsRoot && holderIdentityMatches);
  if (ackWritten) writeFileSync(ackFile, rootAckMarker, { mode: 0o600 });
  const receiptControlsPositive = receiptValid && Object.values(receipt.value).every(Boolean);
  const rootFilePathExists = runnerFile.pathExists;
  const rootFileMetadataReadable = runnerFile.metadataReadable;
  const rootFileOwnerIsRoot = runnerFile.ownerIsRoot;
  const rootFileMode0600 = runnerFile.mode0600;
  const rootFileContentReadable = runnerFile.contentMatches;
  const valid = ackWritten && receiptControlsPositive;
  process.stdout.write(`WIF_ROOT_POST_CHECK ${JSON.stringify({
    receiptValid, receiptOwnerIsRoot, receiptMode0644, receiptControlsPositive,
    holderIdentityReadable, holderAlive, holderIdentityMatches, ackWritten,
    rootFilePathExists, rootFileMetadataReadable, rootFileOwnerIsRoot, rootFileMode0600,
    rootFileContentReadable, valid,
  })}\n`);
  process.exit(valid ? 0 : 1);
}

if (mode === 'verify-controls') {
  const [rootPid, rootFile, controlFile, startTimeFile] = args;
  const stats = statSync(rootFile);
  const rootIdentity = readProcStat(rootPid);
  const valid = process.getuid?.() === 0 && stats.uid === 0 &&
    (stats.mode & 0o777) === 0o600 && fileEquals(rootFile, rootFileCanary) &&
    fileEquals(controlFile, runnerFileCanary) && procContains(rootPid, rootProcCanary) && Boolean(rootIdentity?.alive);
  if (valid) writeFileSync(startTimeFile, `${rootIdentity.startTime}\n`, { mode: 0o600 });
  process.stdout.write(`WIF_ISOLATION_CONTROLS ${JSON.stringify({ valid, rootHolderAliveBefore: rootIdentity?.alive === true })}\n`);
  process.exit(valid ? 0 : 1);
}

if (mode === 'verify-sameuid') {
  const [holderPid, holderFile, startTimeFile, runnerControlFile] = args;
  const identity = readProcStat(holderPid);
  const uids = readProcUids(holderPid);
  const stats = statSync(holderFile);
  const effectiveUid = process.geteuid?.() ?? process.getuid?.();
  const holderUidMatchesRunner = Number.isInteger(effectiveUid) &&
    uids?.[0] === effectiveUid && uids?.[1] === effectiveUid &&
    uids?.[2] === effectiveUid && uids?.[3] === effectiveUid;
  const fileOwnerMatchesRunner = Number.isInteger(effectiveUid) && stats.uid === effectiveUid;
  const fileMode0600 = (stats.mode & 0o777) === 0o600;
  const holderFileReadableBefore = fileEquals(holderFile, sameUidHolderFileCanary);
  const runnerControlReadableBefore = fileEquals(runnerControlFile, runnerFileCanary);
  const holderCanaryReadableBefore = procContains(holderPid, `${sameUidHolderEnvName}=${sameUidHolderCanary}`);
  const holderAliveBefore = identity?.alive === true;
  const valid = holderAliveBefore && holderUidMatchesRunner && fileOwnerMatchesRunner &&
    fileMode0600 && holderFileReadableBefore && runnerControlReadableBefore && holderCanaryReadableBefore;
  if (valid) writeFileSync(startTimeFile, `${identity.startTime}\n`, { mode: 0o600 });
  process.stdout.write(`WIF_SAME_UID_CONTROLS ${JSON.stringify({
    valid: Boolean(valid), holderAliveBefore, holderUidMatchesRunner, fileOwnerMatchesRunner,
    fileMode0600, holderFileReadableBefore, runnerControlReadableBefore, holderCanaryReadableBefore,
  })}\n`);
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
  sameUidHolderPid: process.env.PROBE_SAME_UID_HOLDER_PID,
  sameUidHolderFile: process.env.PROBE_SAME_UID_HOLDER_FILE,
};
if (process.platform !== 'linux' || Object.values(targets).some(value => !value) ||
    !process.env.PROBE_SAME_UID_EXPECTED_UID || !process.env.PROBE_SAME_UID_HOLDER_STARTTIME ||
    process.env.PROBE_SAME_UID_PREFLIGHT_VALID !== 'true') {
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
const scrubbedEnv = { ...process.env };
for (const name of Object.keys(canaries)) delete scrubbedEnv[name];
const hasBooleanKeys = (value, expectedKeys) => value != null &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expectedKeys].sort()) &&
  Object.values(value).every(entry => typeof entry === 'boolean');
const hasExactKeys = (value, expectedKeys) => value != null &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expectedKeys].sort());
const processEnvKeys = ['oidcRequestUrl', 'oidcRequestToken', 'subjectToken', 'apiKey', 'apiAccessToken'];
const receiptKeys = [
  'label', 'processEnv', 'wrapperParentProcEnv', 'rootProcessExists',
  'rootProcessProcEnv', 'rootFilePathExists', 'rootFileMetadataReadable', 'rootFileOwnerIsRoot',
  'rootFileMode0600', 'rootOwnedFileReadable', 'runnerControlFileReadable', 'sameUidHolder',
];
const sameUidHolderKeys = [
  'pidVisible', 'authEnvReadable', 'uidMatchesProcess', 'fileReadable', 'fileMode0600', 'fileOwnerMatchesProcess',
];
function parseShellReceipt(result, expectedLabel) {
  const line = (result.stdout ?? '').split('\n').find(value => value.startsWith('WIF_SHELL_ISOLATION_PROBE '));
  let facts;
  try {
    facts = line ? JSON.parse(line.slice('WIF_SHELL_ISOLATION_PROBE '.length)) : null;
  } catch {
    facts = null;
  }
  const valid = hasExactKeys(facts, receiptKeys) && facts.label === expectedLabel &&
    hasBooleanKeys(facts.processEnv, processEnvKeys) &&
    hasBooleanKeys(facts.wrapperParentProcEnv, ['oidcRequestToken', 'subjectToken', 'apiKey', 'apiAccessToken']) &&
    typeof facts.rootProcessExists === 'boolean' &&
    typeof facts.rootProcessProcEnv === 'boolean' &&
    typeof facts.rootFilePathExists === 'boolean' &&
    typeof facts.rootFileMetadataReadable === 'boolean' &&
    typeof facts.rootFileOwnerIsRoot === 'boolean' &&
    typeof facts.rootFileMode0600 === 'boolean' &&
    typeof facts.rootOwnedFileReadable === 'boolean' &&
    typeof facts.runnerControlFileReadable === 'boolean' &&
    hasBooleanKeys(facts.sameUidHolder, sameUidHolderKeys);
  if (valid) process.stdout.write(`WIF_SHELL_ISOLATION_PROBE ${JSON.stringify(facts)}\n`);
  return { facts, valid };
}

const shellCases = [];
for (const [caseName, childEnv] of [['inherited', process.env], ['scrubbed', scrubbedEnv]]) {
  const label = `shell-sandbox-${caseName}`;
  const observation = sandboxStage(`sandbox-shell-observation-${caseName}`, [
    '/bin/sh', shellProbePath,
    targets.parentPid, targets.rootPid, targets.rootFile, targets.controlFile, label,
    targets.sameUidHolderPid, targets.sameUidHolderFile, process.env.PROBE_SAME_UID_EXPECTED_UID,
  ], 'WIF_SHELL_ISOLATION_PROBE', childEnv);
  const receipt = parseShellReceipt(observation.result, label);
  shellCases.push({ caseName, observation, ...receipt });
}
const inheritedCase = shellCases.find(item => item.caseName === 'inherited');
const scrubbedCase = shellCases.find(item => item.caseName === 'scrubbed');
const inheritedCanariesPresent = inheritedCase.valid &&
  Object.values(inheritedCase.facts.processEnv).every(Boolean);
const scrubbedCanariesAbsent = scrubbedCase.valid &&
  Object.values(scrubbedCase.facts.processEnv).every(value => !value);
const receiptsValid = shellCases.every(item => item.valid);
const rootPidVisible = receiptsValid && shellCases.every(item => item.facts.rootProcessExists);
const rootIdentityAfter = readProcStat(targets.rootPid);
const rootHolderAliveAfter = rootIdentityAfter?.alive === true;
const rootHolderIdentityMatchesAfter = rootHolderAliveAfter &&
  rootIdentityAfter.startTime === process.env.PROBE_ROOT_STARTTIME;
const runnerControlReadable = receiptsValid && shellCases.every(item => item.facts.runnerControlFileReadable);
const shellCommandsPassed = shellCases.every(item => item.observation.facts.passed);
const sameUidIdentityAfter = readProcStat(targets.sameUidHolderPid);
const sameUidHolderIdentityReadableAfter = sameUidIdentityAfter !== null;
const sameUidHolderAliveAfter = sameUidHolderIdentityReadableAfter && sameUidIdentityAfter.alive === true;
const sameUidHolderIdentityMatchesAfter = sameUidHolderAliveAfter &&
  sameUidIdentityAfter.startTime === process.env.PROBE_SAME_UID_HOLDER_STARTTIME;
const sameUidUidsAfter = readProcUids(targets.sameUidHolderPid);
const sameUidHolderUidsReadableAfter = sameUidUidsAfter !== null;
const sameUidExpectedUid = Number(process.env.PROBE_SAME_UID_EXPECTED_UID);
const actionEffectiveUid = process.geteuid?.() ?? process.getuid?.();
const sameUidHolderUidMatchesActionChild = Boolean(Number.isInteger(actionEffectiveUid) &&
  actionEffectiveUid === sameUidExpectedUid && sameUidUidsAfter?.every(uid => uid === sameUidExpectedUid));
let sameUidHolderFileStats;
try {
  sameUidHolderFileStats = statSync(targets.sameUidHolderFile);
} catch {
  sameUidHolderFileStats = null;
}
const sameUidHolderFileMode0600After = sameUidHolderFileStats != null &&
  (sameUidHolderFileStats.mode & 0o777) === 0o600;
const sameUidHolderFileOwnerMatchesActionChild = sameUidHolderFileStats?.uid === actionEffectiveUid &&
  sameUidHolderFileStats?.uid === sameUidExpectedUid;
const sameUidHolderFileReadableByActionChild = fileEquals(targets.sameUidHolderFile, sameUidHolderFileCanary);
const sameUidHolderAuthEnvReadableByActionChild = procContains(
  targets.sameUidHolderPid, `${sameUidHolderEnvName}=${sameUidHolderCanary}`,
);
const sameUidControlValidBefore = process.env.PROBE_SAME_UID_PREFLIGHT_VALID === 'true';
const sameUidRunnerControlReadable = receiptsValid && shellCases.every(item => item.facts.runnerControlFileReadable);
const sameUidHolderObservationComplete = sameUidControlValidBefore && sameUidHolderIdentityMatchesAfter &&
  sameUidHolderUidMatchesActionChild && sameUidHolderFileMode0600After &&
  sameUidHolderFileOwnerMatchesActionChild && sameUidRunnerControlReadable;
const completionReasons = [];
if (!receiptsValid) completionReasons.push('receipt_invalid');
if (receiptsValid && !rootPidVisible) completionReasons.push('root_pid_not_visible');
if (!rootHolderAliveAfter) completionReasons.push('root_holder_ended');
if (!rootHolderIdentityMatchesAfter) completionReasons.push('root_holder_identity_changed');
if (receiptsValid && !runnerControlReadable) completionReasons.push('runner_control_unreadable');
if (!inheritedCanariesPresent) completionReasons.push('inherited_canaries_missing');
if (!scrubbedCanariesAbsent) completionReasons.push('scrubbed_canaries_visible');
if (!shellCommandsPassed) completionReasons.push('sandbox_command_incomplete');
if (!sameUidControlValidBefore) completionReasons.push('same_uid_preflight_incomplete');
if (!sameUidHolderIdentityReadableAfter) completionReasons.push('same_uid_holder_identity_unreadable');
else if (!sameUidHolderAliveAfter) completionReasons.push('same_uid_holder_ended');
else if (!sameUidHolderIdentityMatchesAfter) completionReasons.push('same_uid_holder_identity_changed');
if (!sameUidHolderUidsReadableAfter) completionReasons.push('same_uid_holder_uids_unreadable');
else if (!sameUidHolderUidMatchesActionChild) completionReasons.push('same_uid_holder_uid_mismatch');
if (!sameUidHolderFileMode0600After || !sameUidHolderFileOwnerMatchesActionChild) completionReasons.push('same_uid_file_control_changed');
const controlsComplete = receiptsValid && rootPidVisible && rootHolderAliveAfter &&
  rootHolderIdentityMatchesAfter && runnerControlReadable &&
  inheritedCanariesPresent && scrubbedCanariesAbsent && shellCommandsPassed && sameUidHolderObservationComplete;
process.stdout.write(`WIF_SHELL_ISOLATION_COMPLETION ${JSON.stringify({
  structurallyValid: receiptsValid,
  controlsComplete,
  inheritedCanariesPresent,
  scrubbedCanariesAbsent,
  rootPidVisible,
  rootHolderAliveAfter,
  rootHolderIdentityMatchesAfter,
  runnerControlReadable,
  inheritedCommandStatus: inheritedCase.observation.result.status,
  scrubbedCommandStatus: scrubbedCase.observation.result.status,
  sameUidControlValidBefore,
  sameUidHolderIdentityReadableAfter,
  sameUidHolderAliveAfter,
  sameUidHolderIdentityMatchesAfter,
  sameUidHolderUidsReadableAfter,
  sameUidHolderUidMatchesActionChild,
  sameUidHolderFileMode0600After,
  sameUidHolderFileOwnerMatchesActionChild,
  sameUidHolderFileReadableByActionChild,
  sameUidHolderAuthEnvReadableByActionChild,
  sameUidHolderObservationComplete,
  reasons: completionReasons,
})}\n`);
if (!controlsComplete) {
  process.stderr.write('Sandboxed shell comparison incomplete; observations fail closed.\n');
  const failedStatus = shellCases.find(item => item.observation.result.status != null && item.observation.result.status !== 0)?.observation.result.status;
  process.exit(failedStatus ?? 1);
}

writeFileSync(outputFile, 'Synthetic Linux isolation probe completed.\n', { mode: 0o600 });
