import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { relative, resolve } from 'node:path';

const argumentsList = process.argv.slice(2);
const development = argumentsList.includes('--development');
const packageJson = readJson('package.json', 'package.json');
const version = packageJson.version;

if (!/^\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error(`Invalid version: ${version}`);
}

const releaseNotesPath = `docs/releases/v${version}.md`;
const evidenceTemplatePath = `docs/releases/v${version}-evidence.example.json`;
const defaultEvidencePath = `.github/release-evidence/v${version}.json`;
for (const file of [
  'pnpm-lock.yaml',
  'apps/desktop/src-tauri/Cargo.lock',
  releaseNotesPath,
  evidenceTemplatePath,
]) {
  if (!existsSync(file)) throw new Error(`Required release file missing: ${file}`);
}

const changelog = readFileSync('CHANGELOG.md', 'utf8');
if (development) {
  if (!changelog.includes('## [Не выпущено]')) {
    throw new Error('CHANGELOG must keep an unreleased section during development.');
  }
} else if (!changelog.includes(`## [${version}]`)) {
  throw new Error(`CHANGELOG section ${version} missing`);
}

execFileSync(process.execPath, ['scripts/check-version-consistency.mjs'], { stdio: 'inherit' });
execFileSync(process.execPath, ['scripts/check-v040-readiness.mjs'], { stdio: 'inherit' });
execFileSync(process.execPath, ['scripts/check-v040-release-boundary.mjs'], { stdio: 'inherit' });

const template = readJson(evidenceTemplatePath, evidenceTemplatePath);
validateEvidence(template, { allowIncomplete: true, version });

if (development) {
  console.log(`Release preflight structure OK for FileScope ${version} (development mode; manual release evidence is intentionally not accepted).`);
  process.exit(0);
}

const evidencePath = resolveEvidencePath(argumentsList);
if (!existsSync(evidencePath)) {
  throw new Error(
    `Final release preflight requires structured QA evidence at ${evidencePath}. ` +
      'Pass --evidence <path> or FILESCOPE_RELEASE_EVIDENCE to override the default.',
  );
}

const evidence = readJson(evidencePath, evidencePath);
validateEvidence(evidence, { allowIncomplete: false, version });
validateGitBoundary(evidence.validatedHeadSha, evidencePath, releaseNotesPath);

console.log(
  `Release preflight OK for FileScope ${version}; validated source ${evidence.validatedHeadSha}, ` +
    `${evidence.extendedFuzzRuns.length} extended fuzz runs, Windows artifact SHA-256 ${evidence.windowsArtifact.sha256}.`,
);

function resolveEvidencePath(args) {
  const index = args.indexOf('--evidence');
  if (index >= 0) {
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error('--evidence requires a file path');
    return value;
  }
  return process.env.FILESCOPE_RELEASE_EVIDENCE || defaultEvidencePath;
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot parse ${label}: ${error.message}`);
  }
}

function validateEvidence(evidence, { allowIncomplete, version }) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new Error('Release evidence must be a JSON object.');
  }
  if (evidence.schemaVersion !== 1) throw new Error('Release evidence schemaVersion must be 1.');
  if (evidence.version !== version) {
    throw new Error(`Release evidence version=${evidence.version ?? 'missing'}, expected ${version}.`);
  }
  requireSha(evidence.validatedHeadSha, 'validatedHeadSha');

  const artifact = evidence.windowsArtifact;
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    throw new Error('Release evidence windowsArtifact is required.');
  }
  if (artifact.name !== 'FileScope-Windows-x64') {
    throw new Error('windowsArtifact.name must be FileScope-Windows-x64.');
  }
  if (!/^[0-9a-f]{64}$/i.test(artifact.sha256 ?? '')) {
    throw new Error('windowsArtifact.sha256 must be a 64-character SHA-256 hex digest.');
  }

  if (typeof evidence.operator !== 'string' || evidence.operator.trim().length < 3) {
    throw new Error('Release evidence operator is required.');
  }
  const checkedAt = Date.parse(evidence.checkedAt);
  if (!Number.isFinite(checkedAt)) throw new Error('Release evidence checkedAt must be an ISO date/time.');

  const requiredManualGates = [
    'realV03MigrationRestartRollback',
    'windowsPublicationProcessKill',
    'windowsAclLockedFile',
    'dpapiCrossUserOrMachine',
    'portableAppData',
    'fullClearRestart',
  ];
  if (!evidence.manualQa || typeof evidence.manualQa !== 'object' || Array.isArray(evidence.manualQa)) {
    throw new Error('Release evidence manualQa object is required.');
  }
  for (const gate of requiredManualGates) {
    if (typeof evidence.manualQa[gate] !== 'boolean') {
      throw new Error(`manualQa.${gate} must be boolean.`);
    }
    if (!allowIncomplete && evidence.manualQa[gate] !== true) {
      throw new Error(`Final release blocked: manualQa.${gate} is not confirmed.`);
    }
  }

  if (!Array.isArray(evidence.extendedFuzzRuns)) {
    throw new Error('Release evidence extendedFuzzRuns must be an array.');
  }
  if (!allowIncomplete && evidence.extendedFuzzRuns.length < 2) {
    throw new Error('Final release requires at least two successful extended fuzz runs.');
  }

  const expectedTargets = [
    'report_deserialization',
    'passive_url',
    'rule_engine',
    'file_format_and_pe',
    'zip_metadata',
  ];
  const seenRunIds = new Set();
  let exactHeadManualRun = false;
  for (const [index, run] of evidence.extendedFuzzRuns.entries()) {
    const prefix = `extendedFuzzRuns[${index}]`;
    if (!run || typeof run !== 'object' || Array.isArray(run)) throw new Error(`${prefix} must be an object.`);
    if (!Number.isSafeInteger(run.runId) || run.runId <= 0) throw new Error(`${prefix}.runId must be a positive integer.`);
    if (seenRunIds.has(run.runId)) throw new Error(`${prefix}.runId is duplicated.`);
    seenRunIds.add(run.runId);
    if (!Number.isSafeInteger(run.runAttempt) || run.runAttempt < 1) {
      throw new Error(`${prefix}.runAttempt must be >= 1.`);
    }
    if (!['schedule', 'workflow_dispatch'].includes(run.event)) {
      throw new Error(`${prefix}.event must be schedule or workflow_dispatch.`);
    }
    requireSha(run.headSha, `${prefix}.headSha`);
    if (!Number.isSafeInteger(run.secondsPerTarget) || run.secondsPerTarget < 180) {
      throw new Error(`${prefix}.secondsPerTarget must be >= 180.`);
    }
    if (run.conclusion !== 'success') throw new Error(`${prefix}.conclusion must be success.`);
    if (run.crashArtifacts !== 0) throw new Error(`${prefix}.crashArtifacts must be 0.`);
    if (!Array.isArray(run.targets)) throw new Error(`${prefix}.targets must be an array.`);
    const normalizedTargets = [...new Set(run.targets)].sort();
    const expected = [...expectedTargets].sort();
    if (normalizedTargets.length !== expected.length || normalizedTargets.some((value, targetIndex) => value !== expected[targetIndex])) {
      throw new Error(`${prefix}.targets must contain exactly the five required fuzz targets.`);
    }
    if (run.event === 'workflow_dispatch' && run.headSha === evidence.validatedHeadSha) {
      exactHeadManualRun = true;
    }
  }
  if (!allowIncomplete && !exactHeadManualRun) {
    throw new Error('Final release requires at least one workflow_dispatch extended fuzz run on validatedHeadSha.');
  }
}

function validateGitBoundary(validatedHeadSha, evidencePath, releaseNotesPath) {
  const currentHead = git(['rev-parse', 'HEAD']).trim();
  if (currentHead === validatedHeadSha) return;

  try {
    execFileSync('git', ['merge-base', '--is-ancestor', validatedHeadSha, currentHead], { stdio: 'ignore' });
  } catch {
    throw new Error(`validatedHeadSha ${validatedHeadSha} is not an ancestor of current HEAD ${currentHead}.`);
  }

  const changedFiles = git(['diff', '--name-only', `${validatedHeadSha}..${currentHead}`])
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
  const normalizedEvidence = relative(process.cwd(), resolve(evidencePath)).replaceAll('\\', '/');
  const allowedMetadata = new Set([
    normalizedEvidence,
    releaseNotesPath,
    'CHANGELOG.md',
    '.github/release-request.json',
  ]);
  const forbidden = changedFiles.filter((file) => !allowedMetadata.has(file));
  if (forbidden.length) {
    throw new Error(
      `Release source changed after validatedHeadSha. Non-metadata files: ${forbidden.join(', ')}`,
    );
  }
  console.log(
    `Release evidence targets ancestor ${validatedHeadSha}; only approved release metadata changed before current HEAD ${currentHead}.`,
  );
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8' });
}

function requireSha(value, label) {
  if (!/^[0-9a-f]{40}$/i.test(value ?? '')) throw new Error(`${label} must be a 40-character git SHA.`);
}
