import { existsSync, readFileSync } from 'node:fs';

const required = [
  'scripts/release-preflight.mjs',
  'docs/releases/v0.4.0.md',
  'docs/releases/v0.4.0-evidence.example.json',
  'docs/product/v0.4.0-release-preflight.md',
  'docs/security/fuzzing-policy.md',
  '.github/workflows/ci.yml',
  '.github/workflows/security-fuzz.yml',
  '.github/workflows/release.yml',
  'package.json',
];
const errors = [];
for (const path of required) {
  if (!existsSync(path)) errors.push(`missing ${path}`);
}

if (existsSync('scripts/release-preflight.mjs')) {
  const preflight = readFileSync('scripts/release-preflight.mjs', 'utf8');
  for (const literal of [
    '.github/release-evidence/v${version}.json',
    'realV03MigrationRestartRollback',
    'windowsPublicationProcessKill',
    'windowsAclLockedFile',
    'dpapiCrossUserOrMachine',
    'portableAppData',
    'fullClearRestart',
    'extendedFuzzRuns.length < 2',
    "run.event === 'workflow_dispatch'",
    'run.headSha === evidence.validatedHeadSha',
    'run.secondsPerTarget < 180',
    'run.crashArtifacts !== 0',
    'Release source changed after validatedHeadSha',
    "'CHANGELOG.md'",
    "'.github/release-request.json'",
  ]) {
    if (!preflight.includes(literal)) errors.push(`release-preflight.mjs missing ${literal}`);
  }
  if (!preflight.includes("changelog.includes('## [Не выпущено]')")) {
    errors.push('development preflight must require the unreleased changelog section');
  }
  if (!preflight.includes('changelog.includes(`## [${version}]`)')) {
    errors.push('final preflight must require the versioned changelog section');
  }
}

if (existsSync('package.json')) {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  if (pkg.scripts?.['release:preflight'] !== 'node scripts/release-preflight.mjs') {
    errors.push('package.json release:preflight must call scripts/release-preflight.mjs');
  }
  if (pkg.scripts?.['release:preflight:development'] !== 'node scripts/release-preflight.mjs --development') {
    errors.push('package.json release:preflight:development must stay explicitly development-only');
  }
}

if (existsSync('.github/workflows/ci.yml')) {
  const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
  if (!ci.includes('pnpm release:preflight:development')) {
    errors.push('ci.yml must execute development release preflight');
  }
}

if (existsSync('.github/workflows/release.yml')) {
  const releaseWorkflow = readFileSync('.github/workflows/release.yml', 'utf8');
  if (!releaseWorkflow.includes('pnpm release:preflight')) {
    errors.push('release.yml must execute final release preflight');
  }
  if (releaseWorkflow.includes('pnpm release:preflight:development')) {
    errors.push('release.yml must never substitute development preflight for final preflight');
  }
}

if (existsSync('.github/workflows/security-fuzz.yml')) {
  const fuzz = readFileSync('.github/workflows/security-fuzz.yml', 'utf8');
  for (const literal of [
    'seconds=20',
    'seconds=180',
    "success() && github.event_name != 'pull_request'",
    'FileScope-fuzz-evidence-${{ github.run_id }}',
    'fuzz-evidence/run.json',
    '"secondsPerTarget": ${FUZZ_SECONDS}',
    '"crashArtifacts": 0',
    'FileScope-fuzz-crashes-${{ github.run_id }}',
  ]) {
    if (!fuzz.includes(literal)) errors.push(`security-fuzz.yml missing ${literal}`);
  }
  requireNearby(fuzz, 'FileScope-fuzz-evidence-${{ github.run_id }}', 'retention-days: 3', 600, 'extended fuzz metadata retention must be <= 3 days');
  requireNearby(fuzz, 'FileScope-fuzz-crashes-${{ github.run_id }}', 'retention-days: 3', 600, 'fuzz crash retention must be <= 3 days');
  for (const target of ['report_deserialization', 'passive_url', 'rule_engine', 'file_format_and_pe', 'zip_metadata']) {
    if (!fuzz.includes(`cargo fuzz run ${target}`)) errors.push(`security-fuzz.yml missing target ${target}`);
    if (!fuzz.includes(`"${target}"`)) errors.push(`extended fuzz evidence missing target ${target}`);
  }
}

if (existsSync('docs/releases/v0.4.0-evidence.example.json')) {
  try {
    const example = JSON.parse(readFileSync('docs/releases/v0.4.0-evidence.example.json', 'utf8'));
    if (example.schemaVersion !== 1 || example.version !== '0.4.0') {
      errors.push('v0.4.0 evidence example must keep schemaVersion=1 and version=0.4.0');
    }
    if (!example.manualQa || !Array.isArray(example.extendedFuzzRuns)) {
      errors.push('v0.4.0 evidence example must contain manualQa and extendedFuzzRuns');
    }
  } catch (error) {
    errors.push(`v0.4.0 evidence example is invalid JSON: ${error.message}`);
  }
}

if (errors.length) {
  console.error('FileScope v0.4.0 release boundary check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log('FileScope v0.4.0 release evidence boundary OK.');

function requireNearby(text, anchor, expected, distance, message) {
  const index = text.indexOf(anchor);
  if (index < 0) return;
  const slice = text.slice(index, index + distance);
  if (!slice.includes(expected)) errors.push(message);
}
