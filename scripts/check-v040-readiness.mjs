import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = process.cwd();
const required = [
  'apps/desktop/src/features/analysis/model/history-repository.ts',
  'apps/desktop/src/features/analysis/model/tauri-history-repository.ts',
  'apps/desktop/src/features/analysis/model/report-migration.ts',
  'apps/desktop/src/features/analysis/model/history-privacy.ts',
  'apps/desktop/src/features/analysis/ui/HistoryPrivacySettings.tsx',
  'apps/desktop/src/features/analysis/model/fixtures/history/future-report-schema.json',
  'apps/desktop/src-tauri/src/history_storage.rs',
  'apps/desktop/src-tauri/src/history_protection.rs',
  'apps/desktop/src-tauri/src/analysis/properties.rs',
  'apps/desktop/src-tauri/src/analysis/fuzzing.rs',
  'apps/desktop/src-tauri/fuzz/Cargo.toml',
  '.github/workflows/security-fuzz.yml',
  'docs/architecture/history-storage-migration-v040.md',
  'docs/architecture/history-storage-protection-v040.md',
  'docs/security/fuzzing-policy.md',
  'docs/product/v0.3.4-manual-qa.md',
  'docs/product/v0.4.0-manual-qa.md',
  'docs/product/v0.4.0-readiness-checklist.md',
];
const errors = [];
for (const path of required) if (!existsSync(join(root, path))) errors.push(`missing ${path}`);

const historyLiterals = ['filescope:history:storage-', 'filescope:reports:schema-', 'filescope:v0.2.0:reports'];
const allowedHistoryFiles = new Set([
  'apps/desktop/src/features/analysis/model/history-repository.ts',
  'apps/desktop/src/features/analysis/model/analysis-storage.test.ts',
]);
for (const path of walk(join(root, 'apps/desktop/src'))) {
  const rel = relative(root, path).replaceAll('\\', '/');
  if (allowedHistoryFiles.has(rel)) continue;
  const text = readFileSync(path, 'utf8');
  for (const literal of historyLiterals) if (text.includes(literal)) errors.push(`${rel}: direct history key ${literal}`);
}

const fixtureDirectory = join(root, 'apps/desktop/src/features/analysis/model/fixtures/history');
if (existsSync(fixtureDirectory)) {
  for (const name of readdirSync(fixtureDirectory)) {
    const text = readFileSync(join(fixtureDirectory, name), 'utf8');
    if (name === 'corrupted.json') {
      try { JSON.parse(text); errors.push('corrupted.json must stay intentionally invalid'); } catch { /* expected */ }
    } else {
      try { JSON.parse(text); } catch { errors.push(`${name}: invalid migration fixture`); }
    }
  }
}

const futureReportFixturePath = join(fixtureDirectory, 'future-report-schema.json');
if (existsSync(futureReportFixturePath)) {
  const future = JSON.parse(readFileSync(futureReportFixturePath, 'utf8'));
  if (future.storageVersion !== 1 || !(future.reportSchemaVersion > 1)) {
    errors.push('future-report-schema.json must keep current storageVersion with future reportSchemaVersion');
  }
}

const protectionPath = join(root, 'apps/desktop/src-tauri/src/history_protection.rs');
if (existsSync(protectionPath)) {
  const protection = readFileSync(protectionPath, 'utf8');
  for (const requiredLiteral of ['CryptProtectData', 'CryptUnprotectData', 'CRYPTPROTECT_UI_FORBIDDEN', 'FSDPAPI1', 'LocalFree']) {
    if (!protection.includes(requiredLiteral)) errors.push(`history_protection.rs missing ${requiredLiteral}`);
  }
  if (/CRYPTPROTECT_LOCAL_MACHINE|LOCAL_MACHINE/.test(protection)) {
    errors.push('history_protection.rs must stay current-user scoped; LOCAL_MACHINE is forbidden');
  }
}

const historyStoragePath = join(root, 'apps/desktop/src-tauri/src/history_storage.rs');
if (existsSync(historyStoragePath)) {
  const storage = readFileSync(historyStoragePath, 'utf8');
  for (const requiredLiteral of ['history_protection_status', 'protect_payload', 'unprotect_payload', 'LEGACY_GENERATION_SUFFIX', 'cleanup_plaintext_generations']) {
    if (!storage.includes(requiredLiteral)) errors.push(`history_storage.rs missing ${requiredLiteral}`);
  }
}

const historyRepositoryPath = join(root, 'apps/desktop/src/features/analysis/model/tauri-history-repository.ts');
if (existsSync(historyRepositoryPath)) {
  const repository = readFileSync(historyRepositoryPath, 'utf8');
  for (const requiredLiteral of ['history_protection_status', 'history_rewrite_all', 'inspectTauriHistoryProtection']) {
    if (!repository.includes(requiredLiteral)) errors.push(`tauri-history-repository.ts missing ${requiredLiteral}`);
  }
}

for (const target of ['report_deserialization', 'passive_url', 'rule_engine']) {
  const path = join(root, `apps/desktop/src-tauri/fuzz/fuzz_targets/${target}.rs`);
  if (!existsSync(path)) continue;
  const text = readFileSync(path, 'utf8');
  for (const forbidden of ['std::process::Command', 'reqwest::', 'std::fs::write', 'File::create']) {
    if (text.includes(forbidden)) errors.push(`${target}: forbidden fuzz side effect ${forbidden}`);
  }
}

const fuzzWorkflowPath = join(root, '.github/workflows/security-fuzz.yml');
if (existsSync(fuzzWorkflowPath)) {
  const workflow = readFileSync(fuzzWorkflowPath, 'utf8');
  if (!/permissions:\s*\n\s*contents:\s*read/m.test(workflow)) errors.push('security-fuzz workflow must be contents: read');
  if (/contents:\s*write|environment:\s*production|secrets\./.test(workflow)) errors.push('security-fuzz workflow has forbidden privilege/secrets');
  const retention = [...workflow.matchAll(/retention-days:\s*(\d+)/g)].map((match) => Number(match[1]));
  if (retention.some((days) => days > 3)) errors.push('fuzz crash retention must be <= 3 days');
}

for (const workflow of walk(join(root, '.github/workflows'))) {
  const rel = relative(root, workflow).replaceAll('\\', '/');
  const text = readFileSync(workflow, 'utf8');
  for (const oldAction of ['actions/checkout@v4', 'actions/setup-node@v4', 'actions/upload-artifact@v4', 'actions/download-artifact@v4']) {
    if (text.includes(oldAction)) errors.push(`${rel}: deprecated ${oldAction}`);
  }
  for (const line of text.split(/\r?\n/)) {
    const action = line.match(/^\s*uses:\s*([^\s#]+)/)?.[1];
    if (!action || action.startsWith('./')) continue;
    if (!/@[0-9a-f]{40}$/.test(action)) errors.push(`${rel}: mutable external action ref ${action}`);
  }
}

if (errors.length) {
  console.error('FileScope v0.4.0 readiness check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log('FileScope v0.4.0 readiness boundary OK.');

function* walk(directory) {
  if (!existsSync(directory)) return;
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) yield* walk(path);
    else yield path;
  }
}
