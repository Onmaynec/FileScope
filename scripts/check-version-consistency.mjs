import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = process.cwd();
const read = (path) => readFileSync(join(root, path), 'utf8');
const readJson = (path) => JSON.parse(read(path));
const rootPackage = readJson('package.json');
const desktopPackage = readJson('apps/desktop/package.json');
const contractsPackage = readJson('packages/contracts/package.json');
const tauriConfig = readJson('apps/desktop/src-tauri/tauri.conf.json');
const cargo = read('apps/desktop/src-tauri/Cargo.toml');
const cargoVersion = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const versions = new Map([
  ['package.json', rootPackage.version],
  ['apps/desktop/package.json', desktopPackage.version],
  ['packages/contracts/package.json', contractsPackage.version],
  ['apps/desktop/src-tauri/tauri.conf.json', tauriConfig.version],
  ['apps/desktop/src-tauri/Cargo.toml', cargoVersion],
]);
const expected = rootPackage.version;
const mismatches = [...versions].filter(([, version]) => version !== expected);
if (mismatches.length) {
  console.error(`Version mismatch. Expected ${expected}:`);
  for (const [path, version] of mismatches) console.error(`- ${path}: ${version}`);
  process.exit(1);
}

const forbiddenPatterns = [
  { pattern: /FileScope\s+v?0\.2\.0/g, label: 'старый FileScope v0.2.0' },
  { pattern: /FileScope\s+Core\s+0\.\d+(?:\.\d+)?/g, label: 'ручная строка FileScope Core версии' },
  { pattern: /const\s+APP_VERSION\s*=\s*['"][^'"]+['"]/g, label: 'ручная строка APP_VERSION' },
];
const allowLegacyStorage = new Set([
  'apps/desktop/src/features/analysis/model/analysis-storage.ts',
  'apps/desktop/src/features/analysis/model/analysis-storage.test.ts',
]);
const findings = [];
for (const path of walk(join(root, 'apps/desktop/src'))) {
  const rel = relative(root, path).replaceAll('\\', '/');
  if (allowLegacyStorage.has(rel)) continue;
  const text = readFileSync(path, 'utf8');
  for (const { pattern, label } of forbiddenPatterns) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) findings.push(`${rel}: ${label}`);
  }
}
if (findings.length) {
  console.error('Найдены устаревшие или вручную заданные версии:');
  for (const finding of findings) console.error(`- ${finding}`);
  process.exit(1);
}

const title = tauriConfig.app?.windows?.[0]?.title ?? '';
if (!title.includes(expected)) {
  console.error(`Tauri window title does not contain ${expected}: ${title}`);
  process.exit(1);
}

const rustTypes = read('apps/desktop/src-tauri/src/analysis/types.rs');
const frontendTypes = read('apps/desktop/src/features/analysis/model/types.ts');
const sharedContracts = read('packages/contracts/src/analysis.ts');
const reportFields = [
  ['schema_version', 'schemaVersion'],
  ['app_version', 'appVersion'],
  ['analyzer_version', 'analyzerVersion'],
  ['rule_set_version', 'ruleSetVersion'],
  ['created_by', 'createdBy'],
  ['analysis_completeness', 'analysisCompleteness'],
  ['risk_level', 'riskLevel'],
  ['risk_score', 'riskScore'],
  ['limitations', 'limitations'],
];
const contractErrors = [];
for (const [rustName, tsName] of reportFields) {
  if (!new RegExp(`\\bpub\\s+${rustName}\\s*:`).test(rustTypes)) {
    contractErrors.push(`Rust AnalysisReport missing ${rustName}`);
  }
  if (!new RegExp(`\\b${tsName}\\??\\s*:`).test(frontendTypes)) {
    contractErrors.push(`Frontend AnalysisReport missing ${tsName}`);
  }
  if (!new RegExp(`\\b${tsName}\\??\\s*:`).test(sharedContracts)) {
    contractErrors.push(`Shared contract missing ${tsName}`);
  }
}
const rustSchema = Number(rustTypes.match(/REPORT_SCHEMA_VERSION:\s*u16\s*=\s*(\d+)/)?.[1]);
const frontendSchema = Number(frontendTypes.match(/currentReportSchemaVersion\s*=\s*(\d+)/)?.[1]);
const sharedSchema = Number(sharedContracts.match(/FILESCOPE_REPORT_SCHEMA_VERSION\s*=\s*(\d+)/)?.[1]);
const tauriHistoryRepository = read('apps/desktop/src/features/analysis/model/tauri-history-repository.ts');
const rustHistoryStorage = read('apps/desktop/src-tauri/src/history_storage.rs');
const frontendStorageVersion = Number(tauriHistoryRepository.match(/TAURI_HISTORY_STORAGE_VERSION\s*=\s*(\d+)/)?.[1]);
const rustStorageVersion = Number(rustHistoryStorage.match(/HISTORY_STORAGE_VERSION:\s*u16\s*=\s*(\d+)/)?.[1]);
const sharedStorageVersion = Number(sharedContracts.match(/FILESCOPE_HISTORY_STORAGE_VERSION\s*=\s*(\d+)/)?.[1]);
if (!rustSchema || rustSchema !== frontendSchema || rustSchema !== sharedSchema) {
  contractErrors.push(`Schema mismatch: Rust=${rustSchema}, frontend=${frontendSchema}, contracts=${sharedSchema}`);
}
if (!frontendStorageVersion
  || frontendStorageVersion !== rustStorageVersion
  || frontendStorageVersion !== sharedStorageVersion) {
  contractErrors.push(`History storage mismatch: frontend=${frontendStorageVersion}, Rust=${rustStorageVersion}, contracts=${sharedStorageVersion}`);
}
if (contractErrors.length) {
  console.error('Report contract consistency failed:');
  for (const error of contractErrors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`FileScope version and report contract consistency OK: ${expected}, schema ${rustSchema}, history storage ${rustStorageVersion}`);

function* walk(directory) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) yield* walk(path);
    else if (/\.(ts|tsx|js|jsx)$/.test(entry)) yield path;
  }
}
