import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = process.cwd();
const readJson = (path) => JSON.parse(readFileSync(join(root, path), 'utf8'));
const rootPackage = readJson('package.json');
const desktopPackage = readJson('apps/desktop/package.json');
const contractsPackage = readJson('packages/contracts/package.json');
const tauriConfig = readJson('apps/desktop/src-tauri/tauri.conf.json');
const cargo = readFileSync(join(root, 'apps/desktop/src-tauri/Cargo.toml'), 'utf8');
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
  { pattern: /FileScope\s+Core\s+0\.2/g, label: 'старый FileScope Core 0.2' },
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

console.log(`FileScope version consistency OK: ${expected}`);

function* walk(directory) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) yield* walk(path);
    else if (/\.(ts|tsx|js|jsx)$/.test(entry)) yield path;
  }
}
