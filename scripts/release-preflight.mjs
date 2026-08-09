
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const development = process.argv.includes('--development');
const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
const version = packageJson.version;
if (!/^\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`Invalid version: ${version}`);
for (const file of ['pnpm-lock.yaml', 'apps/desktop/src-tauri/Cargo.lock', `docs/releases/v${version}.md`]) {
  if (!existsSync(file)) throw new Error(`Required release file missing: ${file}`);
}
const changelog = readFileSync('CHANGELOG.md', 'utf8');
if (!changelog.includes(`## [${version}]`)) throw new Error(`CHANGELOG section ${version} missing`);
execFileSync(process.execPath, ['scripts/check-version-consistency.mjs'], { stdio: 'inherit' });
execFileSync(process.execPath, ['scripts/check-v040-readiness.mjs'], { stdio: 'inherit' });
console.log(`Release preflight OK for FileScope ${version}${development ? ' (development mode)' : ''}.`);
