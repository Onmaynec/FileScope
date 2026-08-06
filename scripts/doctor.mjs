import { existsSync, readdirSync, statfsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import process from 'node:process';

const checks = [];
const isWindows = process.platform === 'win32';

function commandOutput(command, args = []) {
  try {
    return execFileSync(command, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    }).trim();
  } catch {
    return '';
  }
}

function commandPath(command) {
  const locator = isWindows ? 'where' : 'which';
  return commandOutput(locator, [command]).split(/\r?\n/).find(Boolean) ?? '';
}

function add(status, name, details, recommendation = '') {
  checks.push({ status, name, details, recommendation });
}

function parseMajor(version) {
  const match = String(version).match(/(\d+)/);
  return match ? Number(match[1]) : 0;
}

function formatBytes(bytes) {
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} ГБ`;
}

const nodeMajor = parseMajor(process.versions.node);
add(
  nodeMajor >= 22 ? 'ok' : 'error',
  'Node.js',
  `v${process.versions.node}`,
  'Установите Node.js 22 LTS: winget install -e --id OpenJS.NodeJS.LTS',
);

const pnpm = commandOutput(isWindows ? 'pnpm.cmd' : 'pnpm', ['--version']);
add(
  pnpm === '10.14.0' ? 'ok' : pnpm ? 'warn' : 'error',
  'pnpm',
  pnpm || 'не найден',
  'Установите проверенную версию: npm install --global pnpm@10.14.0',
);

const rustc = commandOutput(isWindows ? 'rustc.exe' : 'rustc', ['--version']);
add(
  rustc ? 'ok' : 'error',
  'Rust',
  rustc || 'rustc не найден',
  'Установите Rustup: winget install -e --id Rustlang.Rustup',
);

const cargo = commandOutput(isWindows ? 'cargo.exe' : 'cargo', ['--version']);
add(
  cargo ? 'ok' : 'error',
  'Cargo',
  cargo || 'cargo не найден',
  'Переустановите stable-msvc: rustup default stable-msvc',
);

const installedTargets = commandOutput(isWindows ? 'rustup.exe' : 'rustup', ['target', 'list', '--installed']);
const hasMsvcTarget = installedTargets.split(/\r?\n/).includes('x86_64-pc-windows-msvc');
if (isWindows) {
  add(
    hasMsvcTarget ? 'ok' : 'error',
    'Rust target x64 MSVC',
    hasMsvcTarget ? 'x86_64-pc-windows-msvc установлен' : 'target не установлен',
    'Выполните: rustup target add x86_64-pc-windows-msvc',
  );
} else {
  add('skip', 'Rust target x64 MSVC', 'проверка требуется только на Windows');
}

if (isWindows) {
  const linker = commandPath('link.exe');
  add(
    linker ? 'ok' : 'error',
    'MSVC linker link.exe',
    linker || 'не найден в PATH',
    'Установите Visual Studio Build Tools с workload Desktop development with C++ и откройте новый терминал разработчика.',
  );

  const compiler = commandPath('cl.exe');
  add(
    compiler ? 'ok' : 'error',
    'MSVC compiler cl.exe',
    compiler || 'не найден в PATH',
    'Запустите сборку из Developer Command Prompt либо выполните VsDevCmd.bat -arch=x64 -host_arch=x64.',
  );

  const programFilesX86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
  const windowsKits = `${programFilesX86}\\Windows Kits\\10\\bin`;
  let sdkVersion = '';
  if (existsSync(windowsKits)) {
    sdkVersion = readdirSync(windowsKits, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^10\.\d+/.test(entry.name))
      .map((entry) => entry.name)
      .sort()
      .at(-1) ?? '';
  }
  add(
    sdkVersion ? 'ok' : 'error',
    'Windows SDK',
    sdkVersion || 'Windows 10/11 SDK не найден',
    'Добавьте Windows 10 SDK или Windows 11 SDK через Visual Studio Installer.',
  );

  const webViewLocations = [
    `${programFilesX86}\\Microsoft\\EdgeWebView\\Application`,
    `${process.env.LOCALAPPDATA ?? ''}\\Microsoft\\EdgeWebView\\Application`,
  ];
  const webViewPath = webViewLocations.find((location) => location && existsSync(location));
  add(
    webViewPath ? 'ok' : 'warn',
    'Microsoft Edge WebView2 Runtime',
    webViewPath || 'типовой каталог не найден',
    'Установите runtime: winget install -e --id Microsoft.EdgeWebView2Runtime',
  );
} else {
  add('skip', 'MSVC и Windows SDK', `текущая платформа: ${process.platform}`);
  add('skip', 'Microsoft Edge WebView2 Runtime', 'проверка требуется только на Windows');
}

try {
  const disk = statfsSync(process.cwd());
  const freeBytes = Number(disk.bavail) * Number(disk.bsize);
  const minimum = 20 * 1024 * 1024 * 1024;
  add(
    freeBytes >= minimum ? 'ok' : 'warn',
    'Свободное место',
    `${formatBytes(freeBytes)} в файловой системе проекта`,
    'Для первой Rust/Tauri-сборки освободите не менее 20 ГБ.',
  );
} catch (error) {
  add('warn', 'Свободное место', `не удалось определить: ${error instanceof Error ? error.message : String(error)}`);
}

const iconsSource = 'apps/desktop/src-tauri/icons/filescope-logo.svg';
add(
  existsSync(iconsSource) ? 'ok' : 'error',
  'Исходник иконок FileScope',
  existsSync(iconsSource) ? iconsSource : 'файл отсутствует',
  'Восстановите утверждённый SVG-источник логотипа из репозитория.',
);

const marks = { ok: 'OK', warn: 'WARN', error: 'ERROR', skip: 'SKIP' };
console.log('\nFileScope doctor 0.3.2');
console.log('Локальная проверка без сетевых запросов и изменения системы.\n');
for (const check of checks) {
  console.log(`[${marks[check.status]}] ${check.name}: ${check.details}`);
  if (check.status !== 'ok' && check.status !== 'skip' && check.recommendation) {
    console.log(`       ${check.recommendation}`);
  }
}

const errors = checks.filter((check) => check.status === 'error').length;
const warnings = checks.filter((check) => check.status === 'warn').length;
console.log(`\nИтог: ошибок ${errors}, предупреждений ${warnings}.`);
if (errors > 0) {
  console.error('Окружение пока не готово к гарантированной production-сборке FileScope.');
  process.exitCode = 1;
} else {
  console.log('Критичные требования окружения выполнены.');
}
