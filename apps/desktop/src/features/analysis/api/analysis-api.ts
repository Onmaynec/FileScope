import { invoke } from '@tauri-apps/api/core';
import type { AnalysisLimits, AnalysisReport, RiskLevel, ThreatIndicator } from '../model/types';

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function invokeAnalysis(command: string, arguments_: Record<string, unknown>): Promise<AnalysisReport> {
  try {
    return await invoke<AnalysisReport>(command, arguments_);
  } catch (reason) {
    throw new Error(friendlyAnalysisError(reason));
  }
}

export async function analyzeFile(path: string, limits: AnalysisLimits): Promise<AnalysisReport> {
  if (!isTauriRuntime()) throw new Error('Локальный анализ файлов доступен только в desktop-сборке FileScope.');
  return invokeAnalysis('analyze_local_file', { path, limits });
}

export async function analyzeArchive(path: string, limits: AnalysisLimits): Promise<AnalysisReport> {
  if (!isTauriRuntime()) throw new Error('Анализ ZIP-архивов доступен только в desktop-сборке FileScope.');
  return invokeAnalysis('analyze_local_archive', { path, limits });
}

export async function analyzeUrlPassive(url: string): Promise<AnalysisReport> {
  if (isTauriRuntime()) return invokeAnalysis('analyze_url_passive', { url });
  return analyzeUrlInBrowser(url);
}

export async function analyzeUrlActive(url: string, limits: AnalysisLimits): Promise<AnalysisReport> {
  if (!isTauriRuntime()) throw new Error('Активная URL-проверка доступна только в desktop-сборке FileScope.');
  return invokeAnalysis('analyze_url_active', { url, limits });
}

export function analyzeUrlInBrowser(input: string): AnalysisReport {
  const started = performanceNow();
  const parsed = new URL(input.trim());
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Поддерживаются только HTTP- и HTTPS-ссылки.');

  const indicators: ThreatIndicator[] = [];
  const host = parsed.hostname.toLowerCase();
  const labels = host.split('.').filter(Boolean);
  const containsUnicode = Array.from(input).some((character) => (character.codePointAt(0) ?? 0) > 127);
  const add = (indicator: ThreatIndicator) => indicators.push(indicator);
  const make = (
    id: string,
    title: string,
    description: string,
    severity: ThreatIndicator['severity'],
    score: number,
    evidence: string[],
    recommendation: string,
  ): ThreatIndicator => ({ id, title, description, severity, score, evidence, recommendation, category: 'url' });

  if (input.length > 220) add(make('url.length.excessive', 'Необычно длинный URL', 'Длинный адрес затрудняет визуальную проверку.', 'medium', 16, [`Длина: ${input.length}`], 'Проверьте домен и параметры отдельно.'));
  if (host.includes('xn--') || containsUnicode) add(make('url.host.idn', 'Домен содержит IDN/Punycode', 'Символы домена могут визуально имитировать другой адрес.', 'medium', 22, [host], 'Сравните адрес с официальным доменом посимвольно.'));
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) add(make('url.host.ip-address', 'Вместо домена используется IP-адрес', 'Прямой адрес затрудняет проверку владельца ресурса.', 'medium', 18, [host], 'Не вводите учётные данные без подтверждения адреса.'));
  if (parsed.username || parsed.password) add(make('url.credentials.embedded', 'В URL встроены учётные данные', 'Часть до символа @ может скрывать настоящий домен.', 'high', 40, [parsed.href], 'Не открывайте адрес и удалите встроенные учётные данные.'));
  if (labels.length > 5) add(make('url.host.many-subdomains', 'Необычно много поддоменов', 'Длинная цепочка поддоменов может маскировать основной домен.', 'medium', 16, [host], 'Проверяйте домен справа налево.'));
  const redirectKeys = ['url', 'uri', 'redirect', 'redirect_url', 'target', 'next', 'continue', 'dest', 'destination'];
  const redirectParameters = [...parsed.searchParams.entries()]
    .filter(([key, value]) => redirectKeys.includes(key.toLowerCase()) || /^https?:\/\//i.test(value))
    .map(([key, value]) => `${key}=${value}`);
  if (redirectParameters.length) add(make('url.query.redirect-target', 'В параметрах найден вложенный адрес', 'Ссылка может перенаправить пользователя на другой ресурс.', 'medium', 20, redirectParameters, 'Проверьте вложенный адрес отдельно.'));
  if (/\.(exe|scr|msi|bat|cmd|ps1|js|vbs|hta|lnk)$/i.test(parsed.pathname)) add(make('url.path.executable-download', 'Ссылка похожа на загрузку исполняемого файла', 'Путь заканчивается расширением, способным запускать код в Windows.', 'high', 32, [parsed.pathname], 'После загрузки обязательно проверьте сам файл.'));

  const score = Math.min(100, indicators.reduce((sum, item) => sum + item.score, 0));
  const riskLevel: RiskLevel = indicators.some((item) => item.severity === 'critical') || score >= 80
    ? 'dangerous'
    : indicators.some((item) => item.severity === 'high') || score >= 45
      ? 'highRisk'
      : score >= 15
        ? 'caution'
        : 'noThreatsFound';
  const now = new Date().toISOString();

  return {
    id: cryptoId(),
    objectKind: 'url',
    target: input,
    displayName: host,
    startedAt: now,
    completedAt: now,
    durationMs: Math.max(0, performanceNow() - started),
    detectedType: 'HTTP URL',
    riskLevel,
    riskScore: score,
    indicators,
    metadata: { networkAccess: false, browserFallback: true, containsUnicode },
    url: {
      normalizedUrl: parsed.href,
      scheme: parsed.protocol.replace(':', ''),
      host,
      port: parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80,
      path: parsed.pathname,
      queryParameters: [...parsed.searchParams].length,
      containsPunycode: host.includes('xn--'),
      hostIsIp: /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host),
      hasCredentials: Boolean(parsed.username || parsed.password),
      subdomainCount: Math.max(0, labels.length - 2),
      redirectParameters,
      resolvedAddresses: [],
      responseHeaders: [],
      activeCheckPerformed: false,
    },
    isDemo: false,
    limitations: ['Пассивный анализ не выполняет сетевой запрос и не проверяет содержимое страницы.'],
  };
}

export function friendlyAnalysisError(reason: unknown): string {
  const raw = reason instanceof Error ? reason.message : String(reason);
  const value = raw.toLowerCase();

  if (value.includes('access is denied') || value.includes('permission denied') || value.includes('os error 5')) {
    return 'Windows запретила чтение объекта. Проверьте права доступа, закройте программу, которая удерживает файл, и повторите анализ.';
  }
  if (value.includes('not found') || value.includes('не удается найти') || value.includes('os error 2')) {
    return 'Файл больше не найден по выбранному пути. Возможно, он был перемещён, удалён или помещён в карантин другой программой.';
  }
  if (value.includes('too large') || value.includes('слишком велик') || value.includes('превышает установленный лимит')) {
    return 'Объект превышает защитный лимит FileScope. Увеличивайте лимит только для доверенного файла либо используйте отдельную изолированную среду.';
  }
  if (value.includes('invalid zip') || value.includes('архив') && value.includes('повреж')) {
    return 'ZIP-структура повреждена или имеет неподдерживаемый формат. FileScope не извлекал содержимое и остановил структурный разбор.';
  }
  if (value.includes('timed out') || value.includes('timeout') || value.includes('истекло время')) {
    return 'Активная URL-проверка не завершилась за установленное время. Пассивный результат остаётся доступным без повторного сетевого запроса.';
  }
  if (value.includes('dns') || value.includes('resolve')) {
    return 'Не удалось определить IP-адрес домена. Проверьте адрес и сетевое подключение либо используйте только пассивный анализ.';
  }

  return raw || 'Анализ завершился неизвестной ошибкой. Повторите проверку и сохраните точный путь и тип объекта для отчёта.';
}

function cryptoId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `report-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function performanceNow(): number {
  return typeof performance === 'undefined' ? Date.now() : performance.now();
}
