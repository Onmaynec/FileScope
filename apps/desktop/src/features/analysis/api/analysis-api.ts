import { invoke } from '@tauri-apps/api/core';
import type {
  AnalysisCommandError,
  AnalysisFailureCode,
  AnalysisLimits,
  AnalysisReport,
} from '../model/types';

export interface AnalysisMetadata {
  schemaVersion: number;
  appVersion: string;
  analyzerVersion: string;
  ruleSetVersion: string;
}

export class AnalysisError extends Error {
  readonly code: AnalysisFailureCode;

  constructor(code: AnalysisFailureCode, message: string) {
    super(message);
    this.name = 'AnalysisError';
    this.code = code;
  }
}

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function invokeAnalysis(command: string, arguments_: Record<string, unknown>): Promise<AnalysisReport> {
  try {
    return await invoke<AnalysisReport>(command, arguments_);
  } catch (reason) {
    throw normalizeAnalysisError(reason);
  }
}

export async function analyzeFile(
  jobId: string,
  path: string,
  limits: AnalysisLimits,
): Promise<AnalysisReport> {
  requireDesktop('Локальный анализ файлов');
  return invokeAnalysis('analyze_local_file', { jobId, path, limits });
}

export async function analyzeArchive(
  jobId: string,
  path: string,
  limits: AnalysisLimits,
): Promise<AnalysisReport> {
  requireDesktop('Анализ ZIP-архивов');
  return invokeAnalysis('analyze_local_archive', { jobId, path, limits });
}

export async function analyzeUrlPassive(jobId: string, url: string): Promise<AnalysisReport> {
  requireDesktop('Канонический пассивный URL-анализ');
  return invokeAnalysis('analyze_url_passive', { jobId, url });
}

export async function analyzeUrlActive(
  jobId: string,
  url: string,
  limits: AnalysisLimits,
): Promise<AnalysisReport> {
  requireDesktop('Активная URL-проверка');
  return invokeAnalysis('analyze_url_active', { jobId, url, limits });
}

export async function cancelAnalysis(jobId: string): Promise<boolean> {
  if (!isTauriRuntime()) return false;
  return invoke<boolean>('cancel_analysis', { jobId });
}

export async function getAnalysisMetadata(): Promise<AnalysisMetadata> {
  requireDesktop('Метаданные анализатора');
  return invoke<AnalysisMetadata>('get_analysis_metadata');
}

export function friendlyAnalysisError(reason: unknown): string {
  const normalized = normalizeAnalysisError(reason);
  switch (normalized.code) {
    case 'cancelled':
      return 'Анализ отменён пользователем. Rust backend подтвердил остановку задания.';
    case 'timeout':
      return 'Анализ остановлен по максимальному времени выполнения. Частичный результат не сохранён как завершённый отчёт.';
    case 'readLimit':
      return 'Чтение остановлено защитным бюджетом. Увеличивайте лимит только для доверенного объекта.';
    case 'memoryLimit':
      return 'Разбор остановлен защитным бюджетом памяти. Объект не запускался и не извлекался.';
    case 'entryLimit':
      return 'Обход архива остановлен по максимальному количеству записей.';
    case 'fileChanged':
      return 'Файл изменился во время проверки. SHA-256 и структура могли относиться к разным состояниям, поэтому результат не сформирован.';
    case 'unsupportedObject':
      return normalized.message || 'Каталоги, ссылки, reparse points и специальные объекты не поддерживаются.';
    case 'securityBlocked':
      return normalized.message || 'Операция заблокирована защитной политикой FileScope.';
    case 'invalidInput':
      return normalized.message || 'Переданы некорректные данные для анализа.';
    case 'network':
      return normalized.message || 'Активная URL-проверка завершилась сетевой ошибкой.';
    case 'parse':
      return normalized.message || 'Структура объекта повреждена или не поддерживается.';
    default:
      break;
  }

  const raw = normalized.message;
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
  if ((value.includes('invalid zip') || value.includes('архив')) && value.includes('повреж')) {
    return 'ZIP-структура повреждена или имеет неподдерживаемый формат. FileScope не извлекал содержимое и остановил структурный разбор.';
  }
  if (value.includes('timed out') || value.includes('timeout') || value.includes('истекло время')) {
    return 'Активная URL-проверка не завершилась за установленное время. Пассивный результат можно запустить отдельно без сетевого обращения.';
  }
  if (value.includes('dns') || value.includes('resolve')) {
    return 'Не удалось определить разрешённый публичный IP-адрес домена. Проверьте адрес и сетевое подключение либо используйте только пассивный анализ.';
  }
  return raw || 'Анализ завершился неизвестной ошибкой. Повторите проверку и сохраните точный тип объекта для отчёта.';
}

export function normalizeAnalysisError(reason: unknown): AnalysisError {
  if (reason instanceof AnalysisError) return reason;
  const structured = parseStructuredError(reason);
  if (structured) return new AnalysisError(structured.code, structured.message);
  return new AnalysisError('internal', reason instanceof Error ? reason.message : String(reason ?? ''));
}

function parseStructuredError(reason: unknown): AnalysisCommandError | null {
  if (isCommandError(reason)) return reason;
  if (reason instanceof Error) {
    const parsed = parseJson(reason.message);
    if (isCommandError(parsed)) return parsed;
  }
  if (typeof reason === 'string') {
    const parsed = parseJson(reason);
    if (isCommandError(parsed)) return parsed;
  }
  return null;
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function isCommandError(value: unknown): value is AnalysisCommandError {
  return Boolean(
    value
    && typeof value === 'object'
    && 'code' in value
    && 'message' in value
    && typeof (value as { code?: unknown }).code === 'string'
    && typeof (value as { message?: unknown }).message === 'string',
  );
}

function requireDesktop(feature: string): void {
  if (!isTauriRuntime()) {
    throw new AnalysisError(
      'unsupportedObject',
      `${feature} доступен только в desktop-сборке FileScope. Browser preview не выдаёт production verdict.`,
    );
  }
}
