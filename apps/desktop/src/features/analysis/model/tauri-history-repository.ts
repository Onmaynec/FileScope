import { invoke } from '@tauri-apps/api/core';

import {
  settingsService,
  type HistoryPreferences,
} from '../../../shared/services/settings-service';
import {
  minimizeReportForFutureStorage,
  type HistoryPrivacyPolicy,
} from './history-privacy';
import { inspectLegacyHistoryForMigration } from './legacy-history-migration';
import {
  LegacyLocalStorageReportHistoryRepository,
  MAXIMUM_REPORTS,
  type ReportHistoryRepository,
  type ReportHistorySnapshot,
} from './history-repository';
import type { AnalysisReport } from './types';

export const TAURI_HISTORY_STORAGE_VERSION = 2;

export interface TauriReportHistorySnapshot extends ReportHistorySnapshot {
  sizeBytes: number;
  generation?: string;
  backend: 'tauri';
}

export type HistoryProtectionStatus =
  | 'dpapiCurrentUser'
  | 'plaintext'
  | 'mixed'
  | 'empty'
  | 'unavailable'
  | 'notSupported';

export interface HistoryProtectionSnapshot {
  status: HistoryProtectionStatus;
  dpapiGenerations: number;
  plaintextGenerations: number;
  message?: string;
}

export type HistoryCommandBridge = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

export type HistoryPreferencesProvider = () => HistoryPreferences;

type PersistentHistorySnapshot = ReportHistorySnapshot & {
  backend?: 'tauri' | 'webview';
  protectionVerified?: boolean;
};

const defaultBridge: HistoryCommandBridge = (command, args) => invoke(command, args);
const defaultPreferencesProvider: HistoryPreferencesProvider = () => settingsService.load().history;

export class TauriReportHistoryRepository implements ReportHistoryRepository {
  private sessionReports: AnalysisReport[] = [];

  constructor(
    private readonly bridge: HistoryCommandBridge = defaultBridge,
    private readonly legacyRepository = new LegacyLocalStorageReportHistoryRepository(),
    private readonly preferencesProvider: HistoryPreferencesProvider = defaultPreferencesProvider,
  ) {}

  async load(): Promise<ReportHistorySnapshot> {
    const policy = this.preferencesProvider();
    const persistent = await this.loadPersistent(policy);
    const enforced = await this.enforcePersistentPolicy(persistent, policy);
    return this.combineWithSession(enforced, policy);
  }

  async save(report: AnalysisReport): Promise<ReportHistorySnapshot> {
    const policy = this.preferencesProvider();
    const preparedReport = minimizeReportForFutureStorage(report, privacyPolicy(policy));

    if (!policy.enabled || policy.retention === 'session') {
      this.sessionReports = upsertReport(this.sessionReports, preparedReport);
      const persistent = await this.enforcePersistentPolicy(await this.loadPersistent(policy), policy);
      return this.combineWithSession(persistent, policy, !policy.enabled
        ? 'Сохранение новых отчётов отключено: результат доступен только до закрытия FileScope.'
        : 'Выбран срок «текущий сеанс»: новый отчёт не записан на диск.');
    }

    const prepared = await this.enforcePersistentPolicy(await this.loadPersistent(policy), policy);
    if (prepared.status !== 'ready' && prepared.status !== 'empty') {
      this.sessionReports = upsertReport(this.sessionReports, preparedReport);
      return this.combineWithSession(prepared, policy,
        'Постоянное хранилище недоступно для записи: новый отчёт сохранён только в памяти текущего сеанса.');
    }

    const saved = await this.readTauri('history_save_report', { report: preparedReport });
    if (!saved.persisted || (saved.status !== 'ready' && saved.status !== 'empty')) {
      this.sessionReports = upsertReport(this.sessionReports, preparedReport);
    }
    return this.combineWithSession(saved, policy,
      saved.persisted ? undefined : 'Запись на диск не подтверждена: новый отчёт сохранён только в памяти текущего сеанса.');
  }

  async delete(id: string): Promise<ReportHistorySnapshot> {
    const policy = this.preferencesProvider();
    this.sessionReports = this.sessionReports.filter((report) => report.id !== id);
    const persistent = await this.enforcePersistentPolicy(await this.loadPersistent(policy), policy);

    if (persistent.status !== 'ready' && persistent.status !== 'empty') {
      return this.combineWithSession(persistent, policy);
    }
    if (persistent.backend !== 'tauri') {
      const legacy = await this.legacyRepository.delete(id);
      return this.combineWithSession(legacy, policy);
    }
    const deleted = await this.readTauri('history_delete_report', { id });
    return this.combineWithSession(deleted, policy);
  }

  async clear(): Promise<ReportHistorySnapshot> {
    this.sessionReports = [];
    const tauri = await this.readTauri('history_clear');
    if (tauri.status !== 'empty' || !tauri.persisted) return tauri;

    const legacy = await this.legacyRepository.clear();
    if (legacy.status !== 'empty' || !legacy.persisted) {
      return {
        reports: [],
        status: 'unavailable',
        persisted: false,
        message: legacy.message
          ? `Rust history удалена, но legacy report payload удалить полностью не удалось: ${legacy.message}`
          : 'Rust history удалена, но legacy report payload удалить полностью не удалось.',
      };
    }
    return {
      ...tauri,
      message: 'Rust history, session history и известные legacy report payload удалены полностью.',
    };
  }

  async inspect(): Promise<ReportHistorySnapshot> {
    const current = await this.readTauri('history_inspect');
    if (current.status !== 'empty') return current;
    const legacy = inspectLegacyHistoryForMigration();
    if (legacy.status === 'empty') return current;
    return {
      ...legacy,
      message: legacy.message
        ? `${legacy.message} Миграция будет выполнена при обычной загрузке истории, если разрешено постоянное сохранение.`
        : 'Обнаружена legacy history; миграция будет выполнена при обычной загрузке истории, если разрешено постоянное сохранение.',
    };
  }

  private async loadPersistent(policy: HistoryPreferences): Promise<PersistentHistorySnapshot> {
    const current = await this.readTauri('history_load');
    if (current.status !== 'empty') return current;

    const legacy = inspectLegacyHistoryForMigration();
    if (legacy.status === 'empty') return current;
    if (legacy.status !== 'ready') {
      return {
        ...legacy,
        backend: 'webview',
        message: legacy.message
          ? `${legacy.message} Rust history store оставлен пустым.`
          : 'Legacy history не может быть автоматически перенесена. Rust history store оставлен пустым.',
      };
    }

    const preparedLegacy = legacy.reports.map((report) =>
      minimizeReportForFutureStorage(report, privacyPolicy(policy)));
    if (!policy.enabled || policy.retention === 'session') {
      return {
        ...legacy,
        reports: preparedLegacy,
        backend: 'webview',
        message: !policy.enabled
          ? 'Legacy history открыта read-only: сохранение истории отключено, поэтому новая Rust-копия не создаётся.'
          : 'Legacy history открыта read-only: режим «текущий сеанс» не создаёт новую постоянную Rust-копию.',
      };
    }

    const retained = applyRetention(preparedLegacy, policy.retention);
    const migrated = await this.readTauri('history_replace_all', { reports: retained });
    if (migrated.persisted && (migrated.status === 'ready' || migrated.status === 'empty')) {
      return {
        ...migrated,
        protectionVerified: true,
        message: `История перенесена из ${legacy.sourceKey ?? 'legacy WebView storage'} в Rust/Tauri storage. Privacy/retention policy применена до записи. Legacy source сохранён только для rollback; новые отчёты туда не записываются.`,
      };
    }
    return migrated;
  }

  private async enforcePersistentPolicy(
    snapshot: PersistentHistorySnapshot,
    policy: HistoryPreferences,
  ): Promise<PersistentHistorySnapshot> {
    if (snapshot.backend !== 'tauri' || snapshot.status !== 'ready') return snapshot;

    const minimized = snapshot.reports.map((report) =>
      minimizeReportForFutureStorage(report, privacyPolicy(policy)));
    const retained = policy.retention === 'session'
      ? minimized
      : applyRetention(minimized, policy.retention);
    const reportsChanged = !sameReports(snapshot.reports, retained);

    if (!reportsChanged && snapshot.protectionVerified) return snapshot;

    let protection: HistoryProtectionSnapshot | undefined;
    if (!reportsChanged) {
      protection = await this.readProtectionStatus();
      if (protection.status !== 'plaintext' && protection.status !== 'mixed') return snapshot;
    }

    const rewritten = await this.readTauri('history_rewrite_all', { reports: retained });
    if (!rewritten.persisted) {
      return {
        ...snapshot,
        persisted: false,
        message: rewritten.message ?? 'Privacy/retention/DPAPI policy не удалось применить к постоянной истории.',
      };
    }
    const protectionMigration = protection?.status === 'plaintext' || protection?.status === 'mixed';
    return {
      ...rewritten,
      protectionVerified: true,
      message: retained.length < snapshot.reports.length
        ? `Retention policy автоматически удалил ${snapshot.reports.length - retained.length} устаревших отчётов.`
        : protectionMigration
          ? 'Legacy plaintext history безопасно переписана в Windows DPAPI current-user storage.'
          : 'Privacy policy применена к ранее сохранённой истории.',
    };
  }

  private combineWithSession(
    persistent: PersistentHistorySnapshot,
    policy: HistoryPreferences,
    extraMessage?: string,
  ): ReportHistorySnapshot & { backend?: 'tauri' | 'webview'; sizeBytes?: number; generation?: string; sessionReportCount?: number } {
    const reports = mergeReports(this.sessionReports, persistent.reports);
    const sessionReportCount = this.sessionReports.length;
    const message = [persistent.message, extraMessage].filter(Boolean).join(' ');
    const publicPersistent: PersistentHistorySnapshot = { ...persistent };
    delete publicPersistent.protectionVerified;
    return {
      ...publicPersistent,
      reports,
      status: reports.length ? 'ready' : persistent.status,
      persisted: sessionReportCount === 0 && persistent.persisted,
      message: message || undefined,
      sessionReportCount,
      ...(persistent.backend === 'tauri' ? { backend: 'tauri' as const } : {}),
      ...(policy.retention === 'session' || !policy.enabled
        ? { message: message || 'Новые отчёты хранятся только в памяти текущего сеанса.' }
        : {}),
    };
  }

  private async readTauri(
    command: string,
    args?: Record<string, unknown>,
  ): Promise<TauriReportHistorySnapshot> {
    try {
      const snapshot = await this.bridge<Omit<TauriReportHistorySnapshot, 'backend'>>(command, args);
      return { ...snapshot, backend: 'tauri' };
    } catch (error) {
      return {
        reports: [],
        status: 'unavailable',
        persisted: false,
        sizeBytes: 0,
        backend: 'tauri',
        message: `Rust history command ${command} недоступна: ${errorMessage(error)}`,
      };
    }
  }

  private readProtectionStatus(): Promise<HistoryProtectionSnapshot> {
    return readProtectionStatus(this.bridge);
  }
}

export async function inspectTauriHistoryProtection(
  bridge: HistoryCommandBridge = defaultBridge,
): Promise<HistoryProtectionSnapshot> {
  if (bridge === defaultBridge && !isTauriRuntime()) {
    return {
      status: 'notSupported',
      dpapiGenerations: 0,
      plaintextGenerations: 0,
      message: 'Windows DPAPI status доступен только в Tauri desktop runtime.',
    };
  }
  return readProtectionStatus(bridge);
}

export function createProductionReportHistoryRepository(): ReportHistoryRepository {
  return isTauriRuntime()
    ? new TauriReportHistoryRepository()
    : new LegacyLocalStorageReportHistoryRepository();
}

export function isTauriRuntime(): boolean {
  return typeof globalThis !== 'undefined'
    && '__TAURI_INTERNALS__' in (globalThis as unknown as Record<string, unknown>);
}

async function readProtectionStatus(bridge: HistoryCommandBridge): Promise<HistoryProtectionSnapshot> {
  try {
    return await bridge<HistoryProtectionSnapshot>('history_protection_status');
  } catch (error) {
    return {
      status: 'unavailable',
      dpapiGenerations: 0,
      plaintextGenerations: 0,
      message: `Не удалось получить Windows DPAPI status: ${errorMessage(error)}`,
    };
  }
}

function privacyPolicy(preferences: HistoryPreferences): HistoryPrivacyPolicy {
  return {
    preserveFullPath: preferences.preserveFullPath,
    preserveUrlQuery: preferences.preserveFullUrl,
    preserveUrlFragment: preferences.preserveFullUrl,
  };
}

function applyRetention(reports: AnalysisReport[], retention: HistoryPreferences['retention']): AnalysisReport[] {
  const retentionMs = retentionMilliseconds(retention);
  if (retentionMs === null) return reports.slice(0, MAXIMUM_REPORTS);
  const cutoff = Date.now() - retentionMs;
  return reports.filter((report) => reportTimestamp(report) >= cutoff).slice(0, MAXIMUM_REPORTS);
}

function retentionMilliseconds(retention: HistoryPreferences['retention']): number | null {
  if (retention === '1d') return 24 * 60 * 60 * 1000;
  if (retention === '7d') return 7 * 24 * 60 * 60 * 1000;
  if (retention === '30d') return 30 * 24 * 60 * 60 * 1000;
  return null;
}

function reportTimestamp(report: AnalysisReport): number {
  const completed = Date.parse(report.completedAt);
  if (Number.isFinite(completed)) return completed;
  const started = Date.parse(report.startedAt);
  return Number.isFinite(started) ? started : 0;
}

function upsertReport(reports: AnalysisReport[], report: AnalysisReport): AnalysisReport[] {
  return [report, ...reports.filter((item) => item.id !== report.id)].slice(0, MAXIMUM_REPORTS);
}

function mergeReports(session: AnalysisReport[], persistent: AnalysisReport[]): AnalysisReport[] {
  const ids = new Set(session.map((report) => report.id));
  return [...session, ...persistent.filter((report) => !ids.has(report.id))].slice(0, MAXIMUM_REPORTS);
}

function sameReports(left: AnalysisReport[], right: AnalysisReport[]): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}
