import type { AnalysisReport } from './types';

export interface HistoryPrivacyPolicy {
  preserveFullPath: boolean;
  preserveUrlQuery: boolean;
  preserveUrlFragment: boolean;
}

export const proposedV040PrivacyPolicy: HistoryPrivacyPolicy = {
  preserveFullPath: false,
  preserveUrlQuery: false,
  preserveUrlFragment: false,
};

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key',
  'x-auth-token', 'proxy-authenticate', 'www-authenticate',
]);

export function redactUrlForHistory(value: string, policy: HistoryPrivacyPolicy): string {
  try {
    const parsed = new URL(value);
    parsed.username = '';
    parsed.password = '';
    if (!policy.preserveUrlQuery) parsed.search = '';
    if (!policy.preserveUrlFragment) parsed.hash = '';
    return parsed.toString();
  } catch {
    return value.replace(/\/\/[^/@\s]+@/g, '//[credentials-redacted]@');
  }
}

export function minimizePathForHistory(value: string, preserveFullPath: boolean): string {
  if (preserveFullPath) return value;
  const normalized = value.replaceAll('\\', '/');
  return normalized.split('/').filter(Boolean).at(-1) ?? value;
}

export function filterHeadersForHistory(headers: [string, string][]): [string, string][] {
  return headers.filter(([name]) => !SENSITIVE_HEADER_NAMES.has(name.trim().toLocaleLowerCase('en-US')));
}

export function minimizeReportForFutureStorage(
  report: AnalysisReport,
  policy: HistoryPrivacyPolicy = proposedV040PrivacyPolicy,
): AnalysisReport {
  const isUrl = report.objectKind === 'url';
  const target = isUrl
    ? redactUrlForHistory(report.target, policy)
    : minimizePathForHistory(report.target, policy.preserveFullPath);
  const originalHeaders = report.url?.responseHeaders ?? [];
  const filteredHeaders = filterHeadersForHistory(originalHeaders);
  const previousRedactions = readPreviousRedactions(report.metadata.privacyRedactions);
  const credentialsRemovedFromUrls = previousRedactions.credentialsRemovedFromUrls
    || isUrl
    || Boolean(report.url);
  const fullPathMinimized = previousRedactions.fullPathMinimized
    || (!isUrl && !policy.preserveFullPath);
  const queryRemovedFromUrls = previousRedactions.queryRemovedFromUrls || !policy.preserveUrlQuery;
  const fragmentRemovedFromUrls = previousRedactions.fragmentRemovedFromUrls || !policy.preserveUrlFragment;
  const sensitiveResponseHeadersRemoved = previousRedactions.sensitiveResponseHeadersRemoved
    + (originalHeaders.length - filteredHeaders.length);
  const url = report.url
    ? {
        ...report.url,
        normalizedUrl: redactUrlForHistory(report.url.normalizedUrl, policy),
        finalUrl: report.url.finalUrl ? redactUrlForHistory(report.url.finalUrl, policy) : undefined,
        responseHeaders: filteredHeaders,
      }
    : undefined;
  return {
    ...report,
    target,
    url,
    metadata: {
      ...report.metadata,
      privacyPreparedForV040: true,
      fullPathPreserved: policy.preserveFullPath && !fullPathMinimized,
      urlQueryPreserved: policy.preserveUrlQuery && !queryRemovedFromUrls,
      urlFragmentPreserved: policy.preserveUrlFragment && !fragmentRemovedFromUrls,
      privacyRedactions: {
        credentialsRemovedFromUrls,
        fullPathMinimized,
        queryRemovedFromUrls,
        fragmentRemovedFromUrls,
        sensitiveResponseHeadersRemoved,
      },
    },
  };
}

function readPreviousRedactions(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {
      credentialsRemovedFromUrls: false,
      fullPathMinimized: false,
      queryRemovedFromUrls: false,
      fragmentRemovedFromUrls: false,
      sensitiveResponseHeadersRemoved: 0,
    };
  }
  const redactions = value as Record<string, unknown>;
  return {
    credentialsRemovedFromUrls: redactions.credentialsRemovedFromUrls === true,
    fullPathMinimized: redactions.fullPathMinimized === true,
    queryRemovedFromUrls: redactions.queryRemovedFromUrls === true,
    fragmentRemovedFromUrls: redactions.fragmentRemovedFromUrls === true,
    sensitiveResponseHeadersRemoved: typeof redactions.sensitiveResponseHeadersRemoved === 'number'
      && Number.isFinite(redactions.sensitiveResponseHeadersRemoved)
      && redactions.sensitiveResponseHeadersRemoved > 0
      ? Math.floor(redactions.sensitiveResponseHeadersRemoved)
      : 0,
  };
}
