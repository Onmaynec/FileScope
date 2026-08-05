export interface UpdateCheckResult {
  status: 'upToDate' | 'available' | 'error';
  currentVersion: string;
  availableVersion?: string;
  releaseNotes?: string[];
}

export interface IUpdateService {
  checkForUpdates(): Promise<UpdateCheckResult>;
}

export class MockUpdateService implements IUpdateService {
  async checkForUpdates(): Promise<UpdateCheckResult> {
    await new Promise((resolve) => window.setTimeout(resolve, 350));
    return {
      status: 'upToDate',
      currentVersion: '0.1.0',
    };
  }
}

export const updateService: IUpdateService = new MockUpdateService();
