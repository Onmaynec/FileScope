export interface LicenseState {
  tier: 'free' | 'pro';
  status: 'active' | 'expired' | 'unavailable';
  expiresAt?: string;
  autoRenew: boolean;
  source: 'local' | 'account' | 'development';
}

export interface ILicenseService {
  getState(): Promise<LicenseState>;
  restore(): Promise<LicenseState>;
}

export class MockLicenseService implements ILicenseService {
  async getState(): Promise<LicenseState> {
    return { tier: 'free', status: 'active', autoRenew: false, source: 'local' };
  }

  async restore(): Promise<LicenseState> {
    return { tier: 'free', status: 'active', autoRenew: false, source: 'local' };
  }
}

export const licenseService: ILicenseService = new MockLicenseService();
