export interface QuarantineItem {
  id: string;
  displayName: string;
  originalPath: string;
  quarantinedAt: string;
  reason: string;
  canRestore: boolean;
  isDemo: true;
}

export interface IQuarantineService {
  list(): Promise<QuarantineItem[]>;
  add(displayName: string): Promise<QuarantineItem>;
  restore(id: string): Promise<void>;
  remove(id: string): Promise<void>;
}

export class MockQuarantineService implements IQuarantineService {
  private items: QuarantineItem[] = [];

  async list(): Promise<QuarantineItem[]> {
    return [...this.items];
  }

  async add(displayName: string): Promise<QuarantineItem> {
    const existing = this.items.find((item) => item.displayName === displayName);
    if (existing) return existing;
    const item: QuarantineItem = {
      id: `demo-quarantine-${this.items.length + 1}`,
      displayName,
      originalPath: `C:\\Demo\\${displayName}`,
      quarantinedAt: new Date().toISOString(),
      reason: 'Демонстрационное действие',
      canRestore: true,
      isDemo: true,
    };
    this.items = [...this.items, item];
    return item;
  }

  async restore(id: string): Promise<void> {
    this.items = this.items.filter((item) => item.id !== id);
  }

  async remove(id: string): Promise<void> {
    this.items = this.items.filter((item) => item.id !== id);
  }
}

export const quarantineService: IQuarantineService = new MockQuarantineService();
