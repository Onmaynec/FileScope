declare global {
  const describe: (name: string, fn: () => void) => void;
  const it: {
    (name: string, fn: () => Promise<void | symbol>): void;
    only(name: string, fn: () => Promise<void | symbol>): void;
    skip(name: string, fn: () => Promise<void | symbol>): void;
    todo(name: string): void;
  };
  const test: typeof it;
  const expect: (actual: unknown) => import('vitest').Assertion<unknown>;
  const beforeEach: (fn: () => void | Promise<void>) => void;
  const afterEach: (fn: () => void | Promise<void>) => void;
  const beforeAll: (fn: () => void | Promise<void>) => void;
  const afterAll: (fn: () => void | Promise<void>) => void;
}

declare module 'vitest' {
  interface Assertion {
    toHaveTextContent(text: string | RegExp): void;
    toHaveAttribute(name: string, value?: string): void;
  }
}

export {};
