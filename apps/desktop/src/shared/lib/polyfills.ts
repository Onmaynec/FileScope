declare global {
  interface Array<T> {
    toSorted(compareFn?: (left: T, right: T) => number): T[];
  }
}

if (!Array.prototype.toSorted) {
  Object.defineProperty(Array.prototype, 'toSorted', {
    value<T>(this: T[], compareFn?: (left: T, right: T) => number): T[] {
      return [...this].sort(compareFn);
    },
    configurable: true,
    writable: true,
  });
}

export {};
