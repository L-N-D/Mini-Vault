import type { ShareProvider } from "./share-provider.js";

export class FakeShareProvider implements ShareProvider {
  constructor(private readonly shares: string[]) {}

  async requestShares(k: number): Promise<string[]> {
    if (k < 1 || !Number.isInteger(k)) {
      throw new Error("FakeShareProvider: k must be a positive integer");
    }
    if (this.shares.length < k) {
      throw new Error("FakeShareProvider: not enough preconfigured shares");
    }
    return this.shares.slice(0, k);
  }
}
