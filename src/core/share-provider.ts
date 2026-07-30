export interface ShareProvider {
  requestShares(k: number): Promise<string[]>;
}
