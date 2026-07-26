import type { MasterPassphraseProvider } from "./master-passphrase-provider.js";

export class FakePassphraseProvider implements MasterPassphraseProvider {
  private index = 0;

  constructor(private readonly phrases: string[]) {}

  async requestPassphrase(_prompt?: string): Promise<string> {
    const value = this.phrases[this.index] ?? this.phrases[this.phrases.length - 1];
    this.index += 1;
    if (value === undefined) {
      throw new Error("FakePassphraseProvider exhausted");
    }
    return value;
  }
}
