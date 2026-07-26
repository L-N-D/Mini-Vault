export interface MasterPassphraseProvider {
  requestPassphrase(prompt?: string): Promise<string>;
}
