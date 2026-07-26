import readline from "node:readline";
import type { MasterPassphraseProvider } from "./master-passphrase-provider.js";

/** Hidden stdin prompt — does not echo characters when TTY supports it. */
export class HiddenStdinPassphraseProvider implements MasterPassphraseProvider {
  async requestPassphrase(prompt = "Master Passphrase: "): Promise<string> {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY) {
      stdin.setRawMode?.(true);
    }

    return new Promise((resolve, reject) => {
      process.stdout.write(prompt);
      let buf = "";

      const onData = (chunk: Buffer) => {
        const s = chunk.toString("utf8");
        for (const ch of s) {
          if (ch === "\n" || ch === "\r") {
            cleanup();
            process.stdout.write("\n");
            resolve(buf);
            return;
          }
          if (ch === "\u0003") {
            cleanup();
            reject(new Error("Interrupted"));
            return;
          }
          if (ch === "\u007f" || ch === "\b") {
            buf = buf.slice(0, -1);
            continue;
          }
          buf += ch;
        }
      };

      const cleanup = () => {
        stdin.off("data", onData);
        if (stdin.isTTY) {
          stdin.setRawMode?.(wasRaw ?? false);
        }
        rl.close();
      };

      stdin.on("data", onData);
    });
  }
}
