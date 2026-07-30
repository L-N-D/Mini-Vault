import readline from "node:readline";
import type { ShareProvider } from "./share-provider.js";

/** Hidden stdin prompts for Shamir share strings (no echo when TTY supports it). */
export class HiddenStdinShareProvider implements ShareProvider {
  async requestShares(k: number): Promise<string[]> {
    if (!Number.isInteger(k) || k < 1) {
      throw new Error("requestShares: k must be a positive integer");
    }
    const out: string[] = [];
    for (let i = 1; i <= k; i++) {
      const share = await this.promptHidden(`Share ${i}/${k}: `);
      out.push(share.trim());
    }
    return out;
  }

  private async promptHidden(prompt: string): Promise<string> {
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
