import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root,
  plugins: [
    {
      name: "resolve-js-to-ts",
      enforce: "pre",
      resolveId(source, importer) {
        if (!importer || !source.endsWith(".js")) return null;
        if (source.startsWith("\0") || source.includes("node_modules")) {
          return null;
        }
        const base = path.dirname(importer);
        const candidate = path.resolve(base, source.replace(/\.js$/, ".ts"));
        if (fs.existsSync(candidate)) {
          return candidate;
        }
        return null;
      },
    },
  ],
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
