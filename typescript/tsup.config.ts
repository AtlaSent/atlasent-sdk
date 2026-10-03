import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/hono.ts",
    "src/behavior.ts",
    "src/state.ts",
    "src/protectionCatalog.ts",
  ],
  format: ["esm", "cjs"],
  target: "node20",
  // Declarations are built by scripts/build-dts.mjs (TypeScript 7; see #482).
  dts: false,
  sourcemap: true,
  clean: true,
  splitting: false,
  minify: false,
  outExtension({ format }) {
    return { js: format === "cjs" ? ".cjs" : ".js" };
  },
});
