#!/usr/bin/env node
// Bundled declaration build (issue #482).
//
// tsup's `dts: true` drives a copy of rollup-plugin-dts vendored inside tsup
// itself, and that copy calls the TypeScript compiler API. TypeScript 7's
// `typescript` package ships no compiler API (its main export is a version
// string), so `dts: true` crashes on TS7 and no released tsup fixes it.
//
// This script reproduces what tsup's dts step did, in two stages:
//
//   1. TypeScript 7's own `tsc` emits per-file declarations for `src/` into a
//      scratch directory (tsconfig.dts.json). The declarations therefore come
//      from the same compiler that typechecks the package.
//   2. rollup + rollup-plugin-dts (>= 6.5, which supports TS7 by loading the
//      `@typescript/typescript6` API package) bundles those `.d.ts` files into
//      the same entry/chunk layout tsup produced: one rollup build written
//      twice, `[name].d.ts` for ESM and `[name].d.cts` for CJS.
//
// The JS bundles are still built by tsup (`dts: false`); this script only
// writes declaration files. It fails non-zero on any compiler or bundling
// error, so a broken declaration build cannot pass as green.

import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { rollup } from "rollup";
import { dts } from "rollup-plugin-dts";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmpDir = path.join(root, ".dts-tmp");
const outDir = path.join(root, "dist");

// Keep in step with tsup.config.ts `entry`.
const ENTRIES = ["index", "hono", "behavior", "state", "protectionCatalog"];

// Resolve TypeScript 7's compiler explicitly. Do NOT use `node_modules/.bin/tsc`:
// `@typescript/typescript6` depends on `@typescript/old` (an alias of
// typescript@6) whose `tsc` bin is what npm links there.
const tsPkgPath = require.resolve("typescript/package.json");
const tsPkg = JSON.parse(readFileSync(tsPkgPath, "utf8"));
if (!/^7\./.test(tsPkg.version)) {
  console.error(`build-dts: expected TypeScript 7, found ${tsPkg.version}`);
  process.exit(1);
}
const tscBin = path.join(path.dirname(tsPkgPath), "bin", "tsc");

class BuildError extends Error {}

rmSync(tmpDir, { recursive: true, force: true });
try {
  const tsc = spawnSync(process.execPath, [tscBin, "-p", "tsconfig.dts.json"], {
    cwd: root,
    stdio: "inherit",
  });
  if (tsc.status !== 0) {
    throw new BuildError(`tsc ${tsPkg.version} failed (exit ${tsc.status})`);
  }

  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  // Same rule tsup used: dependencies + peerDependencies stay external.
  const deps = [
    ...new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.peerDependencies ?? {}),
    ]),
  ];

  const input = {};
  for (const name of ENTRIES) {
    const file = path.join(tmpDir, `${name}.d.ts`);
    if (!existsSync(file)) {
      throw new BuildError(`tsc did not emit ${path.relative(root, file)}`);
    }
    input[name] = file;
  }

  const bundle = await rollup({
    input,
    plugins: [dts()],
    external: deps.map((dep) => new RegExp(`^${dep}($|\\/|\\\\)`)),
    onwarn(warning, handler) {
      // Same warnings tsup suppressed for its dts build.
      if (
        warning.code === "UNRESOLVED_IMPORT" ||
        warning.code === "CIRCULAR_DEPENDENCY" ||
        warning.code === "EMPTY_BUNDLE"
      ) {
        return;
      }
      handler(warning);
    },
  });
  try {
    for (const ext of [".d.ts", ".d.cts"]) {
      await bundle.write({
        dir: outDir,
        format: "esm",
        exports: "named",
        entryFileNames: `[name]${ext}`,
        // Chunk names come from the `.d.ts` module id (`protect.d`); strip the
        // `.d` so the shared chunk keeps tsup's `<name>-<hash>` shape.
        chunkFileNames: (chunk) =>
          `${chunk.name.replace(/\.d$/, "")}-[hash]${ext}`,
      });
    }
  } finally {
    await bundle.close();
  }

  // Every file the package's `exports` map points at must exist, so a missed
  // entry or a renamed output fails the build instead of shipping.
  const targets = [pkg.main, pkg.module, pkg.types];
  const walk = (node) => {
    if (typeof node === "string") targets.push(node);
    else if (node && typeof node === "object") Object.values(node).forEach(walk);
  };
  walk(pkg.exports);
  const missing = [...new Set(targets)]
    .filter((t) => t && t.startsWith("./dist/"))
    .filter((t) => !existsSync(path.join(root, t)));
  if (missing.length > 0) {
    throw new BuildError(`exports map points at missing files: ${missing.join(", ")}`);
  }
} catch (err) {
  if (!(err instanceof BuildError)) throw err;
  console.error(`build-dts: ${err.message}`);
  process.exitCode = 1;
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
