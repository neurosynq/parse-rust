#!/usr/bin/env node
//
// Does the upstream checkout's `lib/` come from its `src/`?
//
// Usage: node tools/bench/verify-upstream-build.cjs <parse-server checkout>
//
// `lib/` is ignored by git, so a clean tree at the pin says nothing about what was built, and
// comparing modification times says only that something was built after the sources last
// changed, not from what. This recompiles every source file in memory with the checkout's own
// babel and `.babelrc`, exactly as `npm run build` does (`babel src/ -d lib/ --copy-files
// --extensions '.ts,.js'`), and compares the result to `lib/` byte for byte, inline source map
// included. Files `--copy-files` carries are compared as bytes.
//
// It also refuses what the comparison alone would miss:
//   - a change to `src/` that git sees, tracked or untracked, since `lib/` built from the pin is
//     then not what the sources say, and the sources are not the pin;
//   - two sources that compile to one output (`index.ts` and an `index.js` beside it), where
//     which one `lib/` holds depends on build order;
//   - a file in `lib/` that no source produces.
//
// What it cannot check: it trusts the checkout's `node_modules`. The compiler that rebuilds the
// sources and every runtime dependency parse-server loads come from there, and git pins neither;
// `npm ci` against the pinned lockfile is what makes them the pin's. A modified compiler that
// emits the same tampered output for `src/` and `lib/` would pass.
//
// Exits 0 and prints one line when `lib/` matches; exits 1 naming the differences otherwise.

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.resolve(process.argv[2] || '');
const src = path.join(root, 'src');
const lib = path.join(root, 'lib');
const problems = [];

function fail(message) {
  console.error(`verify-upstream-build: ${message}`);
  process.exit(1);
}

if (!process.argv[2] || !fs.existsSync(src)) fail(`no src/ under ${root}`);
if (!fs.existsSync(lib)) fail(`no lib/ under ${root}; run npm ci && npm run build there`);

let babel;
try {
  babel = require(require.resolve('@babel/core', { paths: [root] }));
} catch (e) {
  fail(`cannot load @babel/core from ${root}/node_modules; run npm ci there`);
}

const status = execFileSync('git', ['status', '--porcelain', '--untracked-files=all', '--', 'src'], {
  cwd: root,
  encoding: 'utf8',
});
for (const line of status.split('\n').filter(Boolean)) {
  problems.push(`src/ is not the pin's: ${line}`);
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const compiled = name => /\.(js|ts)$/.test(name) && !name.endsWith('.d.ts');
const produced = new Map();
for (const file of walk(src)) {
  const rel = path.relative(src, file);
  const outRel = compiled(rel) ? rel.replace(/\.ts$/, '.js') : rel;
  if (produced.has(outRel)) {
    problems.push(`src/${produced.get(outRel)} and src/${rel} both build lib/${outRel}`);
    continue;
  }
  produced.set(outRel, rel);
  const out = path.join(lib, outRel);
  if (!fs.existsSync(out)) {
    problems.push(`lib/${outRel} is missing; src/${rel} produces it`);
    continue;
  }
  if (compiled(rel)) {
    const want = babel.transformFileSync(file, {
      cwd: root,
      filename: file,
      sourceMaps: 'inline',
      sourceFileName: path.relative(path.dirname(out), file),
    }).code;
    if (fs.readFileSync(out, 'utf8').trimEnd() !== want.trimEnd()) {
      problems.push(`lib/${outRel} is not what src/${rel} compiles to`);
    }
  } else if (!fs.readFileSync(out).equals(fs.readFileSync(file))) {
    problems.push(`lib/${outRel} differs from src/${rel}`);
  }
}

for (const file of walk(lib)) {
  const rel = path.relative(lib, file);
  if (!produced.has(rel)) problems.push(`lib/${rel} has no source in src/`);
}

if (problems.length) {
  console.error(`verify-upstream-build: ${root}/lib was not built from its src/ at HEAD`);
  for (const p of problems.slice(0, 20)) console.error(`  ${p}`);
  if (problems.length > 20) console.error(`  and ${problems.length - 20} more`);
  console.error('  rebuild with npm run build, after restoring src/ to the pin');
  process.exit(1);
}
console.log(`verify-upstream-build: ${root}/lib matches src/ (${produced.size} files)`);
