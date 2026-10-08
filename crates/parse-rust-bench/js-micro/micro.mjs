// The Node side of the four comparable microbenchmark families, over every frozen corpus.
//
// Counterpart to `src/bin/micro.rs`. The code under test is the pinned upstream's own built
// modules, resolved from PARSE_SERVER_ROOT (default ../parse-server-pinned, relative to the
// repository root), so the number is parse-server's and not a reimplementation of it.
//
// The measurement discipline is the Rust side's, constant for constant. Records have the same
// shape, and the corpus hash is computed the same way (sha256 of the file bytes, first 16 hex
// characters), so a cell's two records pair up by (family, corpus.name, corpus.hash).
//
// Usage: node micro.mjs [--out <file>]. Records are appended.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const corpusDir = path.resolve(here, '../corpus');
const upstreamRoot = path.resolve(
  repoRoot,
  process.env.PARSE_SERVER_ROOT || '../parse-server-pinned'
);

// Duplicated from micro.rs. Change both or neither.
const WARMUP = 1000n;
// A 200 B operation is near hrtime's useful resolution, so short operations are batched and a
// sample is the batch's elapsed time divided by the batch size. `batch` is in the record.
const MIN_SAMPLE_NS = 1000n;
const BUDGET_NS = 400_000_000n;
const MIN_SAMPLES = 1000n;
const MAX_SAMPLES = 100_000n;

const SIZES = ['200b', '2kb', '8kb'];
const SHAPES = ['flat', 'nested', 'pointers', 'dated'];
const CLASS_NAME = 'BenchObject';
const SCHEMA = 'parse-rust-bench/1';
const VERDICT = 'baseline-unclassified';

const require = createRequire(path.join(upstreamRoot, 'package.json'));
const { parseObjectToMongoObjectForCreate, mongoObjectToParseObject } = require(
  path.join(upstreamRoot, 'lib/Adapters/Storage/Mongo/MongoTransform.js')
);

function sha256Hex16(bytes) {
  return createHash('sha256').update(bytes).digest('hex').slice(0, 16);
}

function git(cwd, args) {
  try {
    return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

function pinnedSha() {
  try {
    const line = readFileSync(path.join(repoRoot, 'PIN'), 'utf8')
      .split('\n')
      .find(l => l.startsWith('parse-server '));
    return line ? line.split(/\s+/)[2] : 'unknown';
  } catch {
    return 'unknown';
  }
}

function outPath() {
  const i = process.argv.indexOf('--out');
  if (i >= 0) {
    if (!process.argv[i + 1]) {
      throw new Error('--out needs a path');
    }
    return path.resolve(process.argv[i + 1]);
  }
  const ts = Math.floor(Date.now() / 1000);
  return path.join(repoRoot, 'target/bench', `micro-${ts}.jsonl`);
}

// What upstream does to a create body between the wire and the schema check: body-parser's
// JSON.parse, then RestWrite's `this.data = structuredClone(data)` (RestWrite.js:78). Upstream
// has no typed decode step; type recognition happens later, inside validateObject's getType,
// which is not exported and needs a loaded schema.
function decode(bytes) {
  return structuredClone(JSON.parse(bytes));
}

// The schema shape MongoTransform reads (`schema.fields[key].type`), typed by value the way
// getType would (SchemaController.js:1555), for the corpus's top-level fields.
function inferSchema(body) {
  const fields = {};
  for (const [key, value] of Object.entries(body)) {
    if (value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      fields[key] = { type: 'Array' };
    } else if (typeof value === 'object') {
      if (value.__type === 'Pointer') {
        fields[key] = { type: 'Pointer', targetClass: value.className };
      } else if (value.__type) {
        fields[key] = { type: value.__type };
      } else {
        fields[key] = { type: 'Object' };
      }
    } else {
      fields[key] = { type: { boolean: 'Boolean', number: 'Number', string: 'String' }[typeof value] };
    }
  }
  return { fields };
}

// Exact order statistics over the per-operation samples, with HdrHistogram's rank rule (the
// smallest value at or above the quantile). Node carries no HdrHistogram, and the Rust side's is
// set to three significant figures, so the two agree to within 0.1 percent of a value.
function latency(samplesNs) {
  const sorted = Float64Array.from(samplesNs).sort();
  const at = q => sorted[Math.max(0, Math.ceil(q * sorted.length) - 1)] / 1000;
  return {
    p50: at(0.5),
    p90: at(0.9),
    p99: at(0.99),
    p999: at(0.999),
    max: sorted[sorted.length - 1] / 1000,
    samples: sorted.length,
  };
}

const bigMax = (a, b) => (a > b ? a : b);
const bigClamp = (v, lo, hi) => (v < lo ? lo : v > hi ? hi : v);

// Warm up, size the batch and sample count from the warmup, then time each sample. See
// `measure` in micro.rs; this is the same procedure.
function measure(op) {
  let start = process.hrtime.bigint();
  for (let i = 0n; i < WARMUP; i++) {
    op();
  }
  const perOp = bigMax((process.hrtime.bigint() - start) / WARMUP, 1n);
  const batch = bigMax((MIN_SAMPLE_NS + perOp - 1n) / perOp, 1n);
  const samples = bigClamp(BUDGET_NS / (perOp * batch), MIN_SAMPLES, MAX_SAMPLES);

  const out = new Array(Number(samples));
  const b = Number(batch);
  let sink = 0;
  for (let s = 0; s < out.length; s++) {
    const t = process.hrtime.bigint();
    for (let i = 0; i < b; i++) {
      // Keeps the result observable so the call cannot be eliminated.
      if (op() === sink) {
        sink++;
      }
    }
    out[s] = Number(bigMax((process.hrtime.bigint() - t) / batch, 1n));
  }
  return {
    latency: latency(out),
    iterations: Number(samples * batch),
    samples: Number(samples),
    batch: b,
  };
}

function writeRecord(file, record) {
  for (const required of ['db_share_p50', 'transport']) {
    if (!(required in record)) {
      throw new Error(`refusing a record without \`${required}\`: ${JSON.stringify(record)}`);
    }
  }
  appendFileSync(file, JSON.stringify({ ...record, schema: SCHEMA, verdict: VERDICT }) + '\n');
}

function main() {
  const file = outPath();
  mkdirSync(path.dirname(file), { recursive: true });
  const context = {
    git_sha: git(repoRoot, ['rev-parse', 'HEAD']),
    git_dirty: git(repoRoot, ['status', '--porcelain']) !== '',
    node: process.version,
    upstream_root: upstreamRoot,
    upstream_sha: git(upstreamRoot, ['rev-parse', 'HEAD']),
    upstream_dirty: git(upstreamRoot, ['status', '--porcelain', '--untracked-files=no']) !== '',
    pin_sha: pinnedSha(),
    os: os.platform(),
    arch: os.arch(),
    kernel: `${os.type()} ${os.release()}`,
  };
  const noDatabase = { not_measured: 'no database in this measurement' };

  for (const size of SIZES) {
    for (const shape of SHAPES) {
      const name = `${size}-${shape}`;
      const bytes = readFileSync(path.join(corpusDir, `${name}.json`));
      const hash = sha256Hex16(bytes);
      // JSON.parse takes a string. Decoding UTF-8 is part of what body-parser does too, so it is
      // inside the timed operation.
      const body = decode(bytes.toString('utf8'));
      const schema = inferSchema(body);
      const doc = parseObjectToMongoObjectForCreate(CLASS_NAME, body, schema);
      const raised = mongoObjectToParseObject(CLASS_NAME, doc, schema);
      if (Object.keys(raised).length !== Object.keys(body).length) {
        throw new Error(`${name}: round trip changed the field count`);
      }

      const cells = [
        [
          'json.decode',
          'utf8 decode, JSON.parse, then structuredClone as RestWrite does (RestWrite.js:78)',
          () => decode(bytes.toString('utf8')),
        ],
        ['json.encode', 'JSON.stringify on the decoded body', () => JSON.stringify(body)],
        [
          'parse-to-bson',
          'MongoTransform.parseObjectToMongoObjectForCreate on the decoded body, schema declaring every top-level field',
          () => parseObjectToMongoObjectForCreate(CLASS_NAME, body, schema),
        ],
        [
          'bson-to-parse',
          'MongoTransform.mongoObjectToParseObject on the parse-to-bson output',
          () => mongoObjectToParseObject(CLASS_NAME, doc, schema),
        ],
      ];
      for (const [family, method, op] of cells) {
        const m = measure(op);
        console.log(
          `node  ${family.padEnd(14)} ${name.padEnd(13)} p50 ${m.latency.p50
            .toFixed(3)
            .padStart(9)} us  batch ${m.batch}`
        );
        writeRecord(file, {
          kind: 'micro',
          target: 'node',
          family,
          method,
          corpus: { name, hash },
          latency_us: m.latency,
          iterations: m.iterations,
          samples: m.samples,
          batch: m.batch,
          warmup: Number(WARMUP),
          db_share_p50: noDatabase,
          transport: 'none',
          context,
        });
      }
    }
  }
  console.log(`wrote ${file}`);
}

try {
  main();
} catch (e) {
  console.error(`micro.mjs: ${e.stack || e}`);
  process.exit(1);
}
