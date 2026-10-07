//! The Rust side of the four comparable microbenchmark families, over every frozen corpus.
//!
//! The families are the ones the benchmark plan names as directly
//! comparable with Node: `json.decode`, `json.encode`, `parse-to-bson` and `bson-to-parse`. The
//! Node side is `js-micro/micro.mjs`, and the two share one measurement discipline, described on
//! [`measure`], so a cell's two records differ in the code under test and nothing else this
//! harness controls.
//!
//! Usage: `micro [--out <file>]`. Records are appended, so the Node side can write to the same
//! file afterwards.

use std::hint::black_box;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Instant;

use bson::Document;
use parse_rust_bench::{histogram, no_database, Corpus, Latency, Writer};
use parse_rust_core::op::OpPath;
use parse_rust_core::{classify_field, FieldWrite, ParseError, ParseMap, ParseValue};
use parse_rust_mongo::transform::{mongo_object_to_parse, parse_object_to_mongo_create};
use parse_rust_storage::{ClassSchema, FieldType};
use serde_json::{json, Value as Json};

/// The constants below are duplicated in `js-micro/micro.mjs`. Change both or neither.
const WARMUP: u64 = 1_000;
/// A timed sample spans at least this long. A single 200 B encode is near the timer's resolution
/// (one tick is about 42 ns on Apple silicon), so short operations are run in batches and each
/// sample records the batch's elapsed time divided by the batch size. The batch size is in the
/// record, so a reader can see when a percentile is a per-batch mean rather than one operation.
const MIN_SAMPLE_NS: u64 = 1_000;
/// Wall time to spend sampling one cell, which sets the sample count within the bounds below.
const BUDGET_NS: u64 = 400_000_000;
const MIN_SAMPLES: u64 = 1_000;
const MAX_SAMPLES: u64 = 100_000;

const CLASS_NAME: &str = "BenchObject";

/// Bytes to the decoded write body, the way the create path receives it.
///
/// This is the decode half of `parse_rust_rest::write::decode_write_body`, which this crate cannot
/// call because `parse-rust-rest` is not a dependency. It omits that function's `File` validation
/// walk, which finds nothing in these corpora, and collects into a `ParseMap` because no corpus
/// carries an operation.
fn decode(bytes: &[u8]) -> Result<ParseMap, ParseError> {
    let json: Json =
        serde_json::from_slice(bytes).map_err(|e| ParseError::invalid_json(e.to_string()))?;
    let Json::Object(fields) = json else {
        return Err(ParseError::invalid_json("body must be an object"));
    };
    let mut out = ParseMap::with_capacity(fields.len());
    for (key, value) in fields {
        match classify_field(value, OpPath::Create)? {
            FieldWrite::Value(v) => {
                out.insert(key, v);
            }
            FieldWrite::Op(_) => {
                return Err(ParseError::invalid_json("corpus carries an operation"));
            }
        }
    }
    Ok(out)
}

/// The class schema a create of this body would have produced: each top-level field typed by its
/// value. Pointer fields must be declared, or the transform does not give them their `_p_` column.
fn infer_schema(body: &ParseMap) -> ClassSchema {
    let mut schema = ClassSchema::new(CLASS_NAME);
    for (key, value) in body {
        let ty = match value {
            ParseValue::Bool(_) => FieldType::Boolean,
            ParseValue::Number(_) => FieldType::Number,
            ParseValue::String(_) => FieldType::String,
            ParseValue::Array(_) => FieldType::Array,
            ParseValue::Date(_) => FieldType::Date,
            ParseValue::Pointer { class_name, .. } => FieldType::Pointer {
                target_class: class_name.clone(),
            },
            ParseValue::GeoPoint { .. } => FieldType::GeoPoint,
            ParseValue::Bytes(_) => FieldType::Bytes,
            ParseValue::File { .. } => FieldType::File,
            ParseValue::Polygon(_) => FieldType::Polygon,
            ParseValue::Relation { class_name } => FieldType::Relation {
                target_class: class_name.clone(),
            },
            // A null creates no field upstream, so it has no type to declare.
            ParseValue::Null => continue,
            ParseValue::Object(_) => FieldType::Object,
        };
        schema = schema.with_field(key.clone(), ty);
    }
    schema
}

struct Measured {
    latency: Latency,
    iterations: u64,
    samples: u64,
    batch: u64,
}

/// Warm up, size the batch and the sample count from the warmup, then time each sample.
///
/// Warmup runs `WARMUP` operations untimed except for their total, which estimates the cost of
/// one. The batch is the smallest count whose expected duration reaches `MIN_SAMPLE_NS`, and the
/// sample count is what fits in `BUDGET_NS`, clamped. Every sample's per-operation nanoseconds go
/// into the histogram.
fn measure(mut op: impl FnMut()) -> Measured {
    let start = Instant::now();
    for _ in 0..WARMUP {
        op();
    }
    let per_op = (start.elapsed().as_nanos() as u64 / WARMUP).max(1);
    let batch = MIN_SAMPLE_NS.div_ceil(per_op).max(1);
    let samples = (BUDGET_NS / (per_op * batch)).clamp(MIN_SAMPLES, MAX_SAMPLES);

    let mut hist = histogram();
    for _ in 0..samples {
        let t = Instant::now();
        for _ in 0..batch {
            op();
        }
        let ns = (t.elapsed().as_nanos() as u64 / batch).max(1);
        // Out of range means above an hour, which no operation here approaches.
        let _ = hist.record(ns);
    }
    Measured {
        latency: Latency::from_nanos(&hist),
        iterations: samples * batch,
        samples,
        batch,
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn context() -> Json {
    json!({
        "git_sha": command_output("git", &["rev-parse", "HEAD"]),
        "git_dirty": !command_output("git", &["status", "--porcelain"]).is_empty(),
        "rustc": command_output("rustc", &["--version"]),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": command_output("uname", &["-sr"]),
    })
}

fn out_path() -> Result<PathBuf, String> {
    let args: Vec<String> = std::env::args().collect();
    match args.iter().position(|a| a == "--out") {
        Some(i) => args
            .get(i + 1)
            .map(PathBuf::from)
            .ok_or_else(|| "--out needs a path".to_string()),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/bench")
                .join(format!("micro-{ts}.jsonl")))
        }
    }
}

/// Everything a cell needs prepared outside its timed loop, built once per corpus and checked to
/// succeed before anything is timed, so an error inside a loop cannot masquerade as a fast run.
struct Prepared {
    body: ParseMap,
    value: ParseValue,
    schema: ClassSchema,
    doc: Document,
}

fn prepare(corpus: &Corpus) -> Result<Prepared, String> {
    let body = decode(&corpus.bytes).map_err(|e| format!("{}: decode: {e:?}", corpus.name))?;
    let schema = infer_schema(&body);
    let doc = parse_object_to_mongo_create(&schema, &body)
        .map_err(|e| format!("{}: parse-to-bson: {e:?}", corpus.name))?;
    let raised = mongo_object_to_parse(&schema, &doc)
        .map_err(|e| format!("{}: bson-to-parse: {e:?}", corpus.name))?;
    if raised.len() != body.len() {
        return Err(format!(
            "{}: round trip changed the field count from {} to {}",
            corpus.name,
            body.len(),
            raised.len()
        ));
    }
    Ok(Prepared {
        value: ParseValue::Object(body.clone()),
        body,
        schema,
        doc,
    })
}

fn run() -> Result<PathBuf, String> {
    let path = out_path()?;
    let corpora = Corpus::all().map_err(|e| format!("cannot load corpora: {e}"))?;
    let mut writer = Writer::create(path.clone()).map_err(|e| e.to_string())?;
    let ctx = context();

    for corpus in &corpora {
        let p = prepare(corpus)?;
        let cells: [(&str, &str, Measured); 4] = [
            (
                "json.decode",
                "serde_json::from_slice, then parse_rust_core::classify_field(OpPath::Create) per \
                 field into a ParseMap",
                measure(|| {
                    let _ = black_box(decode(black_box(&corpus.bytes)));
                }),
            ),
            (
                "json.encode",
                "parse_rust_core::ParseValue::to_json on the decoded body",
                measure(|| {
                    black_box(black_box(&p.value).to_json());
                }),
            ),
            (
                "parse-to-bson",
                "parse_rust_mongo::transform::parse_object_to_mongo_create on the decoded body, \
                 schema declaring every top-level field",
                measure(|| {
                    let _ = black_box(parse_object_to_mongo_create(
                        black_box(&p.schema),
                        black_box(&p.body),
                    ));
                }),
            ),
            (
                "bson-to-parse",
                "parse_rust_mongo::transform::mongo_object_to_parse on the parse-to-bson output",
                measure(|| {
                    let _ = black_box(mongo_object_to_parse(
                        black_box(&p.schema),
                        black_box(&p.doc),
                    ));
                }),
            ),
        ];
        for (family, method, m) in cells {
            println!(
                "rust  {family:<14} {:<13} p50 {:>9.3} us  batch {}",
                corpus.name, m.latency.p50, m.batch
            );
            writer
                .write(json!({
                    "kind": "micro",
                    "target": "rust",
                    "family": family,
                    "method": method,
                    "corpus": { "name": corpus.name, "hash": corpus.hash },
                    "latency_us": m.latency,
                    "iterations": m.iterations,
                    "samples": m.samples,
                    "batch": m.batch,
                    "warmup": WARMUP,
                    "db_share_p50": no_database(),
                    "transport": "none",
                    "context": ctx,
                }))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(path)
}

fn main() -> ExitCode {
    match run() {
        Ok(path) => {
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("micro: {e}");
            ExitCode::FAILURE
        }
    }
}
