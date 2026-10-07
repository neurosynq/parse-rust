//! The benchmark harness's shared pieces: the record every measurement is written as, the frozen
//! corpora, and histogram summaries.
//!
//! **Two fields are load-bearing and the writer refuses a record without them**: `db_share` and
//! `transport`. They are the two mechanisms that keep
//! a number honest about what it measured, and the first place either would quietly decay into
//! optional metadata is a writer that accepts a record missing them. Where a measurement has no
//! database share, a microbenchmark or an uninstrumented historical binary, the field is present
//! and says so.
//!
//! Every 0.3.0 record is labelled `baseline-unclassified`. No `faster`, `slower` or `equivalent`
//! verdict is written until 0.4.0's A/A noise floor exists to justify one.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The schema every record carries, so a reader can refuse one it does not understand.
pub const SCHEMA: &str = "parse-rust-bench/1";

/// The only verdict 0.3.0 may write.
pub const VERDICT: &str = "baseline-unclassified";

/// The nine frozen corpora: three sizes in three shapes.
pub const SIZES: [&str; 3] = ["200b", "2kb", "8kb"];
pub const SHAPES: [&str; 3] = ["flat", "nested", "pointers"];

/// Where the committed corpora live.
pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

/// One frozen corpus: its name, its bytes and their hash.
#[derive(Debug, Clone)]
pub struct Corpus {
    pub name: String,
    pub bytes: Vec<u8>,
    pub hash: String,
}

impl Corpus {
    pub fn load(size: &str, shape: &str) -> std::io::Result<Self> {
        let name = format!("{size}-{shape}");
        let bytes = std::fs::read(corpus_dir().join(format!("{name}.json")))?;
        let hash = sha256_hex(&bytes);
        Ok(Self { name, bytes, hash })
    }

    pub fn all() -> std::io::Result<Vec<Self>> {
        let mut out = Vec::new();
        for size in SIZES {
            for shape in SHAPES {
                out.push(Self::load(size, shape)?);
            }
        }
        Ok(out)
    }

    /// The corpus as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..16]
        .to_string()
}

/// Percentiles in microseconds from a histogram recorded in nanoseconds.
#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
    pub samples: u64,
}

impl Latency {
    pub fn from_nanos(h: &hdrhistogram::Histogram<u64>) -> Self {
        let us = |v: u64| v as f64 / 1000.0;
        Self {
            p50: us(h.value_at_quantile(0.50)),
            p90: us(h.value_at_quantile(0.90)),
            p99: us(h.value_at_quantile(0.99)),
            p999: us(h.value_at_quantile(0.999)),
            max: us(h.max()),
            samples: h.len(),
        }
    }
}

/// A new histogram: nanoseconds, up to an hour, three significant figures.
pub fn histogram() -> hdrhistogram::Histogram<u64> {
    hdrhistogram::Histogram::new_with_bounds(1, 3_600_000_000_000, 3)
        .unwrap_or_else(|_| hdrhistogram::Histogram::new(3).unwrap_or_else(|_| unreachable_hist()))
}

fn unreachable_hist() -> hdrhistogram::Histogram<u64> {
    // `new(3)` cannot fail for a significant-figure count in range; this keeps the function total.
    hdrhistogram::Histogram::new(2).expect("two significant figures is always valid")
}

/// Appends records to a run's JSONL file, refusing any without `db_share` or `transport`.
pub struct Writer {
    file: std::fs::File,
    pub path: PathBuf,
}

impl Writer {
    pub fn create(path: PathBuf) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self { file, path })
    }

    pub fn write(&mut self, mut record: Value) -> std::io::Result<()> {
        let obj = record
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("a record must be an object"))?;
        for required in ["db_share_p50", "transport"] {
            if !obj.contains_key(required) {
                return Err(std::io::Error::other(format!(
                    "refusing a record without `{required}`: {}",
                    Value::Object(obj.clone())
                )));
            }
        }
        obj.insert("schema".into(), json!(SCHEMA));
        obj.insert("verdict".into(), json!(VERDICT));
        writeln!(self.file, "{}", serde_json::to_string(&record)?)?;
        Ok(())
    }
}

/// `db_share` for a measurement with no database in it at all.
pub fn no_database() -> Value {
    json!({ "not_measured": "no database in this measurement" })
}
