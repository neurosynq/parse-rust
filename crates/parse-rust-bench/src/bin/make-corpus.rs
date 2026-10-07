//! Writes the nine frozen corpora: `corpus/{200b,2kb,8kb}-{flat,nested,pointers}.json`.
//!
//! Each file is one Parse object body as a REST client sends it on a create. The corpora are
//! frozen: every microbenchmark record carries the hash of the file it ran on, so a corpus that
//! changed would silently change every historical number filed under its name. This generator
//! exists so the files can be reproduced byte for byte, not so they can drift. Regenerating with
//! different output is a deliberate baseline reset.
//!
//! Determinism is the whole contract: a fixed seed, a hand-written PRNG rather than a crate whose
//! output may change across versions, no clock, and no randomness from the OS.
//!
//! Usage: `make-corpus` writes the files; `make-corpus --check` compares the committed files
//! against a fresh generation and exits non-zero on any difference.

use std::process::ExitCode;

use parse_rust_bench::{corpus_dir, SHAPES, SIZES};
use serde_json::{json, Map, Value};

/// SplitMix64. Chosen because it is a dozen lines with a published reference output, so the
/// sequence cannot change underneath the corpora the way a library PRNG's might.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// Alphanumeric, the same alphabet as an `objectId`.
    fn alnum(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| ALPHABET[self.below(ALPHABET.len() as u64) as usize] as char)
            .collect()
    }

    /// Lowercase words separated by spaces, closer to user text than an alphanumeric run.
    fn text(&mut self, len: usize) -> String {
        let mut s = String::with_capacity(len);
        while s.len() < len {
            if !s.is_empty() {
                s.push(' ');
            }
            let word = 2 + self.below(8) as usize;
            for _ in 0..word {
                s.push((b'a' + self.below(26) as u8) as char);
            }
        }
        s.truncate(len);
        s.trim_end().to_string()
    }

    /// A number whose shortest round-trip form is the same in every formatter: an integer, or a
    /// multiple of a quarter. Otherwise the two sides' encoders would be compared on different
    /// text, and the corpus would test float formatting rather than object encoding.
    fn number(&mut self) -> Value {
        if self.below(2) == 0 {
            json!(self.below(1_000_000))
        } else {
            json!(self.below(40_000) as f64 / 4.0 + 0.25)
        }
    }

    /// A fixed calendar range, built from the seed rather than the clock.
    fn date(&mut self) -> Value {
        let iso = format!(
            "20{:02}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            10 + self.below(16),
            1 + self.below(12),
            1 + self.below(28),
            self.below(24),
            self.below(60),
            self.below(60),
            self.below(1000)
        );
        json!({ "__type": "Date", "iso": iso })
    }

    fn pointer(&mut self) -> Value {
        json!({ "__type": "Pointer", "className": "Target", "objectId": self.alnum(10) })
    }
}

/// The overhead of the trailing `,"pad":""` field, which absorbs the remainder so each corpus
/// lands on its target size.
const PAD_OVERHEAD: usize = r#","pad":"""#.len();

fn target_bytes(size: &str) -> usize {
    match size {
        "200b" => 200,
        "2kb" => 2048,
        _ => 8192,
    }
}

fn scalar(rng: &mut Rng, i: usize) -> Value {
    match i % 4 {
        0 => {
            let len = 8 + rng.below(17) as usize;
            json!(rng.text(len))
        }
        1 | 2 => rng.number(),
        _ => json!(rng.below(2) == 0),
    }
}

/// A plain object three levels deep, with an array at the second level.
fn nested_unit(rng: &mut Rng) -> Value {
    let label_len = 6 + rng.below(10) as usize;
    let leaf_len = 4 + rng.below(8) as usize;
    json!({
        "label": rng.text(label_len),
        "count": rng.below(10_000),
        "tags": [rng.alnum(6), rng.number(), rng.below(2) == 0],
        "inner": {
            "enabled": rng.below(2) == 0,
            "score": rng.number(),
            "leaf": { "name": rng.text(leaf_len), "rank": rng.below(100) }
        }
    })
}

/// One body for a shape, grown one field at a time until the next field would overshoot.
///
/// The body is rebuilt from its parts on each step rather than mutated, so that `refs` stays the
/// last key of a pointer body however many pointer fields precede it.
fn generate_one(shape: &str, target: usize, rng: &mut Rng) -> Vec<u8> {
    let mut fields: Vec<(String, Value)> = Vec::new();
    let mut refs: Vec<Value> = Vec::new();

    let render = |fields: &[(String, Value)], refs: &[Value]| -> Map<String, Value> {
        let mut map: Map<String, Value> = fields.iter().cloned().collect();
        if shape == "pointers" {
            map.insert("refs".into(), Value::Array(refs.to_vec()));
        }
        map
    };
    let size = |map: &Map<String, Value>| serde_json::to_vec(map).map(|v| v.len()).unwrap_or(0);

    match shape {
        "flat" => fields.push(("when".into(), rng.date())),
        "nested" => fields.push(("title".into(), json!(rng.text(12)))),
        _ => {
            fields.push(("title".into(), json!(rng.text(12))));
            refs.push(rng.pointer());
        }
    }

    for i in 0.. {
        let mut next_fields = fields.clone();
        let mut next_refs = refs.clone();
        match shape {
            "flat" => next_fields.push((format!("f{i:03}"), scalar(rng, i))),
            "nested" => next_fields.push((format!("n{i:03}"), nested_unit(rng))),
            _ if i % 2 == 0 => next_fields.push((format!("p{i:03}"), rng.pointer())),
            _ => next_refs.push(rng.pointer()),
        }
        if size(&render(&next_fields, &next_refs)) + PAD_OVERHEAD > target {
            break;
        }
        fields = next_fields;
        refs = next_refs;
    }

    let mut map = render(&fields, &refs);
    let remaining = target.saturating_sub(size(&map) + PAD_OVERHEAD);
    map.insert("pad".into(), json!(rng.alnum(remaining)));
    // A trailing newline so the committed files are well-formed text. It is part of the hashed
    // bytes, and both harnesses read the file as-is.
    let mut bytes = serde_json::to_vec(&map).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Every corpus, in `SIZES` by `SHAPES` order, each from its own seed so that adding a shape
/// later cannot perturb the bytes of an existing one.
fn generate() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (si, size) in SIZES.iter().enumerate() {
        for (hi, shape) in SHAPES.iter().enumerate() {
            let seed = 0x5041_5253_455F_5253_u64 ^ ((si as u64) << 8 | hi as u64);
            let mut rng = Rng(seed);
            let bytes = generate_one(shape, target_bytes(size), &mut rng);
            out.push((format!("{size}-{shape}.json"), bytes));
        }
    }
    out
}

fn main() -> ExitCode {
    let check = std::env::args().any(|a| a == "--check");
    let dir = corpus_dir();
    let mut failed = false;
    for (name, bytes) in generate() {
        let path = dir.join(&name);
        if check {
            match std::fs::read(&path) {
                Ok(existing) if existing == bytes => println!("ok    {name}"),
                Ok(_) => {
                    eprintln!("DIFF  {name}: committed file differs from a fresh generation");
                    failed = true;
                }
                Err(e) => {
                    eprintln!("MISS  {name}: {e}");
                    failed = true;
                }
            }
        } else {
            if let Err(e) =
                std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, &bytes))
            {
                eprintln!("cannot write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            println!("wrote {name} ({} bytes)", bytes.len());
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed corpora are exactly what the generator produces. If this fails, either the
    /// generator changed, which resets every baseline and must be deliberate, or a corpus file was
    /// edited by hand.
    #[test]
    fn committed_corpora_are_byte_identical_to_a_regeneration() {
        for (name, bytes) in generate() {
            let committed = std::fs::read(corpus_dir().join(&name)).unwrap();
            assert!(committed == bytes, "{name} differs from a fresh generation");
        }
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(generate(), generate());
    }

    #[test]
    fn sizes_are_within_ten_percent_of_target() {
        for (name, bytes) in generate() {
            let size = name.split('-').next().unwrap();
            let target = target_bytes(size) as f64;
            let actual = bytes.len() as f64;
            assert!(
                (actual - target).abs() <= target * 0.10,
                "{name} is {actual} bytes against a target of {target}"
            );
        }
    }

    #[test]
    fn every_corpus_is_a_json_object_with_its_shape() {
        for (name, bytes) in generate() {
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            let map = v.as_object().unwrap();
            if name.ends_with("-pointers.json") {
                let fields = map
                    .values()
                    .filter(|v| v.get("__type") == Some(&json!("Pointer")))
                    .count();
                assert!(fields >= 1, "{name} has no pointer field");
                assert!(map["refs"].as_array().is_some_and(|a| !a.is_empty()));
            }
            if name.ends_with("-flat.json") {
                assert!(map.values().all(|v| !v.is_array()));
                assert_eq!(map["when"]["__type"], json!("Date"));
            }
        }
    }
}
