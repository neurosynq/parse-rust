//! The two-target end-to-end driver: Gate J of 0.3.0.
//!
//! ```text
//! driver [--samples N] [--warmup N] [--rungs 0,1,10] [--out FILE] [--historical]
//! ```
//!
//! **Order is the honesty rule** (the benchmark design's):
//!
//! 1. Preflight. The upstream checkout is at the revision `PIN` records with no tracked change, the
//!    benchmark stack is up under its own prefix, and toxiproxy answers.
//! 2. **Gate mode, before any timing.** Both targets run side by side on separate databases, every
//!    workload runs once against each, and the responses are compared by the workload's declared
//!    comparison class. A workload that disagrees is not timed and the run fails.
//! 3. **Measure mode.** One target process at a time, a fresh seeded database per rung, the database
//!    latency set through toxiproxy, warmup, then sequential requests into an HdrHistogram. The
//!    first measured request's command shapes are checked against the committed fixture.
//! 4. Calibration. At the 10 ms rung, each instrumented target's database time must be within
//!    tolerance of its command count times 10 ms, or no `db_share` it reports is trusted.
//! 5. Completeness. Every workload, every rung, both targets, or the run fails.
//!
//! The released 0.2.0 and 0.2.1 binaries, with `--historical`, are timed beside the matrix for
//! wall-clock only. They carry no instrumentation, so their `db_share` is recorded as not measured,
//! and they are never part of the completeness check.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use parse_rust_bench::{histogram, sha256_hex, Corpus, Latency, Writer};
use serde_json::{json, Value};

const APP_ID: &str = "bench";
const MASTER_KEY: &str = "bench-master";

type Http = Client<HttpConnector, Full<Bytes>>;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("gate J: {message}");
    std::process::exit(1);
}

// -------------------------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------------------------

struct Args {
    samples: usize,
    warmup: usize,
    rungs: Vec<u64>,
    out: PathBuf,
    historical: bool,
}

fn args() -> Args {
    let raw: Vec<String> = std::env::args().collect();
    let get = |name: &str| {
        raw.iter()
            .position(|a| a == name)
            .and_then(|i| raw.get(i + 1).cloned())
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Args {
        samples: get("--samples").and_then(|v| v.parse().ok()).unwrap_or(300),
        warmup: get("--warmup").and_then(|v| v.parse().ok()).unwrap_or(50),
        rungs: get("--rungs")
            .unwrap_or_else(|| "0,1,10".into())
            .split(',')
            .filter_map(|v| v.parse().ok())
            .collect(),
        out: get("--out")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo().join(format!("target/bench/e2e-{stamp}.jsonl"))),
        historical: raw.iter().any(|a| a == "--historical"),
    }
}

struct Stack {
    mongo_direct: String,
    mongo_proxied: String,
    toxiproxy: String,
}

fn stack() -> Stack {
    // The same three variables, with the same defaults, that `compose.yaml` publishes on, so the
    // driver cannot connect somewhere the stack is not. Each stays in the 28xxx benchmark block.
    let port = |name: &str, default: u16| -> u16 {
        let value = std::env::var(name)
            .ok()
            .map(|v| {
                v.parse::<u16>()
                    .unwrap_or_else(|_| fail(format!("{name}={v} is not a port")))
            })
            .unwrap_or(default);
        if !(28000..=28999).contains(&value) {
            fail(format!(
                "{name} {value} is outside the 28xxx benchmark block"
            ));
        }
        value
    };
    let mongo = port("PRBENCH_MONGO_PORT", 28017);
    let proxied = port("PRBENCH_MONGO_PROXY_PORT", 28018);
    let api = port("PRBENCH_TOXIPROXY_API_PORT", 28474);
    Stack {
        mongo_direct: format!("mongodb://127.0.0.1:{mongo}"),
        mongo_proxied: format!("mongodb://127.0.0.1:{proxied}"),
        toxiproxy: format!("http://127.0.0.1:{api}"),
    }
}

// -------------------------------------------------------------------------------------------
// Context every record carries
// -------------------------------------------------------------------------------------------

fn run(cmd: &str, args: &[&str], dir: &Path) -> String {
    Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn ps_root() -> PathBuf {
    std::env::var("PARSE_SERVER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo().join("../parse-server-pinned"))
}

/// The upstream checkout must be the pinned revision with no tracked change. Untracked files do not
/// change what `lib/` was built from and are not counted.
fn verify_upstream() -> Value {
    let pin = std::fs::read_to_string(repo().join("PIN")).unwrap_or_default();
    let want = pin
        .lines()
        .find(|l| l.starts_with("parse-server "))
        .and_then(|l| l.split_whitespace().nth(2))
        .unwrap_or("")
        .to_string();
    let root = ps_root();
    let head = run("git", &["rev-parse", "HEAD"], &root);
    let dirty = !Command::new("git")
        .args(["diff", "--quiet", "HEAD"])
        .current_dir(&root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if head != want {
        fail(format!(
            "upstream at {} is {head}, not the pin {want}",
            root.display()
        ));
    }
    if dirty {
        fail(format!(
            "upstream at {} has tracked changes",
            root.display()
        ));
    }
    if !root.join("lib/index.js").exists() {
        fail(format!(
            "upstream at {} is not built; run npm ci && npm run build",
            root.display()
        ));
    }
    // `lib/` is ignored by git, so a clean tree at the pin says nothing about what was built. A
    // source file newer than the build means `lib/` came from some other revision, as
    // `tools/test.sh` checks for the gates.
    let built = std::fs::metadata(root.join("lib/index.js")).and_then(|m| m.modified());
    if let Ok(built) = built {
        if let Some(newer) = newer_than(&root.join("src"), built) {
            fail(format!(
                "upstream lib/ is older than {}; rebuild with npm run build",
                newer.display()
            ));
        }
    }
    json!({ "sha": head, "clean": true })
}

/// The first file under `dir` modified after `than`, if any.
fn newer_than(dir: &Path, than: std::time::SystemTime) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = newer_than(&path, than) {
                return Some(found);
            }
        } else if entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|m| m > than)
        {
            return Some(path);
        }
    }
    None
}

fn context(upstream: &Value) -> Value {
    let root = repo();
    json!({
        "parse_rust_sha": run("git", &["rev-parse", "HEAD"], &root),
        "parse_rust_dirty": !run("git", &["status", "--porcelain", "--untracked-files=no"], &root).is_empty(),
        "upstream": upstream,
        "node": run("node", &["--version"], &root),
        "rustc": run("rustc", &["--version"], &root),
        "os": format!("{} {}", std::env::consts::OS, run("uname", &["-r"], &root)),
        "cpu": run("sysctl", &["-n", "machdep.cpu.brand_string"], &root),
        "machine_id": run("hostname", &[], &root),
        "prefix": std::env::var("PRBENCH_PREFIX").unwrap_or_else(|_| "prbench".into()),
        "harness": "parse-rust-bench/0.3.0",
    })
}

// -------------------------------------------------------------------------------------------
// Targets
// -------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Kind {
    Node,
    Rust(PathBuf),
}

#[derive(Clone)]
struct Target {
    name: String,
    kind: Kind,
    instrumented: bool,
}

struct Running {
    child: Child,
    url: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(target: &Target, db_uri: &str) -> Running {
    let mut cmd = match &target.kind {
        Kind::Rust(bin) => {
            let mut c = Command::new(bin);
            c.env("PARSE_SERVER_APPLICATION_ID", APP_ID)
                .env("PARSE_SERVER_MASTER_KEY", MASTER_KEY)
                .env("PARSE_SERVER_DATABASE_URI", db_uri)
                .env("PARSE_SERVER_MOUNT_PATH", "/parse")
                .env("PARSE_SERVER_HOST", "127.0.0.1")
                .env("PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION", "true")
                .env("PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID", "true")
                .env("PORT", "0");
            c
        }
        Kind::Node => {
            let mut c = Command::new("node");
            c.arg(repo().join("crates/parse-rust-bench/js/node-target.mjs"))
                .env("PS_ROOT", ps_root())
                .env("BENCH_DB_URI", db_uri)
                .env("BENCH_APP_ID", APP_ID)
                .env("BENCH_MASTER_KEY", MASTER_KEY)
                .env("NODE_OPTIONS", "");
            c
        }
    };
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| fail(format!("cannot start {}: {e}", target.name)));
    let stdout = child.stdout.take().unwrap_or_else(|| fail("no stdout"));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix("parse-rust listening on ") {
                let _ = tx.send(format!("{}/parse", rest.trim()));
            } else if let Some(rest) = line.strip_prefix("NODE-TARGET ") {
                if let Some(url) = serde_json::from_str::<Value>(rest)
                    .ok()
                    .and_then(|v| v["url"].as_str().map(String::from))
                {
                    let _ = tx.send(url);
                }
            }
        }
    });
    let url = rx
        .recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| fail(format!("{} never reported its address", target.name)));
    Running { child, url }
}

// -------------------------------------------------------------------------------------------
// HTTP
// -------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Req {
    method: &'static str,
    path: String,
    body: Option<Value>,
    master: bool,
}

struct Resp {
    status: u16,
    body: Value,
    db_micros: Option<u64>,
    db_ops: Option<u64>,
    shapes: Option<Vec<String>>,
    elapsed: Duration,
}

async fn send(http: &Http, base: &str, req: &Req) -> Resp {
    let mut builder = hyper::Request::builder()
        .method(req.method)
        .uri(format!("{base}{}", req.path))
        .header("X-Parse-Application-Id", APP_ID)
        .header("Content-Type", "application/json");
    if req.master {
        builder = builder.header("X-Parse-Master-Key", MASTER_KEY);
    }
    let body = req
        .body
        .as_ref()
        .map(|b| Bytes::from(serde_json::to_vec(b).unwrap_or_default()))
        .unwrap_or_default();
    let request = builder
        .body(Full::new(body))
        .unwrap_or_else(|e| fail(format!("bad request: {e}")));
    let started = Instant::now();
    let response = http
        .request(request)
        .await
        .unwrap_or_else(|e| fail(format!("{} {}: {e}", req.method, req.path)));
    let status = response.status().as_u16();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let db_micros = header("x-bench-db-micros").and_then(|v| v.parse().ok());
    let db_ops = header("x-bench-db-ops").and_then(|v| v.parse().ok());
    let shapes = header("x-bench-db-shape").and_then(|v| serde_json::from_str(&v).ok());
    let bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let elapsed = started.elapsed();
    Resp {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        db_micros,
        db_ops,
        shapes,
        elapsed,
    }
}

// -------------------------------------------------------------------------------------------
// Workloads: the seven 0.3.0 pilots (benchmarks.md section 3)
// -------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Class {
    /// Byte-for-byte on status and body, no normalization.
    Exact,
    /// Generated values scrubbed and shape-checked, then compared with key order.
    Normalized,
}

struct Workload {
    name: &'static str,
    class: Class,
    corpus: Option<Corpus>,
    request: Req,
}

fn id(prefix: &str, n: usize) -> String {
    format!("{prefix}{n:0>width$}", width = 10 - prefix.len())
}

fn workloads() -> Vec<Workload> {
    let corpus = |size: &str, shape: &str| {
        Corpus::load(size, shape).unwrap_or_else(|e| fail(format!("corpus {size}-{shape}: {e}")))
    };
    let nested = corpus("2kb", "nested");
    let small = corpus("200b", "flat");
    let batch: Vec<Value> = (0..50)
        .map(|_| json!({ "method": "POST", "path": "/parse/classes/BenchBatch", "body": small.json() }))
        .collect();
    vec![
        Workload {
            name: "floor.health",
            class: Class::Exact,
            corpus: None,
            request: Req { method: "GET", path: "/health".into(), body: None, master: false },
        },
        Workload {
            name: "read.get",
            class: Class::Normalized,
            corpus: Some(nested.clone()),
            request: Req {
                method: "GET",
                path: format!("/classes/BenchItem/{}", id("item", 1)),
                body: None,
                master: false,
            },
        },
        Workload {
            name: "create.nested",
            class: Class::Normalized,
            corpus: Some(nested.clone()),
            request: Req {
                method: "POST",
                path: "/classes/BenchItem".into(),
                body: Some(nested.json()),
                master: false,
            },
        },
        Workload {
            name: "update.ops",
            class: Class::Normalized,
            corpus: None,
            request: Req {
                method: "PUT",
                path: format!("/classes/BenchCounter/{}", id("counter", 1)),
                body: Some(json!({
                    "counter": { "__op": "Increment", "amount": 1 },
                    "tags": { "__op": "AddUnique", "objects": ["bench"] },
                })),
                master: false,
            },
        },
        Workload {
            name: "batch.50",
            class: Class::Normalized,
            corpus: Some(small.clone()),
            request: Req {
                method: "POST",
                path: "/batch".into(),
                body: Some(json!({ "requests": batch })),
                master: false,
            },
        },
        Workload {
            name: "query.protected",
            class: Class::Normalized,
            corpus: None,
            request: Req {
                method: "GET",
                path: "/classes/BenchProtected?where=%7B%22n%22%3A%7B%22%24lt%22%3A50%7D%7D&order=n&limit=50"
                    .into(),
                body: None,
                master: false,
            },
        },
        Workload {
            name: "include.wide",
            class: Class::Normalized,
            corpus: None,
            request: Req {
                method: "GET",
                path: "/classes/BenchHolder?include=a,b,c,d&order=n&limit=20".into(),
                body: None,
                master: false,
            },
        },
    ]
}

/// The same data on every target, through the API with the master key and fixed objectIds.
async fn seed(http: &Http, base: &str) {
    let post = |path: String, body: Value| Req {
        method: "POST",
        path,
        body: Some(body),
        master: true,
    };
    let mut must = Vec::new();
    let nested = Corpus::load("2kb", "nested")
        .map(|c| c.json())
        .unwrap_or(Value::Null);
    let mut item = nested.clone();
    item["objectId"] = json!(id("item", 1));
    must.push(post("/classes/BenchItem".into(), item));
    must.push(post(
        "/classes/BenchCounter".into(),
        json!({ "objectId": id("counter", 1), "counter": 0, "tags": [] }),
    ));
    must.push(post(
        "/schemas/BenchProtected".into(),
        json!({
            "className": "BenchProtected",
            "fields": { "n": {"type": "Number"}, "secret": {"type": "String"}, "label": {"type": "String"} },
            "classLevelPermissions": {
                "find": {"*": true}, "count": {"*": true}, "get": {"*": true}, "create": {"*": true},
                "update": {"*": true}, "delete": {"*": true}, "addField": {"*": true},
                "protectedFields": { "*": ["secret"] },
            },
        }),
    ));
    for n in 0..50 {
        must.push(post(
            "/classes/BenchProtected".into(),
            json!({ "objectId": id("prot", n), "n": n, "secret": format!("s{n}"), "label": format!("row {n}") }),
        ));
    }
    let flat = Corpus::load("200b", "flat")
        .map(|c| c.json())
        .unwrap_or(Value::Null);
    for t in 0..4 {
        let mut target = flat.clone();
        target["objectId"] = json!(id("target", t));
        // Distinct content per target. The correctness gate scrubs `objectId`, so four identical
        // bodies would let an `include` that resolved every pointer to one target compare equal.
        target["slot"] = json!(t);
        must.push(post("/classes/BenchTarget".into(), target));
    }
    for n in 0..20 {
        let p = |t: usize| json!({ "__type": "Pointer", "className": "BenchTarget", "objectId": id("target", t) });
        must.push(post(
            "/classes/BenchHolder".into(),
            json!({ "objectId": id("holder", n), "n": n, "a": p(0), "b": p(1), "c": p(2), "d": p(3) }),
        ));
    }
    for req in must {
        let r = send(http, base, &req).await;
        if !(200..300).contains(&r.status) {
            fail(format!(
                "seeding {} answered {}: {}",
                req.path, r.status, r.body
            ));
        }
    }
}

// -------------------------------------------------------------------------------------------
// The correctness gate
// -------------------------------------------------------------------------------------------

const SCRUBBED: [&str; 4] = ["objectId", "createdAt", "updatedAt", "sessionToken"];

/// Replace generated values, never keys, and check each against its shape.
fn normalize(value: &Value, problems: &mut Vec<String>) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if SCRUBBED.contains(&k.as_str()) {
                        check_shape(k, v, problems);
                        (k.clone(), json!("<scrubbed>"))
                    } else {
                        (k.clone(), normalize(v, problems))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| normalize(v, problems)).collect()),
        other => other.clone(),
    }
}

fn check_shape(key: &str, value: &Value, problems: &mut Vec<String>) {
    // Inside an included object the dates are `{"__type":"Date","iso":...}` envelopes, on both
    // servers; the instant inside is what has the shape.
    let s = value
        .as_str()
        .or_else(|| {
            (value["__type"] == "Date")
                .then(|| value["iso"].as_str())
                .flatten()
        })
        .unwrap_or("");
    let ok = match key {
        "objectId" => s.len() == 10 && s.chars().all(|c| c.is_ascii_alphanumeric()),
        "createdAt" | "updatedAt" => {
            s.len() == 24 && s.ends_with('Z') && s.as_bytes().get(19) == Some(&b'.')
        }
        "sessionToken" => {
            s.starts_with("r:") && s.len() == 34 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
        }
        _ => true,
    };
    if !ok {
        problems.push(format!("{key} has the wrong shape: {value}"));
    }
}

/// One target's answer to one workload request: status, body, and the shape checks it failed.
type Answer = (u16, Value, Vec<String>);

async fn gate(
    http: &Http,
    stack: &Stack,
    targets: &[Target],
    workloads: &[Workload],
    tag: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut answers: BTreeMap<&str, Vec<Answer>> = BTreeMap::new();
    for target in targets {
        let db = format!(
            "{}/prbench_gate_{tag}_{}",
            stack.mongo_direct,
            target.name.replace('.', "_")
        );
        let running = start(target, &db);
        seed(http, &running.url).await;
        for w in workloads {
            let r = send(http, &running.url, &w.request).await;
            let mut problems = Vec::new();
            let body = match w.class {
                Class::Exact => r.body.clone(),
                Class::Normalized => normalize(&r.body, &mut problems),
            };
            answers
                .entry(w.name)
                .or_default()
                .push((r.status, body, problems));
        }
        drop(running);
        drop_database(&db).await;
    }
    for (name, results) in answers {
        let (first_status, first_body, _) = &results[0];
        for (status, body, problems) in &results {
            for p in problems {
                failures.push(format!("{name}: {p}"));
            }
            if status != first_status
                || serde_json::to_string(body).ok() != serde_json::to_string(first_body).ok()
            {
                failures.push(format!(
                    "{name}: the targets disagree:\n    {} {}\n    {} {}",
                    first_status,
                    truncate(first_body),
                    status,
                    truncate(body)
                ));
            }
        }
    }
    failures
}

fn truncate(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 400 {
        format!("{}...", &s[..400])
    } else {
        s
    }
}

async fn drop_database(uri: &str) {
    let _ = Command::new("mongosh")
        .args(["--quiet", uri, "--eval", "db.dropDatabase()"])
        .output();
}

// -------------------------------------------------------------------------------------------
// Toxiproxy
// -------------------------------------------------------------------------------------------

async fn toxiproxy(http: &Http, stack: &Stack, method: &str, path: &str, body: Value) -> u16 {
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("{}{path}", stack.toxiproxy))
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|e| fail(format!("toxiproxy request: {e}")));
    match http.request(request).await {
        Ok(r) => r.status().as_u16(),
        Err(e) => fail(format!(
            "toxiproxy at {} is not answering: {e}",
            stack.toxiproxy
        )),
    }
}

/// The proxy to MongoDB, and the latency toxic for one rung. Downstream only: a command's reply is
/// delayed once, so a command costs one rung of latency, which is what calibration assumes.
async fn set_rung(http: &Http, stack: &Stack, rung: u64) {
    toxiproxy(http, stack, "DELETE", "/proxies/mongo", json!({})).await;
    let created = toxiproxy(
        http,
        stack,
        "POST",
        "/proxies",
        json!({ "name": "mongo", "listen": "0.0.0.0:28018", "upstream": "mongo:27017" }),
    )
    .await;
    if !(200..300).contains(&created) {
        fail(format!("toxiproxy refused the proxy: {created}"));
    }
    if rung > 0 {
        let added = toxiproxy(
            http,
            stack,
            "POST",
            "/proxies/mongo/toxics",
            json!({ "name": "rung", "type": "latency", "stream": "downstream", "attributes": { "latency": rung } }),
        )
        .await;
        if !(200..300).contains(&added) {
            fail(format!("toxiproxy refused the {rung} ms toxic: {added}"));
        }
    }
}

// -------------------------------------------------------------------------------------------
// Measuring
// -------------------------------------------------------------------------------------------

fn shapes_path(target: &str, workload: &str) -> PathBuf {
    repo().join(format!(
        "crates/parse-rust-bench/shapes/{target}/{workload}.json"
    ))
}

/// The command shapes a workload's request issues on a target, against the committed fixture.
/// A missing fixture fails; `UPDATE_SHAPES=1` writes it, which is the explicit switch.
fn check_shapes(
    target: &str,
    workload: &str,
    shapes: &[String],
    problems: &mut Vec<String>,
) -> String {
    let path = shapes_path(target, workload);
    let text = serde_json::to_string_pretty(shapes).unwrap_or_default() + "\n";
    let hash = sha256_hex(text.as_bytes());
    if std::env::var("UPDATE_SHAPES").as_deref() == Ok("1") {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&path, &text);
        return hash;
    }
    match std::fs::read_to_string(&path) {
        Ok(committed) if committed == text => {}
        Ok(committed) => problems.push(format!(
            "{target} {workload}: query shape changed from the fixture\n    fixture: {}\n    now:     {}",
            committed.replace('\n', " "),
            text.replace('\n', " ")
        )),
        Err(_) => problems.push(format!("{target} {workload}: no query-shape fixture at {}", path.display())),
    }
    hash
}

#[allow(clippy::too_many_arguments)]
async fn measure(
    http: &Http,
    stack: &Stack,
    target: &Target,
    rung: u64,
    workloads: &[Workload],
    args: &Args,
    writer: &mut Writer,
    ctx: &Value,
    run_id: &str,
    problems: &mut Vec<String>,
) {
    set_rung(http, stack, rung).await;
    let db = format!(
        "{}/prbench_{run_id}_{}_{rung}",
        stack.mongo_proxied,
        target.name.replace('.', "_")
    );
    let running = start(target, &db);
    seed(http, &running.url).await;
    for w in workloads {
        for _ in 0..args.warmup {
            send(http, &running.url, &w.request).await;
        }
        let mut latency = histogram();
        let mut db_micros = histogram();
        let mut db_ops = histogram();
        let mut shares = histogram();
        let mut shape_hash = Value::Null;
        let started = Instant::now();
        for i in 0..args.samples {
            let r = send(http, &running.url, &w.request).await;
            if !(200..300).contains(&r.status) {
                problems.push(format!(
                    "{} {} answered {} while measuring",
                    target.name, w.name, r.status
                ));
                break;
            }
            let nanos = u64::try_from(r.elapsed.as_nanos())
                .unwrap_or(u64::MAX)
                .max(1);
            if latency.record(nanos).is_err() {
                problems.push(format!(
                    "{} {}: a latency of {nanos} ns is outside the histogram",
                    target.name, w.name
                ));
            }
            // A target built to be measured that answers without the headers is a binary built
            // without the instrumentation, and its `db_share` would be silently absent.
            if target.instrumented && (r.db_micros.is_none() || r.db_ops.is_none()) {
                problems.push(format!(
                    "{} {} answered without database-time headers; was it built with bench-instrumentation?",
                    target.name, w.name
                ));
                break;
            }
            if let (Some(micros), Some(ops)) = (r.db_micros, r.db_ops) {
                let _ = db_micros.record(micros);
                let _ = db_ops.record(ops);
                // Parts per million, so the share survives the integer histogram.
                let _ =
                    shares.record(((micros as f64 * 1000.0 / nanos as f64) * 1_000_000.0) as u64);
            }
            if i == 0 && target.instrumented {
                let shapes = r.shapes.clone().unwrap_or_default();
                shape_hash = json!(check_shapes(&target.name, w.name, &shapes, problems));
            }
        }
        let wall = started.elapsed();
        let instrumented = target.instrumented && !db_micros.is_empty();
        let record = json!({
            "run_id": run_id,
            "kind": if target.instrumented { "e2e" } else { "historical" },
            "target": target.name,
            "workload": w.name,
            "comparison_class": match w.class { Class::Exact => "exact", Class::Normalized => "normalized" },
            "params": { "concurrency": 1, "samples": args.samples, "warmup": args.warmup },
            "db_latency_rung_ms": rung,
            "corpus": w.corpus.as_ref().map(|c| json!({ "name": c.name, "hash": c.hash })),
            "latency_us": Latency::from_nanos(&latency),
            "throughput_rps": args.samples as f64 / wall.as_secs_f64(),
            "db_micros_p50": if instrumented { json!(db_micros.value_at_quantile(0.5)) } else { Value::Null },
            "db_ops_p50": if instrumented { json!(db_ops.value_at_quantile(0.5)) } else { Value::Null },
            "db_share_p50": if instrumented {
                json!(shares.value_at_quantile(0.5) as f64 / 1_000_000.0)
            } else {
                json!({ "not_measured": "released binary, built without instrumentation" })
            },
            "transport": "tcp-loopback",
            "query_shape_hash": shape_hash,
            "context": ctx,
        });
        if let Err(e) = writer.write(record) {
            fail(e);
        }
        println!(
            "  {:<12} {:>2} ms  {:<16} p50 {:>9.1} us  p99 {:>9.1} us{}",
            target.name,
            rung,
            w.name,
            latency.value_at_quantile(0.5) as f64 / 1000.0,
            latency.value_at_quantile(0.99) as f64 / 1000.0,
            if instrumented {
                format!(
                    "  db {} us / {} ops",
                    db_micros.value_at_quantile(0.5),
                    db_ops.value_at_quantile(0.5)
                )
            } else {
                String::new()
            }
        );
    }
    drop(running);
    drop_database(&db.replace(&stack.mongo_proxied, &stack.mongo_direct)).await;
}

// -------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args = args();
    let stack = stack();
    let http: Http = Client::builder(TokioExecutor::new()).build_http();
    let upstream = verify_upstream();
    let ctx = context(&upstream);
    let run_id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        ctx["parse_rust_sha"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(8)
            .collect::<String>()
    );

    let rust_bin = repo().join("target/bench-build/release/parse-rust");
    if !rust_bin.exists() {
        fail(format!(
            "{} is missing. Build it with:\n  CARGO_TARGET_DIR=target/bench-build cargo build --release -p parse-rust-cli --features bench-instrumentation",
            rust_bin.display()
        ));
    }
    let targets = vec![
        Target {
            name: "node".into(),
            kind: Kind::Node,
            instrumented: true,
        },
        Target {
            name: "rust".into(),
            kind: Kind::Rust(rust_bin),
            instrumented: true,
        },
    ];
    let workloads = workloads();

    println!("gate J: correctness gate");
    let failures = gate(&http, &stack, &targets, &workloads, &run_id).await;
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  - {f}");
        }
        fail("the correctness gate failed; nothing was timed");
    }
    println!("  every workload agrees on both targets");

    let mut writer = Writer::create(args.out.clone()).unwrap_or_else(|e| fail(e));
    let mut problems = Vec::new();
    let mut measured = targets.clone();
    if args.historical {
        for version in ["0.2.0", "0.2.1"] {
            let bin = repo().join(format!("target/bench/historical/{version}/bin/parse-rust"));
            if bin.exists() {
                measured.push(Target {
                    name: format!("rust-{version}"),
                    kind: Kind::Rust(bin),
                    instrumented: false,
                });
            } else {
                println!(
                    "  historical {version}: no binary at {}, skipped (not a gate failure)",
                    bin.display()
                );
            }
        }
    }
    for target in &measured {
        for &rung in &args.rungs {
            measure(
                &http,
                &stack,
                target,
                rung,
                &workloads,
                &args,
                &mut writer,
                &ctx,
                &run_id,
                &mut problems,
            )
            .await;
        }
    }
    set_rung(&http, &stack, 0).await;

    // A gate run measures exactly the three rungs the contract names; anything else is a
    // diagnostic and cannot report clean.
    let mut rungs = args.rungs.clone();
    rungs.sort_unstable();
    if rungs != [0, 1, 10] {
        problems.push(format!(
            "rungs {:?}: a gate run measures 0, 1 and 10 ms; this is a diagnostic run",
            args.rungs
        ));
    }

    // Calibration and completeness, from what was written.
    let records: Vec<Value> = std::fs::read_to_string(&writer.path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|r: &Value| r["run_id"] == run_id)
        .collect();
    for target in targets.iter().filter(|t| t.instrumented) {
        for w in &workloads {
            for &rung in &args.rungs {
                if !records.iter().any(|r| {
                    r["target"] == target.name
                        && r["workload"] == w.name
                        && r["db_latency_rung_ms"] == rung
                }) {
                    problems.push(format!(
                        "missing cell: {} {} at {rung} ms",
                        target.name, w.name
                    ));
                }
            }
        }
        // At 10 ms each command's reply is delayed 10 ms, so database time should be its command
        // count times that, plus what the database itself spent. A boundary that drops a command,
        // double counts one, or picks up a heartbeat lands outside this.
        //
        // **Only over workloads whose commands run one after another.** A server that overlaps its
        // round trips, as parse-server does for a batch and for an include, is correctly reported
        // as a union of intervals well below `ops * 10 ms`, so those workloads say nothing about
        // the boundary. The calibration set is fixed here rather than inferred from the result.
        //
        // **The command count is declared here, not read from the instrumentation.** Taking it from
        // the same hook that measures the time would let a dropped command lower both and still
        // pass. Each count is what the workload issues on that server, from its query-shape
        // fixture as reviewed: parse-server one, parse-rust two, the second being the per-request
        // `_SCHEMA` read. A server change that alters a count must change it here too.
        const CALIBRATION: [(&str, u64, u64); 4] = [
            // (workload, node commands, rust commands)
            ("read.get", 1, 2),
            ("create.nested", 1, 2),
            ("update.ops", 1, 2),
            ("query.protected", 1, 2),
        ];
        for (workload, node_ops, rust_ops) in CALIBRATION {
            let declared = if target.name == "node" {
                node_ops
            } else {
                rust_ops
            };
            let found = records.iter().find(|r| {
                r["kind"] == "e2e"
                    && r["target"] == target.name
                    && r["db_latency_rung_ms"] == 10
                    && r["workload"] == workload
            });
            let Some(r) = found else {
                problems.push(format!(
                    "calibration: {} {workload} has no record at 10 ms",
                    target.name
                ));
                continue;
            };
            let (Some(micros), Some(ops)) = (r["db_micros_p50"].as_f64(), r["db_ops_p50"].as_f64())
            else {
                problems.push(format!(
                    "calibration: {} {workload} has no database time",
                    target.name
                ));
                continue;
            };
            if ops != declared as f64 {
                problems.push(format!(
                    "calibration: {} {workload} attributed {ops} commands, the workload is declared to issue {declared}",
                    target.name
                ));
            }
            {
                let expected = declared as f64 * 10_000.0;
                let ok = micros >= expected * 0.95 && micros <= expected * 1.25 + 3_000.0;
                let calibration = json!({
                    "run_id": run_id, "kind": "calibration", "target": target.name, "workload": r["workload"],
                    "db_micros_p50": micros, "db_ops_p50": ops, "expected_micros": expected, "passed": ok,
                    "db_share_p50": r["db_share_p50"], "transport": "tcp-loopback", "context": ctx,
                });
                if let Err(e) = writer.write(calibration) {
                    fail(e);
                }
                if !ok {
                    problems.push(format!(
                        "calibration: {} {workload} reports {micros} us of database time for {declared} commands at 10 ms each",
                        target.name
                    ));
                }
            }
        }
    }

    println!("\nrecords: {}", writer.path.display());
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("  - {p}");
        }
        fail(format!("{} problem(s)", problems.len()));
    }
    println!("gate J: clean, labelled baseline-unclassified; no verdict is published");
}
