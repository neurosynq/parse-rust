//! A minimal HTTP client and a per-test server, for the end-to-end tests.
//!
//! **Every test binds port 0 and reads the address back**, so parallel batteries cannot collide
//! with each other, with a stock parse-server, or with another copy of themselves. Nothing sleeps
//! to wait for readiness: `serve` returns only after the listener is bound, so there is nothing to
//! poll for.
//!
//! The client is written by hand rather than pulled in, so the exact bytes on the wire are visible
//! in the test and so the tests exercise the same stack an SDK does. A oneshot against the router
//! would bypass the parts most likely to differ from Express.

#![allow(dead_code)]

use parse_rust_mongo::MongoAdapter;
use parse_rust_server::{AppState, ServerConfig};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const APP_ID: &str = "test";
pub const MASTER_KEY: &str = "test";
pub const MAINTENANCE_KEY: &str = "maint";
pub const REST_KEY: &str = "rest";
/// Configured as well as the REST key, because the JavaScript SDK's body-credential key is
/// `_JavaScriptKey` and there is no body key for the REST one.
pub const JS_KEY: &str = "js";

/// A booted server and the database it is pointed at.
pub struct Server {
    pub host: String,
    pub database: String,
}

/// `allowClientClassCreation`, enabled for the shared harness.
///
/// **The server default is `false`, matching upstream, and this override is a test-fixture
/// decision rather than a statement about the default.** Most tests here set up their subject by
/// having an ordinary client write to a class that does not exist yet, which the default refuses;
/// leaving it off would make every one of them fail on the setup step and measure the option
/// instead of what they are about. The acceptance gates configure their upstream parse-server the
/// same way and say so.
///
/// The default itself is asserted where it belongs, in `parse-rust-rest`'s pipeline tests, which
/// check that the *default* options refuse and that master and the system classes are exempt. A
/// test that wants the shipped default here should use [`boot_fresh_with`] and leave it alone.
const TEST_ALLOW_CLIENT_CLASS_CREATION: bool = true;

/// Boot on an ephemeral port against a fresh database.
///
/// The database name carries the process id and a counter, so two tests in one binary and two
/// binaries on one machine never share state.
pub async fn boot() -> Server {
    let database = format!(
        "parse_rust_it_{}_{}",
        std::process::id(),
        next_database_ordinal()
    );
    let server = boot_on(&database, base_config()).await;
    Server {
        host: server,
        database,
    }
}

/// Boot a second process-equivalent against an existing database.
///
/// This is what "a session survives a restart" means: nothing is carried over except the rows.
pub async fn reboot(database: &str) -> String {
    boot_on(database, base_config()).await
}

/// The harness baseline every default boot starts from.
///
/// Separate from `ServerConfig::new` so that the shipped defaults stay visible: anything set here
/// is a fixture decision, and a test that cares about a shipped default should say so explicitly
/// rather than inherit this.
fn base_config() -> ServerConfig {
    let mut config = ServerConfig::new(APP_ID, MASTER_KEY);
    config.maintenance_key = Some(MAINTENANCE_KEY.to_string());
    config.allow_client_class_creation = TEST_ALLOW_CLIENT_CLASS_CREATION;
    config
}

/// Boot with a caller-supplied config, for the option tests.
pub async fn boot_with(database: &str, config: ServerConfig) -> String {
    boot_on(database, config).await
}

/// Boot with a caller-supplied config against a **fresh** database.
///
/// For options that only take effect at startup, such as the index creation flags: pointing a
/// second config at a database that already has the index proves nothing, because nothing drops
/// it again.
pub async fn boot_fresh_with(mut build: impl FnMut(ServerConfig) -> ServerConfig) -> Server {
    let database = format!(
        "parse_rust_it_{}_{}",
        std::process::id(),
        next_database_ordinal()
    );
    // The closure receives the harness baseline, so an option test can still turn any of it off.
    let config = build(base_config());
    let host = boot_on(&database, config).await;
    Server { host, database }
}

async fn boot_on(database: &str, config: ServerConfig) -> String {
    let config = config
        .rest_api_key(REST_KEY)
        .javascript_key(JS_KEY)
        .mount_path("/parse");
    let storage = MongoAdapter::connect("mongodb://127.0.0.1:27017", database)
        .await
        .expect("MongoDB must be running on 27017");
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let (bound, server) = parse_rust_server::serve(AppState::new(config, storage), addr)
        .await
        .expect("bind failed");
    tokio::spawn(server);
    bound.to_string()
}

/// Every index name MongoDB actually holds for a collection.
///
/// Asserted against directly rather than through `_SCHEMA`, because the whole point of the index
/// tests is that `_metadata.indexes` can claim something the database does not have.
pub async fn index_names(database: &str, collection: &str) -> Vec<String> {
    let client = mongodb::Client::with_uri_str("mongodb://127.0.0.1:27017")
        .await
        .expect("MongoDB must be running on 27017");
    client
        .database(database)
        .collection::<bson::Document>(collection)
        .list_index_names()
        .await
        .unwrap_or_default()
}

fn next_database_ordinal() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // The clock is mixed in so that two runs of the same binary do not reuse a database whose rows
    // a previous run left behind. A stale row is exactly the kind of state that makes an isolation
    // test pass while proving nothing.
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    });
    seed.wrapping_add(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// One request, and its parsed response.
pub struct Response {
    pub status: u16,
    pub body: Value,
    pub raw: String,
}

impl Response {
    /// The Parse error code, or `None` for a success or for the `code`-less HTTP envelope.
    pub fn code(&self) -> Option<i64> {
        self.body.get("code").and_then(Value::as_i64)
    }

    pub fn error(&self) -> String {
        self.body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn results(&self) -> Vec<Value> {
        self.body
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}

/// Who a request is made as.
#[derive(Debug, Clone, Default)]
pub struct As {
    pub master: bool,
    pub maintenance: bool,
    pub session_token: Option<String>,
    /// Send no `X-Parse-*` headers at all, which is what the JavaScript SDK does: it puts the
    /// credentials in the body so a browser never sends a CORS preflight.
    pub no_headers: bool,
}

impl As {
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// No credential headers at all. The body has to carry them.
    pub fn anonymous_without_keys() -> Self {
        Self {
            no_headers: true,
            ..Self::default()
        }
    }

    pub fn master() -> Self {
        Self {
            master: true,
            ..Self::default()
        }
    }

    /// Authenticated with the **maintenance** key, which is not the master key.
    ///
    /// The two apply the same ACL treatment and are therefore easy to conflate, but at least one
    /// decision reads them differently: `validateClientClassCreation` exempts maintenance on a
    /// write and not on a read.
    pub fn maintenance() -> Self {
        Self {
            maintenance: true,
            ..Self::default()
        }
    }

    pub fn user(token: &str) -> Self {
        Self {
            session_token: Some(token.to_string()),
            ..Self::default()
        }
    }
}

pub async fn request(
    host: &str,
    method: &str,
    path: &str,
    who: &As,
    body: Option<&Value>,
) -> Response {
    let mut headers = if who.no_headers {
        Vec::new()
    } else {
        vec![
            ("X-Parse-Application-Id".to_string(), APP_ID.to_string()),
            ("X-Parse-REST-API-Key".to_string(), REST_KEY.to_string()),
        ]
    };
    if who.master {
        headers.push(("X-Parse-Master-Key".to_string(), MASTER_KEY.to_string()));
    }
    if who.maintenance {
        headers.push((
            "X-Parse-Maintenance-Key".to_string(),
            MAINTENANCE_KEY.to_string(),
        ));
    }
    if let Some(token) = &who.session_token {
        headers.push(("X-Parse-Session-Token".to_string(), token.clone()));
    }

    let payload = body.map(|b| serde_json::to_string(b).expect("serialize"));
    let mut req = format!("{method} /parse{path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in &headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(payload) = &payload {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    if let Some(payload) = &payload {
        req.push_str(payload);
    }

    let mut socket = tokio::net::TcpStream::connect(host).await.expect("connect");
    socket
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let mut raw = String::new();
    socket
        .read_to_string(&mut raw)
        .await
        .expect("read response");

    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {raw}"));
    let text = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Response { status, body, raw }
}

pub async fn get(host: &str, path: &str, who: &As) -> Response {
    request(host, "GET", path, who, None).await
}

pub async fn post(host: &str, path: &str, who: &As, body: &Value) -> Response {
    request(host, "POST", path, who, Some(body)).await
}

pub async fn put(host: &str, path: &str, who: &As, body: &Value) -> Response {
    request(host, "PUT", path, who, Some(body)).await
}

pub async fn delete(host: &str, path: &str, who: &As) -> Response {
    request(host, "DELETE", path, who, None).await
}

/// Sign up and return `(objectId, sessionToken)`.
pub async fn signup(host: &str, username: &str, password: &str) -> (String, String) {
    let response = post(
        host,
        "/users",
        &As::anonymous(),
        &serde_json::json!({ "username": username, "password": password }),
    )
    .await;
    assert_eq!(response.status, 201, "signup failed: {}", response.raw);
    (
        response.body["objectId"]
            .as_str()
            .expect("objectId")
            .to_string(),
        response.body["sessionToken"]
            .as_str()
            .expect("sessionToken")
            .to_string(),
    )
}

/// A URL-encoded `where` query string.
pub fn where_query(value: Value) -> String {
    format!("?where={}", urlencode(&value.to_string()))
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Create a unique index directly, bypassing the schema API.
///
/// The `indexes` block builds **non-unique** indexes, so a test that needs a real collision cannot
/// get one through the API. No name is passed, so MongoDB auto-generates `<field>_1`, which is the
/// shape `duplicated_field` reads.
pub async fn create_unique_index(database: &str, collection: &str, field: &str) {
    use mongodb::options::IndexOptions;
    use mongodb::{Client, IndexModel};
    let client = Client::with_uri_str("mongodb://127.0.0.1:27017")
        .await
        .expect("mongo client");
    client
        .database(database)
        .collection::<bson::Document>(collection)
        .create_index(
            IndexModel::builder()
                .keys(bson::doc! { field: 1 })
                .options(IndexOptions::builder().unique(true).sparse(true).build())
                .build(),
        )
        .await
        .expect("create unique index");
}
