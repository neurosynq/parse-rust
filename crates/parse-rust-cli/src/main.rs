//! The parse-rust binary. Argument parsing and nothing else.
//!
//! Everything real lives in `parse-rust-server`. This exists as a separate package so that a
//! library embedder cannot have its dependencies pulled back in by a sibling crate's feature
//! choice.

use std::net::SocketAddr;

use parse_rust_mongo::MongoAdapter;
use parse_rust_server::{AppState, ServerConfig};

#[tokio::main]
async fn main() {
    // Returning `io::Result` from main would print the error through `Debug`, so a missing
    // master key reads as `Error: Custom { kind: Other, error: "..." }`. This is the first
    // thing a new user sees when they get the configuration wrong, so it gets the message and
    // nothing else.
    if let Err(e) = run().await {
        eprintln!("parse-rust: {e}");
        std::process::exit(1);
    }
}

async fn run() -> std::io::Result<()> {
    // Placeholder wiring. Upstream has roughly 292 options and a real option surface is not built
    // yet; reading a handful of environment variables is enough to serve the routes that exist,
    // and pretending otherwise would be worse than saying so.
    let env = |k: &str| std::env::var(k).ok();

    // **The identity has no defaults, deliberately.** Upstream's documentation uses `myAppId` and
    // `myMasterKey` as examples, and defaulting to them here would mean a server started without
    // configuration answers to a master key printed in every Parse tutorial. The master key is
    // total authority: it bypasses ACLs, CLPs and the class-security gate. A server that refuses
    // to start is a loud, fixable mistake; one that starts with a guessable master key is a
    // silent, unfixable one.
    let required = |k: &str| -> std::io::Result<String> {
        std::env::var(k).map_err(|_| {
            std::io::Error::other(format!(
                "{k} is required. parse-rust has no default application id or master key: \
                 the master key bypasses every access control, so a default would be a \
                 published credential."
            ))
        })
    };
    let app_id = required("PARSE_SERVER_APPLICATION_ID")?;
    let master_key = required("PARSE_SERVER_MASTER_KEY")?;
    let mut config = ServerConfig::new(app_id, master_key);
    if let Some(k) = env("PARSE_SERVER_JAVASCRIPT_KEY") {
        config.javascript_key = Some(k);
    }
    if let Some(k) = env("PARSE_SERVER_REST_API_KEY") {
        config.rest_api_key = Some(k);
    }
    if let Some(m) = env("PARSE_SERVER_MOUNT_PATH") {
        config.mount_path = m;
    }

    let uri = env("PARSE_SERVER_DATABASE_URI")
        .unwrap_or_else(|| "mongodb://127.0.0.1:27017/parse".into());
    let database = database_from_uri(&uri).to_string();
    let storage = MongoAdapter::connect(&uri, &database)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Not 1337. This project must be able to run *beside* a stock parse-server on the same
    // machine, and 1337 is exactly where that one is. The default sits in the 27xxx block this
    // repository has registered for differential runs. `PORT=0` binds an ephemeral port and is
    // what every test uses, so parallel test batteries cannot collide with each other.
    let port: u16 = env("PORT").and_then(|p| p.parse().ok()).unwrap_or(27800);

    // `PARSE_SERVER_HOST` is upstream's option name, but the default is deliberately different:
    // upstream defaults to `0.0.0.0` (`Options/Definitions.js:320-322`) and this defaults to
    // loopback. parse-rust is not production software yet, and a default that only listens
    // locally cannot expose a half-built server to a network by accident. Set the variable to
    // `0.0.0.0` to publish it, which is what a container needs.
    let host = env("PARSE_SERVER_HOST").unwrap_or_else(|| "127.0.0.1".into());
    let ip: std::net::IpAddr = host.parse().map_err(|_| {
        std::io::Error::other(format!("PARSE_SERVER_HOST is not an IP address: {host}"))
    })?;
    let addr = SocketAddr::new(ip, port);

    // `serve` creates the unique indexes before binding, so the binary does not do it here. That
    // is deliberate: every embedder needs them, and a step only the binary performs is a step an
    // embedded deployment silently skips.
    let state = AppState::new(config, storage);
    let (bound, server) = parse_rust_server::serve(state, addr).await?;
    // Machine-readable on its own line, so a harness can bind port 0 and discover the result.
    println!("parse-rust listening on http://{bound}");
    server.await
}

/// Default database name when the URI selects none. Upstream's own default is `parse`.
const DEFAULT_DATABASE: &str = "parse";

/// The database a MongoDB URI selects.
///
/// It is the path segment after the authority, with any query string or fragment removed. Taking
/// the last `/`-separated segment of the whole URI looks equivalent and is not: for a URI with no
/// database path at all, `mongodb://127.0.0.1:27017`, that yields `127.0.0.1:27017` as the
/// database name. Mongo does not reject that until a much later operation, in a message that
/// says nothing about the URI.
fn database_from_uri(uri: &str) -> &str {
    let after_scheme = uri.split_once("://").map(|(_, rest)| rest).unwrap_or(uri);
    // Everything up to the first `/` is credentials, hosts and ports. Both are percent-encoded in
    // a valid URI, so no `/` can appear inside them.
    let Some((_, path)) = after_scheme.split_once('/') else {
        return DEFAULT_DATABASE;
    };
    match path.split(['?', '#']).next() {
        Some(name) if !name.is_empty() => name,
        _ => DEFAULT_DATABASE,
    }
}

#[cfg(test)]
mod tests {
    use super::database_from_uri;

    #[test]
    fn plain_uri() {
        assert_eq!(
            database_from_uri("mongodb://127.0.0.1:27017/parse"),
            "parse"
        );
    }

    #[test]
    fn query_string_is_not_part_of_the_name() {
        assert_eq!(
            database_from_uri("mongodb://host/app?retryWrites=true&w=majority"),
            "app"
        );
        assert_eq!(database_from_uri("mongodb://host/app#frag"), "app");
    }

    #[test]
    fn no_database_path_falls_back_rather_than_naming_the_host() {
        // The case the previous implementation got wrong, in both its forms.
        assert_eq!(database_from_uri("mongodb://127.0.0.1:27017"), "parse");
        assert_eq!(database_from_uri("mongodb://127.0.0.1:27017/"), "parse");
        assert_eq!(
            database_from_uri("mongodb://127.0.0.1:27017/?tls=true"),
            "parse"
        );
    }

    #[test]
    fn credentials_and_replica_sets_do_not_confuse_it() {
        assert_eq!(
            database_from_uri("mongodb://user:pass@a:27017,b:27017/app?replicaSet=rs0"),
            "app"
        );
        assert_eq!(
            database_from_uri("mongodb+srv://user:pass@cluster.example/app"),
            "app"
        );
    }
}
