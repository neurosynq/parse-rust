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
    //
    // **An empty variable is unset**, for every option, because upstream's CLI reads one only
    // when it is truthy (`cli/utils/commander.js:64`, `if (env[key])`), so `FOO=` in a compose
    // file means the default there. Reading it as a value would put the API at the root for an
    // empty `PARSE_SERVER_MOUNT_PATH` where upstream serves `/parse`.
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());

    // **The identity has no defaults, deliberately.** Upstream's documentation uses `myAppId` and
    // `myMasterKey` as examples, and defaulting to them here would mean a server started without
    // configuration answers to a master key printed in every Parse tutorial. The master key is
    // total authority: it bypasses ACLs, CLPs and the class-security gate. A server that refuses
    // to start is a loud, fixable mistake; one that starts with a guessable master key is a
    // silent, unfixable one.
    let required = |k: &str| -> std::io::Result<String> {
        env(k).ok_or_else(|| {
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
        config.check_mount_path().map_err(|why| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("PARSE_SERVER_MOUNT_PATH: {why}"),
            )
        })?;
    }

    // Every option below carries upstream's env var name and upstream's default, read at the pin.
    // A wrong default here is a security default, so each one is checked rather than guessed, and
    // an unparsable value is a hard failure rather than a silent fallback to the default: a typo
    // in `PARSE_SERVER_EXPIRE_INACTIVE_SESSIONS` must not quietly produce sessions that never
    // expire.
    if let Some(v) = env("PARSE_SERVER_SESSION_LENGTH") {
        config.session.session_length_secs = number(&v, "PARSE_SERVER_SESSION_LENGTH")?;
    }
    if let Some(v) = env("PARSE_SERVER_EXPIRE_INACTIVE_SESSIONS") {
        config.session.expire_inactive_sessions =
            boolean(&v, "PARSE_SERVER_EXPIRE_INACTIVE_SESSIONS")?;
    }
    if let Some(v) = env("PARSE_SERVER_PROTECTED_FIELDS_OWNER_EXEMPT") {
        config.protected_fields_owner_exempt =
            boolean(&v, "PARSE_SERVER_PROTECTED_FIELDS_OWNER_EXEMPT")?;
    }
    if let Some(v) = env("PARSE_SERVER_PROTECTED_FIELDS_SAVE_RESPONSE_EXEMPT") {
        config.protected_fields_save_response_exempt =
            boolean(&v, "PARSE_SERVER_PROTECTED_FIELDS_SAVE_RESPONSE_EXEMPT")?;
    }
    // Default `true`, which withholds the reason from every denial. Setting it to `false` puts
    // the detailed message back on the wire, which is a disclosure and is why it is opt-in.
    if let Some(v) = env("PARSE_SERVER_ENABLE_SANITIZED_ERROR_RESPONSE") {
        config.enable_sanitized_error_response =
            boolean(&v, "PARSE_SERVER_ENABLE_SANITIZED_ERROR_RESPONSE")?;
    }
    // Upstream's env var name sits under the `DATABASE_` prefix because the option lives in the
    // `databaseOptions` group, not because it is namespaced by subsystem elsewhere.
    if let Some(v) = env("PARSE_SERVER_DATABASE_CREATE_INDEX_ROLE_NAME") {
        config.create_index_role_name =
            boolean(&v, "PARSE_SERVER_DATABASE_CREATE_INDEX_ROLE_NAME")?;
    }
    if let Some(v) = env("PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID") {
        config.allow_custom_object_id = boolean(&v, "PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID")?;
    }
    // Comma-separated, because a list is not expressible in one environment variable otherwise.
    // Upstream takes an array in the config file and a comma-separated string from the environment
    // through the same parser, so the spelling matches.
    if let Some(v) = env("PARSE_SERVER_ALLOW_ORIGIN") {
        config.allow_origin = list(&v);
    }
    if let Some(v) = env("PARSE_SERVER_ALLOW_HEADERS") {
        config.allow_headers = list(&v);
    }
    // Both must be positive (`Config.js:674-690`). Upstream refuses to boot otherwise, and so does
    // this.
    if let Some(v) = env("PARSE_SERVER_DEFAULT_LIMIT") {
        config.default_limit = positive(&v, "PARSE_SERVER_DEFAULT_LIMIT")?;
    }
    if let Some(v) = env("PARSE_SERVER_MAX_LIMIT") {
        config.max_limit = Some(positive(&v, "PARSE_SERVER_MAX_LIMIT")?);
    }
    // Stringified JSON, `{"duration": minutes, "threshold": attempts}`, as upstream's
    // `objectParser` takes it, and refused at boot with upstream's messages when out of range.
    if let Some(v) = env("PARSE_SERVER_ACCOUNT_LOCKOUT") {
        config.account_lockout = Some(account_lockout(&v)?);
    }
    // Milliseconds, as upstream compares it, whatever its help text says; zero or unset never
    // expires. See `parse_rust_server::schema_cache`.
    if let Some(v) = env("PARSE_SERVER_DATABASE_SCHEMA_CACHE_TTL") {
        config.schema_cache_ttl = parse_rust_server::schema_cache::ttl_from_millis(number(
            &v,
            "PARSE_SERVER_DATABASE_SCHEMA_CACHE_TTL",
        )?);
    }
    // Sessions are always revoked when a password changes. Accepting `false` would promise an
    // operator that they survive, and they do not.
    if let Some(v) = env("PARSE_SERVER_REVOKE_SESSION_ON_PASSWORD_RESET") {
        if !boolean(&v, "PARSE_SERVER_REVOKE_SESSION_ON_PASSWORD_RESET")? {
            return Err(std::io::Error::other(
                "PARSE_SERVER_REVOKE_SESSION_ON_PASSWORD_RESET=false is not supported by \
                 parse-rust; a password change always revokes the user's other sessions",
            ));
        }
    }
    // Change-stream invalidation is not implemented. Accepting `true` would promise a multi-node
    // deployment fresh schemas and deliver a cache that only the TTL refreshes.
    if let Some(v) = env("PARSE_SERVER_DATABASE_ENABLE_SCHEMA_HOOKS") {
        if boolean(&v, "PARSE_SERVER_DATABASE_ENABLE_SCHEMA_HOOKS")? {
            return Err(std::io::Error::other(
                "PARSE_SERVER_DATABASE_ENABLE_SCHEMA_HOOKS is not supported by parse-rust; \
                 bound schema staleness with PARSE_SERVER_DATABASE_SCHEMA_CACHE_TTL instead",
            ));
        }
    }
    if let Some(v) = env("PARSE_SERVER_DATABASE_ALLOW_PUBLIC_EXPLAIN") {
        config.allow_public_explain = boolean(&v, "PARSE_SERVER_DATABASE_ALLOW_PUBLIC_EXPLAIN")?;
    }
    if let Some(v) = env("PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION") {
        config.allow_client_class_creation =
            boolean(&v, "PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION")?;
    }
    if let Some(v) = env("PARSE_SERVER_REQUEST_COMPLEXITY_BATCH_REQUEST_LIMIT") {
        config.batch_request_limit =
            number(&v, "PARSE_SERVER_REQUEST_COMPLEXITY_BATCH_REQUEST_LIMIT")?;
    }
    // The master key's address allowlist. Left unset it keeps upstream's default, which is loopback
    // only, so a deployment that wants to use the master key from elsewhere has to say so.
    //
    // **`maintenanceKeyIps` deliberately has no variable here, and upstream does define one.**
    // The pin declares both `PARSE_SERVER_MAINTENANCE_KEY` and `PARSE_SERVER_MAINTENANCE_KEY_IPS`
    // (`Options/Definitions.js:387`, `:392`), so this is a parse-rust CLI limitation rather than a
    // gap on upstream's side, and an earlier version of this comment claimed the opposite.
    //
    // The key itself is not exposed by this binary, so its allowlist is not either: a variable
    // configuring the allowlist of a credential the binary cannot hold would read as support for
    // the credential. Why the key stays unexposed is on `ServerConfig::maintenance_key`, and the
    // reason is no longer the missing IP filter.
    //
    // **The empty array cannot be expressed here and that is upstream's limitation too**: there is
    // no way to pass an empty array through an environment variable, so `masterKeyIps: []`, which
    // disables the key entirely, is reachable only through `ServerConfig`. Setting the variable to
    // an empty string is unset, so it keeps the loopback default, as upstream's CLI skips it; an
    // empty entry inside a list, such as `127.0.0.1,`, is refused at start.
    if let Some(v) = env("PARSE_SERVER_MASTER_KEY_IPS") {
        config.master_key_ips = ip_allowlist(&v, "PARSE_SERVER_MASTER_KEY_IPS")?;
    }
    // `protectedFields` is stringified JSON upstream, `{"ClassName": {"entity": ["field"]}}`.
    //
    // **Setting it adds to the defaults rather than replacing them** (`ParseServer.ts:657-673`),
    // so this parses into a fresh map and folds the defaults back in rather than assigning over
    // `config.protected_fields`. Assigning is the obvious translation and it silently unprotects
    // `_User.email` for any deployment whose configuration names only its own classes. Read after
    // `PARSE_SERVER_PROTECTED_FIELDS_OWNER_EXEMPT` above, because that option changes the merge.
    if let Some(v) = env("PARSE_SERVER_PROTECTED_FIELDS") {
        let mut configured = protected_fields(&v)?;
        parse_rust_server::config::merge_protected_fields_defaults(
            &mut configured,
            config.protected_fields_owner_exempt,
        );
        config.protected_fields = configured;
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
    // An unparsable `PORT` is refused rather than replaced by the default, because a typo must not
    // quietly put the server on a port nobody configured. An empty one is unset, as every variable
    // is.
    let port: u16 = match env("PORT") {
        Some(p) => p
            .parse()
            .map_err(|_| std::io::Error::other(format!("PORT must be a port number, got {p:?}")))?,
        None => 27800,
    };

    // `PARSE_SERVER_HOST` is upstream's option name, but the default is deliberately different:
    // upstream defaults to `0.0.0.0` (`Options/Definitions.js:326-328`) and this defaults to
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
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stopping = stop.clone();
    let (bound, server) =
        parse_rust_server::serve_with_shutdown(
            state,
            addr,
            async move { stopping.notified().await },
        )
        .await?;
    // Machine-readable on its own line, so a harness can bind port 0 and discover the result.
    println!("parse-rust listening on http://{bound}");
    // SIGTERM is how `docker stop` and most supervisors ask a process to end, and a container's
    // first process has no default action for it, so without a handler it ran until killed. On
    // the signal the server stops accepting connections and lets the requests already in flight
    // finish, a batch included, for at most `DRAIN`: inside Docker's default 10 s stop window, so
    // the drain ends on its own terms rather than by the kill that follows.
    const DRAIN: std::time::Duration = std::time::Duration::from_secs(8);
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => return result,
        _ = shutdown_signal() => {}
    }
    stop.notify_one();
    match tokio::time::timeout(DRAIN, server).await {
        Ok(result) => result,
        Err(_) => {
            eprintln!("parse-rust: requests still running after {DRAIN:?}; stopping anyway");
            Ok(())
        }
    }
}

/// SIGTERM or Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `parsers.arrayParser`, which is a plain `split(',')` and nothing else
/// (`Options/parsers.js:42-50`).
///
/// **No trimming and no dropping of empty entries**, as upstream's split keeps them: an empty entry
/// such as the one in `https://a.example,` matches no browser origin. A variable that is empty as a
/// whole never reaches this, because an empty variable is unset, so `PARSE_SERVER_ALLOW_ORIGIN=`
/// is upstream's default `*`, as upstream's CLI reads it.
fn list(value: &str) -> Vec<String> {
    value.split(',').map(str::to_string).collect()
}

/// `parsers.booleanParser` (`Options/parsers.js:64-69`), **with one deliberate difference**.
///
/// Upstream is `opt == true || opt == 'true' || opt == '1'`, and **everything else returns false**.
/// It never reports a bad value: `PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID=yes` is silently `false`
/// there, and so is `treu`.
///
/// `true` and `1` are accepted here for the same reason upstream accepts them, because an operator
/// who wrote `=1` meant it. An unrecognised value is a startup failure rather than a silent
/// `false`, and that is the difference: every option this parses is a security default, so reading
/// a typo as "off" is the failure mode worth refusing. A server that will not start is a mistake
/// you fix in a minute; one that started with `expireInactiveSessions` quietly off is not.
///
/// Blast radius: a deployment relying on upstream's coercion of a junk value to `false` gets a
/// startup failure instead.
fn boolean(value: &str, name: &str) -> std::io::Result<bool> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(std::io::Error::other(format!(
            "{name} must be `true` or `false`, got {other:?}"
        ))),
    }
}

/// `parsers.numberParser` (`Options/parsers.js:1-9`), **with one deliberate difference**.
///
/// Upstream is `parseInt`, which stops at the first non-digit: `parseInt("5abc")` is `5`, and only
/// a value with no leading digits at all throws. This requires the whole string to be an integer.
///
/// Same reasoning as the boolean above. `PARSE_SERVER_SESSION_LENGTH=30d` meaning thirty seconds is
/// a silent misconfiguration of a security default, and the shape of typo that produces it, a unit
/// suffix, is the likely one. Blast radius: a value upstream would truncate is refused here.
fn number(value: &str, name: &str) -> std::io::Result<i64> {
    value
        .parse()
        .map_err(|_| std::io::Error::other(format!("{name} must be a number, got {value:?}")))
}

/// `accountLockout` from its environment variable.
fn account_lockout(value: &str) -> std::io::Result<parse_rust_server::lockout::AccountLockout> {
    let parsed: serde_json::Value = serde_json::from_str(value).map_err(|e| {
        std::io::Error::other(format!("PARSE_SERVER_ACCOUNT_LOCKOUT must be JSON: {e}"))
    })?;
    let duration = parsed.get("duration").and_then(serde_json::Value::as_f64);
    let threshold = parsed
        .get("threshold")
        .and_then(serde_json::Value::as_u64)
        .and_then(|t| u32::try_from(t).ok());
    let unlock = match parsed.get("unlockOnPasswordReset") {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => {
            return Err(std::io::Error::other(
                "Parse Server option accountLockout.unlockOnPasswordReset must be a boolean.",
            ))
        }
    };
    let policy = parse_rust_server::lockout::AccountLockout {
        duration: duration.unwrap_or(f64::NAN),
        threshold: threshold.unwrap_or(0),
        unlock_on_password_reset: unlock,
    };
    policy.validate().map_err(std::io::Error::other)?;
    Ok(policy)
}

/// A positive whole number of rows, for `defaultLimit` and `maxLimit`.
fn positive(value: &str, name: &str) -> std::io::Result<u32> {
    match value.parse::<u32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(std::io::Error::other(format!(
            "{name} must be a whole number greater than 0, got {value:?}"
        ))),
    }
}

/// `parsers.objectParser`: stringified JSON, `{"ClassName": {"entity": ["field", ...]}}`.
fn protected_fields(value: &str) -> std::io::Result<parse_rust_server::ProtectedFieldsConfig> {
    let parsed: parse_rust_server::ProtectedFieldsConfig =
        serde_json::from_str(value).map_err(|e| {
            std::io::Error::other(format!(
                "PARSE_SERVER_PROTECTED_FIELDS must be JSON of the form \
                 {{\"ClassName\": {{\"entity\": [\"field\"]}}}}: {e}"
            ))
        })?;
    Ok(parsed)
}

/// A comma-separated address allowlist, for `masterKeyIps` and `maintenanceKeyIps`.
///
/// **Upstream refuses a malformed entry too, and this is the same refusal.** `arrayParser` only
/// splits on commas (`Options/parsers.js:42-50`), and `Config.validateIps` then rejects any entry
/// whose address portion is not an IP, naming it (`Config.js:632-641`). So neither server trims,
/// and an empty value fails to boot on both.
///
/// The one difference is the mask, which upstream strips before validating: `127.0.0.1/999` boots
/// there and throws out of `BlockList.addSubnet` on the first master-key request, which the client
/// sees as a 500. Refusing it at boot is the same information before it matters.
fn ip_allowlist(value: &str, name: &str) -> std::io::Result<parse_rust_server::IpAllowlist> {
    parse_rust_server::IpAllowlist::parse_env(value)
        .map_err(|e| std::io::Error::other(format!("{name}: {e}")))
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
