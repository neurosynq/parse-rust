//! Request identity, derived from headers.
//!
//! Mirrors the parts of `handleParseHeaders` (`middlewares.js:73-289`) that the current routes
//! need. The order of checks is upstream's and is load-bearing.

use crate::config::ServerConfig;

/// Header names. Case-insensitive on the wire; `http::HeaderMap` handles that.
pub mod headers {
    pub const APP_ID: &str = "x-parse-application-id";
    pub const MASTER_KEY: &str = "x-parse-master-key";
    pub const MAINTENANCE_KEY: &str = "x-parse-maintenance-key";
    pub const JAVASCRIPT_KEY: &str = "x-parse-javascript-key";
    pub const REST_API_KEY: &str = "x-parse-rest-api-key";
    pub const CLIENT_KEY: &str = "x-parse-client-key";
    pub const DOT_NET_KEY: &str = "x-parse-windows-key";
    pub const SESSION_TOKEN: &str = "x-parse-session-token";
    pub const INSTALLATION_ID: &str = "x-parse-installation-id";
}

/// How a request authenticated.
///
/// An enum rather than a bag of booleans on purpose. Upstream threads `isMaster` as a boolean
/// and `acl === undefined` as a master sentinel, and a missed check on either is a fail-open
/// privilege bug. A caller here has to name the case it is handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    /// Master key presented and matched.
    Master,
    /// Maintenance key presented and matched.
    Maintenance,
    /// A client key matched, or none was required.
    Client,
}

/// What authority a request carries, plus the two headers that are not credentials.
///
/// The split mirrors `handleParseHeaders`: `req.auth` decides privilege, while `req.info` carries
/// the session token and installation id **regardless of how the request authenticated**. Keeping
/// the token out of [`Credentials`] is what makes that true here: a master request still knows
/// which token it presented, which is what `GET /sessions/me` reads, while
/// [`crate::request::resolve`] never looks the token up for a master caller
/// (`middlewares.js:249-251`).
///
/// `installationId` is not a credential and grants nothing. It is carried because exactly one
/// behavior reads it: `destroyDuplicatedSessions` revokes a user's other sessions for the *same*
/// installation when a new one is minted (`RestWrite.js:1153`), so a request that drops the
/// header logs the user in twice on one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub credentials: Credentials,
    pub session_token: Option<String>,
    pub installation_id: Option<String>,
}

impl Authority {
    /// True only for the master key. **Not** true for maintenance, and deliberately not a field
    /// that can be set independently of how the request authenticated.
    pub fn is_master(&self) -> bool {
        matches!(self.credentials, Credentials::Master)
    }

    /// True for master or maintenance, which is the gate every class-security check uses.
    pub fn is_privileged(&self) -> bool {
        matches!(
            self.credentials,
            Credentials::Master | Credentials::Maintenance
        )
    }

    /// The session token this request presented, if any.
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

/// Why a request was refused before reaching a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderRejection {
    /// Wrong or missing appId, or a required client key was absent or wrong.
    ///
    /// Upstream answers all of these identically: HTTP 403, body `{"error":"unauthorized"}`,
    /// with **no `code` field** (`middlewares.js:829-832`). Collapsing the reasons is
    /// deliberate upstream, and reproducing it means not adding a more helpful message.
    Unauthorized,
}

/// Resolve authority from headers.
///
/// Upstream ordering that matters:
/// 1. The appId must match, else `invalidRequest`.
/// 2. **Master or maintenance short-circuits**, returning before client-key validation
///    (`middlewares.js:249-251`). A request carrying both a master key and a session token is a
///    master request, and the token is not resolved.
/// 3. Otherwise, if any client key is configured, one must match.
pub fn resolve(
    config: &ServerConfig,
    headers: &http::HeaderMap,
) -> Result<Authority, HeaderRejection> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    let installation_id = get(headers::INSTALLATION_ID).map(str::to_string);
    let session_token = get(headers::SESSION_TOKEN).map(str::to_string);
    let with = |credentials: Credentials| Authority {
        credentials,
        session_token: session_token.clone(),
        installation_id: installation_id.clone(),
    };

    match get(headers::APP_ID) {
        Some(id) if id == config.app_id => {}
        _ => return Err(HeaderRejection::Unauthorized),
    }

    if let Some(k) = get(headers::MASTER_KEY) {
        if k == config.master_key {
            return Ok(with(Credentials::Master));
        }
    }
    if let (Some(k), Some(expected)) = (get(headers::MAINTENANCE_KEY), &config.maintenance_key) {
        if k == expected {
            return Ok(with(Credentials::Maintenance));
        }
    }

    if config.requires_client_key() {
        let matched = [
            (get(headers::JAVASCRIPT_KEY), &config.javascript_key),
            (get(headers::REST_API_KEY), &config.rest_api_key),
            (get(headers::CLIENT_KEY), &config.client_key),
            (get(headers::DOT_NET_KEY), &config.dot_net_key),
        ]
        .iter()
        .any(|(presented, expected)| match (presented, expected) {
            (Some(p), Some(e)) => p == e,
            _ => false,
        });
        if !matched {
            return Err(HeaderRejection::Unauthorized);
        }
    }

    Ok(with(Credentials::Client))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ServerConfig {
        ServerConfig::new("app", "master").javascript_key("js")
    }

    fn hm(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut m = http::HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    fn credentials(
        config: &ServerConfig,
        pairs: &[(&str, &str)],
    ) -> Result<Credentials, HeaderRejection> {
        resolve(config, &hm(pairs)).map(|a| a.credentials)
    }

    fn anonymous() -> Credentials {
        Credentials::Client
    }

    #[test]
    fn master_key_wins_and_short_circuits_client_key_validation() {
        // A javascript key is configured, but a master request need not present one.
        let a = credentials(
            &cfg(),
            &[
                ("x-parse-application-id", "app"),
                ("x-parse-master-key", "master"),
            ],
        );
        assert_eq!(a, Ok(Credentials::Master));
    }

    #[test]
    fn master_key_beats_a_session_token_on_the_same_request() {
        // Upstream returns before resolving the token. A request carrying both is a master
        // request, not a user request.
        let a = resolve(
            &cfg(),
            &hm(&[
                ("x-parse-application-id", "app"),
                ("x-parse-master-key", "master"),
                ("x-parse-session-token", "r:tok"),
            ]),
        )
        .unwrap();
        assert_eq!(a.credentials, Credentials::Master);
        assert!(a.is_master());
        // The token is still visible, because `req.info` carries it regardless of privilege.
        // What master skips is resolving it into a user; see `crate::request::resolve`.
        assert_eq!(a.session_token(), Some("r:tok"));
    }

    #[test]
    fn a_configured_client_key_becomes_mandatory() {
        // Easy to trip over: with a client key configured, omitting it fails with a bare 403
        // that reads like an authorization problem rather than a missing header.
        let missing = credentials(&cfg(), &[("x-parse-application-id", "app")]);
        assert_eq!(missing, Err(HeaderRejection::Unauthorized));

        let wrong = credentials(
            &cfg(),
            &[
                ("x-parse-application-id", "app"),
                ("x-parse-javascript-key", "nope"),
            ],
        );
        assert_eq!(wrong, Err(HeaderRejection::Unauthorized));

        let right = credentials(
            &cfg(),
            &[
                ("x-parse-application-id", "app"),
                ("x-parse-javascript-key", "js"),
            ],
        );
        assert_eq!(right, Ok(anonymous()));
    }

    #[test]
    fn no_client_key_configured_means_none_required() {
        let c = ServerConfig::new("app", "master");
        assert_eq!(
            credentials(&c, &[("x-parse-application-id", "app")]),
            Ok(anonymous())
        );
    }

    #[test]
    fn any_one_of_the_configured_keys_suffices() {
        let c = ServerConfig::new("app", "master")
            .javascript_key("js")
            .rest_api_key("rest");
        for (k, v) in [
            ("x-parse-javascript-key", "js"),
            ("x-parse-rest-api-key", "rest"),
        ] {
            assert!(credentials(&c, &[("x-parse-application-id", "app"), (k, v)]).is_ok());
        }
    }

    #[test]
    fn wrong_or_missing_app_id_is_unauthorized() {
        assert_eq!(credentials(&cfg(), &[]), Err(HeaderRejection::Unauthorized));
        assert_eq!(
            credentials(&cfg(), &[("x-parse-application-id", "other")]),
            Err(HeaderRejection::Unauthorized)
        );
    }

    #[test]
    fn a_wrong_master_key_falls_through_rather_than_short_circuiting() {
        // It must not be treated as master, and it must not bypass client-key validation.
        let a = credentials(
            &cfg(),
            &[
                ("x-parse-application-id", "app"),
                ("x-parse-master-key", "wrong"),
            ],
        );
        assert_eq!(a, Err(HeaderRejection::Unauthorized));
    }

    #[test]
    fn session_token_is_carried_on_client_authority() {
        let a = resolve(
            &cfg(),
            &hm(&[
                ("x-parse-application-id", "app"),
                ("x-parse-javascript-key", "js"),
                ("x-parse-session-token", "r:abc"),
            ]),
        )
        .unwrap();
        assert_eq!(a.session_token(), Some("r:abc"));
    }

    #[test]
    fn maintenance_is_not_master() {
        let mut c = ServerConfig::new("app", "master");
        c.maintenance_key = Some("maint".into());
        let a = resolve(
            &c,
            &hm(&[
                ("x-parse-application-id", "app"),
                ("x-parse-maintenance-key", "maint"),
            ]),
        )
        .unwrap();
        assert_eq!(a.credentials, Credentials::Maintenance);
        assert!(
            !a.is_master(),
            "maintenance must not satisfy a master-key gate"
        );
        assert!(
            a.is_privileged(),
            "but it does satisfy the class-security gate"
        );
    }

    /// The installation id travels on every authority, not just on a client request. A master-key
    /// signup mints a session too, and that session's duplicate destruction reads it.
    #[test]
    fn the_installation_id_is_carried_regardless_of_how_the_request_authenticated() {
        for extra in [
            ("x-parse-master-key", "master"),
            ("x-parse-javascript-key", "js"),
        ] {
            let a = resolve(
                &cfg(),
                &hm(&[
                    ("x-parse-application-id", "app"),
                    extra,
                    ("x-parse-installation-id", "inst-1"),
                ]),
            )
            .unwrap();
            assert_eq!(a.installation_id.as_deref(), Some("inst-1"));
        }
    }
}
