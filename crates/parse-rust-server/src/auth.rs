//! Request identity, derived from headers.
//!
//! Mirrors the parts of `handleParseHeaders` (`middlewares.js:73-289`) that the current routes
//! need. The order of checks is upstream's and is load-bearing.

use std::net::IpAddr;

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
    pub const CLOUD_CONTEXT: &str = "x-parse-cloud-context";
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
/// installation when a new one is minted (`RestWrite.js:1245`), so a request that drops the
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
    /// with **no `code` field** (`middlewares.js:845-848`). Collapsing the reasons is
    /// deliberate upstream, and reproducing it means not adding a more helpful message.
    Unauthorized,
}

/// Where a request came from, as far as the allowlist is concerned.
///
/// **An enum rather than an `Option<IpAddr>`, because the two cases fail in opposite directions**
/// and the one that is easy to write is the wrong one. `Unknown` means the transport did not
/// supply a peer address, which happens when an embedder mounts [`crate::router`] into its own
/// axum app without `into_make_service_with_connect_info`. A privileged key is refused in that
/// case: an allowlist that cannot see the address it is filtering on has not been satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// The address the socket reports.
    Address(IpAddr),
    /// No peer address is available. Every privileged key is refused.
    Unknown,
}

impl Peer {
    fn allowed_by(self, allowlist: &crate::ip_allowlist::IpAllowlist) -> bool {
        match self {
            Peer::Address(ip) => allowlist.allows(ip),
            Peer::Unknown => false,
        }
    }
}

impl From<std::net::SocketAddr> for Peer {
    fn from(addr: std::net::SocketAddr) -> Self {
        Peer::Address(addr.ip())
    }
}

/// Resolve authority from headers and the peer address.
///
/// Upstream ordering that matters:
/// 1. The appId must match, else `invalidRequest`.
/// 2. **Master or maintenance short-circuits**, returning before client-key validation
///    (`middlewares.js:249-251`). A request carrying both a master key and a session token is a
///    master request, and the token is not resolved.
/// 3. Otherwise, if any client key is configured, one must match.
///
/// **The peer address is the socket's, never a header's.** Upstream's `getClientIp` is `req.ip`
/// (`middlewares.js:358-360`), and Express resolves that from the connection unless `trust proxy`
/// is set, which parse-server does not set. An allowlist that reads `X-Forwarded-For` is not an
/// allowlist, because the caller writes it. A deployment behind a load balancer therefore sees
/// every request as coming from the balancer and must widen the option; that is an availability
/// failure rather than an authorization one, and it is the correct direction to fail in until
/// trusted-proxy configuration exists.
///
/// A matching master key from a non-allowlisted address is **refused**, not demoted to a client
/// request. Upstream throws (`middlewares.js:453-462`) rather than falling through, so a caller
/// cannot use a rejected master key to skip client-key validation.
pub fn resolve_with_peer(
    config: &ServerConfig,
    headers: &http::HeaderMap,
    peer: Peer,
) -> Result<Authority, HeaderRejection> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    let installation_id = get(headers::INSTALLATION_ID).map(str::to_string);
    // Empty is absent: upstream builds an anonymous `Auth` on `!info.sessionToken`
    // (`middlewares.js:281-287`), so a blank header is not a token to look up and fail.
    let session_token = get(headers::SESSION_TOKEN)
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let with = |credentials: Credentials| Authority {
        credentials,
        session_token: session_token.clone(),
        installation_id: installation_id.clone(),
    };

    match get(headers::APP_ID) {
        Some(id) if id == config.app_id => {}
        _ => return Err(HeaderRejection::Unauthorized),
    }

    // **Maintenance is tested first, and the order is upstream's** (`resolveKeyAuth`,
    // `middlewares.js:436-455`). It was reversed here until the two keys grew separate address
    // allowlists, at which point it became observable: a request carrying both valid keys from an
    // address allowed for one and not the other resolves to a different authority on each server,
    // or is accepted by one and refused by the other.
    if let (Some(k), Some(expected)) = (get(headers::MAINTENANCE_KEY), &config.maintenance_key) {
        if k == expected {
            if !peer.allowed_by(&config.maintenance_key_ips) {
                return Err(HeaderRejection::Unauthorized);
            }
            return Ok(with(Credentials::Maintenance));
        }
    }
    if let Some(k) = get(headers::MASTER_KEY) {
        if k == config.master_key {
            if !peer.allowed_by(&config.master_key_ips) {
                return Err(HeaderRejection::Unauthorized);
            }
            return Ok(with(Credentials::Master));
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

/// The 0.2.0 signature, kept so a patch release does not stop a downstream crate compiling.
///
/// **It fails closed rather than preserving 0.2.0's behavior**, which is the point: 0.2.0's
/// behavior here is the defect. With no peer address there is nothing to check `masterKeyIps`
/// against, so the master and maintenance keys are refused and every other request is unaffected.
/// A caller that wants them to work has to say where the request came from, which is
/// [`resolve_with_peer`].
///
/// Cargo treats 0.2.1 as compatible with 0.2.0 and will upgrade into it without being asked, so
/// removing this would turn a security patch into a build failure for anyone calling `resolve`
/// directly. Keeping it means their build still succeeds and their privileged keys stop working
/// until they pass an address, which is loud at runtime and safe in the meantime.
#[deprecated(
    since = "0.2.1",
    note = "the master key is filtered by source address; call resolve_with_peer. \
            This form refuses every master and maintenance key because it has no address to check."
)]
pub fn resolve(
    config: &ServerConfig,
    headers: &http::HeaderMap,
) -> Result<Authority, HeaderRejection> {
    resolve_with_peer(config, headers, Peer::Unknown)
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

    /// The address the whole existing battery speaks from, and the one the shipped default
    /// allows. Tests about the allowlist itself name their address explicitly.
    fn loopback() -> Peer {
        Peer::Address("127.0.0.1".parse().expect("loopback"))
    }

    fn from(address: &str) -> Peer {
        Peer::Address(address.parse().expect("test address"))
    }

    fn resolve_from(
        config: &ServerConfig,
        pairs: &[(&str, &str)],
        peer: Peer,
    ) -> Result<Authority, HeaderRejection> {
        resolve_with_peer(config, &hm(pairs), peer)
    }

    fn credentials(
        config: &ServerConfig,
        pairs: &[(&str, &str)],
    ) -> Result<Credentials, HeaderRejection> {
        resolve_with_peer(config, &hm(pairs), loopback()).map(|a| a.credentials)
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
        let a = resolve_with_peer(
            &cfg(),
            &hm(&[
                ("x-parse-application-id", "app"),
                ("x-parse-master-key", "master"),
                ("x-parse-session-token", "r:tok"),
            ]),
            loopback(),
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
        let a = resolve_with_peer(
            &cfg(),
            &hm(&[
                ("x-parse-application-id", "app"),
                ("x-parse-javascript-key", "js"),
                ("x-parse-session-token", "r:abc"),
            ]),
            loopback(),
        )
        .unwrap();
        assert_eq!(a.session_token(), Some("r:abc"));
    }

    #[test]
    fn maintenance_is_not_master() {
        let mut c = ServerConfig::new("app", "master");
        c.maintenance_key = Some("maint".into());
        let a = resolve_with_peer(
            &c,
            &hm(&[
                ("x-parse-application-id", "app"),
                ("x-parse-maintenance-key", "maint"),
            ]),
            loopback(),
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
            let a = resolve_with_peer(
                &cfg(),
                &hm(&[
                    ("x-parse-application-id", "app"),
                    extra,
                    ("x-parse-installation-id", "inst-1"),
                ]),
                loopback(),
            )
            .unwrap();
            assert_eq!(a.installation_id.as_deref(), Some("inst-1"));
        }
    }

    // -----------------------------------------------------------------------------------------
    // masterKeyIps
    // -----------------------------------------------------------------------------------------

    const MASTER: [(&str, &str); 2] = [
        ("x-parse-application-id", "app"),
        ("x-parse-master-key", "master"),
    ];

    /// The shipped defect. 0.2.0 answered `Credentials::Master` here, from any address on a
    /// server nobody had configured.
    #[test]
    fn a_master_key_from_a_non_allowlisted_address_is_refused_at_the_default() {
        let c = ServerConfig::new("app", "master");
        for peer in ["127.0.0.2", "10.0.0.5", "203.0.113.9", "2001:db8::1"] {
            assert_eq!(
                resolve_from(&c, &MASTER, from(peer)),
                Err(HeaderRejection::Unauthorized),
                "{peer} must not be able to use the master key at the default"
            );
        }
    }

    /// The control for the default: refusing everything would satisfy the test above.
    #[test]
    fn a_master_key_from_loopback_still_works_at_the_default() {
        let c = ServerConfig::new("app", "master");
        for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(
                resolve_from(&c, &MASTER, from(peer)).map(|a| a.credentials),
                Ok(Credentials::Master),
                "{peer} is the machine the server runs on"
            );
        }
    }

    /// The control for the filter: adding the address makes the identical request succeed, so the
    /// refusal above is the allowlist and not a broken master key.
    #[test]
    fn adding_the_address_admits_the_same_request() {
        let mut c = ServerConfig::new("app", "master");
        c.master_key_ips =
            crate::ip_allowlist::IpAllowlist::parse(["127.0.0.1", "::1", "127.0.0.2"])
                .expect("entries");
        assert_eq!(
            resolve_from(&c, &MASTER, from("127.0.0.2")).map(|a| a.credentials),
            Ok(Credentials::Master)
        );
    }

    /// **A refused master key is refused, not demoted.** Falling through to client-key validation
    /// would let a caller holding a master key it is not allowed to use skip a check it would
    /// otherwise have to satisfy, and would answer 200 for a request upstream answers 403.
    #[test]
    fn a_refused_master_key_does_not_fall_through_to_the_client_key() {
        let c = ServerConfig::new("app", "master").javascript_key("js");
        let with_client_key = [
            ("x-parse-application-id", "app"),
            ("x-parse-master-key", "master"),
            ("x-parse-javascript-key", "js"),
        ];
        assert_eq!(
            resolve_from(&c, &with_client_key, from("10.0.0.5")),
            Err(HeaderRejection::Unauthorized)
        );
    }

    /// A wrong master key is not a master key at all, so the allowlist never applies to it and the
    /// request is still an ordinary client request.
    #[test]
    fn a_wrong_master_key_is_unaffected_by_the_allowlist() {
        let c = ServerConfig::new("app", "master").javascript_key("js");
        let wrong = [
            ("x-parse-application-id", "app"),
            ("x-parse-master-key", "nope"),
            ("x-parse-javascript-key", "js"),
        ];
        assert_eq!(
            resolve_from(&c, &wrong, from("10.0.0.5")).map(|a| a.credentials),
            Ok(Credentials::Client)
        );
    }

    /// An ordinary request is not filtered. The allowlist governs the two privileged keys and
    /// nothing else, so a client from anywhere is still a client.
    #[test]
    fn the_allowlist_does_not_touch_an_ordinary_client_request() {
        let c = ServerConfig::new("app", "master").javascript_key("js");
        let client = [
            ("x-parse-application-id", "app"),
            ("x-parse-javascript-key", "js"),
        ];
        assert_eq!(
            resolve_from(&c, &client, from("203.0.113.9")).map(|a| a.credentials),
            Ok(Credentials::Client)
        );
    }

    /// The empty array means the key cannot be used at all, including from the server itself.
    #[test]
    fn an_empty_allowlist_refuses_loopback_too() {
        let mut c = ServerConfig::new("app", "master");
        c.master_key_ips = crate::ip_allowlist::IpAllowlist::deny_all();
        for peer in ["127.0.0.1", "::1"] {
            assert_eq!(
                resolve_from(&c, &MASTER, from(peer)),
                Err(HeaderRejection::Unauthorized)
            );
        }
    }

    /// The maintenance key carries the same filter and the same default. Filtering one privileged
    /// key and not the other would leave the identical hole one header away.
    #[test]
    fn the_maintenance_key_is_filtered_the_same_way() {
        let mut c = ServerConfig::new("app", "master");
        c.maintenance_key = Some("maint".into());
        let maint = [
            ("x-parse-application-id", "app"),
            ("x-parse-maintenance-key", "maint"),
        ];
        assert_eq!(
            resolve_from(&c, &maint, loopback()).map(|a| a.credentials),
            Ok(Credentials::Maintenance)
        );
        assert_eq!(
            resolve_from(&c, &maint, from("10.0.0.5")),
            Err(HeaderRejection::Unauthorized)
        );
    }

    /// Failing closed when the transport gave no peer address. An allowlist that cannot see the
    /// address it filters on has not been satisfied, and the alternative reading, "no address
    /// means no restriction", is the shipped defect written a second time.
    #[test]
    fn an_unknown_peer_cannot_present_a_privileged_key() {
        let mut c = ServerConfig::new("app", "master");
        c.maintenance_key = Some("maint".into());
        assert_eq!(
            resolve_from(&c, &MASTER, Peer::Unknown),
            Err(HeaderRejection::Unauthorized)
        );
        assert_eq!(
            resolve_from(
                &c,
                &[
                    ("x-parse-application-id", "app"),
                    ("x-parse-maintenance-key", "maint"),
                ],
                Peer::Unknown,
            ),
            Err(HeaderRejection::Unauthorized)
        );
        // ...and an ordinary client request is unaffected, so an embedder without connect info
        // still serves everything except the two privileged keys.
        assert_eq!(
            resolve_from(&c, &[("x-parse-application-id", "app")], Peer::Unknown)
                .map(|a| a.credentials),
            Ok(Credentials::Client)
        );
    }

    /// **Both keys on one request resolve to maintenance, which is upstream's order.**
    /// `resolveKeyAuth` tests `maintenanceKeyValue` before the master key, and this was reversed
    /// here. It was unobservable until the two keys grew separate allowlists, and the tests below
    /// are the ones that would have caught it.
    #[test]
    fn both_keys_on_one_request_resolve_to_maintenance() {
        let mut c = ServerConfig::new("app", "master");
        c.maintenance_key = Some("maint".into());
        let both = [
            ("x-parse-application-id", "app"),
            ("x-parse-master-key", "master"),
            ("x-parse-maintenance-key", "maint"),
        ];
        assert_eq!(
            resolve_from(&c, &both, loopback()).map(|a| a.credentials),
            Ok(Credentials::Maintenance)
        );
    }

    /// The consequence that makes the order matter, in both directions. Whichever key is tested
    /// first decides which allowlist applies, so a request carrying both is accepted by one server
    /// and refused by the other if the two disagree about the order.
    #[test]
    fn with_both_keys_the_maintenance_allowlist_is_the_one_that_decides() {
        let both = [
            ("x-parse-application-id", "app"),
            ("x-parse-master-key", "master"),
            ("x-parse-maintenance-key", "maint"),
        ];

        // Maintenance refuses this address, master would have allowed it. Upstream refuses.
        let mut refusing = ServerConfig::new("app", "master");
        refusing.maintenance_key = Some("maint".into());
        refusing.maintenance_key_ips = crate::ip_allowlist::IpAllowlist::deny_all();
        assert_eq!(
            resolve_from(&refusing, &both, loopback()),
            Err(HeaderRejection::Unauthorized),
            "the maintenance allowlist decides, so a master key on the same request cannot rescue it"
        );

        // The converse: master refuses, maintenance allows. Upstream accepts, as maintenance.
        let mut allowing = ServerConfig::new("app", "master");
        allowing.maintenance_key = Some("maint".into());
        allowing.master_key_ips = crate::ip_allowlist::IpAllowlist::deny_all();
        assert_eq!(
            resolve_from(&allowing, &both, loopback()).map(|a| a.credentials),
            Ok(Credentials::Maintenance),
            "and a refused master key on the same request does not taint an allowed maintenance one"
        );
    }

    /// **The forgery case.** `resolve_with_peer` is given the socket's address and never reads a
    /// header, so
    /// there is nothing here for `X-Forwarded-For` to influence. Asserted rather than assumed,
    /// because "the code does not read the header" is exactly the kind of claim that stays true
    /// until someone adds proxy support and reads it by default.
    #[test]
    fn a_forwarded_header_moves_a_caller_neither_in_nor_out() {
        let c = ServerConfig::new("app", "master");
        let forged = [
            ("x-parse-application-id", "app"),
            ("x-parse-master-key", "master"),
            ("x-forwarded-for", "127.0.0.1"),
        ];
        assert_eq!(
            resolve_from(&c, &forged, from("10.0.0.5")),
            Err(HeaderRejection::Unauthorized),
            "a client-supplied header must not admit a non-allowlisted peer"
        );

        let pointing_out = [
            ("x-parse-application-id", "app"),
            ("x-parse-master-key", "master"),
            ("x-forwarded-for", "10.0.0.5"),
        ];
        assert_eq!(
            resolve_from(&c, &pointing_out, loopback()).map(|a| a.credentials),
            Ok(Credentials::Master),
            "and it must not evict an allowlisted one either"
        );
    }
}
