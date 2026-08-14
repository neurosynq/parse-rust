//! Server configuration.
//!
//! A deliberately small slice of upstream's ~292 options: what `/serverInfo` and the header
//! layer actually need. Options are added when a route needs one, not speculatively, so that
//! every field here has a behavior behind it.

/// The parse-server version parse-rust reports as its own.
///
/// **This is a decision, not an oversight.** `/serverInfo` returns `parseServerVersion`, and
/// SDKs branch on it: the Ruby SDK warns below 7.0.0, and features gate on version comparisons.
/// Reporting `parse-rust 0.0.0` would fail every one of those checks, so the wire-compatible
/// answer is the parse-server version whose behavior this server implements. It is the same
/// number recorded in `PIN`.
///
/// If parse-rust ever needs to advertise itself distinctly, that belongs in a separate field
/// that upstream does not define, not in this one.
pub const REPORTED_PARSE_SERVER_VERSION: &str = "9.10.1-alpha.6";

/// What this server can actually do, as reported by `GET /serverInfo`.
///
/// **The key set and the nesting of the `features` object are wire contract. The booleans are
/// not.** Upstream hardcodes nearly all of them to `true` (`FeaturesRouter.js`) because upstream
/// implements the subsystems behind them. Transcribing those literals would advertise a schema
/// API, cloud jobs, hooks, a global config and a log API that all answer 404 here.
///
/// That matters because the object is not documentation: Parse Dashboard builds its UI from it,
/// so an advertised capability becomes a button that fails when a user presses it. This is a
/// deliberate difference from upstream, in the direction of telling the truth. Every field is
/// `false` until the subsystem behind it exists, and flipping one is part of landing that
/// subsystem rather than a follow-up.
#[derive(Debug, Clone, Default)]
pub struct FeatureSupport {
    /// `/config`. Not implemented.
    pub global_config: bool,
    /// `/hooks`. Not implemented.
    pub hooks: bool,
    /// Cloud Code jobs. Not implemented; `TriggerHost` is the milestone that lands them.
    pub cloud_code_jobs: bool,
    /// The log API. Not implemented.
    pub logs: bool,
    /// The schema API, `/schemas`. Not implemented. Note this is the *API*: schema inference
    /// and enforcement do work, but no route exposes them.
    pub schemas: bool,
    /// Push, including audiences and localization. Not implemented.
    pub push_audiences: bool,
}

/// The keys and identity a request is checked against.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub app_id: String,
    pub master_key: String,
    /// The read-only master key sets `isMaster` upstream (`Auth.js:63`), with the restriction
    /// enforced by scattered checks. Not implemented yet; recorded so the gap is visible.
    pub maintenance_key: Option<String>,
    pub javascript_key: Option<String>,
    pub rest_api_key: Option<String>,
    pub client_key: Option<String>,
    pub dot_net_key: Option<String>,
    /// Where the API is mounted, e.g. `/parse`. A **builder input, never inferred from the
    /// request path**: axum's `nest` and Express's `app.use` differ here, and every generated
    /// file URL is built from this value.
    pub mount_path: String,
    /// `enableSanitizedErrorResponse`, default true (`Options/Definitions.js:253-258`). When
    /// true, a 403 from the master-key gate says `Permission denied` rather than naming the
    /// reason.
    pub enable_sanitized_error_response: bool,
    pub has_push_support: bool,
    pub has_push_scheduled_support: bool,
    pub security_check_enabled: bool,
    /// What `/serverInfo` advertises. Defaults to the truth: nothing unimplemented.
    pub features: FeatureSupport,
}

impl ServerConfig {
    pub fn new(app_id: impl Into<String>, master_key: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            master_key: master_key.into(),
            maintenance_key: None,
            javascript_key: None,
            rest_api_key: None,
            client_key: None,
            dot_net_key: None,
            mount_path: "/parse".to_string(),
            enable_sanitized_error_response: true,
            has_push_support: false,
            has_push_scheduled_support: false,
            security_check_enabled: false,
            features: FeatureSupport::default(),
        }
    }

    pub fn javascript_key(mut self, k: impl Into<String>) -> Self {
        self.javascript_key = Some(k.into());
        self
    }

    pub fn rest_api_key(mut self, k: impl Into<String>) -> Self {
        self.rest_api_key = Some(k.into());
        self
    }

    pub fn mount_path(mut self, p: impl Into<String>) -> Self {
        self.mount_path = p.into();
        self
    }

    /// True when any client key is configured. Upstream's rule is all-or-nothing: if *any* of
    /// these is set, a non-master request must present one that matches
    /// (`middlewares.js:255-265`). If none is configured, none is required.
    pub fn requires_client_key(&self) -> bool {
        self.javascript_key.is_some()
            || self.rest_api_key.is_some()
            || self.client_key.is_some()
            || self.dot_net_key.is_some()
    }
}
