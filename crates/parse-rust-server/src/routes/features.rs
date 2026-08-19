//! `GET /serverInfo`. Master-key gated.
//!
//! Upstream: `src/Routers/FeaturesRouter.js`. The `features` object is a static capability
//! advertisement with three values read from config. Parse Dashboard reads it, so the key set
//! and nesting are wire contract, not documentation.

use serde_json::{json, Value as Json};

use crate::config::{ServerConfig, REPORTED_PARSE_SERVER_VERSION};

/// The response body. The master-key gate is applied by the dispatcher, not here.
///
/// The key set and nesting are transcribed from `FeaturesRouter` and are wire contract. The
/// values are **not** transcribed: upstream hardcodes almost all of them to `true` because
/// upstream implements them, and repeating that here would advertise hooks, a global config,
/// cloud jobs, a log API and push, none of which have routes. Parse Dashboard renders its UI from
/// this object, so a copied `true` becomes a control that 404s when a user clicks it. See
/// `FeatureSupport` for the reasoning; each flag flips as its subsystem lands.
pub fn server_info_body(config: &ServerConfig) -> Json {
    let f = &config.features;
    let features = json!({
        "globalConfig": {
            "create": f.global_config, "read": f.global_config,
            "update": f.global_config, "delete": f.global_config,
        },
        "hooks": {
            "create": f.hooks, "read": f.hooks, "update": f.hooks, "delete": f.hooks,
        },
        "cloudCode": { "jobs": f.cloud_code_jobs },
        "logs": {
            "level": f.logs, "size": f.logs, "order": f.logs, "until": f.logs, "from": f.logs,
        },
        "push": {
            "immediatePush": config.has_push_support,
            "scheduledPush": config.has_push_scheduled_support,
            "storedPushData": config.has_push_support,
            "pushAudiences": f.push_audiences,
            "localization": f.push_audiences,
        },
        "schemas": {
            "addField": f.schemas,
            "removeField": f.schemas,
            "addClass": f.schemas,
            "removeClass": f.schemas,
            "clearAllDataFromClass": f.schemas,
            // Upstream ships this as `false` even with the schema API fully present, so it stays
            // false here for both reasons and never follows `f.schemas`.
            "exportClass": false,
            "editClassLevelPermissions": f.schemas,
            "editPointerPermissions": f.schemas,
        },
        "settings": { "securityCheck": config.security_check_enabled },
    });

    json!({
        "features": features,
        "parseServerVersion": REPORTED_PARSE_SERVER_VERSION,
    })
}
