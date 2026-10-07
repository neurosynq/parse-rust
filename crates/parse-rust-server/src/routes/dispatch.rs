//! One route table, two entry points.
//!
//! Upstream's `/batch` re-enters its own router: `handleBatch` calls
//! `router.tryRouteRequest(method, routablePath, request)` (`batch.js:172`) against the same
//! `PromiseRouter` every HTTP request goes through, so a sub-request and a top-level request are
//! the same code. That includes the route middlewares, because `PromiseRouter.route` folds them
//! into the handler (`PromiseRouter.js:66-84`), which is why a `/schemas` sub-request still needs
//! the master key.
//!
//! Reproducing that shape here is what keeps a sub-request from drifting from its top-level twin.
//! The axum handlers build a [`Route`] from their path extractors; `/batch` builds one from a
//! string. Both then call [`dispatch`].

use parse_rust_core::ParseError;
use serde_json::Value as Json;

use crate::auth::Authority;
use crate::params::Params;
use crate::request::RequestContext;
use crate::response::HttpError;
use crate::routes::{classes, schemas, sessions, users};
use crate::state::AppState;

/// A resolved route. Every path parse-rust serves has a variant, and anything else is unroutable.
///
/// `/roles` and `/sessions` have their own variants rather than folding into [`Route::Classes`],
/// even though upstream implements them as `ClassesRouter` with `className()` pinned. The reason
/// is the method set: `POST /sessions` and `PUT /sessions/:objectId` are out of scope for 0.2.0
/// and have to 404, and a shared variant could not tell them apart from the class route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Health,
    ServerInfo,
    Users,
    UsersMe,
    Login,
    Logout,
    Classes {
        class_name: String,
    },
    ClassObject {
        class_name: String,
        object_id: String,
    },
    Roles,
    RoleObject {
        object_id: String,
    },
    Sessions,
    SessionsMe,
    SessionObject {
        object_id: String,
    },
    Schemas,
    SchemaClass {
        class_name: String,
    },
    Purge {
        class_name: String,
    },
    Batch,
}

/// What a handler produced.
pub struct RouteResponse {
    pub status: http::StatusCode,
    pub body: Json,
}

impl RouteResponse {
    fn ok(body: Json) -> Self {
        Self {
            status: http::StatusCode::OK,
            body,
        }
    }

    fn created(body: Json) -> Self {
        Self {
            status: http::StatusCode::CREATED,
            body,
        }
    }
}

/// Why a handler failed.
///
/// Two variants because Parse has two error envelopes and they are not interchangeable: a
/// `Parse.Error` carries a numeric `code`, an HTTP-level rejection does not
/// (`middlewares.js:596-645`). Collapsing them into one type is how a route ends up emitting the
/// wrong one.
pub enum RouteError {
    Parse(ParseError),
    Http(HttpError),
    /// No route serves this method and path.
    ///
    /// A third variant because the two entry points answer it differently and both are upstream's.
    /// Over HTTP an unmatched path falls off the end of the express router and Express answers a
    /// bare 404; inside a batch it is `tryRouteRequest`'s `INVALID_JSON` `cannot route <M> <p>`
    /// (`PromiseRouter.js:123-125`). Folding it into `Parse` gave `POST /sessions` a 400 with a
    /// Parse code, which is neither.
    NotFound {
        method: http::Method,
        path: String,
    },
}

impl From<ParseError> for RouteError {
    fn from(e: ParseError) -> Self {
        RouteError::Parse(e)
    }
}

/// Match a path against the 0.2.0 route table.
///
/// The order of the arms is the order upstream registers them, and it is load-bearing in two
/// places: `PromiseRouter.match` returns the first route whose layer matches
/// (`PromiseRouter.js:90-105`), so `/users/me` has to precede `/users/:objectId` and
/// `/sessions/me` has to precede `/sessions/:objectId`. Here the literals are matched before the
/// parameterized arms for the same reason, spelled out rather than left to declaration order.
pub fn route_of(path: &str) -> Option<Route> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    Some(match segments.as_slice() {
        ["health"] => Route::Health,
        ["serverInfo"] => Route::ServerInfo,
        ["batch"] => Route::Batch,

        ["users"] => Route::Users,
        ["users", "me"] => Route::UsersMe,
        ["login"] => Route::Login,
        ["logout"] => Route::Logout,

        ["classes", class_name] => Route::Classes {
            class_name: (*class_name).to_string(),
        },
        ["classes", class_name, object_id] => Route::ClassObject {
            class_name: (*class_name).to_string(),
            object_id: (*object_id).to_string(),
        },

        ["roles"] => Route::Roles,
        ["roles", object_id] => Route::RoleObject {
            object_id: (*object_id).to_string(),
        },

        ["sessions"] => Route::Sessions,
        ["sessions", "me"] => Route::SessionsMe,
        ["sessions", object_id] => Route::SessionObject {
            object_id: (*object_id).to_string(),
        },

        ["schemas"] => Route::Schemas,
        ["schemas", class_name] => Route::SchemaClass {
            class_name: (*class_name).to_string(),
        },
        ["purge", class_name] => Route::Purge {
            class_name: (*class_name).to_string(),
        },

        _ => return None,
    })
}

/// One request, as the dispatcher sees it.
///
/// A struct rather than a parameter list because both entry points build the same five values and
/// a positional call of that width is where an argument silently swaps places.
pub struct Incoming {
    pub method: http::Method,
    pub route: Route,
    /// The routable path. Used only to build the one error message that quotes it
    /// (`SchemasRouter.js:90`) and the unroutable-path message.
    pub path: String,
    pub params: Params,
    pub body: Option<Json>,
}

/// Run one route.
pub async fn dispatch(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    incoming: &Incoming,
) -> Result<RouteResponse, RouteError> {
    use http::Method as M;

    let Incoming {
        method,
        route,
        path,
        params,
        body,
    } = incoming;
    let path = path.as_str();

    // The body every write path needs. A route that reaches here with no body is a malformed
    // request, not an empty write: `Option<Json>` is `None` for an unparsable or oversized body
    // as well as an absent one, so treating it as `{}` would turn a rejection into a write.
    let body = || -> Result<&Json, RouteError> {
        body.as_ref().ok_or_else(|| {
            RouteError::Parse(ParseError::invalid_json("body must be a JSON object"))
        })
    };

    let response = match (route, method) {
        (Route::Health, &M::GET | &M::POST) => RouteResponse::ok(crate::routes::health::body()),

        (Route::ServerInfo, &M::GET) => {
            master_only(state, authority)?;
            RouteResponse::ok(crate::routes::features::server_info_body(state.config()))
        }

        (Route::Users, &M::POST) => {
            RouteResponse::created(users::signup_core(state, rc, authority, body()?).await?)
        }
        (Route::UsersMe, &M::GET) => RouteResponse::ok(users::me_core(state, rc).await?),
        (Route::Login, &M::POST) => {
            RouteResponse::ok(users::login_core(state, rc, authority, body()?).await?)
        }
        (Route::Logout, &M::POST) => RouteResponse::ok(users::logout_core(state, rc).await?),

        (Route::Classes { class_name }, &M::GET) => {
            RouteResponse::ok(classes::find_core(state, rc, authority, class_name, params).await?)
        }
        (Route::Classes { class_name }, &M::POST) => RouteResponse::created(
            classes::create_core(state, rc, authority, class_name, body()?).await?,
        ),
        (
            Route::ClassObject {
                class_name,
                object_id,
            },
            &M::GET,
        ) => RouteResponse::ok(
            classes::get_core(state, rc, authority, class_name, object_id, params).await?,
        ),
        (
            Route::ClassObject {
                class_name,
                object_id,
            },
            &M::PUT,
        ) => RouteResponse::ok(
            classes::update_core(state, rc, authority, class_name, object_id, body()?).await?,
        ),
        (
            Route::ClassObject {
                class_name,
                object_id,
            },
            &M::DELETE,
        ) => RouteResponse::ok(
            classes::delete_core(state, rc, authority, class_name, object_id).await?,
        ),

        // `RolesRouter` is `ClassesRouter` with `className()` pinned to `_Role` and zero special
        // handling (`RolesRouter.js:1-27`), so these are the same cores with a fixed class name.
        // `_Role` requires `name` and `ACL` on write (`SchemaController.js:154-160`), which the
        // schema crate enforces on the way through.
        (Route::Roles, &M::GET) => {
            RouteResponse::ok(classes::find_core(state, rc, authority, ROLE_CLASS, params).await?)
        }
        (Route::Roles, &M::POST) => RouteResponse::created(
            classes::create_core(state, rc, authority, ROLE_CLASS, body()?).await?,
        ),
        (Route::RoleObject { object_id }, &M::GET) => RouteResponse::ok(
            classes::get_core(state, rc, authority, ROLE_CLASS, object_id, params).await?,
        ),
        (Route::RoleObject { object_id }, &M::PUT) => RouteResponse::ok(
            classes::update_core(state, rc, authority, ROLE_CLASS, object_id, body()?).await?,
        ),
        (Route::RoleObject { object_id }, &M::DELETE) => RouteResponse::ok(
            classes::delete_core(state, rc, authority, ROLE_CLASS, object_id).await?,
        ),

        (Route::SessionsMe, &M::GET) => RouteResponse::ok(sessions::me_core(state, rc).await?),
        (Route::Sessions, &M::GET) => RouteResponse::ok(
            classes::find_core(state, rc, authority, classes::SESSION_CLASS, params).await?,
        ),
        (Route::SessionObject { object_id }, &M::GET) => RouteResponse::ok(
            classes::get_core(
                state,
                rc,
                authority,
                classes::SESSION_CLASS,
                object_id,
                params,
            )
            .await?,
        ),
        (Route::SessionObject { object_id }, &M::DELETE) => {
            RouteResponse::ok(classes::delete_session_core(state, rc, object_id).await?)
        }

        (Route::Schemas, &M::GET) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::get_all(state).await?)
        }
        (Route::Schemas, &M::POST) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::create(state, path, None, body()?).await?)
        }
        (Route::SchemaClass { class_name }, &M::GET) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::get_one(state, class_name).await?)
        }
        (Route::SchemaClass { class_name }, &M::POST) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::create(state, path, Some(class_name), body()?).await?)
        }
        (Route::SchemaClass { class_name }, &M::PUT) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::update(state, class_name, body()?).await?)
        }
        (Route::SchemaClass { class_name }, &M::DELETE) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::delete(state, class_name).await?)
        }
        (Route::Purge { class_name }, &M::DELETE) => {
            master_only(state, authority)?;
            RouteResponse::ok(schemas::purge(state, class_name).await?)
        }

        // Everything else, including `/batch`, which is reached only from the HTTP layer: a
        // nested one is refused before dispatch. See `batch::handle`.
        _ => return Err(unroutable(method, path)),
    };
    Ok(response)
}

/// `_Role`, pinned by `RolesRouter.className()`.
const ROLE_CLASS: &str = "_Role";

fn unroutable(method: &http::Method, path: &str) -> RouteError {
    RouteError::NotFound {
        method: method.clone(),
        path: path.to_string(),
    }
}

/// `promiseEnforceMasterKeyAccess`. Master only; maintenance does not satisfy it, because upstream
/// checks `request.auth.isMaster`.
fn master_only(state: &AppState, authority: &Authority) -> Result<(), RouteError> {
    if authority.is_master() {
        return Ok(());
    }
    Err(RouteError::Http(HttpError::master_key_required(
        state.config().error_detail(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_literal_me_routes_win_over_the_parameterized_ones() {
        // The trap upstream depends on registration order for (`UsersRouter.js:838-843`,
        // `SessionsRouter.js:113-121`). Here it is spelled out, so it cannot depend on the order
        // axum happens to try patterns in.
        assert_eq!(route_of("/users/me"), Some(Route::UsersMe));
        assert_eq!(route_of("/sessions/me"), Some(Route::SessionsMe));
        assert_eq!(
            route_of("/sessions/abc123"),
            Some(Route::SessionObject {
                object_id: "abc123".into()
            })
        );
    }

    #[test]
    fn class_and_object_paths_are_distinguished_by_depth() {
        assert_eq!(
            route_of("/classes/Post"),
            Some(Route::Classes {
                class_name: "Post".into()
            })
        );
        assert_eq!(
            route_of("/classes/Post/abc"),
            Some(Route::ClassObject {
                class_name: "Post".into(),
                object_id: "abc".into()
            })
        );
    }

    #[test]
    fn everything_outside_the_milestone_surface_is_unroutable() {
        for path in [
            "/upgradeToRevocableSession",
            "/functions/foo",
            "/config",
            "/hooks/functions",
            "/aggregate/Post",
            "/classes",
            "/classes/Post/a/b",
            "",
            "/",
        ] {
            assert!(route_of(path).is_none(), "{path} must not route");
        }
    }

    #[test]
    fn a_leading_and_trailing_slash_do_not_change_the_match() {
        assert_eq!(route_of("/schemas/"), Some(Route::Schemas));
        assert_eq!(
            route_of("/purge/Post"),
            Some(Route::Purge {
                class_name: "Post".into()
            })
        );
    }
}
