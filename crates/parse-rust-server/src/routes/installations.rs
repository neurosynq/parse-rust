//! The front of `handleInstallation` (`RestWrite.js:1393-1446`): the checks and normalizations a
//! `_Installation` write gets before anything else looks at it, and the sanity checks an update
//! meets against the stored row ([`check_update`]).
//!
//! **Not the deduplication that follows them.** Upstream then looks up existing installations by
//! `objectId`, `installationId` and `deviceToken`, merges or deletes conflicting rows, and can turn
//! a create into an update. That is out of 0.3.0's scope and is recorded as such; what is here is
//! what a single write can be judged by on its own.

use parse_rust_core::{ErrorCode, FieldWrite, Op, ParseError, ParseValue};
use parse_rust_rest::WriteBody;

pub const INSTALLATION_CLASS: &str = "_Installation";

/// Validate and normalize an `_Installation` write in place.
///
/// `header_installation_id` is the request's `X-Parse-Installation-Id`, which upstream counts as an
/// id for the create check (`this.auth.installationId`).
pub fn prepare(
    body: &mut WriteBody,
    is_create: bool,
    header_installation_id: Option<&str>,
) -> Result<(), ParseError> {
    // **The three values the deduplication splices into its queries must be strings**
    // (`RestWrite.js:1408-1423`). Upstream added this for an operator-injection advisory
    // (GHSA-cc6h-c8m4-hgrx) because the deduplication runs with master privileges. parse-rust has
    // no deduplication, so nothing here is injectable, but the refusal is on the wire and is
    // reproduced with upstream's message.
    for field in ["deviceToken", "installationId", "appIdentifier"] {
        let actual = match body.get(field) {
            None | Some(FieldWrite::Value(ParseValue::Null | ParseValue::String(_))) => continue,
            Some(FieldWrite::Op(Op::Delete)) if field == "appIdentifier" => continue,
            Some(FieldWrite::Value(ParseValue::Array(_))) => "Array",
            Some(FieldWrite::Value(ParseValue::Number(_))) => "Number",
            Some(FieldWrite::Value(ParseValue::Bool(_))) => "Boolean",
            // An operation, a tagged value and a plain object are all `typeof 'object'`.
            Some(_) => "Object",
        };
        return Err(ParseError::new(
            ErrorCode::IncorrectType,
            format!("schema mismatch for _Installation.{field}; expected String but got {actual}"),
        ));
    }

    // At least one id on a create (`RestWrite.js:1425-1435`). Truthiness, so an empty string is no
    // id, and the installation id header counts.
    let has = |field: &str| matches!(body.get(field), Some(FieldWrite::Value(ParseValue::String(s))) if !s.is_empty());
    if is_create
        && !has("deviceToken")
        && !has("installationId")
        && header_installation_id.is_none_or(str::is_empty)
    {
        return Err(ParseError::new(
            ErrorCode::MissingClassName,
            "at least one ID field (deviceToken, installationId) must be specified in this operation",
        ));
    }

    // A create names its `deviceType`, unless it resolves onto an existing installation
    // (`RestWrite.js:1552-1554`). Without the deduplication nothing ever resolves, so every create
    // needs one; upstream asks the same of every create that matches no existing row.
    let has_device_type = truthy(body.get("deviceType"));
    if is_create && !has_device_type {
        return Err(ParseError::new(
            ErrorCode::MissingClassName,
            "deviceType must be specified in this operation",
        ));
    }

    // A 64-character device token is taken to be an APNs token and lowercased
    // (`RestWrite.js:1439-1441`). `length` is UTF-16 code units, which is what is counted here.
    if let Some(FieldWrite::Value(ParseValue::String(token))) = body.get_mut("deviceToken") {
        if token.encode_utf16().count() == 64 {
            *token = token.to_lowercase();
        }
    }
    // Every `installationId` is lowercased (`RestWrite.js:1444-1446`).
    if let Some(FieldWrite::Value(ParseValue::String(id))) = body.get_mut("installationId") {
        *id = id.to_lowercase();
    }
    Ok(())
}

/// `this.data[field]` is truthy. An operation is an object on the JavaScript side, so it is
/// truthy: a `deviceType` sent as `{"__op":"Delete"}` counts as present, as it does upstream.
fn truthy(write: Option<&FieldWrite>) -> bool {
    match write {
        None => false,
        Some(FieldWrite::Value(v)) => parse_rust_core::is_js_truthy(v),
        Some(FieldWrite::Op(_)) => true,
    }
}

/// The value a write sets, for upstream's `!==` against the stored one. An operation is never
/// equal to anything stored, because it is an object compared by identity.
fn written_string(write: Option<&FieldWrite>) -> Option<&str> {
    match write {
        Some(FieldWrite::Value(ParseValue::String(s))) => Some(s),
        _ => None,
    }
}

/// The update half of `handleInstallation`'s sanity checks (`RestWrite.js:1514-1541`): an
/// existing installation keeps its `installationId`, its `deviceToken` while neither side has an
/// `installationId`, and its `deviceType`.
///
/// **Runs only when the update touches something critical**, upstream's
/// `!this.data.deviceToken && !installationId && !this.data.deviceType` early return, where
/// `installationId` falls back to the request's `X-Parse-Installation-Id` for a non-privileged
/// caller (`RestWrite.js:1450-1461`). So a client sending that header gets the lookup on every
/// update, and a missing row is `Object not found for update.` rather than the pipeline's
/// `Object not found.`.
///
/// The lookup is upstream's: unrestricted, by objectId (`RestWrite.js:1491-1500`). The
/// deduplication that follows these checks upstream is not implemented; see the module note.
pub async fn check_update<S: parse_rust_storage::StorageAdapter>(
    storage: &S,
    snapshot: &parse_rust_rest::SchemaSnapshot,
    object_id: &str,
    body: &WriteBody,
    privileged: bool,
    header_installation_id: Option<&str>,
) -> Result<(), ParseError> {
    let header = header_installation_id
        .filter(|id| !id.is_empty() && !privileged)
        .map(str::to_lowercase);
    let critical = truthy(body.get("deviceToken"))
        || truthy(body.get("installationId"))
        || header.is_some()
        || truthy(body.get("deviceType"));
    if !critical {
        return Ok(());
    }

    let schema = snapshot.get_or_default(INSTALLATION_CLASS);
    let query =
        parse_rust_storage::Query::from_constraints(vec![parse_rust_storage::Constraint::equal(
            "objectId",
            ParseValue::String(object_id.into()),
        )]);
    let rows = storage
        .find(
            &schema,
            &query,
            &parse_rust_storage::QueryOptions::default(),
        )
        .await?;
    let Some(stored) = rows.into_iter().next() else {
        return Err(ParseError::new(
            ErrorCode::ObjectNotFound,
            "Object not found for update.",
        ));
    };
    let stored_string = |field: &str| match stored.get(field) {
        Some(ParseValue::String(s)) if !s.is_empty() => Some(s.as_str()),
        _ => None,
    };
    let changed = |field: &str| {
        ParseError::new(
            ErrorCode::UnchangeableField,
            format!("{field} may not be changed in this operation"),
        )
    };

    let data_installation_id = written_string(body.get("installationId")).filter(|s| !s.is_empty());
    if let (Some(data), Some(stored)) = (data_installation_id, stored_string("installationId")) {
        if data != stored {
            return Err(changed("installationId"));
        }
    }
    if truthy(body.get("deviceToken"))
        && data_installation_id.is_none()
        && stored_string("installationId").is_none()
    {
        if let Some(stored) = stored_string("deviceToken") {
            if written_string(body.get("deviceToken")) != Some(stored) {
                return Err(changed("deviceToken"));
            }
        }
    }
    // `this.data.deviceType !== objectIdMatch.deviceType`, so an absent stored value differs from
    // any written one, and an operation differs from everything.
    if truthy(body.get("deviceType")) {
        let stored = match stored.get("deviceType") {
            Some(ParseValue::String(s)) => Some(s.as_str()),
            _ => None,
        };
        if stored.is_none() || written_string(body.get("deviceType")) != stored {
            return Err(changed("deviceType"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::op::OpPath;

    fn body(json: &str, path: OpPath) -> WriteBody {
        parse_rust_rest::decode_write_body(&serde_json::from_str(json).expect("json"), path)
            .expect("decode")
    }

    #[test]
    fn a_create_needs_an_id_from_the_body_or_the_header() {
        let mut b = body(r#"{"deviceType":"ios"}"#, OpPath::Create);
        let e = prepare(&mut b, true, None).expect_err("no id");
        assert_eq!(e.code.as_i32(), 135);
        assert_eq!(
            e.message,
            "at least one ID field (deviceToken, installationId) must be specified in this operation"
        );
        prepare(&mut b, true, Some("abc")).expect("the header counts");
        let mut empty = body(
            r#"{"installationId":"","deviceType":"ios"}"#,
            OpPath::Create,
        );
        prepare(&mut empty, true, None).expect_err("an empty id is no id");
        let mut update = body(r#"{"deviceType":"ios"}"#, OpPath::Update);
        prepare(&mut update, false, None).expect("an update needs none");
    }

    #[test]
    fn ids_are_lowercased_as_upstream_lowercases_them() {
        let token = "A".repeat(64);
        let mut b = body(
            &format!(r#"{{"deviceToken":"{token}","installationId":"ABC","deviceType":"ios"}}"#),
            OpPath::Create,
        );
        prepare(&mut b, true, None).expect("valid");
        assert!(
            matches!(b.get("deviceToken"), Some(FieldWrite::Value(ParseValue::String(s))) if s == &"a".repeat(64))
        );
        assert!(
            matches!(b.get("installationId"), Some(FieldWrite::Value(ParseValue::String(s))) if s == "abc")
        );

        let mut short = body(
            r#"{"deviceToken":"ABC","deviceType":"ios"}"#,
            OpPath::Create,
        );
        prepare(&mut short, true, None).expect("valid");
        assert!(
            matches!(short.get("deviceToken"), Some(FieldWrite::Value(ParseValue::String(s))) if s == "ABC")
        );
    }

    #[test]
    fn a_non_string_id_is_a_schema_mismatch() {
        for (json, message) in [
            (
                r#"{"deviceToken":{"$ne":null}}"#,
                "schema mismatch for _Installation.deviceToken; expected String but got Object",
            ),
            (
                r#"{"installationId":5}"#,
                "schema mismatch for _Installation.installationId; expected String but got Number",
            ),
            (
                r#"{"installationId":"a","appIdentifier":["x"]}"#,
                "schema mismatch for _Installation.appIdentifier; expected String but got Array",
            ),
        ] {
            let mut b = body(json, OpPath::Create);
            let e = prepare(&mut b, true, None).expect_err(json);
            assert_eq!(e.code, ErrorCode::IncorrectType);
            assert_eq!(e.message, message);
        }
        let mut b = body(
            r#"{"installationId":"a","appIdentifier":{"__op":"Delete"}}"#,
            OpPath::Update,
        );
        prepare(&mut b, false, None).expect("deleting appIdentifier is allowed");
    }

    #[test]
    fn a_create_names_its_device_type() {
        let mut b = body(r#"{"installationId":"a"}"#, OpPath::Create);
        let e = prepare(&mut b, true, None).expect_err("no deviceType");
        assert_eq!(e.code.as_i32(), 135);
        assert_eq!(e.message, "deviceType must be specified in this operation");
        let mut update = body(r#"{"installationId":"a"}"#, OpPath::Update);
        prepare(&mut update, false, None).expect("an update need not");
    }
}
