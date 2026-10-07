//! The front of `handleInstallation` (`RestWrite.js:1393-1446`): the checks and normalizations a
//! `_Installation` write gets before anything else looks at it.
//!
//! **Not the deduplication that follows it.** Upstream then looks up existing installations by
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
    let has_device_type = matches!(
        body.get("deviceType"),
        Some(FieldWrite::Value(v)) if parse_rust_core::is_js_truthy(v)
    );
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
