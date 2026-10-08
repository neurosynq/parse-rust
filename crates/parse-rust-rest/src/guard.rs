//! Guards applied to a client-supplied body before it reaches the pipeline.

use parse_rust_core::{ParseError, ParseMap, ParseValue};

/// Refuse a body that carries a server-internal column.
///
/// Server-internal columns are `_`-prefixed: `_hashed_password`, `_rperm`, `_wperm`,
/// `_session_token`, `_perishable_token`. The schema layer deliberately does not validate them,
/// because the server sets them itself. That makes this guard the only thing standing between a
/// client and, for example, writing its own `_rperm` to grant itself read access, or supplying a
/// `_hashed_password` it chose.
///
/// Applied at the REST boundary rather than in the schema layer so that the server's own writes,
/// which legitimately carry these keys, do not have to route around their own validation.
pub fn reject_reserved_keys(body: &ParseMap) -> Result<(), ParseError> {
    reject_reserved_keys_in(body.keys().map(String::as_str))
}

/// The same guard over any key sequence, for a body that has already been decoded into
/// [`crate::WriteBody`] and no longer has a `ParseMap` to hand.
pub fn reject_reserved_keys_in<'a>(
    keys: impl IntoIterator<Item = &'a str>,
) -> Result<(), ParseError> {
    for key in keys {
        if key.starts_with('_') {
            return Err(ParseError::invalid_key_name(format!(
                "Invalid field name: {key}."
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::ParseValue;

    fn m(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut map = ParseMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v);
        }
        map
    }

    #[test]
    fn ordinary_fields_pass() {
        assert!(reject_reserved_keys(&m(vec![
            ("title", ParseValue::String("x".into())),
            ("ACL", ParseValue::Null),
        ]))
        .is_ok());
    }

    /// The privilege-escalation cases this exists to stop.
    #[test]
    fn a_client_cannot_supply_a_server_internal_column() {
        for key in [
            "_hashed_password",
            "_rperm",
            "_wperm",
            "_session_token",
            "_perishable_token",
            "_anything",
        ] {
            let e =
                reject_reserved_keys(&m(vec![(key, ParseValue::String("x".into()))])).unwrap_err();
            assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidKeyName, "{key}");
            assert!(e.message.contains(key));
        }
    }
}

/// Remove every `_`-prefixed key from a row before it becomes a response.
///
/// Upstream does the same unconditionally in `filterSensitiveData`
/// (`DatabaseController.js:288-292`), for every class rather than just `_User`. It is what keeps
/// `_rperm`, `_wperm`, `_hashed_password` and anything else internal off the wire even when an
/// earlier step forgot.
///
/// Applied at the response boundary rather than deep in the pipeline, so there is exactly one
/// place to audit and no path that reaches a client without passing through it.
pub fn strip_internal_keys(row: &mut ParseMap) {
    row.retain(|k, _| !k.starts_with('_'));
}

/// Timestamp fields that are **bare ISO strings** at the top level of an object.
///
/// The same logical Date has two wire forms depending on position: a user-defined Date field is
/// `{"__type":"Date","iso":"..."}`, but `createdAt` and `updatedAt` at the top level are plain
/// strings (`MongoTransform.js:1174-1186`). Conflating them is a real bug that a well-known Rust
/// Parse client shipped, and it is invisible until an SDK tries to parse the response.
///
/// `expiresAt` is deliberately absent: it encodes as a full Date object even at the top level,
/// which is the asymmetry inside the asymmetry.
const BARE_ISO_FIELDS: [&str; 3] = ["createdAt", "updatedAt", "lastUsed"];

/// Rewrite top-level timestamp fields into their bare-string wire form.
pub fn flatten_top_level_dates(row: &mut ParseMap) {
    for key in BARE_ISO_FIELDS {
        if let Some(ParseValue::Date(d)) = row.get(key) {
            let iso = d.to_iso();
            row.insert(key.to_string(), ParseValue::String(iso));
        }
    }
}

/// Everything a row needs before it becomes a response body.
///
/// One function so there is exactly one place to audit, and no route can apply half of it.
pub fn to_response_body(row: &ParseMap) -> ParseMap {
    into_response_body(row.clone())
}

/// [`to_response_body`] for a row the caller no longer needs, without copying it.
pub fn into_response_body(mut row: ParseMap) -> ParseMap {
    strip_internal_keys(&mut row);
    flatten_top_level_dates(&mut row);
    row
}

#[cfg(test)]
mod strip_tests {
    use super::*;
    use parse_rust_core::ParseValue;

    #[test]
    fn every_underscore_key_is_removed() {
        let mut row = ParseMap::new();
        row.insert("title".into(), ParseValue::String("x".into()));
        row.insert("_hashed_password".into(), ParseValue::String("h".into()));
        row.insert("_rperm".into(), ParseValue::Array(vec![]));
        row.insert("_anything".into(), ParseValue::Null);
        strip_internal_keys(&mut row);
        assert_eq!(row.len(), 1);
        assert!(row.contains_key("title"));
    }

    #[test]
    fn the_acl_field_survives_because_it_is_not_underscore_prefixed() {
        let mut row = ParseMap::new();
        row.insert("ACL".into(), ParseValue::Object(ParseMap::new()));
        strip_internal_keys(&mut row);
        assert!(row.contains_key("ACL"), "ACL is a client-visible field");
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use parse_rust_core::ParseDate;

    #[test]
    fn top_level_timestamps_become_bare_strings() {
        let mut row = ParseMap::new();
        let d = ParseDate::parse_iso("2026-08-14T13:34:33.581Z").expect("date");
        row.insert("createdAt".into(), ParseValue::Date(d));
        row.insert("updatedAt".into(), ParseValue::Date(d));
        // A user-defined Date field keeps its envelope.
        row.insert("dueDate".into(), ParseValue::Date(d));

        let out = to_response_body(&row);
        assert!(
            matches!(out.get("createdAt"), Some(ParseValue::String(s)) if s == "2026-08-14T13:34:33.581Z"),
            "createdAt must be a bare ISO string at the top level"
        );
        assert!(matches!(out.get("updatedAt"), Some(ParseValue::String(_))));
        assert!(
            matches!(out.get("dueDate"), Some(ParseValue::Date(_))),
            "a user-defined Date keeps its __type envelope"
        );
    }

    #[test]
    fn the_response_body_is_stripped_and_flattened_together() {
        let mut row = ParseMap::new();
        row.insert("_hashed_password".into(), ParseValue::String("h".into()));
        row.insert(
            "createdAt".into(),
            ParseValue::Date(ParseDate::parse_iso("2026-01-01T00:00:00.000Z").expect("d")),
        );
        let out = to_response_body(&row);
        assert!(out.get("_hashed_password").is_none());
        assert!(matches!(out.get("createdAt"), Some(ParseValue::String(_))));
    }
}
