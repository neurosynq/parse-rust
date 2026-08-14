//! Type inference, name validation, and default columns.
//!
//! Upstream: `getType` and `getObjectType` (`SchemaController.js:1555-1640`), plus
//! `classNameIsValid` and `fieldNameIsValid` (`:446-480`).
//!
//! Inference is what makes Parse's schema implicit: the first write that mentions a field decides
//! its type forever. Everything downstream, including the error a client sees on the *second*
//! write, follows from getting this exactly right.

use parse_rust_core::{ParseError, ParseValue};
use parse_rust_storage::FieldType;

/// The four columns every class has (`defaultColumns._Default`).
///
/// A client cannot create or redefine these: `fieldNameIsValidForClass` refuses a field name that
/// collides with a default column.
pub const DEFAULT_COLUMNS: [(&str, FieldType); 4] = [
    ("objectId", FieldType::String),
    ("createdAt", FieldType::Date),
    ("updatedAt", FieldType::Date),
    ("ACL", FieldType::Acl),
];

/// The additional default columns of `_User` (`defaultColumns._User`).
///
/// Without these, `email` infers its type from whatever the first write happens to contain, so a
/// numeric email is accepted and permanently fixes the column as a Number.
pub const USER_COLUMNS: [(&str, FieldType); 5] = [
    ("username", FieldType::String),
    ("password", FieldType::String),
    ("email", FieldType::String),
    ("emailVerified", FieldType::Boolean),
    ("authData", FieldType::Object),
];

/// Classes Parse defines itself.
pub const SYSTEM_CLASSES: [&str; 8] = [
    "_User",
    "_Installation",
    "_Role",
    "_Session",
    "_Product",
    "_PushStatus",
    "_JobStatus",
    "_JobSchedule",
];

/// Infer a field type from a value, as `getType` does.
///
/// **`None` means "no type", not "unknown".** A literal `null` yields `undefined` upstream, and
/// the write path skips the field rather than creating it, which is why writing `null` to a new
/// field never adds a column. Returning `Option` here keeps that distinction at the type level
/// instead of leaving it to a caller to remember.
///
/// A tagged value with its required member missing also yields `None`: upstream's `switch` breaks
/// out of the case and falls through to returning `undefined`, so `{"__type":"Pointer"}` with no
/// `className` is not a Pointer and not an error at this stage.
pub fn infer_type(value: &ParseValue) -> Option<FieldType> {
    match value {
        ParseValue::Null => None,
        ParseValue::Bool(_) => Some(FieldType::Boolean),
        ParseValue::String(_) => Some(FieldType::String),
        ParseValue::Number(_) => Some(FieldType::Number),
        ParseValue::Array(_) => Some(FieldType::Array),
        ParseValue::Object(_) => Some(FieldType::Object),
        ParseValue::Date(_) => Some(FieldType::Date),
        ParseValue::Bytes(_) => Some(FieldType::Bytes),
        ParseValue::GeoPoint { .. } => Some(FieldType::GeoPoint),
        ParseValue::Polygon(_) => Some(FieldType::Polygon),
        ParseValue::File { .. } => Some(FieldType::File),
        ParseValue::Pointer { class_name, .. } => Some(FieldType::Pointer {
            target_class: class_name.clone(),
        }),
        ParseValue::Relation { class_name } => Some(FieldType::Relation {
            target_class: class_name.clone(),
        }),
    }
}

/// `classAndFieldRegex`, `/^[A-Za-z][A-Za-z0-9_]*$/`.
fn matches_class_and_field_regex(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Is this a class a client may address?
///
/// Three ways to be valid: a system class, a join table, or an ordinary name matching the regex.
/// The join-table form matters because `_Join:` names are the only underscore-prefixed classes a
/// non-system path constructs.
pub fn class_name_is_valid(class_name: &str) -> bool {
    if SYSTEM_CLASSES.contains(&class_name) {
        return true;
    }
    if let Some(rest) = class_name.strip_prefix("_Join:") {
        // `/^_Join:[A-Za-z0-9_]+:[A-Za-z0-9_]+/`. Note upstream's regex is unanchored at the end,
        // so trailing content is accepted; reproduce that rather than tightening it.
        let mut parts = rest.splitn(2, ':');
        let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let ok =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        // The second segment only needs a valid prefix, since the regex is unanchored.
        let b_prefix: String = b
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        return ok(a) && !b_prefix.is_empty();
    }
    matches_class_and_field_regex(class_name)
}

/// Field names a client may not use at all.
///
/// `className` is refused on every class except `_Hooks`, which is the exception upstream carves
/// out because a hook document legitimately carries one.
pub fn field_name_is_valid(field_name: &str, class_name: &str) -> bool {
    if !class_name.is_empty() && class_name != "_Hooks" && field_name == "className" {
        return false;
    }
    matches_class_and_field_regex(field_name)
}

/// Additionally refuses the default columns, which a client cannot redefine.
pub fn field_name_is_valid_for_class(field_name: &str, class_name: &str) -> bool {
    if !field_name_is_valid(field_name, class_name) {
        return false;
    }
    !DEFAULT_COLUMNS.iter().any(|(name, _)| *name == field_name)
}

/// The `INCORRECT_TYPE` a client sees when a write disagrees with the stored type.
///
/// The message is API. `spec/` asserts on it, and the parametric rendering `Pointer<_User>` is
/// part of the string (`SchemaController.js:1165-1173`, `typeToString` at `:697-705`).
pub fn schema_mismatch(
    class_name: &str,
    field_name: &str,
    expected: &FieldType,
    got: &FieldType,
) -> ParseError {
    ParseError::incorrect_type(format!(
        "schema mismatch for {class_name}.{field_name}; expected {} but got {}",
        expected.to_wire_string(),
        got.to_wire_string()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::{ParseDate, ParseMap};

    #[test]
    fn null_infers_no_type_at_all() {
        // The rule behind "writing null never creates a field". Modeled as None rather than as a
        // Null type so a caller cannot accidentally create a column for it.
        assert_eq!(infer_type(&ParseValue::Null), None);
    }

    #[test]
    fn scalars_infer_as_upstream_does() {
        assert_eq!(
            infer_type(&ParseValue::Bool(true)),
            Some(FieldType::Boolean)
        );
        assert_eq!(
            infer_type(&ParseValue::String("x".into())),
            Some(FieldType::String)
        );
        assert_eq!(
            infer_type(&ParseValue::Number(1.0)),
            Some(FieldType::Number)
        );
        // Integral versus fractional does not change the inferred type; both are Number. The
        // Int32/Double split is a storage concern, not a schema one.
        assert_eq!(
            infer_type(&ParseValue::Number(1.5)),
            Some(FieldType::Number)
        );
    }

    #[test]
    fn containers_and_tagged_values() {
        assert_eq!(
            infer_type(&ParseValue::Array(vec![])),
            Some(FieldType::Array)
        );
        assert_eq!(
            infer_type(&ParseValue::Object(ParseMap::new())),
            Some(FieldType::Object)
        );
        assert_eq!(
            infer_type(&ParseValue::Date(
                ParseDate::parse_iso("2026-01-01T00:00:00.000Z").expect("date")
            )),
            Some(FieldType::Date)
        );
        assert_eq!(
            infer_type(&ParseValue::GeoPoint {
                latitude: 1.0,
                longitude: 2.0
            }),
            Some(FieldType::GeoPoint)
        );
    }

    #[test]
    fn pointers_and_relations_carry_their_target() {
        assert_eq!(
            infer_type(&ParseValue::Pointer {
                class_name: "_User".into(),
                object_id: "x".into()
            }),
            Some(FieldType::Pointer {
                target_class: "_User".into()
            })
        );
        assert_eq!(
            infer_type(&ParseValue::Relation {
                class_name: "Post".into()
            }),
            Some(FieldType::Relation {
                target_class: "Post".into()
            })
        );
    }

    #[test]
    fn class_names_follow_the_regex() {
        assert!(class_name_is_valid("Post"));
        assert!(class_name_is_valid("A1_b"));
        assert!(!class_name_is_valid(""));
        assert!(!class_name_is_valid("1Post"), "must not start with a digit");
        assert!(!class_name_is_valid("_Custom"), "must not start with _");
        assert!(!class_name_is_valid("has-dash"));
        assert!(!class_name_is_valid("has space"));
    }

    #[test]
    fn system_and_join_classes_are_valid_despite_the_underscore() {
        for c in SYSTEM_CLASSES {
            assert!(class_name_is_valid(c), "{c} should be valid");
        }
        assert!(class_name_is_valid("_Join:likes:Post"));
        assert!(!class_name_is_valid("_Join:likes"), "needs both segments");
    }

    #[test]
    fn class_name_is_refused_as_a_field_except_on_hooks() {
        assert!(!field_name_is_valid("className", "Post"));
        // The one carve-out upstream makes.
        assert!(field_name_is_valid("className", "_Hooks"));
    }

    #[test]
    fn default_columns_cannot_be_redefined() {
        for (name, _) in DEFAULT_COLUMNS {
            assert!(
                !field_name_is_valid_for_class(name, "Post"),
                "{name} is a default column"
            );
        }
        assert!(field_name_is_valid_for_class("title", "Post"));
    }

    #[test]
    fn the_mismatch_message_is_byte_exact() {
        let e = schema_mismatch(
            "Post",
            "author",
            &FieldType::Pointer {
                target_class: "_User".into(),
            },
            &FieldType::String,
        );
        assert_eq!(
            e.message,
            "schema mismatch for Post.author; expected Pointer<_User> but got String"
        );
        assert_eq!(e.code, parse_rust_core::ErrorCode::IncorrectType);
    }
}
