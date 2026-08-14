//! Enforcing a schema against a write, and growing it implicitly.
//!
//! Upstream splits this across `enforceFieldExists`, `validateObject` and
//! `validateRequiredColumns` (`SchemaController.js`). The part that matters for 0.1.0 is the pair
//! of decisions made per field on every write: does this field already have a type, and does the
//! incoming value agree with it.

use parse_rust_core::{ParseError, ParseMap, ParseValue};
use parse_rust_storage::{ClassSchema, FieldType};

use crate::infer::{
    class_name_is_valid, field_name_is_valid_for_class, infer_type, schema_mismatch,
    DEFAULT_COLUMNS,
};

/// What a write implies for the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDelta {
    /// Fields that do not exist yet and would be created, in the order they appeared.
    pub added: Vec<(String, FieldType)>,
}

impl SchemaDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
    }
}

/// The schema a brand new class starts with: the four default columns and nothing else.
pub fn default_schema(class_name: &str) -> ClassSchema {
    let mut schema = ClassSchema::new(class_name);
    for (name, ty) in DEFAULT_COLUMNS {
        schema.fields.insert(name.to_string(), ty);
    }
    // System classes carry additional columns whose types are fixed by Parse rather than inferred.
    if class_name == "_User" {
        for (name, ty) in crate::infer::USER_COLUMNS {
            schema.fields.insert(name.to_string(), ty);
        }
    }
    schema
}

/// Validate a write against a class schema and report what it would add.
///
/// **Does not mutate.** The caller persists the delta only if the write commits, which is the
/// ordering that stops a rejected write from leaving a phantom column behind.
///
/// Order of checks per field is upstream's and is observable, because the first failure is the
/// error the client sees:
/// 1. Skip `null`, which creates nothing.
/// 2. If the field exists, the types must agree, else `INCORRECT_TYPE`.
/// 3. Otherwise the name must be legal, and it is an addition.
pub fn validate_write(schema: &ClassSchema, object: &ParseMap) -> Result<SchemaDelta, ParseError> {
    if !class_name_is_valid(&schema.class_name) {
        return Err(ParseError::new(
            parse_rust_core::ErrorCode::InvalidClassName,
            format!(
                "Invalid classname: {}, classnames can only have alphanumeric characters and _, \
                 and must start with an alpha character",
                schema.class_name
            ),
        ));
    }

    let mut added = Vec::new();

    for (field_name, value) in object {
        // Server-internal columns are not schema fields and are not validated.
        //
        // `_hashed_password`, `_rperm`, `_wperm` and friends are set by the server, never by a
        // client, and they are stored under names the field-name regex deliberately rejects. The
        // guard that keeps a *client* from supplying one is `reject_reserved_keys`, applied at the
        // REST boundary before a body ever reaches here. Splitting it that way means the schema
        // layer does not need to know which internal columns exist, and a client-supplied `_` key
        // is refused with an error rather than silently accepted as a column.
        if field_name.starts_with('_') {
            continue;
        }

        // `ACL` is a default column of type `Acl`, but a client sends it as a plain JSON object,
        // which infers as `Object`. Type-checking it against the column would reject every write
        // that carries an ACL, which is exactly what happened: `schema mismatch for X.ACL;
        // expected ACL but got Object`. The REST layer lowers it into `_rperm`/`_wperm` after
        // validation, so there is nothing here to check and nothing to add.
        if field_name == "ACL" {
            match value {
                ParseValue::Object(_) | ParseValue::Null => continue,
                other => {
                    return Err(schema_mismatch(
                        &schema.class_name,
                        field_name,
                        &FieldType::Acl,
                        &infer_type(other).unwrap_or(FieldType::Object),
                    ))
                }
            }
        }

        // A literal null creates nothing. This is why `infer_type` returns Option.
        let Some(incoming) = infer_type(value) else {
            continue;
        };

        if let Some(existing) = schema.field(field_name) {
            if existing != &incoming {
                return Err(schema_mismatch(
                    &schema.class_name,
                    field_name,
                    existing,
                    &incoming,
                ));
            }
            continue;
        }

        if !field_name_is_valid_for_class(field_name, &schema.class_name) {
            return Err(ParseError::invalid_key_name(format!(
                "Invalid field name: {field_name}."
            )));
        }

        added.push((field_name.clone(), incoming));
    }

    Ok(SchemaDelta { added })
}

/// Apply a delta. Separate from [`validate_write`] so the caller controls when it happens.
pub fn apply(schema: &mut ClassSchema, delta: &SchemaDelta) {
    for (name, ty) in &delta.added {
        schema.fields.insert(name.clone(), ty.clone());
    }
}

/// Does a value belong in a field of this type?
///
/// `null` is assignable to any field, because upstream never type-checks it: it has no type.
pub fn value_matches(ty: &FieldType, value: &ParseValue) -> bool {
    match infer_type(value) {
        None => true,
        Some(t) => &t == ty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::ParseDate;

    fn m(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut map = ParseMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v);
        }
        map
    }

    #[test]
    fn a_new_class_starts_with_the_four_default_columns() {
        let s = default_schema("Post");
        assert_eq!(s.fields.len(), 4);
        for (name, _) in DEFAULT_COLUMNS {
            assert!(s.field(name).is_some(), "{name} missing");
        }
    }

    #[test]
    fn the_first_write_infers_and_adds() {
        let s = default_schema("Post");
        let delta = validate_write(
            &s,
            &m(vec![
                ("title", ParseValue::String("x".into())),
                ("views", ParseValue::Number(1.0)),
            ]),
        )
        .expect("validate");
        assert_eq!(
            delta.added,
            vec![
                ("title".to_string(), FieldType::String),
                ("views".to_string(), FieldType::Number),
            ],
            "order of addition follows the object's key order"
        );
    }

    /// The behavior that makes stubbing this impossible: the *second* write is where it bites.
    #[test]
    fn the_second_write_is_enforced_against_the_first() {
        let mut s = default_schema("Post");
        let delta = validate_write(&s, &m(vec![("title", ParseValue::String("x".into()))]))
            .expect("first write");
        apply(&mut s, &delta);

        let again = validate_write(&s, &m(vec![("title", ParseValue::String("y".into()))]))
            .expect("second write");
        assert!(again.is_empty());

        let err = validate_write(&s, &m(vec![("title", ParseValue::Number(1.0))])).unwrap_err();
        assert_eq!(
            err.message,
            "schema mismatch for Post.title; expected String but got Number"
        );
    }

    #[test]
    fn pointer_target_class_is_part_of_the_type() {
        let mut s = default_schema("Post");
        let delta = validate_write(
            &s,
            &m(vec![(
                "author",
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "a".into(),
                },
            )]),
        )
        .expect("first");
        apply(&mut s, &delta);

        let err = validate_write(
            &s,
            &m(vec![(
                "author",
                ParseValue::Pointer {
                    class_name: "Admin".into(),
                    object_id: "a".into(),
                },
            )]),
        )
        .unwrap_err();
        assert_eq!(
            err.message,
            "schema mismatch for Post.author; expected Pointer<_User> but got Pointer<Admin>"
        );
    }

    /// Regression: an ACL used to be rejected as `expected ACL but got Object`, which made every
    /// write carrying one fail. ACL enforcement is a stated 0.1.0 feature and it never worked.
    #[test]
    fn user_columns_are_typed_rather_than_inferred() {
        let s = default_schema("_User");
        assert_eq!(s.field("email"), Some(&FieldType::String));
        assert_eq!(s.field("emailVerified"), Some(&FieldType::Boolean));
        // A numeric email used to be accepted, permanently fixing the column as a Number.
        let err = validate_write(&s, &m(vec![("email", ParseValue::Number(42.0))])).unwrap_err();
        assert!(
            err.message.contains("expected String but got Number"),
            "{}",
            err.message
        );
    }

    #[test]
    fn an_acl_object_is_accepted_and_adds_no_column() {
        let s = default_schema("Post");
        let mut acl = ParseMap::new();
        let mut entry = ParseMap::new();
        entry.insert("read".into(), ParseValue::Bool(true));
        acl.insert("*".into(), ParseValue::Object(entry));

        let delta =
            validate_write(&s, &m(vec![("ACL", ParseValue::Object(acl))])).expect("validate");
        assert!(delta.is_empty(), "ACL is a default column, not a new field");

        // Null clears it, and is also fine.
        assert!(validate_write(&s, &m(vec![("ACL", ParseValue::Null)])).is_ok());

        // Anything else is still a type error.
        let err =
            validate_write(&s, &m(vec![("ACL", ParseValue::String("nope".into()))])).unwrap_err();
        assert!(
            err.message.contains("expected ACL but got String"),
            "{}",
            err.message
        );
    }

    #[test]
    fn writing_null_creates_nothing() {
        let s = default_schema("Post");
        let delta = validate_write(&s, &m(vec![("ghost", ParseValue::Null)])).expect("validate");
        assert!(
            delta.is_empty(),
            "a null must not create a column, or every optional field becomes a schema entry"
        );
    }

    #[test]
    fn null_is_assignable_to_an_existing_field_of_any_type() {
        let mut s = default_schema("Post");
        apply(
            &mut s,
            &SchemaDelta {
                added: vec![("title".into(), FieldType::String)],
            },
        );
        let delta = validate_write(&s, &m(vec![("title", ParseValue::Null)])).expect("validate");
        assert!(delta.is_empty());
        assert!(value_matches(&FieldType::String, &ParseValue::Null));
    }

    #[test]
    fn default_columns_are_writable_but_not_redefinable() {
        let s = default_schema("Post");
        let ok = validate_write(
            &s,
            &m(vec![(
                "createdAt",
                ParseValue::Date(ParseDate::parse_iso("2026-01-01T00:00:00.000Z").expect("d")),
            )]),
        )
        .expect("validate");
        assert!(ok.is_empty());

        let err = validate_write(&s, &m(vec![("createdAt", ParseValue::Number(1.0))])).unwrap_err();
        assert!(err.message.contains("expected Date but got Number"));
    }

    #[test]
    fn reserved_and_malformed_field_names_are_refused() {
        let s = default_schema("Post");
        // `_leading` is deliberately NOT here: an underscore-prefixed key is a server-internal
        // column from this layer's point of view, and refusing a client one is
        // `parse_rust_rest::reject_reserved_keys`'s job at the REST boundary. Splitting it that way is
        // what lets signup write `_hashed_password` without routing around its own validation.
        for bad in ["className", "1field", "has-dash"] {
            let err =
                validate_write(&s, &m(vec![(bad, ParseValue::String("x".into()))])).unwrap_err();
            assert_eq!(
                err.code,
                parse_rust_core::ErrorCode::InvalidKeyName,
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn an_invalid_class_name_is_refused_before_any_field() {
        let s = ClassSchema::new("1Bad");
        let err = validate_write(&s, &m(vec![("a", ParseValue::String("x".into()))])).unwrap_err();
        assert_eq!(err.code, parse_rust_core::ErrorCode::InvalidClassName);
    }

    #[test]
    fn server_internal_columns_are_not_schema_fields() {
        // `_hashed_password` is written by signup and must not become a `_SCHEMA` column, nor be
        // rejected as a malformed field name. Keeping a client from supplying one is
        // `reject_reserved_keys`'s job, at the REST boundary.
        let s = default_schema("_User");
        let delta = validate_write(
            &s,
            &m(vec![
                // Already a `_User` default column, so it is accepted and adds nothing.
                ("username", ParseValue::String("alice".into())),
                // Server-internal, so skipped entirely.
                ("_hashed_password", ParseValue::String("$2b$10$...".into())),
                ("_rperm", ParseValue::Array(vec![])),
                // A genuinely new client field is the only thing that becomes a column.
                ("nickname", ParseValue::String("al".into())),
            ]),
        )
        .expect("validate");
        assert_eq!(
            delta.added,
            vec![("nickname".to_string(), FieldType::String)],
            "internal columns must not become schema fields"
        );
    }

    #[test]
    fn validate_does_not_mutate_so_a_rejected_write_leaves_no_column() {
        let s = default_schema("Post");
        let before = s.fields.len();
        let _ = validate_write(&s, &m(vec![("title", ParseValue::String("x".into()))]));
        assert_eq!(
            s.fields.len(),
            before,
            "validation must be pure; the caller applies only on commit"
        );
    }
}
