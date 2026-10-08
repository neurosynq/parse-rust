//! Enforcing a schema against a write, and growing it implicitly.
//!
//! Upstream splits this across `enforceFieldExists`, `validateObject` and
//! `validateRequiredColumns` (`SchemaController.js`). The part that matters for 0.1.0 is the pair
//! of decisions made per field on every write: does this field already have a type, and does the
//! incoming value agree with it.

use indexmap::IndexMap;
use parse_rust_core::{FieldWrite, ParseError, ParseMap, ParseValue};
use parse_rust_storage::{ClassSchema, FieldType};

use crate::infer::{
    class_name_is_valid, default_columns_for, field_name_is_valid_for_class, infer_op_type,
    infer_type, invalid_class_name_message, required_write_columns, schema_mismatch,
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

/// The schema a brand new class starts with: the four default columns, plus the class's own.
///
/// `injectDefaultSchema` spreads `_Default` then `defaultColumns[className]`
/// (`SchemaController.js:618-632`), and the order matters only in that a class table may not
/// shadow a `_Default` column; none does.
///
/// The class-specific columns are not decoration. Without `_Role.users` and `_Role.roles` typed
/// as Relations, the first write to a role infers them from whatever it happens to carry, and
/// the join collections a role's membership lives in are never created.
pub fn default_schema(class_name: &str) -> ClassSchema {
    let mut schema = ClassSchema::new(class_name);
    for (name, ty) in DEFAULT_COLUMNS {
        schema.fields.insert(name.to_string(), ty);
    }
    for (name, ty) in default_columns_for(class_name) {
        schema.fields.insert(name.to_string(), ty);
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
            invalid_class_name_message(&schema.class_name),
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

        reconcile(schema, field_name, incoming, &mut added)?;
    }

    Ok(SchemaDelta { added })
}

/// The op-aware form of [`validate_write`].
///
/// Same rules, one extra source of type information: an `{"__op":...}` field infers through
/// [`infer_op_type`] rather than [`infer_type`], so `AddRelation` reserves
/// `Relation<targetClass>` and `Increment` reserves `Number`. Upstream does not distinguish the
/// two paths at all, because `getType` handles literals and ops in one function
/// (`SchemaController.js:1555-1657`); the split here exists because parse-rust decodes ops into
/// [`FieldWrite`] before the schema layer sees them.
///
/// [`validate_write`] is kept for callers that hold a plain body. It is not a subset: a body that
/// still carries `{"__op":"Increment"}` as a literal object infers `Object` through it, which is
/// how 0.1.0 came to store the op envelope as a column value.
pub fn validate_write_fields(
    schema: &ClassSchema,
    fields: &IndexMap<String, FieldWrite>,
) -> Result<SchemaDelta, ParseError> {
    if !class_name_is_valid(&schema.class_name) {
        return Err(ParseError::new(
            parse_rust_core::ErrorCode::InvalidClassName,
            invalid_class_name_message(&schema.class_name),
        ));
    }

    // **One GeoPoint per object, counted over the incoming body alone**
    // (`SchemaController.js:1287-1302`). Upstream runs this first, before any per-field type
    // check, and it counts only what this write carries: `geocount` is incremented inside a loop
    // over `object`, never over the stored schema. So two GeoPoints in one body are refused here,
    // and a *second* GeoPoint added by a later write is not, because that body carries one. The
    // later case is caught during field reservation instead, with a different message, which is
    // why this is not the whole rule.
    //
    // Measured against parse-server at the pin: two in one create answers 111 `there can only
    // be one geopoint field in a class`, and adding a second later answers 111 `MongoDB only
    // supports one GeoPoint field in a class.`
    let mut geo_count = 0;
    for (field_name, write) in fields {
        if let FieldWrite::Value(value) = write {
            if matches!(infer_type(value), Some(FieldType::GeoPoint)) {
                geo_count += 1;
            }
        }
        if geo_count > 1 {
            let _ = field_name;
            return Err(ParseError::incorrect_type(
                "there can only be one geopoint field in a class".to_string(),
            ));
        }
    }

    let mut added = Vec::new();

    for (field_name, write) in fields {
        if field_name.starts_with('_') {
            continue;
        }
        // Every object carries an ACL implicitly, so it is never type-checked and never added
        // (`SchemaController.js:1312-1315`).
        if field_name == "ACL" {
            continue;
        }

        let incoming = match write {
            FieldWrite::Value(value) => infer_type(value),
            FieldWrite::Op(op) => infer_op_type(op)?,
        };
        let Some(incoming) = incoming else {
            continue;
        };

        reconcile(schema, field_name, incoming, &mut added)?;
    }

    Ok(SchemaDelta { added })
}

/// The half of the per-field decision that does not depend on how the type was inferred.
fn reconcile(
    schema: &ClassSchema,
    field_name: &str,
    incoming: FieldType,
    added: &mut Vec<(String, FieldType)>,
) -> Result<(), ParseError> {
    if let Some(existing) = schema.field(field_name) {
        if existing != &incoming {
            return Err(schema_mismatch(
                &schema.class_name,
                field_name,
                existing,
                &incoming,
            ));
        }
        return Ok(());
    }

    if !field_name_is_valid_for_class(field_name, &schema.class_name) {
        return Err(ParseError::invalid_key_name(format!(
            "Invalid field name: {field_name}."
        )));
    }

    added.push((field_name.to_string(), incoming));
    Ok(())
}

/// Enforce `requiredColumns.write` (`validateRequiredColumns`, `SchemaController.js:1332-1354`).
///
/// Two things about this are easy to get wrong, and both are wire-visible.
///
/// **Only the first missing column is reported.** `missingColumns[0] + ' is required.'`, so a
/// `_Role` with neither `name` nor `ACL` reports `name is required.` and nothing about the ACL.
///
/// **Create and update ask different questions.** On create the test is JavaScript falsiness, so
/// `""`, `0` and `false` are all missing, not just absent. On update the column is only missing
/// if the body is actively deleting it, which is why an ordinary role rename does not have to
/// resend the ACL. `is_update` is upstream's `query && query.objectId`.
///
/// `_Role`'s `ACL` requirement is the load-bearing one: without it a role saves with no ACL and
/// is therefore world-writable, so any client can add itself to it. That also fixes where the
/// call belongs: pass the client-supplied body, before the REST layer lowers `ACL` into
/// `_rperm`/`_wperm`, or the check looks at a key that is no longer there.
pub fn validate_required_columns(
    class_name: &str,
    object: &ParseMap,
    is_update: bool,
) -> Result<(), ParseError> {
    for column in required_write_columns(class_name) {
        let missing = match object.get(*column) {
            None => !is_update,
            Some(value) => {
                if is_update {
                    is_delete_op(value)
                } else {
                    is_falsy(value)
                }
            }
        };
        if missing {
            return Err(ParseError::incorrect_type(format!("{column} is required.")));
        }
    }
    Ok(())
}

/// JavaScript falsiness over a decoded value.
///
/// Upstream's create-path test is `!object[column]`, so this has to agree with `!` and not with
/// "is absent". `NaN` is falsy in JavaScript; every tagged value is an object and therefore
/// truthy.
fn is_falsy(value: &ParseValue) -> bool {
    match value {
        ParseValue::Null => true,
        ParseValue::Bool(b) => !*b,
        ParseValue::Number(n) => *n == 0.0 || n.is_nan(),
        ParseValue::String(s) => s.is_empty(),
        _ => false,
    }
}

/// `object[column].__op == 'Delete'` (`SchemaController.js:1340-1342`), against a body whose ops
/// have not been decoded.
///
/// Deliberately shape-matching rather than taking a `FieldWrite`: upstream runs this check on the
/// raw REST body, before anything has interpreted the op, and a caller holding a decoded body can
/// answer the question itself.
fn is_delete_op(value: &ParseValue) -> bool {
    match value {
        ParseValue::Object(map) => {
            matches!(map.get("__op"), Some(ParseValue::String(op)) if op == "Delete")
        }
        _ => false,
    }
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
    fn role_and_session_carry_their_class_specific_columns() {
        let role = default_schema("_Role");
        assert_eq!(role.field("name"), Some(&FieldType::String));
        assert_eq!(
            role.field("users"),
            Some(&FieldType::Relation {
                target_class: "_User".into()
            })
        );
        assert_eq!(
            role.field("roles"),
            Some(&FieldType::Relation {
                target_class: "_Role".into()
            })
        );

        let session = default_schema("_Session");
        assert_eq!(
            session.field("user"),
            Some(&FieldType::Pointer {
                target_class: "_User".into()
            })
        );
        for (name, ty) in [
            ("installationId", FieldType::String),
            ("sessionToken", FieldType::String),
            ("expiresAt", FieldType::Date),
            ("createdWith", FieldType::Object),
        ] {
            assert_eq!(session.field(name), Some(&ty), "{name}");
        }
    }

    /// Without the typed columns, the first role write decides these types from its payload, and
    /// a role whose `users` came back as an Array has no join collection at all.
    #[test]
    fn a_role_write_is_checked_against_the_typed_relation_columns() {
        let s = default_schema("_Role");
        let err = validate_write(&s, &m(vec![("users", ParseValue::Array(vec![]))])).unwrap_err();
        assert_eq!(
            err.message,
            "schema mismatch for _Role.users; expected Relation<_User> but got Array"
        );
    }

    #[test]
    fn a_role_needs_a_name_and_an_acl_on_create() {
        // The first missing column, and only the first.
        let err = validate_required_columns("_Role", &ParseMap::new(), false).unwrap_err();
        assert_eq!(err.message, "name is required.");
        assert_eq!(err.code, parse_rust_core::ErrorCode::IncorrectType);

        // An ACL-less role would be world-writable, so this is the one that matters.
        let err = validate_required_columns(
            "_Role",
            &m(vec![("name", ParseValue::String("Admins".into()))]),
            false,
        )
        .unwrap_err();
        assert_eq!(err.message, "ACL is required.");

        let ok = m(vec![
            ("name", ParseValue::String("Admins".into())),
            ("ACL", ParseValue::Object(ParseMap::new())),
        ]);
        assert!(validate_required_columns("_Role", &ok, false).is_ok());
    }

    /// The create test is JavaScript falsiness, not absence, so an empty name is still missing.
    #[test]
    fn a_falsy_required_column_counts_as_missing_on_create() {
        for value in [
            ParseValue::String(String::new()),
            ParseValue::Null,
            ParseValue::Bool(false),
            ParseValue::Number(0.0),
        ] {
            let body = m(vec![
                ("name", value),
                ("ACL", ParseValue::Object(ParseMap::new())),
            ]);
            assert_eq!(
                validate_required_columns("_Role", &body, false)
                    .unwrap_err()
                    .message,
                "name is required."
            );
        }
    }

    /// On update the column is only missing if the body is deleting it, which is why a rename
    /// does not have to resend the ACL.
    #[test]
    fn an_update_only_objects_to_deleting_a_required_column() {
        let rename = m(vec![("name", ParseValue::String("Ops".into()))]);
        assert!(validate_required_columns("_Role", &rename, true).is_ok());

        let mut delete = ParseMap::new();
        delete.insert("__op".into(), ParseValue::String("Delete".into()));
        let body = m(vec![("ACL", ParseValue::Object(delete))]);
        assert_eq!(
            validate_required_columns("_Role", &body, true)
                .unwrap_err()
                .message,
            "ACL is required."
        );
    }

    #[test]
    fn a_class_with_no_required_columns_never_fails() {
        assert!(validate_required_columns("Post", &ParseMap::new(), false).is_ok());
        assert!(validate_required_columns("_User", &ParseMap::new(), false).is_ok());
    }

    #[test]
    fn ops_infer_their_own_types() {
        use parse_rust_core::Op;

        let s = default_schema("Post");
        let mut fields: IndexMap<String, FieldWrite> = IndexMap::new();
        fields.insert("views".into(), FieldWrite::Op(Op::Increment(1.0)));
        fields.insert(
            "tags".into(),
            FieldWrite::Op(Op::Add(vec![ParseValue::String("x".into())])),
        );
        fields.insert("gone".into(), FieldWrite::Op(Op::Delete));
        let delta = validate_write_fields(&s, &fields).expect("validate");
        assert_eq!(
            delta.added,
            vec![
                ("views".to_string(), FieldType::Number),
                ("tags".to_string(), FieldType::Array),
            ],
            "Delete has no type and must not create a column"
        );
    }

    /// The relation ops take their target class from the first pointer in the payload, which is
    /// the only place it appears. Without this a `_Role.users` write reserves nothing.
    #[test]
    fn relation_ops_infer_their_target_from_the_first_pointer() {
        use parse_rust_core::Op;

        let s = default_schema("Post");
        let pointer = ParseValue::Pointer {
            class_name: "_User".into(),
            object_id: "abc".into(),
        };
        for op in [
            Op::AddRelation(vec![pointer.clone()]),
            Op::RemoveRelation(vec![pointer.clone()]),
            Op::Batch(vec![Op::AddRelation(vec![pointer.clone()])]),
        ] {
            let mut fields: IndexMap<String, FieldWrite> = IndexMap::new();
            fields.insert("members".into(), FieldWrite::Op(op));
            let delta = validate_write_fields(&s, &fields).expect("validate");
            assert_eq!(
                delta.added,
                vec![(
                    "members".to_string(),
                    FieldType::Relation {
                        target_class: "_User".into()
                    }
                )]
            );
        }
    }

    /// Upstream has no defined type for this shape. Declining to create a column is the nearest
    /// safe behavior; see `infer_op_type`.
    #[test]
    fn a_relation_op_with_no_pointers_creates_nothing() {
        use parse_rust_core::Op;

        let s = default_schema("Post");
        let mut fields: IndexMap<String, FieldWrite> = IndexMap::new();
        fields.insert("members".into(), FieldWrite::Op(Op::AddRelation(vec![])));
        fields.insert("other".into(), FieldWrite::Op(Op::Batch(vec![])));
        assert!(validate_write_fields(&s, &fields)
            .expect("validate")
            .is_empty());
    }

    #[test]
    fn the_op_aware_path_enforces_the_same_types_as_the_value_path() {
        use parse_rust_core::Op;

        let mut s = default_schema("Post");
        apply(
            &mut s,
            &SchemaDelta {
                added: vec![("title".into(), FieldType::String)],
            },
        );
        let mut fields: IndexMap<String, FieldWrite> = IndexMap::new();
        fields.insert("title".into(), FieldWrite::Op(Op::Increment(1.0)));
        let err = validate_write_fields(&s, &fields).unwrap_err();
        assert_eq!(
            err.message,
            "schema mismatch for Post.title; expected String but got Number"
        );
    }

    /// The trailing space is upstream's and reaches the client.
    #[test]
    fn the_invalid_class_name_message_is_byte_exact() {
        let s = ClassSchema::new("1Bad");
        let err = validate_write(&s, &m(vec![("a", ParseValue::String("x".into()))])).unwrap_err();
        assert_eq!(
            err.message,
            "Invalid classname: 1Bad, classnames can only have alphanumeric characters and _, and \
             must start with an alpha character "
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
