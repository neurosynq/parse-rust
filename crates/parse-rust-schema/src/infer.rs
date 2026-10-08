//! Type inference, name validation, and default columns.
//!
//! Upstream: `getType` and `getObjectType` (`SchemaController.js:1555-1640`), plus
//! `classNameIsValid` and `fieldNameIsValid` (`:446-480`).
//!
//! Inference is what makes Parse's schema implicit: the first write that mentions a field decides
//! its type forever. Everything downstream, including the error a client sees on the *second*
//! write, follows from getting this exactly right.

use parse_rust_core::{Op, ParseError, ParseValue};
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

/// Field names no class may use (`invalidColumns`, `SchemaController.js:163`).
///
/// One entry, and it is not arbitrary: `length` collides with `Array.prototype.length` on the
/// JavaScript side, so upstream refuses it everywhere `fieldNameIsValid` is consulted, which
/// includes class names.
pub const INVALID_COLUMNS: [&str; 1] = ["length"];

/// Classes Parse defines itself (`systemClasses`, `SchemaController.js:165-176`).
///
/// **Not the same list as [`VOLATILE_CLASSES`]**, and the two are frequently conflated. See that
/// constant for the difference.
pub const SYSTEM_CLASSES: [&str; 10] = [
    "_User",
    "_Installation",
    "_Role",
    "_Session",
    "_Product",
    "_PushStatus",
    "_JobStatus",
    "_JobSchedule",
    "_Audience",
    "_Idempotency",
];

/// Classes held in memory rather than loaded from `_SCHEMA` (`volatileClasses`,
/// `SchemaController.js:178-187`).
///
/// The two lists overlap but neither contains the other, and the difference is the point.
///
/// - `_Hooks`, `_GlobalConfig` and `_GraphQLConfig` are volatile but **not** system classes, so
///   `classNameIsValid` refuses them: a client cannot address `/classes/_Hooks`. They are reached
///   only through their own routers.
/// - `_User`, `_Installation`, `_Role`, `_Session` and `_Product` are system but **not**
///   volatile: they are real, persisted, client-addressable classes.
/// - `_JobStatus`, `_PushStatus`, `_JobSchedule`, `_Audience` and `_Idempotency` are both.
///
/// `SchemaData` skips a volatile class when reading `_SCHEMA` and injects a synthetic entry
/// instead (`SchemaController.js:566-568`, `:596-614`), so a stored document for one of these is
/// ignored rather than merged.
pub const VOLATILE_CLASSES: [&str; 8] = [
    "_JobStatus",
    "_PushStatus",
    "_Hooks",
    "_GlobalConfig",
    "_GraphQLConfig",
    "_JobSchedule",
    "_Audience",
    "_Idempotency",
];

/// The additional default columns of one class, or empty for a class that has none.
///
/// `defaultColumns` is a table of thirteen classes upstream. Only the four parse-rust writes to
/// today are modelled, because a table entry that is never exercised is a transcription that
/// nothing checks. Adding a class here is required before that class can be served.
///
/// Not a `const`, because `Relation`/`Pointer` carry an owned target class.
pub fn default_columns_for(class_name: &str) -> Vec<(&'static str, FieldType)> {
    let pointer = |target: &str| FieldType::Pointer {
        target_class: target.to_string(),
    };
    let relation = |target: &str| FieldType::Relation {
        target_class: target.to_string(),
    };
    match class_name {
        "_User" => USER_COLUMNS.iter().map(|(n, t)| (*n, t.clone())).collect(),
        // `SchemaController.js:64-69`.
        "_Role" => vec![
            ("name", FieldType::String),
            ("users", relation("_User")),
            ("roles", relation("_Role")),
        ],
        // `SchemaController.js:70-77`. Note `user` is a Pointer while `_Role`'s memberships are
        // Relations, so a session has a column and a role has a join collection.
        "_Session" => vec![
            ("user", pointer("_User")),
            ("installationId", FieldType::String),
            ("sessionToken", FieldType::String),
            ("expiresAt", FieldType::Date),
            ("createdWith", FieldType::Object),
        ],
        _ => Vec::new(),
    }
}

/// Is this field a default column of this class, counting both `_Default` and the class's own?
pub fn is_default_column(class_name: &str, field_name: &str) -> bool {
    DEFAULT_COLUMNS.iter().any(|(n, _)| *n == field_name)
        || default_columns_for(class_name)
            .iter()
            .any(|(n, _)| *n == field_name)
}

/// Columns that must be present for a **write** to a class to be accepted
/// (`requiredColumns.write`, `SchemaController.js:157-160`).
///
/// `_Role`'s `ACL` entry is load-bearing rather than cosmetic: a role saved without an ACL is
/// world-writable, so any client could add itself to it.
pub fn required_write_columns(class_name: &str) -> &'static [&'static str] {
    match class_name {
        "_Product" => &["productIdentifier", "icon", "order", "title", "subtitle"],
        "_Role" => &["name", "ACL"],
        _ => &[],
    }
}

/// Columns that must be present for a **read** of a class (`requiredColumns.read`,
/// `SchemaController.js:154-156`).
///
/// Carried for completeness of the table. Upstream exports `requiredColumns` whole and only the
/// write half is consulted by `validateRequiredColumns`; the read half is used by the GraphQL
/// schema builder, which is out of scope until M7.
pub fn required_read_columns(class_name: &str) -> &'static [&'static str] {
    match class_name {
        "_User" => &["username"],
        _ => &[],
    }
}

/// `invalidClassNameMessage` (`SchemaController.js:483-489`).
///
/// **Note the trailing space.** It is in the upstream string literal, it reaches the client, and
/// a client matching on the message would not match without it.
pub fn invalid_class_name_message(class_name: &str) -> String {
    format!(
        "Invalid classname: {class_name}, classnames can only have alphanumeric characters and _, \
         and must start with an alpha character "
    )
}

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

/// Infer a field type from an **operation**, as `getObjectType`'s `__op` arm does
/// (`SchemaController.js:1634-1655`).
///
/// `None` means "no type", exactly as in [`infer_type`], so the field is skipped and no column is
/// created. `Delete` is upstream's own `None` case (`:1638-1639`).
///
/// The relation ops are the interesting ones: the type comes from the *first pointer in the
/// payload*, not from the op, so `AddRelation` with `[Pointer<Post>]` reserves
/// `Relation<Post>` on the field. `Batch` recurses into its first op (`:1650-1651`), which is
/// how the SDK's add-then-remove batch still infers a target class.
///
/// **Divergence, deliberate.** Upstream's arm reads `obj.objects[0].className` directly, so an
/// empty `objects` array and a non-pointer first element have no defined type there. Neither is
/// reachable here: both cases yield `None`, which routes the field down the same path `Delete`
/// takes. Inventing an error code for either would be worse.
///
/// `SetOnInsert` is the case that returns `Err`. `getObjectType` has arms for every other op and
/// a `default: throw` (`SchemaController.js:1652-1653`), and `SetOnInsert` is not among them, so
/// upstream refuses it at that point too.
///
/// The op is nonetheless plumbed through the rest of upstream, flattening on create
/// (`DatabaseController.js:333-335`), lowering to `$setOnInsert` (`MongoTransform.js:993-998`) and
/// echoing its result back (`DatabaseController.js:2153`), because internal callers reach
/// `DatabaseController` without passing `validateSchema`. parse-rust carries the same plumbing for
/// the same reason and refuses it at the same place, so a client cannot get a write past
/// parse-rust that parse-server would have rejected.
pub fn infer_op_type(op: &Op) -> Result<Option<FieldType>, ParseError> {
    Ok(match op {
        Op::Increment(_) => Some(FieldType::Number),
        Op::Delete => None,
        Op::Add(_) | Op::AddUnique(_) | Op::Remove(_) => Some(FieldType::Array),
        Op::AddRelation(objects) | Op::RemoveRelation(objects) => match objects.first() {
            Some(ParseValue::Pointer { class_name, .. }) => Some(FieldType::Relation {
                target_class: class_name.clone(),
            }),
            _ => None,
        },
        Op::Batch(ops) => match ops.first() {
            Some(first) => infer_op_type(first)?,
            None => None,
        },
        Op::SetOnInsert(_) => {
            return Err(ParseError::internal(format!(
                "unexpected op: {}",
                op.name()
            )))
        }
    })
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
///
/// The third branch is `fieldNameIsValid(className, className)` upstream
/// (`SchemaController.js:454`), not the bare regex, which is why a class called `length` is
/// refused: `invalidColumns` is consulted for class names too.
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
    field_name_is_valid(class_name, class_name)
}

/// Field names a client may not use at all.
///
/// `className` is refused on every class except `_Hooks`, which is the exception upstream carves
/// out because a hook document legitimately carries one.
pub fn field_name_is_valid(field_name: &str, class_name: &str) -> bool {
    if !class_name.is_empty() && class_name != "_Hooks" && field_name == "className" {
        return false;
    }
    matches_class_and_field_regex(field_name) && !INVALID_COLUMNS.contains(&field_name)
}

/// Additionally refuses the default columns, which a client cannot redefine.
///
/// Both tables are consulted, `_Default` and the class's own (`SchemaController.js:474-479`).
/// The second is what makes `name` un-addable on `_Role` while the same name is ordinary on any
/// other class, and it only reaches as far as [`default_columns_for`] models: a class absent from
/// that table has no class-specific columns to protect, so `_Installation`'s
/// `field localeIdentifier cannot be added` is not reachable yet.
pub fn field_name_is_valid_for_class(field_name: &str, class_name: &str) -> bool {
    if !field_name_is_valid(field_name, class_name) {
        return false;
    }
    !is_default_column(class_name, field_name)
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
    fn length_is_refused_as_a_field_and_as_a_class() {
        // `invalidColumns`, and `classNameIsValid` routes through `fieldNameIsValid`, so the ban
        // applies to class names too.
        assert!(!field_name_is_valid("length", "Post"));
        assert!(!class_name_is_valid("length"));
        assert!(field_name_is_valid("width", "Post"));
    }

    #[test]
    fn the_audience_and_idempotency_classes_are_system_classes() {
        // Missing from an earlier eight-entry transcription. Without them `_Idempotency` fails
        // `classNameIsValid` and the idempotency middleware cannot create its own class.
        assert_eq!(SYSTEM_CLASSES.len(), 10);
        assert!(class_name_is_valid("_Audience"));
        assert!(class_name_is_valid("_Idempotency"));
    }

    #[test]
    fn the_required_columns_table_is_upstreams() {
        assert_eq!(required_read_columns("_User"), ["username"]);
        assert_eq!(required_read_columns("Post"), [] as [&str; 0]);
        assert_eq!(
            required_write_columns("_Product"),
            ["productIdentifier", "icon", "order", "title", "subtitle"]
        );
        assert_eq!(required_write_columns("_Role"), ["name", "ACL"]);
        assert_eq!(required_write_columns("_User"), [] as [&str; 0]);
    }

    #[test]
    fn a_class_default_column_is_refused_for_that_class_only() {
        assert!(!field_name_is_valid_for_class("name", "_Role"));
        assert!(field_name_is_valid_for_class("name", "Post"));
        assert!(!field_name_is_valid_for_class("sessionToken", "_Session"));
        assert!(field_name_is_valid_for_class("sessionToken", "Post"));
    }

    #[test]
    fn ops_infer_the_types_getobjecttype_gives_them() {
        use parse_rust_core::Op;

        assert_eq!(
            infer_op_type(&Op::Increment(1.0)).expect("typed"),
            Some(FieldType::Number)
        );
        assert_eq!(infer_op_type(&Op::Delete).expect("typed"), None);
        for op in [Op::Add(vec![]), Op::AddUnique(vec![]), Op::Remove(vec![])] {
            assert_eq!(infer_op_type(&op).expect("typed"), Some(FieldType::Array));
        }
    }

    /// `getObjectType`'s switch has no `SetOnInsert` arm and its `default` throws a bare string,
    /// so upstream answers `{"code":1,"error":"Internal server error."}` rather than accepting the
    /// op (`SchemaController.js:1652-1653`, `middlewares.js:636-644`). The op is plumbed through
    /// the write path anyway because upstream plumbs it, for callers that never pass here.
    #[test]
    fn set_on_insert_is_the_op_getobjecttype_refuses() {
        use parse_rust_core::{ErrorCode, Op, ParseValue};

        let e = infer_op_type(&Op::SetOnInsert(ParseValue::Number(1.0))).unwrap_err();
        assert_eq!(e.code, ErrorCode::InternalServerError);
        assert_eq!(e.message, "unexpected op: SetOnInsert");
    }

    #[test]
    fn a_batch_recurses_into_its_first_op() {
        use parse_rust_core::Op;

        // The first op decides, even when the second would give a different answer.
        let op = Op::Batch(vec![Op::Increment(1.0), Op::Add(vec![])]);
        assert_eq!(infer_op_type(&op).expect("typed"), Some(FieldType::Number));
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
