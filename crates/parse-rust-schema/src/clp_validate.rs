//! Validating a class-level-permissions block, with upstream's exact messages.
//!
//! Upstream: `validateCLP` (`SchemaController.js:271-399`) and the four helpers it calls,
//! `validateCLPjson` (`:401-420`), `validatePermissionKey` (`:218-235`),
//! `validateProtectedFieldsKey` (`:237-254`) and `validatePointerPermission` (`:422-442`).
//!
//! These messages are wire-visible. `POST /schemas/:className` and `PUT /schemas/:className` both
//! reach here, `parse-dashboard` renders what comes back, and `spec/Schema.spec.js` asserts on the
//! strings. Reproduce them byte for byte, including the quoting, which is inconsistent upstream:
//! the unknown-top-level-key message has no quotes and every other message does.
//!
//! Two things here are the reason this is a module rather than three lines in `schema_api`.
//!
//! **The two entity grammars are not interchangeable.** Operations accept `pointerFields`, `*`,
//! `requiresAuthentication`, `role:<name>` and an objectId. `protectedFields` accepts
//! `userField:<name>`, `*`, `authenticated`, `role:<name>` and an objectId. Neither accepts the
//! other's spellings, and a shared validator gets it wrong in both directions.
//!
//! **The objectId grammar is a configuration input.** `^[a-zA-Z0-9]{1,}$` normally, `^.{1,}$`
//! when `allowCustomObjectId` is on (`SchemaController.js:726-731`). Hardcoding the first one
//! silently rejects valid CLPs on a server configured for the second, which is why
//! [`ClpValidation`] has no `Default` and the caller must state it.

use parse_rust_core::{
    js_number, ClassLevelPermissions, ErrorCode, ParseError, ParseMap, ParseValue,
};
use parse_rust_storage::ClassSchema;

use crate::infer::DEFAULT_COLUMNS;

/// Which strings count as an objectId inside a CLP.
///
/// `SchemaController.js:726-731`. Not a `bool` at the call site, because a bare `true` there
/// reads as "valid" rather than as "custom object ids are enabled".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectIdForm {
    /// `^[a-zA-Z0-9]{1,}$`, the default.
    Generated,
    /// `^.{1,}$`, when `allowCustomObjectId` is on. Any non-empty string.
    Custom,
}

impl ObjectIdForm {
    fn accepts(self, key: &str) -> bool {
        match self {
            ObjectIdForm::Generated => {
                !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric())
            }
            ObjectIdForm::Custom => !key.is_empty(),
        }
    }
}

/// Whether to refuse CLP features parse-rust validates but does not enforce.
///
/// The 0.2.0 milestone excludes `readUserFields`, `writeUserFields` and `userField:` protected
/// fields. Accepting a block that configures them and then not honoring it is the failure mode
/// worth avoiding: a class would report itself as restricted while serving every row. So the
/// default posture is to refuse the write, on the same rule that makes an unsupported query
/// constraint an error rather than a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unenforceable {
    /// Refuse the block. `COMMAND_UNAVAILABLE` (108), naming the key.
    Refuse,
    /// Accept exactly what upstream accepts. For reading a block already in the database, and for
    /// the day the feature lands.
    Accept,
}

/// Everything CLP validation needs that is not the block itself.
///
/// No `Default`. Both fields are decisions with a wire-visible consequence, and a default would
/// let a caller inherit one without making it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClpValidation {
    pub object_id: ObjectIdForm,
    pub unenforceable: Unenforceable,
}

/// Top-level keys a CLP block may carry (`CLPValidKeys`, `SchemaController.js:256-268`).
pub const VALID_KEYS: [&str; 11] = [
    "ACL",
    "find",
    "count",
    "get",
    "create",
    "update",
    "delete",
    "addField",
    "readUserFields",
    "writeUserFields",
    "protectedFields",
];

/// Validate a CLP block against a class, and parse it.
///
/// The block is moved in and comes back inside the returned [`ClassLevelPermissions`], which
/// keeps it verbatim. That is deliberate: a key parse-rust does not model must survive a round
/// trip through `_metadata.class_permissions`, or a parse-server node reading the same database
/// sees the key vanish.
///
/// `schema` supplies the field table for the existence checks. Pass the schema the block is
/// being stored against, meaning the *new* fields on a create and the merged fields on an update,
/// which is what upstream passes (`SchemaController.js:1092`, `:1100`).
pub fn validate_clp(
    raw: ParseMap,
    schema: &ClassSchema,
    opts: ClpValidation,
) -> Result<ClassLevelPermissions, ParseError> {
    for (operation_key, operation) in &raw {
        if !VALID_KEYS.contains(&operation_key.as_str()) {
            // The one message in this module with no quotes around the interpolation.
            return Err(ParseError::invalid_json(format!(
                "{operation_key} is not a valid operation for class level permissions"
            )));
        }

        validate_clp_json(operation, operation_key)?;

        if operation_key == "readUserFields" || operation_key == "writeUserFields" {
            if opts.unenforceable == Unenforceable::Refuse {
                return Err(unenforceable(operation_key));
            }
            // `validateCLPjson` already proved this is an array.
            if let ParseValue::Array(items) = operation {
                for item in items {
                    validate_pointer_permission(item, schema, operation_key)?;
                }
            }
            continue;
        }

        if operation_key == "protectedFields" {
            let entries = js_own_entries(operation);
            for (entity, protected) in &entries {
                let (entity, protected) = (entity.as_str(), protected);
                validate_protected_fields_key(entity, opts.object_id)?;
                if opts.unenforceable == Unenforceable::Refuse && entity.starts_with("userField:") {
                    return Err(unenforceable(entity));
                }

                let ParseValue::Array(fields) = protected else {
                    return Err(ParseError::invalid_json(format!(
                        "'{}' is not a valid value for protectedFields[{entity}] - expected an \
                         array.",
                        js_string(protected)
                    )));
                };

                for field in fields {
                    let name = js_string(field);
                    // Order matters: a default column reports as a default column even though it
                    // also exists on the class.
                    if DEFAULT_COLUMNS.iter().any(|(n, _)| *n == name) {
                        return Err(ParseError::invalid_json(format!(
                            "Default field '{name}' can not be protected"
                        )));
                    }
                    if !schema.fields.contains_key(&name) {
                        return Err(ParseError::invalid_json(format!(
                            "Field '{name}' in protectedFields:{entity} does not exist"
                        )));
                    }
                }
            }
            continue;
        }

        let entries = js_own_entries(operation);
        for (entity, permit) in &entries {
            let (entity, permit) = (entity.as_str(), permit);
            validate_permission_key(entity, opts.object_id)?;

            if entity == "pointerFields" {
                let ParseValue::Array(pointer_fields) = permit else {
                    return Err(ParseError::invalid_json(format!(
                        "'{}' is not a valid value for {operation_key}[{entity}] - expected an \
                         array.",
                        js_string(permit)
                    )));
                };
                for pointer_field in pointer_fields {
                    // UPSTREAM-QUIRK: the third argument here is the whole operation *object*,
                    // not the operation key (`SchemaController.js:355`), so the message ends in
                    // the literal `[object Object]`. The grouped-pointer-permission call site two
                    // branches up passes the key and reads correctly. Reproduced rather than
                    // fixed: it is the string a client sees.
                    validate_pointer_permission(pointer_field, schema, "[object Object]")?;
                }
                continue;
            }

            if operation_key == "ACL" {
                validate_clp_acl_entry(permit)?;
            } else if !matches!(permit, ParseValue::Bool(true)) {
                // The trailing `acl` is upstream's, on a message that has nothing to do with
                // ACLs (`SchemaController.js:394`).
                return Err(ParseError::invalid_json(format!(
                    "'{}' is not a valid value for class level permissions acl \
                     {operation_key}:{entity}",
                    js_string(permit)
                )));
            }
        }
    }

    Ok(ClassLevelPermissions::from_map(raw))
}

/// Tier 2 refusal for a CLP feature 0.2.0 validates but cannot enforce.
///
/// `COMMAND_UNAVAILABLE` (108) is the code the milestone already uses for the other
/// accept-but-do-not-honor case, a `/batch` asking for a transaction. The message is
/// parse-rust's own; there is no upstream string to reproduce, because upstream implements the
/// feature.
fn unenforceable(key: &str) -> ParseError {
    ParseError::new(
        ErrorCode::CommandUnavailable,
        format!(
            "{key} is not supported yet. parse-rust validates it and cannot enforce it, so the \
             class level permissions are refused rather than stored unenforced."
        ),
    )
}

/// `validateCLPjson` (`SchemaController.js:401-420`).
fn validate_clp_json(operation: &ParseValue, operation_key: &str) -> Result<(), ParseError> {
    if operation_key == "readUserFields" || operation_key == "writeUserFields" {
        if !matches!(operation, ParseValue::Array(_)) {
            return Err(ParseError::invalid_json(format!(
                "'{}' is not a valid value for class level permissions {operation_key} - must be \
                 an array",
                js_string(operation)
            )));
        }
        return Ok(());
    }
    // `typeof operation === 'object' && operation !== null`. An array passes this upstream, and
    // so does every tagged value, because all of them are ordinary objects in the raw JSON that
    // reaches `validateCLP`.
    if is_js_object(operation) {
        return Ok(());
    }
    Err(ParseError::invalid_json(format!(
        "'{}' is not a valid value for class level permissions {operation_key} - must be an object",
        js_string(operation)
    )))
}

/// `validatePermissionKey` (`SchemaController.js:218-235`).
///
/// `clpFieldsRegex` is `pointerFields`, `*`, `requiresAuthentication`, `role:.*`, then the
/// objectId regex. Note `/^role:.*/` accepts an empty role name; that is upstream's regex and it
/// is not tightened here.
fn validate_permission_key(key: &str, object_id: ObjectIdForm) -> Result<(), ParseError> {
    let matches_some = key == "pointerFields"
        || key == "*"
        || key == "requiresAuthentication"
        || key.starts_with("role:");
    if matches_some || object_id.accepts(key) {
        return Ok(());
    }
    Err(invalid_clp_key(key))
}

/// `validateProtectedFieldsKey` (`SchemaController.js:237-254`).
///
/// A different set: `userField:.*`, `*`, `authenticated`, `role:.*`. There is no
/// `requiresAuthentication` and no `pointerFields` here, and both of those spellings fall through
/// to the objectId regex, so `requiresAuthentication` is accepted as an objectId rather than as a
/// predicate.
fn validate_protected_fields_key(key: &str, object_id: ObjectIdForm) -> Result<(), ParseError> {
    let matches_some = key.starts_with("userField:")
        || key == "*"
        || key == "authenticated"
        || key.starts_with("role:");
    if matches_some || object_id.accepts(key) {
        return Ok(());
    }
    Err(invalid_clp_key(key))
}

/// Both key validators raise the same message (`:232`, `:251`).
fn invalid_clp_key(key: &str) -> ParseError {
    ParseError::invalid_json(format!(
        "'{key}' is not a valid key for class level permissions"
    ))
}

/// `validatePointerPermission` (`SchemaController.js:422-442`).
///
/// `Pointer<_User>` or `Array`, and nothing else. `Array` is accepted because a schema cannot
/// constrain an array's element type, so the filter later keeps only the elements that are
/// pointers to `_User`.
fn validate_pointer_permission(
    field: &ParseValue,
    schema: &ClassSchema,
    operation: &str,
) -> Result<(), ParseError> {
    let name = js_string(field);
    let ok = match schema.fields.get(&name) {
        Some(ty) => {
            ty.target_class() == Some("_User") && ty.is_pointer()
                || matches!(ty, parse_rust_storage::FieldType::Array)
        }
        None => false,
    };
    if ok {
        return Ok(());
    }
    Err(ParseError::invalid_json(format!(
        "'{name}' is not a valid column for class level pointer permissions {operation}"
    )))
}

/// The `ACL` key's entity values (`SchemaController.js:369-390`).
///
/// This is the CLP's own ACL, so an entity maps to `{read, write}` rather than to `true`. Keys
/// outside `read`/`write` and values that are not booleans are reported separately, each joining
/// every offender with a comma.
fn validate_clp_acl_entry(permit: &ParseValue) -> Result<(), ParseError> {
    // `Object.prototype.toString.call(permit) !== '[object Object]'`. An array is `[object
    // Array]` and fails here even though it passed `validateCLPjson`.
    let ParseValue::Object(entry) = permit else {
        return Err(ParseError::invalid_json(format!(
            "'{}' is not a valid value for class level permissions acl",
            js_string(permit)
        )));
    };

    let invalid_keys: Vec<&str> = entry
        .keys()
        .filter(|k| k.as_str() != "read" && k.as_str() != "write")
        .map(String::as_str)
        .collect();
    if !invalid_keys.is_empty() {
        return Err(ParseError::invalid_json(format!(
            "'{}' is not a valid key for class level permissions acl",
            invalid_keys.join(",")
        )));
    }

    let invalid_values: Vec<String> = entry
        .values()
        .filter(|v| !matches!(v, ParseValue::Bool(_)))
        .map(js_string)
        .collect();
    if !invalid_values.is_empty() {
        return Err(ParseError::invalid_json(format!(
            "'{}' is not a valid value for class level permissions acl",
            invalid_values.join(",")
        )));
    }
    Ok(())
}

/// The `(key, value)` pairs a JavaScript `for...in` would visit.
///
/// `validateCLP` enumerates an operation's entries with `for (const entity in operation)`
/// (`SchemaController.js:301`, `:345`), and `for...in` visits the own enumerable keys of **any**
/// object-like value, not only a plain object. Skipping anything that is not a `ParseValue::Object`
/// was therefore wrong in two directions at once:
///
/// - `{"find": ["*"]}` is an array upstream, so `for...in` yields the index `"0"`, which passes
///   `validatePermissionKey` as an objectId, and the element `"*"` then fails `permit !== true`.
///   Upstream answers `INVALID_JSON`; skipping it answered 200 for a block that grants nothing.
/// - `{"find": {"__type": "Date", ...}}` is a plain object upstream, so its keys are checked and
///   `__type` is refused. Skipping it answered 200 and stored the block, and the CLP reader then
///   reads a truthy non-object as **deny-all**, so the class is silently locked with no error at
///   the time of the write that locked it.
///
/// A primitive yields nothing, which is what `for...in` over a number, boolean or null does.
///
/// **A tagged value's key order is canonical here rather than the client's.** By this point the
/// wire order is lost to classification. Every key of every tagged encoding is refused by
/// `validate_permission_key`, so the outcome is the same refusal either way; only which key the
/// message names can differ from upstream, and only for a body that was already invalid.
fn js_own_entries(value: &ParseValue) -> Vec<(String, ParseValue)> {
    let tagged = |pairs: Vec<(&str, ParseValue)>| {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<Vec<_>>()
    };
    let s = |v: &str| ParseValue::String(v.to_string());
    match value {
        ParseValue::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ParseValue::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v.clone()))
            .collect(),
        // `for...in` over a string visits its character indices.
        ParseValue::String(text) => text
            .chars()
            .enumerate()
            .map(|(i, c)| (i.to_string(), ParseValue::String(c.to_string())))
            .collect(),
        ParseValue::Date(d) => tagged(vec![("__type", s("Date")), ("iso", s(&d.to_iso()))]),
        ParseValue::Pointer {
            class_name,
            object_id,
        } => tagged(vec![
            ("__type", s("Pointer")),
            ("className", s(class_name)),
            ("objectId", s(object_id)),
        ]),
        ParseValue::GeoPoint {
            latitude,
            longitude,
        } => tagged(vec![
            ("__type", s("GeoPoint")),
            ("latitude", ParseValue::Number(*latitude)),
            ("longitude", ParseValue::Number(*longitude)),
        ]),
        ParseValue::Bytes(_) => tagged(vec![("__type", s("Bytes")), ("base64", s(""))]),
        ParseValue::File { name, .. } => tagged(vec![("__type", s("File")), ("name", s(name))]),
        ParseValue::Polygon(_) => tagged(vec![
            ("__type", s("Polygon")),
            ("coordinates", ParseValue::Array(Vec::new())),
        ]),
        ParseValue::Relation { class_name } => tagged(vec![
            ("__type", s("Relation")),
            ("className", s(class_name)),
        ]),
        ParseValue::Null | ParseValue::Bool(_) | ParseValue::Number(_) => Vec::new(),
    }
}

/// Is this what JavaScript's `typeof x === 'object' && x !== null` would say?
///
/// Every tagged Parse value is an ordinary object at this point in upstream, because `validateCLP`
/// runs on the parsed request body before anything classifies it. Arrays are objects too.
fn is_js_object(value: &ParseValue) -> bool {
    !matches!(
        value,
        ParseValue::Null | ParseValue::Bool(_) | ParseValue::Number(_) | ParseValue::String(_)
    )
}

/// JavaScript's `String(x)`, for the messages that interpolate an offending value.
///
/// Needed because the messages quote the value back and a client can match on the result. The
/// cases that matter: a number renders through the ECMAScript algorithm rather than Rust's
/// `Display` (so `1` and not `1.0`), an array joins its elements with a comma and renders `null`
/// as the empty string, and every object renders as the literal `[object Object]`.
///
/// The tagged variants all render as `[object Object]` for the same reason [`is_js_object`] treats
/// them as objects: upstream sees the raw JSON, where they are plain objects.
fn js_string(value: &ParseValue) -> String {
    match value {
        ParseValue::Null => "null".to_string(),
        ParseValue::Bool(b) => b.to_string(),
        ParseValue::Number(n) => js_number::to_ecma_string(*n),
        ParseValue::String(s) => s.clone(),
        ParseValue::Array(items) => items
            .iter()
            .map(|item| match item {
                // `[null].toString()` is `""`, not `"null"`.
                ParseValue::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => "[object Object]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::{classify, OpEntity, Operation, PfEntity};
    use parse_rust_storage::FieldType;

    fn opts() -> ClpValidation {
        ClpValidation {
            object_id: ObjectIdForm::Generated,
            unenforceable: Unenforceable::Accept,
        }
    }

    fn map(json: &str) -> ParseMap {
        match classify(serde_json::from_str(json).expect("test literal must be valid JSON"))
            .expect("classify")
        {
            ParseValue::Object(m) => m,
            other => panic!("expected an object, got {other:?}"),
        }
    }

    fn schema() -> ClassSchema {
        crate::controller::default_schema("Post")
            .with_field("title", FieldType::String)
            .with_field(
                "owner",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
            .with_field(
                "author",
                FieldType::Pointer {
                    target_class: "Writer".into(),
                },
            )
            .with_field("editors", FieldType::Array)
    }

    fn err(json: &str) -> ParseError {
        validate_clp(map(json), &schema(), opts()).expect_err("should be rejected")
    }

    fn ok(json: &str) -> ClassLevelPermissions {
        validate_clp(map(json), &schema(), opts()).expect("should be accepted")
    }

    #[test]
    fn an_unknown_top_level_key_is_refused_without_quotes() {
        let e = err(r#"{"nope":{"*":true}}"#);
        assert_eq!(
            e.message,
            "nope is not a valid operation for class level permissions"
        );
        assert_eq!(e.code, ErrorCode::InvalidJson);
    }

    #[test]
    fn every_valid_top_level_key_is_accepted() {
        // Cheap, and it catches a transcription slip in the table.
        assert_eq!(VALID_KEYS.len(), 11);
        ok(r#"{
            "ACL":{"*":{"read":true,"write":true}},
            "find":{"*":true},"count":{"*":true},"get":{"*":true},
            "create":{"*":true},"update":{"*":true},"delete":{"*":true},
            "addField":{"*":true},
            "readUserFields":["owner"],"writeUserFields":["owner"],
            "protectedFields":{"*":["title"]}
        }"#);
    }

    #[test]
    fn only_literal_true_grants_an_operation() {
        for (json, rendered) in [
            (r#"{"find":{"*":false}}"#, "false"),
            (r#"{"find":{"*":0}}"#, "0"),
            (r#"{"find":{"*":"true"}}"#, "true"),
            (r#"{"find":{"*":null}}"#, "null"),
            (r#"{"find":{"*":1}}"#, "1"),
        ] {
            let e = err(json);
            assert_eq!(
                e.message,
                format!("'{rendered}' is not a valid value for class level permissions acl find:*"),
                "{json}"
            );
        }
    }

    /// The number rendering is not Rust's. `1` must not come out as `1.0`.
    #[test]
    fn numbers_render_through_the_ecmascript_algorithm() {
        assert_eq!(js_string(&ParseValue::Number(1.0)), "1");
        assert_eq!(js_string(&ParseValue::Number(1.5)), "1.5");
        assert_eq!(js_string(&ParseValue::Number(-0.0)), "0");
    }

    #[test]
    fn a_non_object_operation_is_refused_before_its_entities() {
        let e = err(r#"{"find":true}"#);
        assert_eq!(
            e.message,
            "'true' is not a valid value for class level permissions find - must be an object"
        );
        // And the array form has its own message.
        let e = err(r#"{"readUserFields":"owner"}"#);
        assert_eq!(
            e.message,
            "'owner' is not a valid value for class level permissions readUserFields - must be an \
             array"
        );
    }

    #[test]
    fn the_two_entity_grammars_reject_each_others_spellings() {
        // `authenticated` is not an operation entity, but it does match the objectId regex, so it
        // is accepted as an objectId rather than refused. The refusal only bites on a string the
        // objectId regex also rejects.
        let e = err(r#"{"find":{"has-dash":true}}"#);
        assert_eq!(
            e.message,
            "'has-dash' is not a valid key for class level permissions"
        );
        let e = err(r#"{"protectedFields":{"has-dash":["title"]}}"#);
        assert_eq!(
            e.message,
            "'has-dash' is not a valid key for class level permissions"
        );
    }

    #[test]
    fn a_custom_object_id_configuration_widens_the_entity_grammar() {
        let custom = ClpValidation {
            object_id: ObjectIdForm::Custom,
            unenforceable: Unenforceable::Accept,
        };
        // Rejected under the generated-id regex, accepted under the custom one. Hardcoding the
        // first would lock a legitimately configured server out of its own CLP.
        assert!(validate_clp(map(r#"{"find":{"has-dash":true}}"#), &schema(), opts()).is_err());
        assert!(validate_clp(map(r#"{"find":{"has-dash":true}}"#), &schema(), custom).is_ok());
        // Empty is still not an objectId under either form.
        assert!(validate_clp(map(r#"{"find":{"":true}}"#), &schema(), custom).is_err());
    }

    /// `/^role:.*/` accepts an empty role name. Do not tighten it.
    #[test]
    fn an_empty_role_name_is_accepted() {
        let c = ok(r#"{"find":{"role:":true}}"#);
        let perm = c.op(Operation::Find).expect("find is present");
        assert_eq!(perm.entities, vec![OpEntity::Role(String::new())]);
    }

    #[test]
    fn pointer_fields_must_be_an_array_of_user_pointers_or_arrays() {
        ok(r#"{"find":{"pointerFields":["owner"]}}"#);
        ok(r#"{"find":{"pointerFields":["editors"]}}"#);

        // A pointer at the wrong class is not a pointer permission.
        let e = err(r#"{"find":{"pointerFields":["author"]}}"#);
        assert_eq!(
            e.message,
            "'author' is not a valid column for class level pointer permissions [object Object]"
        );
        // Nor is a field of the wrong type, nor one that does not exist.
        assert!(err(r#"{"find":{"pointerFields":["title"]}}"#)
            .message
            .starts_with("'title' is not a valid column"));
        assert!(err(r#"{"find":{"pointerFields":["ghost"]}}"#)
            .message
            .starts_with("'ghost' is not a valid column"));
    }

    /// The grouped arrays pass the operation *key*, so their message reads correctly. The
    /// per-operation `pointerFields` call site passes the operation object and produces
    /// `[object Object]`. Both are upstream's.
    #[test]
    fn the_pointer_permission_message_differs_between_the_two_call_sites() {
        assert_eq!(
            err(r#"{"readUserFields":["title"]}"#).message,
            "'title' is not a valid column for class level pointer permissions readUserFields"
        );
        assert_eq!(
            err(r#"{"writeUserFields":["title"]}"#).message,
            "'title' is not a valid column for class level pointer permissions writeUserFields"
        );
        assert_eq!(
            err(r#"{"find":{"pointerFields":["title"]}}"#).message,
            "'title' is not a valid column for class level pointer permissions [object Object]"
        );
    }

    #[test]
    fn a_non_array_pointer_fields_names_the_operation_and_the_entity() {
        let e = err(r#"{"update":{"pointerFields":"owner"}}"#);
        assert_eq!(
            e.message,
            "'owner' is not a valid value for update[pointerFields] - expected an array."
        );
    }

    #[test]
    fn protected_fields_must_be_arrays_of_existing_non_default_fields() {
        let c = ok(r#"{"protectedFields":{"*":["title"],"role:A":["title","owner"]}}"#);
        assert_eq!(
            c.protected_fields().get(&PfEntity::Public),
            Some(&vec!["title".to_string()])
        );

        let e = err(r#"{"protectedFields":{"*":"title"}}"#);
        assert_eq!(
            e.message,
            "'title' is not a valid value for protectedFields[*] - expected an array."
        );

        let e = err(r#"{"protectedFields":{"role:A":["ghost"]}}"#);
        assert_eq!(
            e.message,
            "Field 'ghost' in protectedFields:role:A does not exist"
        );
    }

    /// The rule that keeps `objectId` from being hidden through the schema API. A protected
    /// `objectId` would make every row unidentifiable to its own owner.
    #[test]
    fn no_default_column_can_be_protected() {
        for column in ["objectId", "createdAt", "updatedAt", "ACL"] {
            let e = err(&format!(r#"{{"protectedFields":{{"*":["{column}"]}}}}"#));
            assert_eq!(
                e.message,
                format!("Default field '{column}' can not be protected")
            );
        }
    }

    #[test]
    fn the_clp_acl_key_takes_read_and_write_booleans() {
        ok(r#"{"ACL":{"*":{"read":true,"write":false}}}"#);

        let e = err(r#"{"ACL":{"*":true}}"#);
        assert_eq!(
            e.message,
            "'true' is not a valid value for class level permissions acl"
        );

        let e = err(r#"{"ACL":{"*":{"read":true,"delete":true,"update":true}}}"#);
        assert_eq!(
            e.message,
            "'delete,update' is not a valid key for class level permissions acl"
        );

        let e = err(r#"{"ACL":{"*":{"read":1,"write":"yes"}}}"#);
        assert_eq!(
            e.message,
            "'1,yes' is not a valid value for class level permissions acl"
        );
    }

    /// 0.2.0 refuses what it cannot enforce rather than storing it unenforced.
    #[test]
    fn unenforceable_features_are_refused_not_ignored() {
        let refuse = ClpValidation {
            object_id: ObjectIdForm::Generated,
            unenforceable: Unenforceable::Refuse,
        };
        for json in [
            r#"{"readUserFields":["owner"]}"#,
            r#"{"writeUserFields":["owner"]}"#,
            r#"{"protectedFields":{"userField:owner":["title"]}}"#,
        ] {
            let e = validate_clp(map(json), &schema(), refuse).expect_err("must be refused");
            assert_eq!(e.code, ErrorCode::CommandUnavailable, "{json}");
        }
        // And the same blocks are accepted when the caller asks for upstream behavior, which is
        // what reading an existing database needs.
        for json in [
            r#"{"readUserFields":["owner"]}"#,
            r#"{"writeUserFields":["owner"]}"#,
            r#"{"protectedFields":{"userField:owner":["title"]}}"#,
        ] {
            assert!(validate_clp(map(json), &schema(), opts()).is_ok(), "{json}");
        }
    }

    /// The refusal must not fire on an entity that merely looks similar.
    #[test]
    fn refusing_user_field_entries_does_not_refuse_ordinary_ones() {
        let refuse = ClpValidation {
            object_id: ObjectIdForm::Generated,
            unenforceable: Unenforceable::Refuse,
        };
        assert!(validate_clp(
            map(r#"{"protectedFields":{"*":["title"],"role:A":["title"],"authenticated":["title"]}}"#),
            &schema(),
            refuse
        )
        .is_ok());
    }

    /// Validation must not normalize. A key parse-rust does not model has to survive, or a
    /// parse-server node reading the same database sees it disappear.
    #[test]
    fn the_raw_block_survives_validation_unchanged() {
        let c = ok(r#"{"find":{"*":true},"ACL":{"*":{"read":true}}}"#);
        assert!(c.raw().contains_key("ACL"));
        assert!(c.raw().contains_key("find"));
        assert_eq!(c.raw().len(), 2);
    }

    /// An empty block is valid and is not the same thing as an absent one.
    #[test]
    fn an_empty_block_validates() {
        let c = ok("{}");
        assert!(c.op(Operation::Find).is_none());
        assert!(c.raw().is_empty());
    }

    /// An array operation value. Upstream's `for...in` yields the index, which passes as an
    /// objectId, and the element then fails `permit !== true`. This answered 200 before.
    #[test]
    fn an_array_operation_value_is_refused() {
        let err = validate_clp(map(r#"{"find": ["*"]}"#), &schema(), opts())
            .expect_err("an array is not a permission object");
        assert_eq!(err.code, parse_rust_core::ErrorCode::InvalidJson);
    }

    /// The one that mattered. A tagged value stored unvalidated reads back as **deny-all**, so the
    /// class locks and nothing reports it at the time of the write that locked it.
    #[test]
    fn a_tagged_operation_value_is_refused_rather_than_silently_locking_the_class() {
        let err = validate_clp(
            map(r#"{"find": {"__type": "Date", "iso": "2026-01-01T00:00:00.000Z"}}"#),
            &schema(),
            opts(),
        )
        .expect_err("a Date is not a permission object");
        assert_eq!(err.code, parse_rust_core::ErrorCode::InvalidJson);
    }

    /// The same hole on `protectedFields`, which uses the same `for...in`.
    #[test]
    fn an_array_protected_fields_value_is_refused() {
        let err = validate_clp(map(r#"{"protectedFields": ["title"]}"#), &schema(), opts())
            .expect_err("an array is not a protectedFields object");
        assert_eq!(err.code, parse_rust_core::ErrorCode::InvalidJson);
    }

    /// A primitive yields no keys, exactly as `for...in` over a number does, so it passes this
    /// stage. Reproducing upstream's silence here is deliberate.
    #[test]
    fn a_primitive_operation_value_yields_no_entries() {
        assert!(js_own_entries(&ParseValue::Number(1.0)).is_empty());
        assert!(js_own_entries(&ParseValue::Bool(true)).is_empty());
        assert!(js_own_entries(&ParseValue::Null).is_empty());
    }
}
