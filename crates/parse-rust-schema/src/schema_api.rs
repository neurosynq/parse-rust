//! Validation for `POST /schemas/:className` and `PUT /schemas/:className`.
//!
//! Pure. No I/O, no routing, no schema cache. A create returns the [`ClassSchema`] the caller
//! should persist; an update returns a [`SchemaMutation`] the caller executes. Upstream fuses
//! validation with execution across `addClassIfNotExists` (`SchemaController.js:832-868`) and
//! `updateClass` (`:870-975`), which is why an upstream field delete can half-happen. Splitting
//! them here does not make the sequence atomic, and it does make the decision reviewable in one
//! place.
//!
//! **0.2.0 scope: field options are stored, not enforced.** `required` and `defaultValue` are
//! validated against the field's type and round-tripped **exactly as sent**: a schema body is
//! decoded without interpreting any `__type` envelope, so an offset instant, unpadded base64 and
//! any key the envelope does not declare all survive. Stored into
//! `ClassSchema::field_options`, which the Mongo adapter writes to `_metadata.fields_options`.
//! Nothing consults them on a write. That is a deliberate exclusion, and storing them anyway is
//! what keeps a mixed fleet honest: a parse-server node reading the same database enforces them,
//! and dropping the keys on a parse-rust rewrite would silently relax a constraint it never
//! agreed to relax.
//!
//! Two error codes upstream uses here are bare numbers with no name in the `parse` SDK's table.
//! They have [`ErrorCode`] variants all the same, named from their messages, because the number is
//! what a client sees. See [`NEEDS_CLASS_NAME_CODE`].

use indexmap::IndexMap;
use parse_rust_core::{
    js_number, ClassLevelPermissions, ErrorCode, ParseError, ParseMap, ParseValue,
};
use parse_rust_storage::{ClassSchema, FieldType};

use crate::clp_validate::{validate_clp, ClpValidation};
use crate::infer::{
    class_name_is_valid, default_columns_for, field_name_is_valid, field_name_is_valid_for_class,
    infer_type, invalid_class_name_message,
};

/// `135`, `type <T> needs a class name` (`SchemaController.js:508`, `SchemasRouter.js:90`).
///
/// **Named constants rather than the variants inline, because these two numbers have no name in
/// `src/Error.js` or in the `parse` SDK.** Upstream throws them as `new Parse.Error(135, ...)`, so
/// there is no upstream symbol to match against and a reader has nothing to check a bare
/// `ErrorCode::MissingClassName` against. The name here is ours, taken from the message.
///
/// `spec/Schema.spec.js` asserts on the numbers directly (`:575`, `:590`, `:620`, `:650`), which is
/// what makes a substitution wire-visible: an earlier version of this file used `IncorrectType`
/// (111) and `InvalidKeyName` (105) on the stated belief that no variant existed for either. Both
/// have existed since the codes were first enumerated (`parse_rust_core::ErrorCode`). Do not
/// substitute a named neighbour again.
pub const NEEDS_CLASS_NAME_CODE: ErrorCode = ErrorCode::MissingClassName;

/// `136`, `field <name> cannot be added` (`SchemaController.js:1038-1039`, `:1242`). See
/// [`NEEDS_CLASS_NAME_CODE`] for why this is a named constant.
pub const FIELD_CANNOT_BE_ADDED_CODE: ErrorCode = ErrorCode::UnchangeableField;

/// What a `fields` entry in a schema-API body asks for.
///
/// `Delete` is spelled `{"__op":"Delete"}` on the wire and is only meaningful on `PUT`. Modelled
/// as a variant rather than as a flag on a struct so that a caller enumerating the plan cannot
/// treat a delete as a weird kind of add.
#[derive(Debug, Clone)]
pub enum FieldChange {
    Set {
        field_type: FieldType,
        /// Everything the wire spec carried besides `type` and `targetClass`, verbatim.
        ///
        /// That is exactly what upstream stores under `_metadata.fields_options.<field>`
        /// (`MongoSchemaCollection.js:262-264`, `:293-295`): it destructures `type` and
        /// `targetClass` off and keeps the rest, including keys it does not understand.
        options: ParseMap,
    },
    Delete,
}

/// A `PUT /schemas/:className` reduced to the work the caller has to do.
///
/// `#[must_use]`, and `deleted` is not an `Option`. Both are deliberate: a caller that applies
/// `added` and forgets `deleted` leaves a class carrying a field the client believes it removed,
/// and the field then reappears in every response.
#[derive(Debug, Clone)]
#[must_use]
pub struct SchemaMutation {
    /// Fields to drop, with their rows' columns and, for a `Relation`, its join collection.
    pub deleted: Vec<String>,
    /// `None` means the body carried no `classLevelPermissions` at all, which upstream treats as
    /// "leave the stored block alone" (`setPermissions` returns early on `undefined`,
    /// `SchemaController.js:1097-1099`). It is **not** the same as an empty block, which
    /// replaces the stored one.
    pub clp: Option<ClassLevelPermissions>,
    /// Every submitted field that is not a delete, in body order, with the options it carried.
    ///
    /// **Includes fields that already exist, and includes empty option sets**, because both are
    /// meaningful. Upstream reaches `enforceFieldExists` for every submitted field, not only the
    /// new ones (`SchemaController.js:930-934`), and resubmitting a field without the options it
    /// was stored with is how a client clears them: `updateFieldOptions` writes whatever is left
    /// after `type` and `targetClass` are removed, which for `{"type":"String"}` is `{}`
    /// (`MongoSchemaCollection.js:284-297`).
    pub set_fields: Vec<SetField>,
}

/// One submitted field spec, split into the parts that are stored in two different places.
#[derive(Debug, Clone)]
pub struct SetField {
    pub name: String,
    pub field_type: FieldType,
    /// Every key of the spec except `type` and `targetClass`. Empty is a value, not an absence.
    pub options: ParseMap,
    /// Absent from the stored schema, so this submission reserves it rather than updating it.
    pub is_new: bool,
}

impl SchemaMutation {
    pub fn is_empty(&self) -> bool {
        self.set_fields.is_empty() && self.deleted.is_empty() && self.clp.is_none()
    }
}

/// Validate a `POST /schemas/:className` body and produce the schema to create.
///
/// Order of checks is upstream's, and it is observable because the first failure is what the
/// client sees: class name, then per field name, name-for-class, type, and options, then the
/// GeoPoint count, then the CLP (`validateNewClass` at `:1009-1020` into `validateSchemaData` at
/// `:1022-1093`).
///
/// The "class already exists" check is not here. It needs the loaded schema set, which is the
/// caller's, and its message is `Class <name> already exists.` with `INVALID_CLASS_NAME`
/// (`:1011`).
pub fn validate_new_class(
    class_name: &str,
    fields: &ParseMap,
    clp: Option<ParseMap>,
    opts: ClpValidation,
) -> Result<ClassSchema, ParseError> {
    if !class_name_is_valid(class_name) {
        return Err(ParseError::new(
            ErrorCode::InvalidClassName,
            invalid_class_name_message(class_name),
        ));
    }

    let changes = parse_fields(fields)?;
    let mut schema = ClassSchema::new(class_name);
    let mut options = ParseMap::new();

    for (name, change) in &changes {
        match change {
            // A delete on a class that does not exist yet. Upstream never reaches its own
            // "does not exist, cannot delete" check here, because `validateNewClass` runs on the
            // submitted fields and `buildMergedSchemaObject` is only used by `updateClass`. It
            // refuses the spec anyway, one step later and for a different reason:
            // `fieldTypeIsInvalid` destructures `{type, targetClass}` off `{"__op":"Delete"}`,
            // finds `type` undefined, and returns `INVALID_JSON` `invalid JSON`
            // (`SchemaController.js:505-518`, called at `:1042-1043`).
            //
            // So the divergence is the code and the message, not the acceptance: both servers
            // refuse the request, upstream with 107 `invalid JSON` and parse-rust with the update
            // path's 255 `Field <name> does not exist, cannot delete.`, which names the actual
            // problem. Recorded rather than reproduced.
            FieldChange::Delete => {
                return Err(ParseError::new(
                    ErrorCode::InvalidSchemaOperation,
                    format!("Field {name} does not exist, cannot delete."),
                ))
            }
            FieldChange::Set {
                field_type,
                options: field_options,
            } => {
                check_new_field(class_name, name, field_type, field_options)?;
                schema.fields.insert(name.clone(), field_type.clone());
                if !field_options.is_empty() {
                    options.insert(name.clone(), ParseValue::Object(field_options.clone()));
                }
            }
        }
    }

    // `for (const fieldName in defaultColumns[className]) fields[fieldName] = ...`
    // (`SchemaController.js:1074-1076`), then `_Default` on top through `injectDefaultSchema`.
    // Merged after the per-field loop so a submitted field that collides with a default column is
    // still reported by `fieldNameIsValidForClass` rather than being silently overwritten.
    for (name, ty) in crate::infer::DEFAULT_COLUMNS {
        schema.fields.insert(name.to_string(), ty);
    }
    for (name, ty) in default_columns_for(class_name) {
        schema.fields.insert(name.to_string(), ty);
    }

    check_one_geopoint(&schema)?;

    if let Some(raw) = clp {
        schema.clp = Some(validate_clp(raw, &schema, opts)?);
    }
    if !options.is_empty() {
        schema.field_options = Some(options);
    }

    Ok(schema)
}

/// Validate a `PUT /schemas/:className` body against the stored schema and produce the plan.
///
/// The two mutation errors are checked before anything else happens, exactly as upstream does at
/// `:880-892`, so a body that both adds a legal field and illegally retypes another adds nothing.
pub fn plan_update(
    existing: &ClassSchema,
    fields: &ParseMap,
    clp: Option<ParseMap>,
    opts: ClpValidation,
) -> Result<SchemaMutation, ParseError> {
    let changes = parse_fields(fields)?;
    let class_name = existing.class_name.as_str();

    for (name, change) in &changes {
        match (existing.field(name), change) {
            // **The pre-check compares the type *name* only, not the target class.** Upstream is
            // `existingFields[name].type !== field.type` (`SchemaController.js:882-887`), and
            // `type` there is the bare string, so `Pointer<Other>` over `Pointer<_User>` passes
            // this gate and is refused one stage later by the field reservation, as
            // `INCORRECT_TYPE` `schema mismatch for <Class>.<field>; expected Pointer<_User> but
            // got Pointer<Other>`. Comparing the whole `FieldType` here reported 255 `Field <name>
            // exists, cannot update.` instead, which is a different code and a different message
            // for the same request. The cited `dbTypeMatchesObjectType` is a different function
            // and is not the gate.
            //
            // Resubmitting a field with different options is still an options update rather than a
            // conflict, which is what makes the comparison a type comparison at all.
            (Some(current), FieldChange::Set { field_type, .. })
                if std::mem::discriminant(current) != std::mem::discriminant(field_type) =>
            {
                return Err(ParseError::new(
                    ErrorCode::InvalidSchemaOperation,
                    format!("Field {name} exists, cannot update."),
                ))
            }
            // **Same kind, different target.** `Pointer<_User>` and `Pointer<Other>` share a
            // discriminant, so the gate above lets them past, and the comment above used to say
            // the field reservation would catch it. It does not: reservation runs only for fields
            // that are *new* (`routes/schemas.rs`), so a retarget answered 200 and silently kept
            // the original target. Measured against parse-server at the pin, which answers
            // `111 schema mismatch for <Class>.<field>; expected Pointer<_User> but got
            // Pointer<Other>`.
            //
            // The check belongs here rather than at the reservation, because this is the only
            // stage that sees the stored type for a field the request is not creating.
            //
            // **Planning, so nothing is applied.** Upstream discovers the mismatch after its
            // deletions have already committed, so its failed request drops a column and says
            // nothing about it. Refusing before any write is the same rule `enforceClassExists`
            // follows and is registered as a deliberate difference with its mixed-fleet cost.
            (Some(current), FieldChange::Set { field_type, .. }) if current != field_type => {
                return Err(crate::infer::schema_mismatch(
                    class_name, name, current, field_type,
                ))
            }
            (None, FieldChange::Delete) => {
                return Err(ParseError::new(
                    ErrorCode::InvalidSchemaOperation,
                    format!("Field {name} does not exist, cannot delete."),
                ))
            }
            _ => {}
        }
    }

    // The merged view the rest of validation runs against: existing fields minus the deletions,
    // plus the additions (`buildMergedSchemaObject`, `:1507-1540`).
    let mut merged = existing.clone();
    let mut set_fields: Vec<SetField> = Vec::new();
    let mut deleted = Vec::new();

    for (name, change) in &changes {
        match change {
            FieldChange::Delete => {
                merged.fields.shift_remove(name.as_str());
                deleted.push(name.clone());
            }
            FieldChange::Set {
                field_type,
                options: field_options,
            } => {
                // The option checks in `validateSchemaData` are all inside its
                // `existingFieldNames.indexOf(fieldName) < 0` guard (`SchemaController.js:1029`),
                // so a field that already exists is not re-validated here. It is validated at the
                // point of the write instead, by `enforceFieldExists`' own `defaultValue` check,
                // which is a strictly narrower rule: no `required` check and no Relation
                // applicability check. See [`check_default_value_type`].
                let is_new = existing.field(name).is_none();
                if is_new {
                    check_new_field(class_name, name, field_type, field_options)?;
                }
                merged.fields.insert(name.clone(), field_type.clone());
                set_fields.push(SetField {
                    name: name.clone(),
                    field_type: field_type.clone(),
                    options: field_options.clone(),
                    is_new,
                });
            }
        }
    }

    check_one_geopoint(&merged)?;

    let clp = match clp {
        Some(raw) => Some(validate_clp(raw, &merged, opts)?),
        None => None,
    };

    // `deleteFields`' own name checks (`:1236-1244`), and they go last on purpose rather than in
    // the loop above. Upstream reaches them only after `validateSchemaData` has run
    // (`:899-923`), so a body that both deletes a default column and carries a broken CLP reports
    // the CLP. Checking earlier would report the field instead, which is a different string for
    // the same request.
    for name in &deleted {
        if !field_name_is_valid(name, class_name) {
            return Err(ParseError::invalid_key_name(format!(
                "invalid field name: {name}"
            )));
        }
        if !field_name_is_valid_for_class(name, class_name) {
            return Err(ParseError::new(
                FIELD_CANNOT_BE_ADDED_CODE,
                format!("field {name} cannot be changed"),
            ));
        }
    }

    Ok(SchemaMutation {
        set_fields,
        deleted,
        clp,
    })
}

/// Decode a `fields` object into per-field changes.
///
/// Every value must be an object. `{"__op":"Delete"}` is a delete; anything else is a type
/// specification.
pub fn parse_fields(fields: &ParseMap) -> Result<IndexMap<String, FieldChange>, ParseError> {
    let mut out = IndexMap::new();
    for (name, spec) in fields {
        let ParseValue::Object(spec) = spec else {
            return Err(ParseError::invalid_json("invalid JSON".to_string()));
        };
        if matches!(spec.get("__op"), Some(ParseValue::String(op)) if op == "Delete") {
            out.insert(name.clone(), FieldChange::Delete);
            continue;
        }
        let field_type = parse_field_type(spec)?;
        let options: ParseMap = spec
            .iter()
            .filter(|(k, _)| k.as_str() != "type" && k.as_str() != "targetClass")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        out.insert(
            name.clone(),
            FieldChange::Set {
                field_type,
                options,
            },
        );
    }
    Ok(out)
}

/// `fieldTypeIsInvalid` (`SchemaController.js:505-524`), inverted into a parse.
///
/// Order is upstream's and it is observable. `Pointer` and `Relation` are checked first, so a
/// `Pointer` with no `targetClass` reports the missing class name rather than anything about the
/// type. Only then is a non-string `type` `invalid JSON`, and only then is an unrecognised one
/// `invalid field type: <type>`.
///
/// `ACL` is a pseudo-type. `convertSchemaToAdapterSchema` deletes the `ACL` field before the
/// schema is stored and `convertAdapterSchemaToParseSchema` puts it back on read
/// (`:526-538`, `:540-557`), so it is accepted on the wire and never written.
pub fn parse_field_type(spec: &ParseMap) -> Result<FieldType, ParseError> {
    let type_name = match spec.get("type") {
        Some(ParseValue::String(s)) => Some(s.as_str()),
        _ => None,
    };

    if matches!(type_name, Some("Pointer") | Some("Relation")) {
        let name = type_name.unwrap_or_default();
        let target = match spec.get("targetClass") {
            // `!targetClass` is falsy, so an empty string is a missing class name too.
            Some(ParseValue::String(t)) if !t.is_empty() => t.clone(),
            Some(ParseValue::String(_)) | None | Some(ParseValue::Null) => {
                return Err(ParseError::new(
                    NEEDS_CLASS_NAME_CODE,
                    format!("type {name} needs a class name"),
                ))
            }
            // `typeof targetClass !== 'string'`. A number or an object is `invalid JSON`, not a
            // missing class name, and the two carry different codes.
            Some(other) if is_falsy_non_string(other) => {
                return Err(ParseError::new(
                    NEEDS_CLASS_NAME_CODE,
                    format!("type {name} needs a class name"),
                ))
            }
            Some(_) => return Err(ParseError::invalid_json("invalid JSON".to_string())),
        };
        if !class_name_is_valid(&target) {
            return Err(ParseError::new(
                ErrorCode::InvalidClassName,
                invalid_class_name_message(&target),
            ));
        }
        return Ok(if name == "Pointer" {
            FieldType::Pointer {
                target_class: target,
            }
        } else {
            FieldType::Relation {
                target_class: target,
            }
        });
    }

    let Some(type_name) = type_name else {
        return Err(ParseError::invalid_json("invalid JSON".to_string()));
    };

    Ok(match type_name {
        "Number" => FieldType::Number,
        "String" => FieldType::String,
        "Boolean" => FieldType::Boolean,
        "Date" => FieldType::Date,
        "Object" => FieldType::Object,
        "Array" => FieldType::Array,
        "GeoPoint" => FieldType::GeoPoint,
        "File" => FieldType::File,
        "Bytes" => FieldType::Bytes,
        "Polygon" => FieldType::Polygon,
        // **`ACL` is deliberately absent, because it is absent from `validNonRelationOrPointerTypes`
        // upstream** (`SchemaController.js:492-502`), so `{"type": "ACL"}` falls through to
        // `INCORRECT_TYPE` `invalid field type: ACL` there (`:520-522`). Accepting it here answered
        // 200 for a field that never came into existence: `field_type_to_storage` renders
        // `FieldType::Acl` as the empty string, so nothing reached `_SCHEMA` and the next
        // `GET /schemas` did not list it. The variant still exists for the *column* named `ACL`,
        // which every class has; what does not exist is a client's ability to ask for the type by
        // name.
        other => {
            return Err(ParseError::incorrect_type(format!(
                "invalid field type: {other}"
            )))
        }
    })
}

/// Everything `validateSchemaData` checks about one *new* field (`:1029-1071`).
fn check_new_field(
    class_name: &str,
    field_name: &str,
    field_type: &FieldType,
    options: &ParseMap,
) -> Result<(), ParseError> {
    // Note the lowercase and the absent trailing period. `enforceFieldExists` raises
    // `Invalid field name: <name>.` for the same condition on the write path (`:1137`), and the
    // two strings are different on purpose because both are asserted upstream.
    if !field_name_is_valid(field_name, class_name) {
        return Err(ParseError::invalid_key_name(format!(
            "invalid field name: {field_name}"
        )));
    }
    if !field_name_is_valid_for_class(field_name, class_name) {
        return Err(ParseError::new(
            FIELD_CANNOT_BE_ADDED_CODE,
            format!("field {field_name} cannot be added"),
        ));
    }
    check_field_options(class_name, field_name, field_type, options)
}

/// `defaultValue` and `required` (`SchemaController.js:1045-1070`).
///
/// `else if`, not two independent checks: a field carrying both only has its `defaultValue`
/// validated, so `{"type":"Relation","targetClass":"X","required":true,"defaultValue":1}` reports
/// the default-value mismatch and never mentions `required`.
fn check_field_options(
    class_name: &str,
    field_name: &str,
    field_type: &FieldType,
    options: &ParseMap,
) -> Result<(), ParseError> {
    if let Some(default_value) = options.get("defaultValue") {
        let inferred = infer_undecoded_type(class_name, field_name, default_value)?;
        // Upstream's guard is `typeof defaultValueType === 'object'`, which is true for exactly
        // the parametric types, the ones `getType` returns an object for.
        if field_type.is_relation() && inferred.as_ref().is_some_and(Inferred::is_parametric) {
            return Err(ParseError::incorrect_type(format!(
                "The 'default value' option is not applicable for {}",
                field_type.to_wire_string()
            )));
        }
        return check_default_value_type(class_name, field_name, field_type, options);
    } else if matches!(options.get("required"), Some(ParseValue::Bool(true)))
        && field_type.is_relation()
    {
        return Err(ParseError::incorrect_type(format!(
            "The 'required' option is not applicable for {}",
            field_type.to_wire_string()
        )));
    }
    Ok(())
}

/// A `targetClass` read off an undecoded value.
///
/// Two cases because upstream's comparison is strict and its rendering is not. Collapsing them into
/// a `String` makes a boolean `true` compare equal to the declared string `"true"`.
#[derive(Debug)]
enum TargetClass {
    Comparable(String),
    NeverEqual(String),
}

/// A type read off an undecoded value, and whether it can compare equal to a declared one.
#[derive(Debug, PartialEq, Eq)]
enum Inferred {
    Type(FieldType),
    /// A parametric type whose `className` was truthy but not a string. `dbTypeMatchesObjectType`
    /// compares `targetClass` with `!==`, so this matches nothing; the string is only for the
    /// mismatch message.
    NeverEqual {
        rendered: String,
    },
}

impl Inferred {
    /// `typeof defaultValueType === 'object'`, which `getObjectType` returns for exactly the two
    /// parametric types. True whatever the `className` turned out to be, because upstream builds
    /// the object before anything compares it.
    fn is_parametric(&self) -> bool {
        match self {
            Inferred::Type(t) => t.target_class().is_some(),
            Inferred::NeverEqual { .. } => true,
        }
    }
}

/// The type of a value that has **not** been through the `__type` decoder.
///
/// `getObjectType` (`SchemaController.js`), which is where upstream reads a `defaultValue`'s type,
/// and it is a **validator as well as a classifier**: every recognized tag is guarded on the key
/// that carries its payload, and anything that falls through, a guard that fails or a tag nobody
/// recognizes, throws `INCORRECT_TYPE` `This is not a valid <tag>`.
///
/// **Both halves are load-bearing here and one of them was a regression.** A schema body is decoded
/// raw so it can be stored as sent, which means the ordinary decoder no longer rejects a malformed
/// envelope on the way in. Reading the tag without re-checking the payload therefore accepted
/// `{"__type": "Date"}` with no `iso`, and accepted an unknown tag as an ordinary object: schema
/// metadata a parse-server node refuses to create, written into a database it shares.
fn infer_undecoded_type(
    class_name: &str,
    field_name: &str,
    value: &ParseValue,
) -> Result<Option<Inferred>, ParseError> {
    let ParseValue::Object(map) = value else {
        return Ok(infer_type(value).map(Inferred::Type));
    };
    // **`if (obj.__type)` is a truthiness test.** Not a presence test and not a type test, and it
    // was read as both. `__type: ""` is falsy, so upstream ignores it and carries on to infer an
    // ordinary `Object`; reading it as presence made that a thrown `This is not a valid `. A truthy
    // non-string like `__type: 7` is the mirror: the `switch` compares against string literals, so
    // it matches no case and falls to the throw, where reading it as a type test let it through as
    // an `Object`.
    let Some(tag_value) = map.get("__type").filter(|v| js_number::is_truthy(v)) else {
        return Ok(infer_type(value).map(Inferred::Type));
    };
    // `'This is not a valid ' + obj.__type` is string concatenation, so the tag is rendered the way
    // JavaScript renders it rather than quoted or debug-printed.
    let tag = js_number::to_ecma_display(tag_value);

    // **Truthiness again, and it is not uniform.** Six of the seven guards are `if (obj.key)`, so
    // an empty string, a zero and a `false` all fail them. `GeoPoint` alone is
    // `obj.latitude != null && obj.longitude != null`, a loose null check, so a latitude of `0`
    // passes there and a name of `""` does not pass anywhere else. Collapsing the two into one
    // predicate is wrong in one direction or the other whichever one you pick.
    let truthy = |key: &str| map.get(key).is_some_and(js_number::is_truthy);
    let not_null = |key: &str| matches!(map.get(key), Some(v) if !matches!(v, ParseValue::Null));
    // **`targetClass: obj.className` keeps the value, and the comparison against it is strict.**
    // `dbTypeMatchesObjectType` is `dbType.targetClass !== objectType.targetClass`
    // (`SchemaController.js:689-695`), so a `className` of boolean `true` never equals a declared
    // `targetClass` of the string `"true"`. Coercing it to a string here made those two match and
    // let the default through: 200 where upstream answers 111, and the accepted metadata is then
    // applied to creates by any parse-server node sharing the database.
    //
    // So the coercion belongs to the message alone, which is `typeToString` and *is* string
    // interpolation (`:701-703`, `Pointer<${targetClass}>`).
    let target = |key: &str| match map.get(key) {
        Some(v) if js_number::is_truthy(v) => Some(match v {
            ParseValue::String(s) => TargetClass::Comparable(s.clone()),
            other => TargetClass::NeverEqual(js_number::to_ecma_display(other)),
        }),
        _ => None,
    };

    // Each arm is upstream's guard, and the key it names is upstream's key. A tag that is truthy
    // but not one of these seven strings matches no case, which is the same fall-through a failed
    // guard takes.
    let parametric = |tag: &str, target: Option<TargetClass>| {
        target.map(|t| match t {
            TargetClass::Comparable(target_class) => Inferred::Type(match tag {
                "Pointer" => FieldType::Pointer { target_class },
                _ => FieldType::Relation { target_class },
            }),
            TargetClass::NeverEqual(rendered) => Inferred::NeverEqual {
                rendered: format!("{tag}<{rendered}>"),
            },
        })
    };
    let inferred = match tag_value {
        ParseValue::String(t) => match t.as_str() {
            "Pointer" => parametric("Pointer", target("className")),
            "Relation" => parametric("Relation", target("className")),
            "File" => truthy("name").then_some(Inferred::Type(FieldType::File)),
            "Date" => truthy("iso").then_some(Inferred::Type(FieldType::Date)),
            "GeoPoint" => (not_null("latitude") && not_null("longitude"))
                .then_some(Inferred::Type(FieldType::GeoPoint)),
            "Bytes" => truthy("base64").then_some(Inferred::Type(FieldType::Bytes)),
            // An empty array is truthy in JavaScript, so `coordinates: []` is a Polygon here.
            "Polygon" => truthy("coordinates").then_some(Inferred::Type(FieldType::Polygon)),
            _ => None,
        },
        _ => None,
    };

    match inferred {
        Some(inferred) => Ok(Some(inferred)),
        // The single throw every failed guard and every unknown tag falls to. The message names the
        // tag the client sent, including one nobody recognizes.
        None => {
            let _ = (class_name, field_name);
            Err(ParseError::incorrect_type(format!(
                "This is not a valid {tag}"
            )))
        }
    }
}

/// The `defaultValue` type check **as `enforceFieldExists` runs it**
/// (`SchemaController.js:1145-1162`), which is the only option validation an already-existing
/// field gets.
///
/// Deliberately narrower than `check_field_options`. `validateSchemaData`'s Relation
/// applicability branches and its `required` check are behind the `existingFieldNames` guard
/// (`:1029`) and never see a field that is already stored, so an existing `Relation` field can be
/// resubmitted with `required: true` and upstream accepts it. This function reproduces only what
/// upstream actually applies there.
pub fn check_default_value_type(
    class_name: &str,
    field_name: &str,
    field_type: &FieldType,
    options: &ParseMap,
) -> Result<(), ParseError> {
    let Some(default_value) = options.get("defaultValue") else {
        return Ok(());
    };
    {
        let inferred = infer_undecoded_type(class_name, field_name, default_value)?;
        // A `null` default has no type and therefore never matches. That is upstream's behavior:
        // `getType(null)` is `undefined`, `typeToString(undefined)` throws, and the request 500s.
        // Reported as a mismatch here instead, with `undefined` as the rendering, because a crash
        // is not a wire behavior worth reproducing.
        let (matches, got) = match &inferred {
            Some(Inferred::Type(t)) => (t == field_type, t.to_wire_string()),
            // A truthy non-string `className`. Never equal under upstream's strict `!==`, and
            // rendered by interpolation for the message.
            Some(Inferred::NeverEqual { rendered }) => (false, rendered.clone()),
            None => (false, "undefined".to_string()),
        };
        if !matches {
            return Err(ParseError::incorrect_type(format!(
                "schema mismatch for {class_name}.{field_name} default value; expected {} but got \
                 {got}",
                field_type.to_wire_string()
            )));
        }
    }
    Ok(())
}

/// At most one GeoPoint per class (`SchemaController.js:1078-1091`).
///
/// The message names the second field and then the first, in the order the merged field table
/// enumerates them, which is why the field table has to be order-preserving.
///
/// There is a **second** one-GeoPoint check on the object-write path, `validateObject` at
/// `:1286-1303`, and it raises a completely different string: `there can only be one geopoint
/// field in a class`, with no field names. A client that matches on one will not match the other.
fn check_one_geopoint(schema: &ClassSchema) -> Result<(), ParseError> {
    let mut geo = schema
        .fields
        .iter()
        .filter(|(_, ty)| **ty == FieldType::GeoPoint)
        .map(|(name, _)| name.as_str());
    let (Some(first), Some(second)) = (geo.next(), geo.next()) else {
        return Ok(());
    };
    Err(ParseError::incorrect_type(format!(
        "currently, only one GeoPoint field may exist in an object. Adding {second} when {first} \
         already exists."
    )))
}

/// Would JavaScript's `!x` be true for this non-string value?
///
/// `fieldTypeIsInvalid` tests `!targetClass` before it tests `typeof targetClass !== 'string'`,
/// so `0` and `false` reach the missing-class-name branch while `1` and `{}` reach the
/// `invalid JSON` one.
fn is_falsy_non_string(value: &ParseValue) -> bool {
    match value {
        ParseValue::Null => true,
        ParseValue::Bool(b) => !*b,
        ParseValue::Number(n) => *n == 0.0 || n.is_nan(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clp_validate::{ObjectIdForm, Unenforceable};
    use parse_rust_core::classify;

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

    fn spec(json: &str) -> FieldType {
        parse_field_type(&map(json)).expect("valid type")
    }

    fn spec_err(json: &str) -> ParseError {
        parse_field_type(&map(json)).expect_err("invalid type")
    }

    /// `getObjectType`'s guards are **JavaScript truthiness**, and reading them as Rust presence
    /// gets three separate things wrong.
    ///
    /// A schema body is decoded raw so it can be stored as sent, so this function is the only thing
    /// standing between a client and `_SCHEMA` metadata that a parse-server node sharing the
    /// database would refuse to create. Every row below is a quotation from `SchemaController.js`:
    /// `if (obj.__type)`, `if (obj.iso)`, `if (obj.className)`, and for GeoPoint alone
    /// `if (obj.latitude != null && obj.longitude != null)`.
    #[test]
    fn undecoded_type_inference_follows_javascript_truthiness() {
        let raw = |json: &str| {
            parse_rust_core::classify_raw(
                serde_json::from_str(json).expect("test literal must be valid JSON"),
            )
            .expect("raw decode")
        };
        let infer = |json: &str| infer_undecoded_type("C", "f", &raw(json));

        // An empty payload is falsy, so the guard fails and the tag falls to the throw. Presence
        // accepted every one of these.
        for (json, tag) in [
            (r#"{"__type":"Date","iso":""}"#, "Date"),
            (r#"{"__type":"Bytes","base64":""}"#, "Bytes"),
            (r#"{"__type":"File","name":""}"#, "File"),
            (r#"{"__type":"Pointer","className":""}"#, "Pointer"),
        ] {
            let err = infer(json).expect_err("a falsy payload fails the guard");
            assert_eq!(err.message, format!("This is not a valid {tag}"), "{json}");
        }

        // GeoPoint is the exception: `!= null` is a loose null check, so a zero coordinate passes
        // where a zero anywhere else would not. `0, 0` is a real place.
        assert_eq!(
            infer(r#"{"__type":"GeoPoint","latitude":0,"longitude":0}"#).expect("null island"),
            Some(Inferred::Type(FieldType::GeoPoint))
        );

        // An empty array is truthy in JavaScript, so this is a Polygon as far as the guard is
        // concerned. Whether the coordinates make a polygon is not asked here.
        assert_eq!(
            infer(r#"{"__type":"Polygon","coordinates":[]}"#).expect("truthy"),
            Some(Inferred::Type(FieldType::Polygon))
        );

        // `__type: ""` is falsy, so upstream never enters the switch and infers an ordinary object.
        // Treating the key as present threw instead, refusing a body upstream stores.
        assert_eq!(
            infer(r#"{"__type":"","a":1}"#).expect("a falsy tag is not a tag"),
            Some(Inferred::Type(FieldType::Object))
        );

        // A truthy non-string tag is the mirror case: the switch compares against string literals,
        // matches nothing, and falls to the throw. Requiring a string let these through as objects.
        // The message renders the tag by concatenation, not by quoting it.
        for (json, rendered) in [
            (r#"{"__type":7}"#, "7"),
            (r#"{"__type":true}"#, "true"),
            (r#"{"__type":{"a":1}}"#, "[object Object]"),
            (r#"{"__type":[1,2]}"#, "1,2"),
        ] {
            let err = infer(json).expect_err("a truthy tag that matches no case throws");
            assert_eq!(
                err.message,
                format!("This is not a valid {rendered}"),
                "{json}"
            );
        }

        // And the falsy non-string tags fall through rather than throwing.
        for json in [
            r#"{"__type":0}"#,
            r#"{"__type":false}"#,
            r#"{"__type":null}"#,
        ] {
            assert_eq!(
                infer(json).expect("falsy tags are not tags"),
                Some(Inferred::Type(FieldType::Object)),
                "{json}"
            );
        }
    }

    #[test]
    fn every_non_parametric_type_parses() {
        for (name, expected) in [
            ("Number", FieldType::Number),
            ("String", FieldType::String),
            ("Boolean", FieldType::Boolean),
            ("Date", FieldType::Date),
            ("Object", FieldType::Object),
            ("Array", FieldType::Array),
            ("GeoPoint", FieldType::GeoPoint),
            ("File", FieldType::File),
            ("Bytes", FieldType::Bytes),
            ("Polygon", FieldType::Polygon),
        ] {
            assert_eq!(spec(&format!(r#"{{"type":"{name}"}}"#)), expected);
        }
    }

    #[test]
    fn acl_is_a_column_every_class_has_and_a_type_no_client_may_name() {
        // Upstream's split, and the reason accepting it was wrong: the request answered 200 for a
        // field that never came into existence, because the renderer emits nothing for it.
        let err = parse_fields(&map(r#"{"acl":{"type":"ACL"}}"#)).expect_err("ACL is not a type");
        assert_eq!(err.code, parse_rust_core::ErrorCode::IncorrectType);
        assert_eq!(err.message, "invalid field type: ACL");
        // The renderer still has to answer for the variant, because the column exists.
        assert!(crate::storage_format::field_type_to_storage(&FieldType::Acl).is_empty());
    }

    #[test]
    fn an_unrecognised_type_names_itself() {
        let e = spec_err(r#"{"type":"Vector"}"#);
        assert_eq!(e.message, "invalid field type: Vector");
        assert_eq!(e.code, ErrorCode::IncorrectType);
    }

    #[test]
    fn parametric_types_need_a_target_class() {
        for name in ["Pointer", "Relation"] {
            let e = spec_err(&format!(r#"{{"type":"{name}"}}"#));
            assert_eq!(e.message, format!("type {name} needs a class name"));
            // An empty string is falsy, so it is a missing class name and not an invalid one.
            let e = spec_err(&format!(r#"{{"type":"{name}","targetClass":""}}"#));
            assert_eq!(e.message, format!("type {name} needs a class name"));
        }
        // A non-string, truthy targetClass is `invalid JSON` instead.
        let e = spec_err(r#"{"type":"Pointer","targetClass":7}"#);
        assert_eq!(e.message, "invalid JSON");
        assert_eq!(e.code, ErrorCode::InvalidJson);
        // And a syntactically invalid class name is a third error.
        let e = spec_err(r#"{"type":"Pointer","targetClass":"1Bad"}"#);
        assert_eq!(e.code, ErrorCode::InvalidClassName);
        assert!(e.message.starts_with("Invalid classname: 1Bad,"));
    }

    /// The trailing space is in the upstream literal and reaches the client.
    #[test]
    fn the_invalid_class_name_message_keeps_its_trailing_space() {
        let m = invalid_class_name_message("1Bad");
        assert_eq!(
            m,
            "Invalid classname: 1Bad, classnames can only have alphanumeric characters and _, and \
             must start with an alpha character "
        );
        assert!(m.ends_with(' '));
    }

    #[test]
    fn a_new_class_carries_its_default_columns() {
        let s = validate_new_class("Post", &map(r#"{"title":{"type":"String"}}"#), None, opts())
            .expect("valid");
        assert_eq!(s.field("title"), Some(&FieldType::String));
        for name in ["objectId", "createdAt", "updatedAt", "ACL"] {
            assert!(s.field(name).is_some(), "{name} missing");
        }
    }

    #[test]
    fn role_and_session_get_their_own_default_columns() {
        let role = validate_new_class("_Role", &ParseMap::new(), None, opts()).expect("valid");
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

        let session =
            validate_new_class("_Session", &ParseMap::new(), None, opts()).expect("valid");
        assert_eq!(
            session.field("user"),
            Some(&FieldType::Pointer {
                target_class: "_User".into()
            })
        );
        assert_eq!(session.field("sessionToken"), Some(&FieldType::String));
        assert_eq!(session.field("expiresAt"), Some(&FieldType::Date));
        assert_eq!(session.field("createdWith"), Some(&FieldType::Object));
        assert_eq!(session.field("installationId"), Some(&FieldType::String));
    }

    #[test]
    fn a_default_column_cannot_be_redeclared() {
        let e = validate_new_class(
            "Post",
            &map(r#"{"objectId":{"type":"String"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(e.message, "field objectId cannot be added");

        // And a class's own default column, which is what makes the second table load-bearing.
        let e = validate_new_class("_Role", &map(r#"{"name":{"type":"String"}}"#), None, opts())
            .expect_err("refused");
        assert_eq!(e.message, "field name cannot be added");
    }

    #[test]
    fn a_malformed_field_name_uses_the_lowercase_message() {
        let e = validate_new_class("Post", &map(r#"{"1bad":{"type":"String"}}"#), None, opts())
            .expect_err("refused");
        assert_eq!(e.message, "invalid field name: 1bad");
        assert_eq!(e.code, ErrorCode::InvalidKeyName);
        // `length` is banned by `invalidColumns` rather than by the regex.
        let e = validate_new_class(
            "Post",
            &map(r#"{"length":{"type":"String"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(e.message, "invalid field name: length");
    }

    #[test]
    fn at_most_one_geopoint_per_class() {
        let e = validate_new_class(
            "Post",
            &map(r#"{"here":{"type":"GeoPoint"},"there":{"type":"GeoPoint"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "currently, only one GeoPoint field may exist in an object. Adding there when here \
             already exists."
        );
        assert_eq!(e.code, ErrorCode::IncorrectType);
        // One is fine.
        assert!(validate_new_class(
            "Post",
            &map(r#"{"here":{"type":"GeoPoint"}}"#),
            None,
            opts()
        )
        .is_ok());
    }

    #[test]
    fn default_value_must_match_the_declared_type() {
        let e = validate_new_class(
            "Post",
            &map(r#"{"views":{"type":"Number","defaultValue":"none"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "schema mismatch for Post.views default value; expected Number but got String"
        );

        let s = validate_new_class(
            "Post",
            &map(r#"{"views":{"type":"Number","defaultValue":0}}"#),
            None,
            opts(),
        )
        .expect("valid");
        // Stored, not enforced, as 0.2.0 shipped it.
        let stored = s.field_options.expect("options stored");
        assert!(stored.contains_key("views"));
    }

    #[test]
    fn required_and_default_value_are_not_applicable_to_a_relation() {
        let e = validate_new_class(
            "Post",
            &map(r#"{"tags":{"type":"Relation","targetClass":"Tag","required":true}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "The 'required' option is not applicable for Relation<Tag>"
        );

        let e = validate_new_class(
            "Post",
            &map(r#"{"tags":{"type":"Relation","targetClass":"Tag",
                    "defaultValue":{"__type":"Pointer","className":"Tag","objectId":"a"}}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "The 'default value' option is not applicable for Relation<Tag>"
        );
    }

    /// `type` and `targetClass` come off; everything else is stored verbatim, including keys
    /// parse-rust does not model. Dropping one would relax a constraint a parse-server node
    /// reading the same database still enforces.
    #[test]
    fn field_options_round_trip_every_key_but_type_and_target_class() {
        let s = validate_new_class(
            "Post",
            &map(r#"{"author":{"type":"Pointer","targetClass":"_User",
                    "required":true,"somethingNew":42}}"#),
            None,
            opts(),
        )
        .expect("valid");
        let stored = s.field_options.expect("options stored");
        let ParseValue::Object(author) = stored.get("author").expect("author") else {
            panic!("expected an object");
        };
        assert_eq!(author.len(), 2);
        assert!(author.contains_key("required"));
        assert!(author.contains_key("somethingNew"));
        assert!(!author.contains_key("type"));
        assert!(!author.contains_key("targetClass"));
    }

    fn post() -> ClassSchema {
        crate::controller::default_schema("Post")
            .with_field("title", FieldType::String)
            .with_field(
                "tags",
                FieldType::Relation {
                    target_class: "Tag".into(),
                },
            )
    }

    #[test]
    fn an_update_plans_adds_and_deletes() {
        let plan = plan_update(
            &post(),
            &map(r#"{"body":{"type":"String"},"tags":{"__op":"Delete"}}"#),
            None,
            opts(),
        )
        .expect("valid");
        assert!(matches!(plan.set_fields.as_slice(), [f] if f.name == "body"
                && f.field_type == FieldType::String
                && f.is_new));
        assert_eq!(plan.deleted, vec!["tags".to_string()]);
        assert!(
            plan.clp.is_none(),
            "an absent CLP must not become an empty one"
        );
    }

    #[test]
    fn retyping_an_existing_field_is_refused_and_nothing_else_in_the_body_applies() {
        let e = plan_update(
            &post(),
            &map(r#"{"body":{"type":"String"},"title":{"type":"Number"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(e.message, "Field title exists, cannot update.");
        assert_eq!(e.code, ErrorCode::InvalidSchemaOperation);
        assert_eq!(e.code.as_i32(), 255);
    }

    #[test]
    fn deleting_a_field_that_does_not_exist_is_refused() {
        let e = plan_update(
            &post(),
            &map(r#"{"ghost":{"__op":"Delete"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(e.message, "Field ghost does not exist, cannot delete.");
        assert_eq!(e.code.as_i32(), 255);
    }

    #[test]
    fn deleting_a_default_column_has_its_own_message() {
        let e = plan_update(
            &post(),
            &map(r#"{"objectId":{"__op":"Delete"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(e.message, "field objectId cannot be changed");
        // Note "changed", not "added". The schema API uses both strings for the same predicate,
        // one on delete and one on add, and a client matching the wrong one matches nothing.
        let e = validate_new_class(
            "Post",
            &map(r#"{"objectId":{"type":"String"}}"#),
            None,
            opts(),
        )
        .expect_err("refused");
        assert_eq!(e.message, "field objectId cannot be added");
    }

    /// Upstream reaches `deleteFields` only after `validateSchemaData`, so a body that is wrong
    /// in both ways reports the CLP. Ordering is wire-visible whenever two checks can both fire.
    #[test]
    fn the_clp_is_validated_before_the_delete_name_check() {
        let e = plan_update(
            &post(),
            &map(r#"{"objectId":{"__op":"Delete"}}"#),
            Some(map(r#"{"nope":{}}"#)),
            opts(),
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "nope is not a valid operation for class level permissions"
        );
    }

    /// Type identity is `(type, targetClass)`, so resubmitting a field with new options is an
    /// options update and not a conflict.
    #[test]
    fn resubmitting_a_field_with_different_options_is_not_a_conflict() {
        let plan = plan_update(
            &post(),
            &map(r#"{"title":{"type":"String","required":true}}"#),
            None,
            opts(),
        )
        .expect("valid");
        assert!(
            matches!(plan.set_fields.as_slice(), [f] if f.name == "title"
                && !f.is_new
                && f.options.contains_key("required")),
            "an existing field is still submitted, so its options can be written"
        );
    }

    /// Resubmitting a field **without** the options it was stored with clears them, and the plan
    /// has to carry the empty set for the route to be able to write it. Recording only non-empty
    /// options made this a silent no-op, so a `required` field could never be made optional again.
    #[test]
    fn resubmitting_a_field_with_no_options_carries_an_empty_option_set() {
        let plan = plan_update(
            &post(),
            &map(r#"{"title":{"type":"String"}}"#),
            None,
            opts(),
        )
        .expect("valid");
        assert!(
            matches!(plan.set_fields.as_slice(), [f] if f.name == "title"
                && !f.is_new
                && f.options.is_empty())
        );
    }

    /// The one option rule that reaches an already-stored field. `validateSchemaData`'s checks are
    /// behind its `existingFieldNames` guard, but `enforceFieldExists` runs the `defaultValue`
    /// type check on every submitted field.
    #[test]
    fn an_existing_fields_default_value_is_still_type_checked() {
        let e = check_default_value_type(
            "Post",
            "title",
            &FieldType::String,
            &map(r#"{"defaultValue":10}"#),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::IncorrectType);
        assert_eq!(
            e.message,
            "schema mismatch for Post.title default value; expected String but got Number"
        );
        assert!(check_default_value_type(
            "Post",
            "title",
            &FieldType::String,
            &map(r#"{"defaultValue":"ok","required":true}"#)
        )
        .is_ok());
    }

    /// The CLP is validated against the *merged* fields, so a field being added in the same body
    /// can be protected by it and a field being deleted cannot.
    #[test]
    fn the_clp_is_validated_against_the_merged_schema() {
        let plan = plan_update(
            &post(),
            &map(r#"{"secret":{"type":"String"}}"#),
            Some(map(r#"{"protectedFields":{"*":["secret"]}}"#)),
            opts(),
        )
        .expect("valid");
        assert!(plan.clp.is_some());

        let e = plan_update(
            &post(),
            &map(r#"{"title":{"__op":"Delete"}}"#),
            Some(map(r#"{"protectedFields":{"*":["title"]}}"#)),
            opts(),
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "Field 'title' in protectedFields:* does not exist"
        );
    }

    #[test]
    fn an_empty_clp_block_is_not_an_absent_one() {
        let plan =
            plan_update(&post(), &ParseMap::new(), Some(ParseMap::new()), opts()).expect("valid");
        let clp = plan.clp.expect("present");
        assert!(clp.raw().is_empty());
        assert!(plan_update(&post(), &ParseMap::new(), None, opts())
            .expect("valid")
            .clp
            .is_none());
    }

    #[test]
    fn a_field_spec_that_is_not_an_object_is_invalid_json() {
        let e = validate_new_class("Post", &map(r#"{"title":"String"}"#), None, opts())
            .expect_err("refused");
        assert_eq!(e.message, "invalid JSON");
    }

    /// The two lists are different and neither contains the other. Conflating them is what makes
    /// `_Hooks` addressable through `/classes`.
    #[test]
    fn system_and_volatile_classes_are_two_different_lists() {
        use crate::infer::{SYSTEM_CLASSES, VOLATILE_CLASSES};
        for name in ["_Hooks", "_GlobalConfig", "_GraphQLConfig"] {
            assert!(VOLATILE_CLASSES.contains(&name), "{name} is volatile");
            assert!(
                !SYSTEM_CLASSES.contains(&name),
                "{name} is not a system class"
            );
            assert!(!class_name_is_valid(name), "{name} must not be addressable");
        }
        for name in ["_User", "_Installation", "_Role", "_Session", "_Product"] {
            assert!(SYSTEM_CLASSES.contains(&name));
            assert!(!VOLATILE_CLASSES.contains(&name));
        }
        for name in [
            "_JobStatus",
            "_PushStatus",
            "_JobSchedule",
            "_Audience",
            "_Idempotency",
        ] {
            assert!(SYSTEM_CLASSES.contains(&name), "{name} is a system class");
            assert!(VOLATILE_CLASSES.contains(&name), "{name} is volatile");
        }
    }
}
