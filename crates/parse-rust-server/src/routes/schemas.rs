//! `/schemas` and `DELETE /purge/:className`. Master key only, on every verb.
//!
//! Upstream: `src/Routers/SchemasRouter.js`. Every route here is wrapped in
//! `promiseEnforceMasterKeyAccess` (`SchemasRouter.js:130-158`), which is the same gate
//! `/serverInfo` uses and which **maintenance does not satisfy**.
//!
//! **These handlers read `_SCHEMA` afresh rather than using the request snapshot.** Upstream does
//! the same, `loadSchema({clearCache: true})` then `getAllClasses({clearCache: true})`
//! (`SchemasRouter.js:18-28`), and here it also keeps the server-level `protectedFields` option
//! out of what a client reads back: the snapshot has that option folded into its CLP blocks, and
//! rendering it would turn a configuration value into a database value on the next write-back.

use parse_rust_core::{ClassLevelPermissions, ErrorCode, ParseError, ParseMap, ParseValue};
use parse_rust_schema::{plan_update, validate_new_class};
use parse_rust_storage::{AddFieldOutcome, ClassSchema, FieldType, Query, StorageAdapter};
use serde_json::{json, Value as Json};

use crate::state::AppState;

/// `GET /schemas`. `{results: [...]}`.
pub async fn get_all(state: &AppState) -> Result<Json, ParseError> {
    let classes = state.storage().all_schemas().await?;
    Ok(json!({
        "results": classes.iter().map(render).collect::<Vec<_>>(),
    }))
}

/// `GET /schemas/:className`. The schema object itself, not wrapped.
///
/// A class that does not exist is `INVALID_CLASS_NAME` (103) `Class <X> does not exist.`, not a
/// 404 (`SchemasRouter.js:30-36`).
pub async fn get_one(state: &AppState, class_name: &str) -> Result<Json, ParseError> {
    let schema = load_one(state, class_name).await?;
    Ok(render(&schema))
}

/// `POST /schemas` and `POST /schemas/:className`.
pub async fn create(
    state: &AppState,
    path: &str,
    class_name: Option<&str>,
    body: &Json,
) -> Result<Json, ParseError> {
    let body = as_object(body)?;
    // A truthy non-string can never equal the path's name, so it is a mismatch wherever the path
    // supplies one, and a class name this server cannot use where it does not.
    let body_class = match class_name_field(&body) {
        ClassNameField::Absent => None,
        ClassNameField::Named(name) => Some(name),
        ClassNameField::Malformed(rendered) => {
            return Err(mismatch(&rendered, class_name.unwrap_or(path)))
        }
    };

    // The mismatch check runs before the missing-name check, and only when both are present
    // (`SchemasRouter.js:82-86`).
    if let (Some(path_class), Some(body_class)) = (class_name, body_class.as_deref()) {
        if path_class != body_class {
            return Err(mismatch(body_class, path_class));
        }
    }

    let Some(class_name) = class_name.or(body_class.as_deref()) else {
        // `throw new Parse.Error(135, ...)` (`SchemasRouter.js:90`). 135 is `MissingClassName`.
        return Err(ParseError::new(
            ErrorCode::MissingClassName,
            format!("POST {path} needs a class name."),
        ));
    };

    let fields = fields_block(&body, class_name)?;
    let clp = clp_block(&body, class_name)?;
    let mut schema = validate_new_class(class_name, &fields, clp, state.config().clp_validation())?;
    // Built before the schema row is written, and recorded from what was built
    // (`MongoStorageAdapter.js:449-452`). `createClass` passes no existing block, because there is
    // no class yet.
    schema.indexes = apply_indexes(
        state,
        class_name,
        index_block(&body, class_name)?.as_ref(),
        None,
        &schema,
        true,
    )
    .await?;

    // **An insert, and the already-exists answer comes from it** (`MongoSchemaCollection.js:183`,
    // reached through `createClass`). Reading the schema list first and then upserting is the
    // shape this had until a review, and it lets two concurrent creates for one class both pass
    // the read and both write, so both report success and the loser's fields and CLP replace the
    // winner's. Only the write is atomic, so only the write can answer the question.
    //
    // `insert_schema` writes `_metadata.class_permissions` only when `clp` is `Some`, which is
    // exactly the distinction that has to survive: an absent block and an empty one are two
    // different documents to a parse-server node reading the same database.
    //
    // The relabelling is upstream's too: the storage layer reports `DUPLICATE_VALUE`, and
    // `addClassIfNotExists` turns it into `INVALID_CLASS_NAME` (`SchemaController.js:861-864`).
    state.storage().insert_schema(&schema).await.map_err(|e| {
        if e.code == ErrorCode::DuplicateValue {
            ParseError::new(
                ErrorCode::InvalidClassName,
                format!("Class {class_name} already exists."),
            )
        } else {
            e
        }
    })?;
    Ok(render(&schema))
}

/// `PUT /schemas/:className`: field add, field delete, CLP replace.
pub async fn update(state: &AppState, class_name: &str, body: &Json) -> Result<Json, ParseError> {
    let body = as_object(body)?;
    match class_name_field(&body) {
        ClassNameField::Absent => {}
        ClassNameField::Named(body_class) if body_class == class_name => {}
        ClassNameField::Named(body_class) => return Err(mismatch(&body_class, class_name)),
        ClassNameField::Malformed(rendered) => return Err(mismatch(&rendered, class_name)),
    }

    let existing = load_one(state, class_name).await?;
    let fields = fields_block(&body, class_name)?;
    let clp = clp_block(&body, class_name)?;
    let mutation = plan_update(&existing, &fields, clp, state.config().clp_validation())?;

    // Deletions first, matching `updateClass`' order (`SchemaController.js:899-923`): a field
    // deleted and re-added in one request ends up added.
    if !mutation.deleted.is_empty() {
        state
            .storage()
            .delete_fields(&existing, &mutation.deleted)
            .await?;
    }

    // The merged view the index field check runs against, which is upstream's `fullNewSchema`
    // (`SchemaController.js:941-946`). It is a local value for validation only; nothing writes it.
    let mut merged = existing.clone();
    for name in &mutation.deleted {
        merged.fields.shift_remove(name.as_str());
    }
    for field in &mutation.set_fields {
        merged
            .fields
            .insert(field.name.clone(), field.field_type.clone());
    }

    // **Every write below is a delta, and nothing writes the whole schema.** Upstream's
    // `updateClass` touches exactly what the request named: `enforceFieldExists` per submitted
    // field (`SchemaController.js:930-934`), `setPermissions` only when a CLP block was sent
    // (`:1097-1099`), and `setIndexesWithSchemaFormat` only when an `indexes` block was
    // (`MongoStorageAdapter.js:353-355`).
    //
    // Sending a whole-schema upsert instead, which is what this did until a review, is not safe
    // even with the added fields excluded. Two interleavings it permits, both silent:
    //
    // - one request deletes field `old`, and a later request holding a stale snapshot `$set`s
    //   `old` back into `_SCHEMA` as part of writing something unrelated;
    // - two requests each add a different field with options, each reserves its own type, and
    //   then each replaces the whole `_metadata.fields_options` block, so the second erases the
    //   first field's options while leaving its type in place.
    for field in &mutation.set_fields {
        if field.is_new {
            // Type and options in one conditional update, because a field reserved without its
            // options is a field whose options a concurrent writer can still win.
            let options = (!field.options.is_empty()).then(|| field.options.clone());
            match state
                .storage()
                .reserve_field(class_name, &field.name, &field.field_type, options.as_ref())
                .await?
            {
                AddFieldOutcome::Added | AddFieldOutcome::AlreadyPresentSameType => {}
                AddFieldOutcome::Conflict { existing } => {
                    return Err(parse_rust_schema::infer::schema_mismatch(
                        class_name,
                        &field.name,
                        &existing,
                        &field.field_type,
                    ))
                }
            }
            continue;
        }

        // An already-stored field. `enforceFieldExists` still runs its own `defaultValue` type
        // check on it, which is the one option rule that reaches an existing field: everything
        // else in `validateSchemaData` sits behind the `existingFieldNames` guard.
        parse_rust_schema::check_default_value_type(
            class_name,
            &field.name,
            &field.field_type,
            &field.options,
        )?;

        // Then `updateFieldOptions`, unconditionally. Upstream skips it only when the stored spec
        // and the submitted one stringify identically, which key ordering makes rare, and the
        // write is idempotent either way. **The empty case is the point**: resubmitting
        // `{"type":"String"}` for a field stored as `{"type":"String","required":true}` writes an
        // empty options object, which is how a client clears options. Recording nothing, which is
        // what this did until a review, left the field required with no way to undo it.
        state
            .storage()
            .set_field_options(class_name, &field.name, &field.options)
            .await?;
    }

    // **CLP before indexes**, which is `updateClass`' order (`SchemaController.js:938-947`). It
    // decides what survives a half-failed request: an index on an unknown field is refused by both
    // servers, and upstream has already written the CLP by then. Writing indexes first would keep
    // the index and drop the permissions, which is the more dangerous half to lose.
    //
    // `None` on the mutation means the body carried no `classLevelPermissions` at all, which
    // leaves the stored block alone; an empty block replaces it.
    if let Some(clp) = mutation.clp.clone() {
        state
            .storage()
            .set_class_permissions(class_name, Some(&clp))
            .await?;
    }

    if let Some(recorded) = apply_indexes(
        state,
        class_name,
        index_block(&body, class_name)?.as_ref(),
        merged.indexes.as_ref(),
        &merged,
        false,
    )
    .await?
    {
        state.storage().set_indexes(class_name, &recorded).await?;
    }

    // **Rendered from a re-read, not from a reconstruction.** Upstream reloads and answers from the
    // reloaded schema (`SchemaController.js:948-962`), and the difference is observable: a
    // reservation that loses a race writes nothing, so a response assembled from the request would
    // report options the database does not have.
    let reloaded = load_one(state, class_name).await?;
    Ok(render(&reloaded))
}

/// `setIndexesWithSchemaFormat` (`MongoStorageAdapter.js:347-410`): build what was asked for, drop
/// what was marked deleted, and answer with the block to record.
///
/// **The order is the whole point.** Indexes are built first and `_metadata.indexes` is written
/// from the result, so a failed build leaves no claim behind. Storing the submitted block without
/// building anything, which is what 0.2.0 did until this review, produces a `_SCHEMA` row asserting
/// an index that does not exist; a parse-server node on the same database reads that row, concludes
/// the index is already there, and never creates it either. The class then runs unindexed forever
/// with both servers believing otherwise.
///
/// `None` means the request carried no `indexes` key at all, which changes nothing
/// (`MongoStorageAdapter.js:353-355`). That is not the same as an empty block.
async fn apply_indexes(
    state: &AppState,
    class_name: &str,
    submitted: Option<&ParseMap>,
    existing: Option<&ParseMap>,
    fields: &ClassSchema,
    is_create: bool,
) -> Result<Option<ParseMap>, ParseError> {
    let Some(submitted) = submitted else {
        return Ok(None);
    };

    // The `_id_` seeding is upstream's and it is wire-visible: a class whose index request arrives
    // with no recorded block reads back afterwards with `_id_` listed beside whatever was added
    // (`MongoStorageAdapter.js:356-358`).
    //
    // **It does not happen on create, and the reason is an ordering detail rather than a rule.**
    // `setIndexesWithSchemaFormat` runs *before* `insertSchema` there
    // (`MongoStorageAdapter.js:449-451`), and its trailing write is a plain `updateOne` with no
    // upsert (`MongoSchemaCollection.js:197-199`), so on a class that does not exist yet it matches
    // nothing and is a no-op. What lands is the insert of the submitted schema
    // (`MongoStorageAdapter.js:130-133`). Seeding here regardless put a phantom `_id_` into
    // `_metadata.indexes` on a database parse-server also reads, and
    // `spec/schemas.spec.js:3150-3184` asserts its absence on create against `:3248-3252` asserting
    // its presence on update.
    let mut recorded = match existing {
        Some(existing) if !existing.is_empty() => existing.clone(),
        _ if is_create => ParseMap::new(),
        _ => {
            let mut seed = ParseMap::new();
            let mut id = ParseMap::new();
            id.insert("_id".to_string(), ParseValue::Number(1.0));
            seed.insert("_id_".to_string(), ParseValue::Object(id));
            seed
        }
    };

    let mut to_build: Vec<parse_rust_storage::SchemaIndex> = Vec::new();
    let mut to_drop: Vec<String> = Vec::new();

    for (name, spec) in submitted {
        let is_delete = matches!(spec, ParseValue::Object(m)
            if matches!(m.get("__op"), Some(ParseValue::String(op)) if op == "Delete"));

        if recorded.contains_key(name.as_str()) && !is_delete {
            return Err(ParseError::invalid_query(format!(
                "Index {name} exists, cannot update."
            )));
        }
        if !recorded.contains_key(name.as_str()) && is_delete {
            return Err(ParseError::invalid_query(format!(
                "Index {name} does not exist, cannot delete."
            )));
        }
        if is_delete {
            to_drop.push(name.clone());
            recorded.shift_remove(name.as_str());
            continue;
        }

        let ParseValue::Object(keys) = spec else {
            return Err(ParseError::invalid_query(format!(
                "Index {name} is not an object."
            )));
        };
        let mut lowered = Vec::with_capacity(keys.len());
        for (key, direction) in keys {
            // `_p_`-prefixed keys name the storage column of a pointer field, so the check strips
            // the prefix before looking the field up (`MongoStorageAdapter.js:380-383`).
            let field = key.strip_prefix("_p_").unwrap_or(key);
            if fields.field(field).is_none()
                && !parse_rust_schema::infer::is_default_column(class_name, field)
            {
                return Err(ParseError::invalid_query(format!(
                    "Field {key} does not exist, cannot add index."
                )));
            }
            lowered.push((key.clone(), direction.clone()));
        }
        to_build.push(parse_rust_storage::SchemaIndex {
            name: name.clone(),
            keys: lowered,
        });
        recorded.insert(name.clone(), spec.clone());
    }

    for name in &to_drop {
        state.storage().drop_index(class_name, name).await?;
    }
    state
        .storage()
        .create_indexes(class_name, &to_build)
        .await?;
    Ok(Some(recorded))
}

/// `DELETE /schemas/:className`.
///
/// A non-empty class is code `255` `Class <X> is not empty, contains <N> objects, cannot drop
/// schema.` (`DatabaseController.js:1621-1626`). Count first, then drop.
pub async fn delete(state: &AppState, class_name: &str) -> Result<Json, ParseError> {
    if !parse_rust_schema::class_name_is_valid(class_name) {
        return Err(ParseError::new(
            ErrorCode::InvalidClassName,
            parse_rust_schema::infer::invalid_class_name_message(class_name),
        ));
    }
    // A class with no `_SCHEMA` row is not an error, and it is **not** a reason to stop either.
    // `getOneSchema` rejects with `undefined`, the caller substitutes `{fields: {}}`, and the count
    // and the drop then run against that (`DatabaseController.js:1603-1627`). The
    // `collectionExists` result is discarded by the `.then(() => ...)` that follows it, so nothing
    // upstream short-circuits on it.
    //
    // Returning `{}` here instead meant a collection whose schema row was missing could never be
    // dropped: the request answered 200 and did nothing, which is what a dashboard "delete class"
    // on such a class looked like. The substituted schema has no fields, which is exactly what
    // upstream counts and drops with.
    let schema = match find_schema(state, class_name).await? {
        Some(schema) => schema,
        None => ClassSchema::new(class_name),
    };
    let count = state.storage().count(&schema, &Query::new()).await?;
    if count > 0 {
        return Err(ParseError::new(
            ErrorCode::InvalidSchemaOperation,
            format!(
                "Class {class_name} is not empty, contains {count} objects, cannot drop schema."
            ),
        ));
    }
    state.storage().delete_class(&schema).await?;
    Ok(json!({}))
}

/// `DELETE /purge/:className`.
///
/// Deletes every row and keeps the class, its schema entry and its join tables
/// (`DatabaseController.js:461-465`, `PurgeRouter.js:19-23`).
///
/// Upstream additionally clears the user cache for `_Session` and the role cache for `_Role`
/// (`PurgeRouter.js:19-23`). parse-rust caches neither, so there is nothing to clear; stating that
/// here rather than leaving the missing branch to be read as an oversight.
pub async fn purge(state: &AppState, class_name: &str) -> Result<Json, ParseError> {
    let Some(schema) = find_schema(state, class_name).await? else {
        // `purgeCollection` rejects on an unknown class and the router swallows it as `{}`
        // (`PurgeRouter.js:26-30`).
        return Ok(json!({}));
    };
    state.storage().delete(&schema, &Query::new()).await?;
    Ok(json!({}))
}

// -------------------------------------------------------------------------------------------
// Rendering
// -------------------------------------------------------------------------------------------

/// The wire shape of a schema: `{className, fields, classLevelPermissions, indexes}`
/// (`MongoSchemaCollection.js:106-111`).
fn render(schema: &ClassSchema) -> Json {
    let mut fields = serde_json::Map::new();
    for (name, ty) in &schema.fields {
        let mut entry = serde_json::Map::new();
        entry.insert("type".to_string(), json!(ty.wire_type()));
        if let Some(target) = ty.target_class() {
            entry.insert("targetClass".to_string(), json!(target));
        }
        // `_metadata.fields_options` is merged onto the field entry, unknown keys included
        // (`MongoSchemaCollection.js:47-57`).
        if let Some(ParseValue::Object(options)) = schema
            .field_options
            .as_ref()
            .and_then(|o| o.get(name.as_str()))
        {
            if let Json::Object(rendered) = to_json(options) {
                for (key, value) in rendered {
                    entry.insert(key, value);
                }
            }
        }
        fields.insert(name.clone(), Json::Object(entry));
    }
    // `mongoSchemaFieldsToParseSchemaFields` appends these unconditionally (`:60-63`). A key that
    // is already present keeps its position, which is what an order-preserving map does too.
    for (name, ty) in [
        ("ACL", "ACL"),
        ("createdAt", "Date"),
        ("updatedAt", "Date"),
        ("objectId", "String"),
    ] {
        if !fields.contains_key(name) {
            fields.insert(name.to_string(), json!({ "type": ty }));
        }
    }

    // **`indexes` is omitted entirely when the class has none, rather than rendered as `{}`.**
    // All three of upstream's renderers guard the key the same way (`SchemaController.js:552-554`
    // for POST, `:628-630` for GET, `:958-960` for PUT), and `spec/schemas.spec.js:3200-3211`
    // compares the whole response object, so an extra key fails the assertion outright. A client
    // distinguishing "no indexes" from "indexes not reported" reads the key's presence.
    let mut body = json!({
        "className": schema.class_name,
        "fields": Json::Object(fields),
        "classLevelPermissions": render_clp(schema.clp.as_ref()),
    });
    if let Some(indexes) = schema.indexes.as_ref().filter(|i| !i.is_empty()) {
        if let Some(map) = body.as_object_mut() {
            map.insert("indexes".to_string(), to_json(indexes));
        }
    }
    body
}

/// The two different defaults, which is the rule that breaks a mixed fleet if it is normalized
/// away (`MongoSchemaCollection.js:67-112`).
///
/// A class whose `_metadata.class_permissions` is **absent** reads back as `defaultCLPS`, fully
/// public and carrying an `ACL` key. A class whose block is **present** reads back as that block
/// merged over `emptyCLPS`, which has no `ACL` key and whose unspecified operations are `{}`. The
/// Mongo adapter already does the present-case merge and keeps `clp` as `None` for absent, so all
/// that is left here is choosing which default to render.
fn render_clp(clp: Option<&ClassLevelPermissions>) -> Json {
    match clp {
        Some(clp) => to_json(clp.raw()),
        None => json!({
            "ACL": { "*": { "read": true, "write": true } },
            "find": { "*": true },
            "count": { "*": true },
            "get": { "*": true },
            "create": { "*": true },
            "update": { "*": true },
            "delete": { "*": true },
            "addField": { "*": true },
            "protectedFields": { "*": [] },
        }),
    }
}

fn to_json(map: &ParseMap) -> Json {
    serde_json::from_str(&ParseValue::Object(map.clone()).to_json()).unwrap_or(Json::Null)
}

// -------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------

async fn find_schema(
    state: &AppState,
    class_name: &str,
) -> Result<Option<ClassSchema>, ParseError> {
    Ok(state
        .storage()
        .all_schemas()
        .await?
        .into_iter()
        .find(|s| s.class_name == class_name))
}

async fn load_one(state: &AppState, class_name: &str) -> Result<ClassSchema, ParseError> {
    find_schema(state, class_name).await?.ok_or_else(|| {
        ParseError::new(
            ErrorCode::InvalidClassName,
            format!("Class {class_name} does not exist."),
        )
    })
}

fn mismatch(body_class: &str, path_class: &str) -> ParseError {
    ParseError::new(
        ErrorCode::InvalidClassName,
        format!("Class name mismatch between {body_class} and {path_class}."),
    )
}

/// Decode a schema body **without interpreting any `__type` envelope**.
///
/// Nothing in a schema body is a column value. `className`, `type` and `targetClass` are strings, a
/// CLP block is objects and booleans, an `indexes` block is numbers and strings, and a
/// `defaultValue` is an opaque value this server stores and never enforces. Running the ordinary
/// decoder over it re-rendered every envelope it recognized: an offset instant became UTC, unpadded
/// base64 was re-padded, and any key the envelope does not declare was dropped, because a decoded
/// `Date` has nowhere to keep it.
///
/// The loss is invisible from here, since parse-rust reads its own storage back the same way it
/// wrote it. It is visible to a parse-server node, which stores what it was sent and therefore
/// reads back something the client never wrote.
///
/// The one consumer that needs the meaning rather than the text is the `defaultValue` type check,
/// and it reads the tag itself; see `check_default_value_type`.
fn as_object(body: &Json) -> Result<ParseMap, ParseError> {
    match parse_rust_core::classify_raw(body.clone())? {
        ParseValue::Object(map) => Ok(map),
        _ => Err(ParseError::invalid_json("body must be an object")),
    }
}

/// The body's `className`: absent, a name, or malformed.
///
/// **A non-string must not read as absent, because absent means the path name wins.** Upstream's
/// check is truthiness plus `!==` (`SchemasRouter.js:82-86`), so every truthy non-string is a
/// mismatch: `PUT /schemas/Widget` carrying `"className": ["Gadget"]` answers 103. Reading it as
/// absent instead lets the request through as an ordinary update of `Widget`, so a body naming one
/// class silently edits another.
///
/// Falsy values are absent, which is upstream exactly. Measured against parse-server
/// 9.10.1-alpha.6: `"className": null` and `"className": ""` both answer 200 and act on the path's
/// class, while `["Gadget"]`, `7`, `true` and `{"a":1}` all answer 103.
enum ClassNameField {
    Absent,
    Named(String),
    /// Present, truthy, and not a string. Carries the JSON rendering for the message.
    Malformed(String),
}

fn class_name_field(body: &ParseMap) -> ClassNameField {
    match body.get("className") {
        None | Some(ParseValue::Null) | Some(ParseValue::Bool(false)) => ClassNameField::Absent,
        Some(ParseValue::Number(n)) if *n == 0.0 => ClassNameField::Absent,
        Some(ParseValue::String(s)) if s.is_empty() => ClassNameField::Absent,
        Some(ParseValue::String(s)) => ClassNameField::Named(s.clone()),
        Some(other) => ClassNameField::Malformed(render_as_js_string(other)),
    }
}

/// The value as JavaScript's string conversion would render it, which is what upstream
/// interpolates into the mismatch message.
///
/// Not a general `String()`: only the shapes a `className` can actually arrive as. A number goes
/// through the ECMAScript formatter this project already carries, an object is the famous
/// `[object Object]`, and an array is its elements joined by commas, which is why `["Gadget"]`
/// reports `Gadget` upstream rather than anything bracketed. Verified against parse-server
/// 9.10.1-alpha.6 for `["Gadget"]`, `7`, `true` and `{"a":1}`.
fn render_as_js_string(value: &ParseValue) -> String {
    match value {
        ParseValue::String(s) => s.clone(),
        ParseValue::Number(n) => parse_rust_core::js_number::to_ecma_string(*n),
        ParseValue::Bool(b) => b.to_string(),
        // `String(null)` is `"null"`, but `Array.prototype.join` renders a null *element* as the
        // empty string, so `[null]` is `""` and not `"null"`. Two different rules for the same
        // value depending on where it sits, which is why the array arm cannot just recurse here.
        ParseValue::Null => "null".to_string(),
        ParseValue::Array(items) => items
            .iter()
            .map(|item| match item {
                ParseValue::Null => String::new(),
                other => render_as_js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => "[object Object]".to_string(),
    }
}

/// The `fields` block, distinguishing "absent" from "present and not an object".
///
/// The third member of the family that already holds [`index_block`] and [`clp_block`], and it was
/// the last one still collapsing the two cases with `unwrap_or_default()`. `"fields": "typo"`
/// therefore created a class with only its default columns, and made a `PUT` a successful no-op,
/// in response to a request that was trying to define fields.
///
/// Upstream's outcome is decided by JSON type, as with the other two. Measured against parse-server
/// 9.10.1-alpha.6: a **string** or non-empty array enumerates to its indices and fails as 105
/// `invalid field name: 0`; a **number**, **boolean** or empty array enumerates to nothing and
/// answers 200 having created the class with no fields; **null** reaches `Object.keys(null)` and
/// answers `{"code":1,"error":"Internal server error."}`.
///
/// Blast radius: a client sending `"fields": []` where it meant `{}` gets a refusal here and a
/// success upstream. No spec file submits a malformed block.
fn fields_block(body: &ParseMap, class_name: &str) -> Result<ParseMap, ParseError> {
    match body.get("fields") {
        None => Ok(ParseMap::new()),
        Some(ParseValue::Object(map)) => Ok(map.clone()),
        Some(_) => Err(ParseError::invalid_json(format!(
            "Invalid fields for class {class_name}: expected an object."
        ))),
    }
}

/// The `classLevelPermissions` block, distinguishing "absent" from "present and not an object".
///
/// **This is the same defect [`index_block`] exists to prevent, in the one place where the silent
/// outcome is an open class.** [`object_field`] collapses both cases to `None`, and `None` means
/// "the request said nothing about permissions". So `{"classLevelPermissions": "typo"}` created a
/// class with no CLP at all, which is default-open, in response to a request that was trying to
/// restrict it. A typo produced the opposite of what it asked for and answered 200.
///
/// Upstream refuses that body. `validateCLP` returns early only on a *falsy* `perms`
/// (`SchemaController.js:272-274`); anything else reaches `for (const operationKey in perms)`, and
/// enumerating a string yields its indices, so `"typo"` throws `INVALID_JSON` `0 is not a valid
/// operation for class level permissions` (`:275-281`).
///
/// **Tier 2, refusing uniformly, for the reason `index_block` gives.** Upstream's outcome is
/// decided by JSON type rather than by any rule about permissions: a non-empty string or array
/// throws, while a number, a boolean or an empty array enumerates to no keys and is accepted, and
/// a falsy value is read as absent. Reproducing that means accepting three malformed spellings and
/// rejecting a fourth. Blast radius: a client sending `"classLevelPermissions": []` or `0` where
/// it meant `{}` gets a refusal here and a success upstream. No spec file submits a malformed
/// block.
fn clp_block(body: &ParseMap, class_name: &str) -> Result<Option<ParseMap>, ParseError> {
    match body.get("classLevelPermissions") {
        None => Ok(None),
        Some(ParseValue::Object(map)) => Ok(Some(map.clone())),
        Some(_) => Err(ParseError::invalid_json(format!(
            "Invalid classLevelPermissions for class {class_name}: expected an object."
        ))),
    }
}

/// The `indexes` block, distinguishing "absent" from "present and not an object".
///
/// [`object_field`] collapses the two into `None`, which for `indexes` means a malformed block is
/// silently ignored and the request succeeds. Upstream never silently ignores it: `submittedIndexes
/// === undefined` is the only early return (`MongoStorageAdapter.js:353-355`), and everything else
/// goes through `Object.keys`.
///
/// **Tier 2, and worth stating why rather than reproducing.** What upstream then does depends on
/// the JSON type, through JavaScript coercion rather than through any rule about indexes:
///
/// - a **string** is indexable, so `Object.keys("x")` is `["0"]` and the block is read as one index
///   named `0` whose key document is the string again, which fails the field check as
///   `Field 0 does not exist, cannot add index.`;
/// - a **number**, **boolean** or **empty array** has no own keys, so the loop body never runs and
///   the request succeeds having recorded only the seeded `_id_`;
/// - a **non-empty array** behaves like the string case, through its elements;
/// - **null** reaches `Object.keys(null)`, which throws a `TypeError` and answers
///   `{"code":1,"error":"Internal server error."}`.
///
/// Three different outcomes for one malformed field, none of which a client could depend on
/// deliberately, and one of which is a crash. So parse-rust answers one thing for all of them. The
/// divergence is recorded under the deliberate differences in `CHANGELOG.md`, with its blast
/// radius: a client sending `"indexes": []` where it meant `{}` gets a refusal here and a success
/// upstream.
fn index_block(body: &ParseMap, class_name: &str) -> Result<Option<ParseMap>, ParseError> {
    match body.get("indexes") {
        None => Ok(None),
        Some(ParseValue::Object(map)) => Ok(Some(map.clone())),
        Some(_) => Err(ParseError::invalid_query(format!(
            "Invalid indexes for class {class_name}: expected an object."
        ))),
    }
}

/// The Parse-side type name, which is not the `_SCHEMA` storage string.
trait WireType {
    fn wire_type(&self) -> &'static str;
}

impl WireType for FieldType {
    fn wire_type(&self) -> &'static str {
        match self {
            FieldType::String => "String",
            FieldType::Number => "Number",
            FieldType::Boolean => "Boolean",
            FieldType::Date => "Date",
            FieldType::Object => "Object",
            FieldType::Array => "Array",
            FieldType::GeoPoint => "GeoPoint",
            FieldType::File => "File",
            FieldType::Bytes => "Bytes",
            FieldType::Polygon => "Polygon",
            FieldType::Acl => "ACL",
            FieldType::Pointer { .. } => "Pointer",
            FieldType::Relation { .. } => "Relation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The asymmetry that breaks a mixed fleet if it is normalized away.
    #[test]
    fn an_absent_clp_block_and_a_present_one_render_differently() {
        let absent = render_clp(None);
        assert!(
            absent.get("ACL").is_some(),
            "defaultCLPS carries an ACL key"
        );
        assert_eq!(absent["find"], json!({ "*": true }));

        let present = ClassLevelPermissions::from_map(
            match parse_rust_core::classify(
                serde_json::from_str(r#"{"find":{"*":true},"count":{},"get":{},"create":{},"update":{},"delete":{},"addField":{},"protectedFields":{}}"#)
                    .expect("literal"),
            )
            .expect("classify")
            {
                ParseValue::Object(m) => m,
                _ => unreachable!(),
            },
        );
        let rendered = render_clp(Some(&present));
        assert!(
            rendered.get("ACL").is_none(),
            "emptyCLPS has no ACL key, so a present block never grows one"
        );
        assert_eq!(
            rendered["count"],
            json!({}),
            "unspecified operations are {{}}"
        );
    }

    #[test]
    fn a_rendered_schema_carries_the_four_implicit_columns() {
        let schema = ClassSchema::new("Post").with_field("title", FieldType::String);
        let rendered = render(&schema);
        assert_eq!(rendered["className"], json!("Post"));
        assert_eq!(rendered["fields"]["title"], json!({ "type": "String" }));
        assert_eq!(rendered["fields"]["ACL"], json!({ "type": "ACL" }));
        assert_eq!(rendered["fields"]["objectId"], json!({ "type": "String" }));
        // Absent, not `{}`. All three upstream renderers guard the key, and the spec suite
        // compares the whole object, so an extra key is a failure rather than a nicety.
        assert!(
            rendered.get("indexes").is_none(),
            "a class with no indexes must not carry the key: {rendered}"
        );
    }

    /// The other half: a class that does have indexes reports them.
    #[test]
    fn a_class_with_indexes_renders_them() {
        let mut schema = ClassSchema::new("Post").with_field("title", FieldType::String);
        let mut indexes = ParseMap::new();
        let mut key = ParseMap::new();
        key.insert("title".to_string(), ParseValue::Number(1.0));
        indexes.insert("title_1".to_string(), ParseValue::Object(key));
        schema.indexes = Some(indexes);

        let rendered = render(&schema);
        assert_eq!(rendered["indexes"]["title_1"]["title"], json!(1));
    }

    #[test]
    fn a_parametric_type_renders_its_target_class_as_a_separate_key() {
        let schema = ClassSchema::new("_Role").with_field(
            "users",
            FieldType::Relation {
                target_class: "_User".into(),
            },
        );
        assert_eq!(
            render(&schema)["fields"]["users"],
            json!({ "type": "Relation", "targetClass": "_User" }),
            "not the `relation<_User>` storage spelling"
        );
    }
}
