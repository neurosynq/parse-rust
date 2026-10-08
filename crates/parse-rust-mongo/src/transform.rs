//! Parse JSON to BSON and back.
//!
//! Upstream: `src/Adapters/Storage/Mongo/MongoTransform.js`. It is full of load-bearing special
//! cases, and those special cases are the whole job: the naive transform is trivial and wrong.
//!
//! The pair implemented here mirrors `parseObjectToMongoObjectForCreate` and
//! `mongoObjectToParseObject`, which are the two functions upstream exports and therefore the
//! two this can be differentially tested against. See `tests/transform_differential.rs`.
//!
//! Scope is the 0.1.0 field set: String, Number, Boolean, Date, Array, Object, Pointer, ACL,
//! plus the 0.2.0 additions: the `$or`/`$and`/`$nor` query tree, `$all`, `$regex`, the update
//! operator set, and Relation fields (which have no column at all).

use bson::{doc, Bson, Document};
use parse_rust_core::{recognize_atom, AtomPosition, ParseDate, ParseError, ParseMap, ParseValue};
use parse_rust_storage::{
    ClassSchema, Clause, Comparison, Constraint, FieldType, Query, Update, UpdateValue,
};

/// Keys that are renamed rather than stored under their Parse name (`transformKey`,
/// `MongoTransform.js:7-30`). The list is closed: everything else keeps its name, except a
/// declared Pointer field, which takes a `_p_` prefix.
pub fn storage_key(schema: &ClassSchema, field: &str) -> String {
    match field {
        "objectId" => return "_id".into(),
        "createdAt" => return "_created_at".into(),
        "updatedAt" => return "_updated_at".into(),
        "sessionToken" => return "_session_token".into(),
        "lastUsed" => return "_last_used".into(),
        "timesUsed" => return "times_used".into(),
        _ => {}
    }
    if schema.is_pointer_field(field) {
        format!("_p_{field}")
    } else {
        field.to_string()
    }
}

/// Server-internal columns that are read back under their own names.
///
/// **Deliberately not upstream's shape.** `mongoObjectToParseObject` rehydrates
/// `_hashed_password` onto the object as `password` (`DatabaseController.js:266-267`), so the hash
/// travels under a user-facing name and one later step has to remove it again. Any path that
/// forgets that step leaks the hash, so parse-rust does not create the condition: the column keeps
/// its internal name all the way through.
/// Keeping the internal name means no code path can mistake the hash for a user-facing field, and
/// `parse_rust_rest::strip_internal_keys` removes every `_`-prefixed key from responses as the
/// unconditional backstop, which is what upstream's `filterSensitiveData` also does
/// (`DatabaseController.js:288-292`).
///
/// `_session_token` is absent because it is already renamed to `sessionToken` above, which is
/// upstream's behavior for that one column.
/// **This list is a mixed-fleet requirement, not a list of what parse-rust writes.** An unknown
/// `_`-prefixed column fails the whole read with `INVALID_QUERY` below, so a column parse-rust
/// never writes but parse-server does still has to be listed here or every row carrying one becomes
/// unreadable. Password reset, email verification, account lockout and a password policy are all
/// unimplemented here and all write columns onto `_User` upstream, so a fleet running one of those
/// features on the parse-server side produces rows this server would otherwise refuse to return:
/// login, `GET /users/me` and any query matching that user would all fail.
///
/// Kept in step with the `switch` at `MongoTransform.js:1152-1168`, which is the authority. Adding
/// a column here is safe by construction, because `strip_internal_keys` removes every `_`-prefixed
/// key from the response afterwards; omitting one is what breaks.
const INTERNAL_COLUMNS: [&str; 12] = [
    "_rperm",
    "_wperm",
    "_hashed_password",
    "_perishable_token",
    "_perishable_token_expires_at",
    "_email_verify_token",
    "_email_verify_token_expires_at",
    "_account_lockout_expires_at",
    "_failed_login_count",
    "_password_changed_at",
    "_password_history",
    "_tombstone",
];

/// The inverse of [`storage_key`].
fn untransform_key(field: &str) -> Option<String> {
    match field {
        "_id" => Some("objectId".into()),
        "_created_at" => Some("createdAt".into()),
        "_updated_at" => Some("updatedAt".into()),
        "_session_token" => Some("sessionToken".into()),
        // The legacy spelling, which upstream still accepts beside the plain one
        // (`MongoTransform.js:1177-1181`). parse-rust only ever writes `expiresAt`, so this is
        // read-side compatibility with a database an older Parse wrote.
        "_expiresAt" => Some("expiresAt".into()),
        "_last_used" => Some("lastUsed".into()),
        "times_used" => Some("timesUsed".into()),
        _ => {
            if let Some(stripped) = field.strip_prefix("_p_") {
                return Some(stripped.to_string());
            }
            if INTERNAL_COLUMNS.contains(&field) || field.starts_with("_auth_data_") {
                return Some(field.to_string());
            }
            None
        }
    }
}

/// Choose the BSON number type.
///
/// **This is the rule that silently corrupts data if it is wrong**, and it is why Gate B of the
/// data-fidelity gate exists. The rule, measured against a real parse-server: a value that
/// is integral and fits in `i32` is stored as `Int32`, everything else as `Double`. The Node
/// driver does the same thing, which is why a database written by parse-server contains a mix of
/// both for what the client thinks is one numeric field.
///
/// Note that this is unrelated to JSON number *formatting*, which is `parse-rust-core::js_number`.
/// Conflating the two is the mistake this project already made once.
fn to_bson_number(n: f64) -> Bson {
    if n.fract() == 0.0 && n >= i32::MIN as f64 && n <= i32::MAX as f64 {
        // `-0.0` is integral and in range. It stores as Int32 0, losing the sign, which is what
        // the Node driver does too.
        Bson::Int32(n as i32)
    } else {
        Bson::Double(n)
    }
}

/// Lower a value that sits **inside** an array or object.
///
/// UPSTREAM-QUIRK: `transformInteriorAtom` (`MongoTransform.js:566`) handles a strictly smaller
/// set than the top level. Only Pointer, Date and Bytes are recognised; a GeoPoint, Polygon or
/// File nested inside an array is stored raw, as the plain `__type` object it arrived as. That is
/// wire-visible on read-back, and it is reproduced deliberately.
///
/// A nested Pointer also keeps its full `{__type, className, objectId}` shape rather than
/// collapsing to `"Class$id"`, because the `_p_` collapse is a *key* transformation and interior
/// values have no key of their own.
///
/// **No regex arm here.** A `{"$regex": ...}` element compiles to a BSON regular expression only on
/// the query side, in [`interior_query_atom_to_bson`]; on a write it is refused as a nested `$`
/// key. This function is the shape shared by both and holds neither policy.
/// Lower an interior value with **no policy applied**: no nested-key guard, no regex compile.
///
/// The shape of every interior lowering, and nothing else. Three callers need three different
/// policies on top of it, and each of the three has at some point been served by a function
/// carrying somebody else's:
///
/// - a **row write** must refuse a `$` or `.` key ([`interior_value_to_bson`]);
/// - a **query atom** must compile `{"$regex": ...}` and must *not* refuse it
///   ([`interior_query_atom_to_bson`]);
/// - **stored metadata** must do neither ([`parse_map_to_bson_document`]).
///
/// Sharing one function across two of those put a compiled regex into a stored array and made the
/// row unreadable; sharing it across the other two turned a legitimate `containsAllStartingWith`
/// query and a valid `defaultValue` into `INVALID_NESTED_KEY`. The policies are the difference, so
/// the policies live in the wrappers and this stays free of them.
fn interior_atom_core(value: &ParseValue) -> Result<Bson, ParseError> {
    Ok(match value {
        ParseValue::Date(d) => date_to_bson(d),
        ParseValue::Bytes(b) => Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: b.clone(),
        }),
        ParseValue::Pointer {
            class_name,
            object_id,
        } => {
            let mut d = Document::new();
            d.insert("__type", "Pointer");
            d.insert("className", class_name.clone());
            d.insert("objectId", object_id.clone());
            Bson::Document(d)
        }
        // The four types `transformInteriorAtom` does **not** recognise. Upstream falls off the
        // end of its `if` chain and does `return atom` (`MongoTransform.js:583`), so the `__type`
        // envelope is what lands in the column. Delegating to `plain_value_to_bson` here instead
        // converted them to their top-level storage forms, which is a stored-format divergence a
        // mixed fleet sees as a disagreement about what the column contains.
        //
        // **Relation belongs here too**, and its absence was not a formatting difference. A
        // Relation has no column of its own, so `plain_value_to_bson` refuses it, and that refusal
        // is right at the top level and wrong inside an array: upstream stores the envelope and
        // parse-rust answered `INCORRECT_TYPE` for a document a parse-server node writes happily.
        ParseValue::GeoPoint { .. }
        | ParseValue::Polygon(_)
        | ParseValue::File { .. }
        | ParseValue::Relation { .. } => raw_typed_value(value)?,
        other => plain_value_to_bson(other)?,
    })
}

/// The interior transform **as a row write uses it**.
///
/// `$` and `.` are refused in a nested key before anything else looks at the value
/// (`transformInteriorValue`, `MongoTransform.js:177-187`). MongoDB gives both characters meaning
/// inside a document key, so a value carrying them is a write parse-server refuses with
/// `INVALID_NESTED_KEY` and parse-rust was storing.
///
/// **Only row writes want this.** A query operand of `{"$regex": "^ab"}` is what
/// `containsAllStartingWith` sends, and a stored `defaultValue` may legitimately contain a `$`
/// key; both go through their own wrapper.
fn interior_value_to_bson(value: &ParseValue) -> Result<Bson, ParseError> {
    if let ParseValue::Object(map) = value {
        if map.keys().any(|k| k.contains('$') || k.contains('.')) {
            return Err(ParseError::new(
                parse_rust_core::ErrorCode::InvalidNestedKey,
                "Nested keys should not contain the '$' or '.' characters",
            ));
        }
    }
    interior_atom_core(value)
}

/// The interior atom transform **as the query path uses it**, which additionally compiles a
/// `{"$regex": "..."}` atom into a real BSON regular expression (`MongoTransform.js:580-581`).
///
/// **Separate from [`interior_value_to_bson`], and the separation is the whole point.** Upstream
/// reaches `transformInteriorAtom` from two directions and they are not equivalent. A *query*
/// reaches it directly, from `$all` and from `transformConstraint`, and a regex there is the
/// operand the SDK's `containsAllStartingWith` sends. A *write* reaches it through
/// `transformInteriorValue`, which refuses any object carrying a `$` or `.` key with
/// `INVALID_NESTED_KEY` **before** delegating (`MongoTransform.js:177-189`), so a regex can never
/// be compiled on a write path there.
///
/// parse-rust reproduces that guard in [`interior_value_to_bson`] now, but the two functions still
/// must not merge: this one additionally compiles the regex and, below, keeps a generic object
/// unchanged. Putting the regex arm in the shared function once stored a BSON regular expression in
/// an ordinary array, which `bson_to_parse_value` cannot decode, so the row became permanently
/// unreadable and poisoned every query that returned it.
fn interior_query_atom_to_bson(value: &ParseValue) -> Result<Bson, ParseError> {
    if let ParseValue::Object(map) = value {
        if let Some(pattern) = interior_regex(map) {
            // A BSON regex is a pair of C strings, so a pattern with a NUL byte has no encoding.
            // Upstream's driver refuses it while serializing the read, inside the promise the read
            // path's `.catch` sanitizes, so a find answers `{"code":1,"error":"An internal server
            // error occurred"}`. bson 3 refuses it here instead, so the error is marked as the
            // query's own failure rather than a query-building one, or it would skip that rewrite.
            let pattern = bson::raw::CString::try_from(pattern).map_err(|_| {
                ParseError::internal("regex pattern contains a NUL byte").at_query()
            })?;
            return Ok(Bson::RegularExpression(bson::Regex {
                pattern,
                options: bson::raw::cstr!("").into(),
            }));
        }
    }
    // **A generic object or array is returned unchanged, not converted.** `transformInteriorAtom`
    // is shallow: its final arm is `return atom` (`MongoTransform.js:583`), so a nested
    // `{"__type": "Date", ...}` inside a query operand stays a literal subdocument and does not
    // become a BSON date. That is why `{"tags": {"$in": [{"at": <Date>}]}}` matches nothing
    // upstream even against a row written from the same body: the stored element holds a real BSON
    // date and the operand holds three string keys.
    //
    // Recursing here instead converted the nested atom and **matched a row upstream does not
    // return**, which is the direction that matters. A query that returns more than upstream would
    // is the failure this project treats as an authorization concern rather than a formatting one.
    match value {
        ParseValue::Object(_) | ParseValue::Array(_) => unchanged_atom_to_bson(value),
        other => interior_atom_core(other),
    }
}

/// A value as it arrived, with no Parse decoding applied to anything inside it.
///
/// The `return atom` arm of `transformInteriorAtom`, expressed for a type system that has already
/// decoded the JSON. Upstream never looks inside a generic object here, so its nested envelopes
/// survive verbatim; parse-rust has to re-emit them, and [`ParseValue::to_json`] is exactly the
/// envelope form they arrived in.
fn unchanged_atom_to_bson(value: &ParseValue) -> Result<Bson, ParseError> {
    Ok(match value {
        ParseValue::Object(map) => {
            let mut d = Document::new();
            for (k, v) in map {
                d.insert(k.clone(), unchanged_atom_to_bson(v)?);
            }
            Bson::Document(d)
        }
        ParseValue::Array(items) => Bson::Array(
            items
                .iter()
                .map(unchanged_atom_to_bson)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        // The three the storage form would otherwise convert. Kept as the objects they arrived as.
        ParseValue::Date(d) => {
            let mut e = Document::new();
            e.insert("__type", "Date");
            e.insert("iso", d.to_iso());
            Bson::Document(e)
        }
        ParseValue::Bytes(b) => {
            let mut e = Document::new();
            e.insert("__type", "Bytes");
            e.insert("base64", parse_rust_core::base64_encode(b));
            Bson::Document(e)
        }
        ParseValue::Pointer {
            class_name,
            object_id,
        } => {
            let mut e = Document::new();
            e.insert("__type", "Pointer");
            e.insert("className", class_name.clone());
            e.insert("objectId", object_id.clone());
            Bson::Document(e)
        }
        ParseValue::GeoPoint { .. }
        | ParseValue::Polygon(_)
        | ParseValue::File { .. }
        | ParseValue::Relation { .. } => raw_typed_value(value)?,
        // **Scalars still go through `plain_value_to_bson`, and that matters for numbers.** Going
        // via JSON instead, which this did first, stored `1` as Int64 where every other path stores
        // Int32: the rule Gate B exists to protect, broken by a serializer chosen for convenience.
        other => plain_value_to_bson(other)?,
    })
}

/// `isStartsWithRegex` (`MongoTransform.js:143-150`): `/\/\^\\Q.*\\E\//` tested, unanchored,
/// against the `RegExp`'s `toString()`, which is `/`, its source, `/`. So the question is whether
/// a `/^\Q` occurs with a `\E/` somewhere after it. The source escapes every line terminator, so
/// `.` spans the rest, but **not** a `/` inside a character class, so `/^\Q` can open mid-pattern:
/// `a[/^\Qx\E/]` is a starts-with regex by this test.
fn is_starts_with_regex(pattern: &str) -> bool {
    let rendered = format!("/{}/", js_regex_source(pattern));
    match (rendered.find("/^\\Q"), rendered.rfind("\\E/")) {
        (Some(open), Some(close)) => close >= open + 4,
        _ => false,
    }
}

/// The `$regex` pattern of an interior `{"$regex": "..."}` atom, if that is what this object is.
///
/// Upstream tests `atom.$regex !== undefined` and nothing else, so an object carrying `$regex`
/// beside other keys is still a regex and the other keys are dropped. A non-string `$regex` is
/// coerced rather than refused, which is what `new RegExp(String(v))` does; see the arms below.
fn interior_regex(map: &parse_rust_core::ParseMap) -> Option<String> {
    // **`new RegExp(atom.$regex)` coerces**, so the value need not be a string
    // (`MongoTransform.js:581`): `new RegExp(7)` is `/7/`. Matching only `String` here left every
    // other shape to fall through to the generic path and, for a number, to a 500. Upstream serves
    // the row.
    //
    // `undefined` is the only value upstream treats as absent, so a `null` still coerces, to
    // `/null/`. The rendering follows `ParseValue`'s own JSON spelling, which is what a client sent.
    match map.get("$regex")? {
        ParseValue::String(pattern) => Some(pattern.clone()),
        ParseValue::Number(n) => Some(parse_rust_core::js_number::to_ecma_string(*n)),
        ParseValue::Bool(b) => Some(b.to_string()),
        ParseValue::Null => Some("null".to_string()),
        // **Arrays and objects coerce too, and leaving them out was a 500.** The previous comment
        // claimed they fell through to "at least not a 500"; measured, all four of `[7]`, `[]`,
        // `{}` and `[1,2]` answered 500 here and 200 upstream. `new RegExp(String(v))` is the whole
        // rule, so an array joins its elements and an object is `[object Object]`, both of which
        // are then read as patterns. `[7]` matches `a7b` upstream, which is the case that shows
        // this is a real answer rather than a degenerate one.
        other => Some(parse_rust_core::js_number::to_ecma_display(other)),
    }
}

/// A tagged value stored as the `__type` object it arrived as, which is upstream's `return atom`.
///
/// Key order matches `ParseValue`'s own JSON rendering, because that is the shape the value had on
/// the way in and the one a reader will compare a stored document against. Latitude precedes
/// longitude here, which is the **wire** order: the GeoJSON swap belongs to the top-level storage
/// form and does not apply to an atom upstream never converts.
fn raw_typed_value(value: &ParseValue) -> Result<Bson, ParseError> {
    let mut d = Document::new();
    match value {
        ParseValue::GeoPoint {
            latitude,
            longitude,
        } => {
            d.insert("__type", "GeoPoint");
            d.insert("latitude", Bson::Double(*latitude));
            d.insert("longitude", Bson::Double(*longitude));
        }
        ParseValue::Polygon(coords) => {
            d.insert("__type", "Polygon");
            d.insert(
                "coordinates",
                Bson::Array(
                    coords
                        .iter()
                        .map(|(lat, lng)| Bson::Array(vec![Bson::Double(*lat), Bson::Double(*lng)]))
                        .collect(),
                ),
            );
        }
        ParseValue::File { name, url } => {
            d.insert("__type", "File");
            d.insert("name", name.clone());
            if let Some(url) = url {
                d.insert("url", url.clone());
            }
        }
        ParseValue::Relation { class_name } => {
            d.insert("__type", "Relation");
            d.insert("className", class_name.clone());
        }
        other => return plain_value_to_bson(other),
    }
    Ok(Bson::Document(d))
}

/// One element of an array as JavaScript's `Array.prototype.join` renders it.
///
/// Only used to build the `$all` mixed-regex message, whose upstream form is string concatenation
/// of the array. `null` and `undefined` join as the empty string, an array joins its own elements
/// with commas, and any other object joins as `[object Object]`.
fn js_join_element(value: &ParseValue) -> String {
    match value {
        ParseValue::Array(items) => items
            .iter()
            .map(js_join_element)
            .collect::<Vec<_>>()
            .join(","),
        ParseValue::String(s) => s.clone(),
        ParseValue::Number(n) => parse_rust_core::js_number::to_ecma_string(*n),
        ParseValue::Bool(b) => b.to_string(),
        ParseValue::Null => String::new(),
        // Upstream joins the values *after* `transformInteriorAtom`, so a regex atom is a `RegExp`
        // by then and renders as `/source/`.
        ParseValue::Object(m) => match interior_regex(m) {
            Some(pattern) => format!("/{}/", js_regex_source(&pattern)),
            None => "[object Object]".to_string(),
        },
        _ => "[object Object]".to_string(),
    }
}

/// `RegExp.prototype.source` for `new RegExp(pattern)`: `(?:)` for an empty pattern, a `/`
/// outside a character class escaped unless it already is, and line terminators spelled as
/// escapes (ECMA-262 `EscapeRegExpPattern`, as V8 implements it).
fn js_regex_source(pattern: &str) -> String {
    if pattern.is_empty() {
        return "(?:)".to_string();
    }
    let mut out = String::with_capacity(pattern.len());
    let mut escaped = false;
    let mut in_class = false;
    for c in pattern.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            '/' if !escaped && !in_class => out.push_str("\\/"),
            _ => out.push(c),
        }
        if !escaped {
            match c {
                '[' => in_class = true,
                ']' => in_class = false,
                _ => {}
            }
        }
        escaped = !escaped && c == '\\';
    }
    out
}

fn date_to_bson(d: &ParseDate) -> Bson {
    Bson::DateTime(bson::DateTime::from_millis(d.timestamp_millis()))
}

/// Everything that is not position-dependent.
fn plain_value_to_bson(value: &ParseValue) -> Result<Bson, ParseError> {
    Ok(match value {
        ParseValue::Null => Bson::Null,
        ParseValue::Bool(b) => Bson::Boolean(*b),
        ParseValue::Number(n) => to_bson_number(*n),
        ParseValue::String(s) => Bson::String(s.clone()),
        ParseValue::Array(items) => Bson::Array(
            items
                .iter()
                .map(interior_value_to_bson)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ParseValue::Object(map) => {
            let mut d = Document::new();
            for (k, v) in map {
                d.insert(k.clone(), interior_value_to_bson(v)?);
            }
            Bson::Document(d)
        }
        ParseValue::Date(d) => date_to_bson(d),
        ParseValue::Bytes(b) => Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: b.clone(),
        }),
        ParseValue::GeoPoint {
            latitude,
            longitude,
        } => {
            // Storage is GeoJSON order, longitude first, the reverse of the wire form.
            Bson::Array(vec![Bson::Double(*longitude), Bson::Double(*latitude)])
        }
        ParseValue::Pointer { .. } => {
            return Err(ParseError::incorrect_type(
                "a top-level Pointer is lowered by key, not by value".to_string(),
            ))
        }
        ParseValue::Polygon(coords) => {
            // **The stored ring is closed and the client's is not, so the write appends the first
            // vertex** (`PolygonCoder.JSONToDatabase`). Storing the ring as sent round-trips
            // perfectly against parse-rust and is one vertex short of what a parse-server node
            // reads back from the same document, which is precisely the class of bug a
            // read-your-own-write test cannot see. Gate B caught it once the type was covered.
            let mut ring = coords.clone();
            match (ring.first(), ring.last()) {
                (Some(first), Some(last)) if first != last => ring.push(*first),
                _ => {}
            }
            // `unique.length < 3` after deduplication, raising `INTERNAL_SERVER_ERROR`
            // `GeoJSON: Loop must have at least 3 different vertices`. Upstream's filter compares
            // by value and keeps first occurrences, so the closing vertex it just appended is not
            // counted twice.
            let mut distinct: Vec<(f64, f64)> = Vec::new();
            for point in &ring {
                if !distinct.contains(point) {
                    distinct.push(*point);
                }
            }
            if distinct.len() < 3 {
                return Err(ParseError::new(
                    parse_rust_core::ErrorCode::InternalServerError,
                    "GeoJSON: Loop must have at least 3 different vertices",
                ));
            }
            Bson::Document({
                let mut d = Document::new();
                d.insert("type", "Polygon");
                d.insert(
                    "coordinates",
                    Bson::Array(vec![Bson::Array(
                        ring.iter()
                            // Stored longitude-first; `PolygonCoder.databaseToJSON` swaps on the
                            // way out (`MongoTransform.js:1362-1372`).
                            .map(|(lat, lng)| {
                                Bson::Array(vec![Bson::Double(*lng), Bson::Double(*lat)])
                            })
                            .collect(),
                    )]),
                );
                d
            })
        }
        ParseValue::File { name, .. } => Bson::String(name.clone()),
        ParseValue::Relation { .. } => {
            return Err(ParseError::incorrect_type(
                "Relation fields are not stored on the object".to_string(),
            ))
        }
    })
}

/// `parseObjectToMongoObjectForCreate`.
///
/// Two behaviors that are easy to miss and both wire-visible:
/// - **Relation values are skipped entirely** (`MongoTransform.js:468-470`). A Relation lives in
///   a join table, not on the object, so a `{__type:"Relation"}` value in a create body is
///   dropped rather than stored or rejected.
/// - **`ACL` becomes three columns**: `_rperm`, `_wperm`, and the legacy `_acl` mirror.
pub fn parse_object_to_mongo_create(
    schema: &ClassSchema,
    object: &ParseMap,
) -> Result<Document, ParseError> {
    let mut out = Document::new();

    for (key, value) in object {
        // A null creates under the field's own name even on a Pointer field: the create transform
        // adds `_p_` only `if (restValue && ...)` (`MongoTransform.js:423-428`), so the row reads
        // back with `"<field>": null`. An update names the column from the schema and writes
        // `_p_<field>: null`, which reads back with no key (`:1231-1233`); the two differ upstream
        // and a client sees which one happened.
        if matches!(value, ParseValue::Null) && schema.is_pointer_field(key) {
            out.insert(key.clone(), Bson::Null);
            continue;
        }
        if let Some((mongo_key, bson)) = field_to_column(schema, key, value)? {
            out.insert(mongo_key, bson);
        }
    }

    Ok(out)
}

/// Lower one top-level field to its column and stored value.
///
/// `Ok(None)` means the field has no column at all, which is true of exactly one thing: a
/// Relation. Both write paths skip it rather than storing or rejecting it
/// (`MongoTransform.js:467-470` on create, `:510-513` on update), because the memberships live in
/// `_Join:<key>:<class>`.
///
/// Shared by create and by an update's `Set`, because upstream's two key transforms
/// (`parseObjectKeyValueToMongoObjectKeyValue` and `transformKeyValueForUpdate`) agree on every
/// key parse-rust supports. Sharing it is what stops the two paths from drifting into writing one
/// field under two different column names.
fn field_to_column(
    schema: &ClassSchema,
    key: &str,
    value: &ParseValue,
) -> Result<Option<(String, Bson)>, ParseError> {
    if matches!(value, ParseValue::Relation { .. }) {
        return Ok(None);
    }
    if key == "ACL" {
        return Err(ParseError::invalid_json(
            "ACL must be lowered through parse_acl_to_columns, not as a field".to_string(),
        ));
    }

    let mongo_key = storage_key(schema, key);

    // A declared Pointer field collapses to "<Class>$<id>" under its `_p_` key.
    if schema.is_pointer_field(key) {
        return match value {
            ParseValue::Pointer {
                class_name,
                object_id,
            } => Ok(Some((
                mongo_key,
                Bson::String(format!("{class_name}${object_id}")),
            ))),
            ParseValue::Null => Ok(Some((mongo_key, Bson::Null))),
            _ => Err(ParseError::incorrect_type(format!(
                "schema mismatch for {}.{key}; expected Pointer but got a non-pointer",
                schema.class_name
            ))),
        };
    }

    // `expiresAt` keeps its name and is coerced to a BSON Date even when it arrives as a string
    // (`MongoTransform.js:378-382`). A `_Session` row whose `expiresAt` is stored as a string
    // never expires, because parse-server compares it as a Date.
    if key == "expiresAt" {
        if let ParseValue::String(s) = value {
            return Ok(Some((mongo_key, date_to_bson(&ParseDate::parse_iso(s)?))));
        }
    }

    Ok(Some((mongo_key, plain_value_to_bson(value)?)))
}

/// `mongoObjectToParseObject`.
///
/// UPSTREAM-QUIRK: an unrecognised `_`-prefixed key raises, and it raises a **bare JavaScript
/// string** rather than a `Parse.Error` (`MongoTransform.js:1236-1237`). On the aggregate path
/// that surfaces to the client as code 102 with an `undefined` message. Reproduced here as an
/// error, though parse-rust cannot reproduce the `undefined` message without inventing one.
///
/// UPSTREAM-QUIRK: the timestamp columns do not all raise to the same wire form.
/// `createdAt`, `updatedAt` and `lastUsed` become bare ISO strings while `expiresAt` keeps a full
/// `{"__type":"Date"}` envelope, all at the top level of the same object
/// (`MongoTransform.js:1172-1187`). Every one of them is a `ParseValue::Date` here, and the
/// position-dependent flattening happens once at the response boundary, so there is a single place
/// to audit rather than a rule spread across the transform.
pub fn mongo_object_to_parse(schema: &ClassSchema, doc: &Document) -> Result<ParseMap, ParseError> {
    let mut out = ParseMap::new();

    for (key, value) in doc {
        // `_acl` is the legacy write-only mirror and is dropped on read, exactly as upstream does
        // (`MongoTransform.js:1155-1156`, a bare `break`).
        //
        // `_rperm` and `_wperm` are NOT dropped here. They are what `parse_rust_rest::acl::raise_acl`
        // rebuilds the `ACL` field from, and dropping them meant a stored ACL could never be
        // returned. The response boundary strips any that survive, so they cannot leak.
        if key == "_acl" {
            continue;
        }

        // `_id` is stringified, not decoded. Upstream writes `restObject['objectId'] = '' +
        // mongoObject[key]` (`MongoTransform.js:1149-1150`), and the coercion is load-bearing
        // rather than incidental: parse-server's own `addRelation` writes join documents with no
        // explicit `_id`, so MongoDB generates a BSON ObjectId, and every production database has
        // them throughout `_Join:*`. Decoding `_id` as an ordinary value rejects those documents
        // and makes role expansion return nothing at all.
        if key == "_id" {
            out.insert(
                "objectId".to_string(),
                ParseValue::String(bson_id_string(value)),
            );
            continue;
        }

        let parse_key = match untransform_key(key) {
            Some(k) => k,
            None if key.starts_with('_') && key != "__type" => {
                return Err(ParseError::invalid_query(format!(
                    "bad key in untransform: {key}"
                )))
            }
            None => key.clone(),
        };

        // A `_p_` field carries "<Class>$<id>". Upstream drops the column, leaving no key, when
        // the schema does not declare it, when it declares another type, and when the stored value
        // is null (`MongoTransform.js:1211-1233`).
        if let Some(stripped) = key.strip_prefix("_p_") {
            if !matches!(schema.field(stripped), Some(FieldType::Pointer { .. })) {
                continue;
            }
            match value {
                Bson::String(s) => {
                    let (class_name, object_id) = s.split_once('$').ok_or_else(|| {
                        ParseError::incorrect_type(format!(
                            "pointer field {stripped} is malformed: {s}"
                        ))
                    })?;
                    out.insert(
                        stripped.to_string(),
                        ParseValue::Pointer {
                            class_name: class_name.to_string(),
                            object_id: object_id.to_string(),
                        },
                    );
                }
                Bson::Null => {}
                _ => {
                    return Err(ParseError::incorrect_type(format!(
                        "pointer field {stripped} is not a string"
                    )))
                }
            }
            continue;
        }

        // **Three of the stored forms are ambiguous and only the schema resolves them.** A
        // GeoPoint is a two-element array, a File is a string and a Polygon is a GeoJSON document,
        // so nothing about the value says what it was. Upstream consults `schema.fields[key].type`
        // for exactly four types and raises only when the stored value also has the right shape
        // (`MongoTransform.js:1136-1166`).
        match schema_raised_value(schema, &parse_key, value) {
            Some(raised) => out.insert(parse_key, raised),
            None => out.insert(parse_key, bson_to_parse_value(value)?),
        };
    }

    // A Relation has no column, so it is synthesized from the schema on every read
    // (`MongoTransform.js:1277-1288`). Upstream spreads the synthesized fields *after* the
    // document, so a stray stored key of the same name is overwritten rather than winning.
    // `IndexMap::insert` keeps an existing key's position and replaces its value, which is what
    // the JavaScript spread does too, so field order survives.
    for (name, target_class) in schema.relation_fields() {
        out.insert(
            name.to_string(),
            ParseValue::Relation {
                class_name: target_class.to_string(),
            },
        );
    }

    Ok(out)
}

/// Raise one column using its **declared type**, for the forms the stored value cannot describe.
///
/// `mongoObjectToParseObject` consults `schema.fields[key].type` for File, GeoPoint, Polygon and
/// Bytes, each gated on the stored value passing that coder's `isValidDatabaseObject`
/// (`MongoTransform.js:1136-1166`). Returns `None` when no rule applies, which is upstream's
/// fall-through to the ordinary raise.
///
/// **The comment on [`bson_to_parse_value`] claimed the stored form is self-describing, and that is
/// true of exactly the types that do not need this.** A Date is a BSON date, a Bytes is BSON
/// Binary, a Pointer is under a `_p_` key. The other three are stored as ordinary values, so
/// without the schema a client that saved a GeoPoint read back a bare two-element array, a File
/// read back as its bare name, and a Polygon as raw GeoJSON with its coordinates still in
/// longitude-first order.
///
/// **Bytes needs an arm here even though BSON Binary raises without a schema.** `BytesCoder`'s
/// `isValidDatabaseObject` is `object instanceof mongodb.Binary || this.isBase64Value(object)`, so
/// a Bytes column holding a **base64 string** is raised to the envelope too. That is not a
/// hypothetical shape: it is what a document written by an older parse-server holds, and running
/// against a database an existing deployment already populated is a stated requirement rather than
/// an aspiration. Leaving it out returned `"aGk="` as a plain string where upstream returns
/// `{"__type":"Bytes","base64":"aGk="}`, and the data-fidelity gate could not see it because
/// everything that gate writes is Binary.
fn schema_raised_value(schema: &ClassSchema, field: &str, value: &Bson) -> Option<ParseValue> {
    let field_type = schema.field(field)?;
    match (field_type, value) {
        // `isBase64Value`: a string matching upstream's own pattern. A Bytes column holding a
        // string that is *not* valid base64 fails the guard and falls through to the ordinary
        // raise, which is upstream's behavior rather than an error.
        //
        // **Returned verbatim, as the envelope, rather than decoded into bytes.** `databaseToJSON`
        // is `if (this.isBase64Value(object)) { value = object; }`, so the stored string is passed
        // through untouched; only the Binary branch encodes. The distinction is invisible for a
        // canonical string and lossy for anything else, because the pattern accepts strings whose
        // final characters carry bits that decoding discards: `AB==` decodes and re-encodes to
        // `AA==`, and `AAB=` to `AAA=`. Both were measured coming back unchanged from a server at
        // the pin. A `ParseValue::Bytes` has nowhere to keep the original, so the raise builds the
        // envelope the wire form needs directly. This is the one place the read path deliberately
        // produces an untyped object.
        (FieldType::Bytes, Bson::String(s)) if parse_rust_core::is_base64_value(s) => {
            let mut envelope = ParseMap::new();
            envelope.insert(
                "__type".to_string(),
                ParseValue::String("Bytes".to_string()),
            );
            envelope.insert("base64".to_string(), ParseValue::String(s.clone()));
            Some(ParseValue::Object(envelope))
        }
        // `typeof object === 'string'`. The url is not stored and is not synthesized here;
        // upstream's `databaseToJSON` returns the name alone.
        (FieldType::File, Bson::String(name)) => Some(ParseValue::File {
            name: name.clone(),
            url: None,
        }),
        // `Array.isArray(object) && object.length == 2`, stored longitude first, so the raise
        // swaps them back. Upstream does not check that the two elements are numbers and will
        // happily return a GeoPoint whose latitude is a string; that shape has no representation
        // here, so it falls through to the ordinary array raise instead.
        (FieldType::GeoPoint, Bson::Array(items)) if items.len() == 2 => {
            match (bson_f64(&items[0]), bson_f64(&items[1])) {
                (Some(longitude), Some(latitude)) => Some(ParseValue::GeoPoint {
                    latitude,
                    longitude,
                }),
                _ => None,
            }
        }
        // `object.type !== 'Polygon' || !Array.isArray(object.coordinates[0])` rejects, then every
        // point must itself be a two-element array. Only the **first ring** is read, and the
        // closing point that `JSONToDatabase` appended is not removed, so a polygon read back
        // carries one more vertex than the client sent. That is upstream's shape, not a rounding
        // of it.
        (FieldType::Polygon, Bson::Document(d)) => {
            if d.get_str("type").ok()? != "Polygon" {
                return None;
            }
            let ring = d.get_array("coordinates").ok()?.first()?.as_array()?;
            let mut points = Vec::with_capacity(ring.len());
            for point in ring {
                let pair = point.as_array()?;
                if pair.len() != 2 {
                    return None;
                }
                // Stored longitude first, raised latitude first.
                points.push((bson_f64(&pair[1])?, bson_f64(&pair[0])?));
            }
            Some(ParseValue::Polygon(points))
        }
        _ => None,
    }
}

/// A stored coordinate, which may be any BSON number width.
fn bson_f64(value: &Bson) -> Option<f64> {
    match value {
        Bson::Double(n) => Some(*n),
        Bson::Int32(n) => Some(*n as f64),
        Bson::Int64(n) => Some(*n as f64),
        _ => None,
    }
}

/// Raise a stored sub-document into Parse form, verbatim.
///
/// Used for the `_metadata` sub-keys, which parse-rust round-trips without interpreting.
pub fn bson_document_to_parse_map(doc: &Document) -> Result<ParseMap, ParseError> {
    let mut out = ParseMap::new();
    for (key, value) in doc {
        out.insert(key.clone(), bson_to_parse_value(value)?);
    }
    Ok(out)
}

/// Lower a Parse map into a stored sub-document, applying no policy.
///
/// **Verbatim, and no longer only as far as this layer can be.** This note used to say that a
/// value carrying a `__type` envelope had been decoded before it arrived, so an offset instant was
/// already UTC and an extra envelope key already gone, and that the loss was an open parity gap
/// above this function. That gap was closed: a schema body is now decoded raw, so the envelope
/// reaches here as the client sent it and is stored that way. The claim outlived the fix.
///
/// The inverse of [`bson_document_to_parse_map`], and the way a CLP block reaches
/// `_metadata.class_permissions` without passing through the column transform: a CLP has keys like
/// `role:Admin` and `*` that are not fields and must never be renamed or `_p_`-prefixed.
pub fn parse_map_to_bson_document(map: &ParseMap) -> Result<Document, ParseError> {
    let mut out = Document::new();
    for (key, value) in map {
        out.insert(key.clone(), raw_metadata_value(value)?);
    }
    Ok(out)
}

/// Lower a metadata value with **no policy at any depth**.
///
/// Metadata is not a row, and the nested-key guard is a rule about rows. `_metadata` legitimately
/// holds keys the guard forbids: a CLP has `role:Admin` and `*`, and a stored `defaultValue` is an
/// arbitrary client-supplied object that upstream stores and echoes verbatim, `$` keys included.
///
/// **Recursion is the point of having this at all.** Applying the guard only at the top and then
/// delegating downward is what a first attempt did, and it still answered 121 for
/// `{"defaultValue": {"$regex": "literal"}}`, because the guarded wrapper was one level down. The
/// write path recurses through its guard deliberately, matching upstream's `transformInteriorValue`
/// which re-enters itself for every array element and object value (`MongoTransform.js:196-199`);
/// this one has to recurse through no guard for the same reason, in the other direction.
fn raw_metadata_value(value: &ParseValue) -> Result<Bson, ParseError> {
    // **Verbatim means the envelope, not the storage form.** Delegating a leaf to
    // `interior_atom_core` turned a `Date` default into a BSON date and a `Bytes` default into BSON
    // Binary, which round-trips perfectly here and is wrong on the wire: a parse-server node
    // reading the same `_SCHEMA` renders them as a bare ISO string and a bare base64 string,
    // because it never decoded them in the first place. The pin stores what the client sent.
    //
    // A local read-back test cannot see this, which is why the one written for the `$regex` case
    // did not: both sides of it were parse-rust.
    unchanged_atom_to_bson(value)
}

/// Raise a stored value. Takes no schema: the stored form is self-describing, which is the
/// asymmetry with lowering, where the schema decides whether a field is a `_p_` pointer.
pub fn bson_to_parse_value(value: &Bson) -> Result<ParseValue, ParseError> {
    Ok(match value {
        Bson::Null => ParseValue::Null,
        Bson::Boolean(b) => ParseValue::Bool(*b),
        // Both integer widths raise to the single JavaScript number type. This is the direction
        // that is lossless; the lossy direction is `to_bson_number`.
        Bson::Int32(n) => ParseValue::Number(*n as f64),
        Bson::Int64(n) => ParseValue::Number(*n as f64),
        Bson::Double(n) => ParseValue::Number(*n),
        Bson::String(s) => ParseValue::String(s.clone()),
        // Straight from the stored milliseconds. Rendering the driver's text and parsing it back
        // gave the same date at twice the cost per value, which a large result set pays per date.
        // The refusal is unchanged: a value outside the representable range is not quoted back,
        // because a stored value does not belong in a client-visible message.
        Bson::DateTime(dt) => ParseValue::Date(
            ParseDate::from_timestamp_millis(dt.timestamp_millis())
                .ok_or_else(|| ParseError::invalid_json("undecodable stored date"))?,
        ),
        Bson::Binary(b) => ParseValue::Bytes(b.bytes.clone()),
        Bson::Array(items) => ParseValue::Array(
            items
                .iter()
                .map(bson_to_parse_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Bson::Document(d) => {
            let mut map = ParseMap::new();
            for (k, v) in d {
                map.insert(k.clone(), bson_to_parse_value(v)?);
            }
            ParseValue::Object(map)
        }
        other => {
            return Err(ParseError::incorrect_type(format!(
                "unsupported BSON type in stored document: {other:?}"
            )))
        }
    })
}

/// JavaScript's `'' + value` for the values an `_id` can hold.
///
/// A string is itself, which is the ordinary Parse case. An ObjectId renders as its 24 hex
/// characters, which is what `String(objectId)` gives in Node and therefore what a client sees
/// for a document parse-server created without an explicit id. Numbers matter too:
/// `_GlobalConfig` and `_GraphQLConfig` store an integer `_id` (`MongoTransform.js:254-259`).
fn bson_id_string(value: &Bson) -> String {
    match value {
        Bson::String(s) => s.clone(),
        Bson::ObjectId(oid) => oid.to_hex(),
        Bson::Int32(n) => n.to_string(),
        Bson::Int64(n) => n.to_string(),
        Bson::Double(n) => parse_rust_core::js_number::to_ecma_string(*n),
        other => other.to_string(),
    }
}

/// Lower a value for use in a query filter on `field`.
///
/// Differs from the create path in one way that matters: a declared Pointer field stores
/// `"Class$id"`, so a query for a pointer has to compare against that string rather than against
/// the `__type` envelope. Getting this wrong makes every pointer query silently return nothing.
///
/// **A bare objectId string is prefixed too, and only the schema knows what to prefix it with.**
/// `transformTopLevelAtom`'s string case is `if (field && field.type === 'Pointer') return
/// `${field.targetClass}$${atom}`` (`MongoTransform.js:600-603`), so `{"author": {"$in":
/// ["abc123"]}}` compares against `"Post$abc123"` upstream. Handling only the `__type` envelope
/// left the raw-string form comparing against the unprefixed id, which matches no stored value:
/// the query answers 200 with no results rather than erroring, so nothing indicates the constraint
/// was meaningless. The class comes from the **schema**, not from the value, because a bare string
/// carries none.
pub fn value_to_bson_for_query(
    schema: &ClassSchema,
    field: &str,
    value: &ParseValue,
) -> Result<Bson, ParseError> {
    match value {
        // **A Pointer atom collapses wherever it appears at the top level, and upstream does not
        // consult the field to do it** (`MongoTransform.js:619-621`: `if (atom.__type == 'Pointer')
        // return \`${atom.className}$${atom.objectId}\``, outside any check on `field`). Gating it
        // on a declared Pointer field answered 111 `a top-level Pointer is lowered by key, not by
        // value` for a query upstream runs, and that sentence is internal vocabulary a client
        // should never see. The class comes from the operand, not from the schema, so a pointer
        // compared against an `Object` field or an undeclared one lowers the same way.
        ParseValue::Pointer {
            class_name,
            object_id,
        } => Ok(Bson::String(format!("{class_name}${object_id}"))),
        // The bare-string shorthand is the one case that *does* consult the field
        // (`:601-603`), because a string carries no class of its own.
        ParseValue::String(object_id) if schema.is_pointer_field(field) => {
            match schema.field(field).and_then(FieldType::target_class) {
                Some(target) => Ok(Bson::String(format!("{target}${object_id}"))),
                None => plain_value_to_bson(value),
            }
        }
        _ => plain_value_to_bson(value),
    }
}

/// Lower one entry of an index key document.
///
/// Deliberately narrow. Mongo accepts a number for a sort direction and a string for an index
/// type, and nothing else belongs in a key document. Anything else is refused rather than passed
/// through, because `createIndexes` would answer with a driver message this layer must not put on
/// the wire, and because the value is about to be written into `_metadata.indexes` where a
/// parse-server node reads it back.
///
/// Upstream does no validation here at all: `setIndexesWithSchemaFormat` checks the *field names*
/// against the schema (`MongoStorageAdapter.js:377-390`) and hands the values straight to the
/// driver. The direction of this divergence is refusing something upstream would have let the
/// driver refuse, and the code and message are the same either way.
pub fn index_key_to_bson(index: &str, field: &str, value: &ParseValue) -> Result<Bson, ParseError> {
    match value {
        ParseValue::Number(n) => Ok(to_bson_number(*n)),
        ParseValue::String(s) => Ok(Bson::String(s.clone())),
        _ => Err(ParseError::invalid_query(format!(
            "Index {index} has an invalid value for {field}"
        ))),
    }
}

/// `transformWhere`: lower a query tree into a Mongo filter document.
///
/// Every sub-query of a logical clause is lowered with the **same schema**, so `_p_` prefixing and
/// `objectId` -> `_id` apply inside a branch exactly as they do at the top level
/// (`MongoTransform.js:290-296`).
pub fn transform_where(schema: &ClassSchema, query: &Query) -> Result<Document, ParseError> {
    transform_where_as(schema, query, false)
}

/// [`transform_where`] for a count, which differs in one place: `$nearSphere` cannot be counted,
/// so upstream rewrites it into an equivalent `$geoWithin` (`MongoTransform.js:812-821`).
pub fn transform_where_for_count(
    schema: &ClassSchema,
    query: &Query,
) -> Result<Document, ParseError> {
    transform_where_as(schema, query, true)
}

fn transform_where_as(
    schema: &ClassSchema,
    query: &Query,
    count: bool,
) -> Result<Document, ParseError> {
    let mut out = Document::new();
    // An error upstream raises only when the driver sends the query (see
    // `ParseErrorInfo::at_query`) is held until every clause is lowered, so any error upstream
    // throws while building the query still wins over it, as it does there.
    let mut deferred = None;
    for clause in &query.clauses {
        match lower_clause(schema, clause, count, &mut out) {
            Ok(()) => {}
            Err(e) if e.info.at_query => {
                deferred.get_or_insert(e);
            }
            Err(e) => return Err(e),
        }
    }
    match deferred {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

fn lower_clause(
    schema: &ClassSchema,
    clause: &Clause,
    count: bool,
    out: &mut Document,
) -> Result<(), ParseError> {
    match clause {
        // `$text` belongs to the whole filter, not to its field.
        Clause::Field(Constraint {
            comparison: Comparison::Text(search),
            ..
        }) => {
            merge_constraint(out, "$text".to_string(), text_to_bson(search)?)?;
        }
        Clause::Field(constraint) => {
            let key = storage_key(schema, &constraint.field);
            let entry = match &constraint.comparison {
                Comparison::Geo(pairs) => geo_to_bson(pairs, count)?,
                _ => comparison_to_bson(schema, constraint)?,
            };
            // Several constraints on one field must merge rather than overwrite. Overwriting
            // is the bug the `tbraun96/parse-rs` query builder shipped, and it silently drops
            // a constraint, which broadens the result set.
            merge_constraint(out, key, entry)?;
        }
        Clause::Or(branches) => {
            insert_logical(out, "$or", lower_branches(schema, branches, count)?)
        }
        Clause::And(branches) => {
            insert_logical(out, "$and", lower_branches(schema, branches, count)?)
        }
        Clause::Nor(branches) => {
            insert_logical(out, "$nor", lower_branches(schema, branches, count)?)
        }
    }
    Ok(())
}

/// The branches of a logical operator, lowered the way the enclosing read is: a count's
/// `$nearSphere` becomes `$geoWithin` inside an `$or` too (`MongoTransform.js:291-297`), which is
/// what lets `Parse.Query.or` over two `withinKilometers` queries be counted at all.
fn lower_branches(
    schema: &ClassSchema,
    branches: &[Query],
    count: bool,
) -> Result<Vec<Bson>, ParseError> {
    collect_deferring(
        branches
            .iter()
            .map(|q| transform_where_as(schema, q, count).map(Bson::Document)),
    )
}

/// Collect results, returning the first error at once unless it is one upstream raises only when
/// the query is sent ([`ParseErrorInfo::at_query`](parse_rust_core::ParseErrorInfo)). That one is
/// held until the rest are built, because upstream builds them all before sending anything: a
/// later sibling's validation error is what it answers with.
fn collect_deferring<T>(
    results: impl Iterator<Item = Result<T, ParseError>>,
) -> Result<Vec<T>, ParseError> {
    let mut out = Vec::new();
    let mut deferred = None;
    for result in results {
        match result {
            Ok(v) => out.push(v),
            Err(e) if e.info.at_query => {
                deferred.get_or_insert(e);
            }
            Err(e) => return Err(e),
        }
    }
    match deferred {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// `$text` (`MongoTransform.js:777-811`), with upstream's messages.
///
/// `null` is the one operand JavaScript cannot read a member of, so `$text: null` and
/// `$search: null` (whose `typeof` is `"object"`, so it passes the shape test) are `TypeError`s
/// and a bare 500. An array `$search` passes the same test and fails on its missing `$term`.
fn text_to_bson(operand: &ParseValue) -> Result<Bson, ParseError> {
    let search = match operand {
        ParseValue::Null => return Err(null_member("$search")),
        ParseValue::Object(m) => m.get("$search"),
        _ => None,
    };
    let empty = parse_rust_core::ParseMap::new();
    let search = match search {
        Some(ParseValue::Object(search)) => search,
        Some(ParseValue::Array(_)) => &empty,
        Some(ParseValue::Null) => return Err(null_member("$term")),
        _ => {
            return Err(ParseError::invalid_json(
                "bad $text: $search, should be object",
            ))
        }
    };
    let mut answer = Document::new();
    match search.get("$term") {
        Some(ParseValue::String(term)) if !term.is_empty() => {
            answer.insert("$search", term.clone());
        }
        _ => {
            return Err(ParseError::invalid_json(
                "bad $text: $term, should be string",
            ))
        }
    }
    let truthy = |v: &ParseValue| parse_rust_core::is_js_truthy(v);
    match search.get("$language") {
        Some(ParseValue::String(language)) if !language.is_empty() => {
            answer.insert("$language", language.clone());
        }
        Some(v) if truthy(v) => {
            return Err(ParseError::invalid_json(
                "bad $text: $language, should be string",
            ))
        }
        _ => {}
    }
    for flag in ["$caseSensitive", "$diacriticSensitive"] {
        match search.get(flag) {
            Some(ParseValue::Bool(true)) => {
                answer.insert(flag, true);
            }
            Some(v) if truthy(v) && !matches!(v, ParseValue::Bool(_)) => {
                return Err(ParseError::invalid_json(format!(
                    "bad $text: {flag}, should be boolean"
                )))
            }
            _ => {}
        }
    }
    Ok(Bson::Document(answer))
}

/// The fields a query asks a `$text` search of, at its top level.
pub fn text_search_fields(query: &Query) -> Vec<String> {
    query
        .clauses
        .iter()
        .filter_map(|c| match c {
            Clause::Field(Constraint {
                field,
                comparison: Comparison::Text(_),
            }) => Some(field.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Geo operators
// ---------------------------------------------------------------------------------------------

/// The geo arms of `transformConstraint` (`MongoTransform.js:812-955`), as one loop.
///
/// **Reverse alphabetical key order is load-bearing** (`:670-675`): `$nearSphere` is visited before
/// any `$maxDistance*`, and the plain `$maxDistance` after the three suffixed spellings, so when
/// several are present the plain one is the distance that survives.
///
/// Two failure kinds, kept apart because the wire shows them apart. A structurally wrong operand
/// is upstream's `INVALID_JSON` with its message. A point whose coordinates are out of range is
/// `Parse.GeoPoint._validate` throwing a `TypeError`, which upstream does not catch, so it is a
/// bare 500.
fn geo_to_bson(pairs: &[(String, ParseValue)], count: bool) -> Result<Bson, ParseError> {
    let mut keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    keys.sort_unstable();
    keys.reverse();
    let get = |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    let mut answer = Document::new();
    for key in keys {
        let Some(value) = get(key) else { continue };
        match key {
            "$nearSphere" => {
                if matches!(value, ParseValue::Null) {
                    return Err(null_member("longitude"));
                }
                let (lon, lat) = (
                    js_member_number(value, "longitude"),
                    js_member_number(value, "latitude"),
                );
                if count {
                    // The raw `$maxDistance`, and only that spelling: upstream reads
                    // `constraint.$maxDistance` here, not the converted value.
                    let distance = get("$maxDistance").map_or(Bson::Null, geo_number);
                    answer.insert(
                        "$geoWithin",
                        doc! { "$centerSphere": [ [lon, lat], distance ] },
                    );
                } else {
                    answer.insert("$nearSphere", Bson::Array(vec![lon, lat]));
                }
            }
            "$maxDistance" => {
                if !count {
                    answer.insert("$maxDistance", geo_number(value));
                }
            }
            "$maxDistanceInRadians" => {
                answer.insert("$maxDistance", geo_number(value));
            }
            "$maxDistanceInMiles" => {
                answer.insert("$maxDistance", scaled(value, 3959.0));
            }
            "$maxDistanceInKilometers" => {
                answer.insert("$maxDistance", scaled(value, 6371.0));
            }
            "$within" => {
                let malformed = || ParseError::invalid_json("malformatted $within arg");
                let ParseValue::Object(within) = value else {
                    return Err(if matches!(value, ParseValue::Null) {
                        null_member("$box")
                    } else {
                        malformed()
                    });
                };
                let Some(ParseValue::Array(corners)) = within.get("$box") else {
                    return Err(malformed());
                };
                if corners.len() != 2 {
                    return Err(malformed());
                }
                if corners.iter().any(|c| matches!(c, ParseValue::Null)) {
                    return Err(null_member("longitude"));
                }
                let corner = |c: &ParseValue| {
                    Bson::Array(vec![
                        js_member_number(c, "longitude"),
                        js_member_number(c, "latitude"),
                    ])
                };
                answer.insert(
                    "$within",
                    doc! { "$box": [corner(&corners[0]), corner(&corners[1])] },
                );
            }
            "$geoWithin" => {
                if let Some(within) = geo_within(value)? {
                    answer.insert("$geoWithin", within);
                }
            }
            "$geoIntersects" => {
                let point = match value {
                    ParseValue::Null => return Err(null_member("$point")),
                    ParseValue::Object(m) => m.get("$point"),
                    _ => None,
                };
                let Some(point) = point.filter(|p| is_geo_point_json(p)) else {
                    return Err(ParseError::invalid_json(
                        "bad $geoIntersect value; $point should be GeoPoint",
                    ));
                };
                let (lat, lon) = validated_point(point)?;
                answer.insert(
                    "$geoIntersects",
                    doc! { "$geometry": { "type": "Point", "coordinates": [lon, lat] } },
                );
            }
            _ => {}
        }
    }
    Ok(Bson::Document(answer))
}

/// `$geoWithin` with either `$polygon` or `$centerSphere` (`MongoTransform.js:862-934`).
fn geo_within(value: &ParseValue) -> Result<Option<Bson>, ParseError> {
    let ParseValue::Object(within) = value else {
        return if matches!(value, ParseValue::Null) {
            Err(null_member("$polygon"))
        } else {
            Ok(None)
        };
    };
    if let Some(polygon) = within.get("$polygon") {
        let points: &Vec<ParseValue> = match polygon {
            // `typeof null === 'object'`, so the next test reads `null.__type`.
            ParseValue::Null => return Err(null_member("__type")),
            ParseValue::Object(p) if matches!(p.get("__type"), Some(ParseValue::String(t)) if t == "Polygon") => {
                match p.get("coordinates") {
                    Some(ParseValue::Array(c)) if c.len() >= 3 => c,
                    _ => {
                        return Err(ParseError::invalid_json(
                            "bad $geoWithin value; Polygon.coordinates should contain at least 3 lon/lat pairs",
                        ))
                    }
                }
            }
            ParseValue::Polygon(_) => {
                return Err(ParseError::invalid_json(
                    "bad $geoWithin value; Polygon.coordinates should contain at least 3 lon/lat pairs",
                ))
            }
            ParseValue::Array(items) => {
                if items.len() < 3 {
                    return Err(ParseError::invalid_json(
                        "bad $geoWithin value; $polygon should contain at least 3 GeoPoints",
                    ));
                }
                items
            }
            _ => {
                return Err(ParseError::invalid_json(
                    "bad $geoWithin value; $polygon should be Polygon object or Array of Parse.GeoPoint's",
                ))
            }
        };
        let mut out = Vec::with_capacity(points.len());
        for point in points {
            match point {
                // A `[lon, lat]` pair is validated as `(lat, lon)` and passed through unchanged.
                ParseValue::Array(pair) if pair.len() == 2 => {
                    validate_coordinates(js_number(&pair[1]), js_number(&pair[0]))?;
                    out.push(Bson::Array(pair.iter().map(geo_number).collect()));
                }
                p if is_geo_point_json(p) => {
                    let (lat, lon) = validated_point(p)?;
                    out.push(Bson::Array(vec![lon, lat]));
                }
                _ => return Err(ParseError::invalid_json("bad $geoWithin value")),
            }
        }
        return Ok(Some(Bson::Document(doc! { "$polygon": out })));
    }
    if let Some(center) = within.get("$centerSphere") {
        let ParseValue::Array(parts) = center else {
            return Err(ParseError::invalid_json(
                "bad $geoWithin value; $centerSphere should be an array of Parse.GeoPoint and distance",
            ));
        };
        if parts.len() < 2 {
            return Err(ParseError::invalid_json(
                "bad $geoWithin value; $centerSphere should be an array of Parse.GeoPoint and distance",
            ));
        }
        let (lat, lon) = match &parts[0] {
            ParseValue::Array(pair) if pair.len() == 2 => {
                let (lat, lon) = (js_number(&pair[1]), js_number(&pair[0]));
                validate_coordinates(lat, lon)?;
                (Bson::Double(lat), Bson::Double(lon))
            }
            p if is_geo_point_json(p) => validated_point(p)?,
            _ => {
                return Err(ParseError::invalid_json(
                    "bad $geoWithin value; $centerSphere geo point invalid",
                ))
            }
        };
        // `isNaN(distance) || distance < 0` coerces, so `"1"` and `null` pass; the value itself is
        // passed on uncoerced, and the database refuses what is not a number.
        let distance = parse_rust_core::js_number::to_number(&parts[1]);
        if distance.is_nan() || distance < 0.0 {
            return Err(ParseError::invalid_json(
                "bad $geoWithin value; $centerSphere distance invalid",
            ));
        }
        return Ok(Some(Bson::Document(
            doc! { "$centerSphere": [ [lon, lat], raw_scalar(&parts[1]) ] },
        )));
    }
    Ok(None)
}

/// `GeoPointCoder.isValidJSON`: an object whose `__type` is `GeoPoint`, nothing more.
fn is_geo_point_json(value: &ParseValue) -> bool {
    match value {
        ParseValue::GeoPoint { .. } => true,
        ParseValue::Object(m) => {
            matches!(m.get("__type"), Some(ParseValue::String(t)) if t == "GeoPoint")
        }
        _ => false,
    }
}

/// A recognized point's coordinates, through `Parse.GeoPoint._validate`.
fn validated_point(value: &ParseValue) -> Result<(Bson, Bson), ParseError> {
    let lat = js_number(&member(value, "latitude"));
    let lon = js_number(&member(value, "longitude"));
    validate_coordinates(lat, lon)?;
    Ok((Bson::Double(lat), Bson::Double(lon)))
}

/// `Parse.GeoPoint._validate`, which throws a `TypeError`: a bare 500 on the wire.
fn validate_coordinates(lat: f64, lon: f64) -> Result<(), ParseError> {
    if lat.is_nan() || lon.is_nan() {
        return Err(ParseError::internal(
            "GeoPoint latitude and longitude must be valid numbers",
        ));
    }
    if !(-90.0..=90.0).contains(&lat) {
        return Err(ParseError::internal(format!(
            "GeoPoint latitude out of bounds: {lat}"
        )));
    }
    if !(-180.0..=180.0).contains(&lon) {
        return Err(ParseError::internal(format!(
            "GeoPoint longitude out of bounds: {lon}"
        )));
    }
    Ok(())
}

/// `value[name]`, for a raw object or a decoded GeoPoint.
fn member(value: &ParseValue, name: &str) -> ParseValue {
    match (value, name) {
        (ParseValue::GeoPoint { latitude, .. }, "latitude") => ParseValue::Number(*latitude),
        (ParseValue::GeoPoint { longitude, .. }, "longitude") => ParseValue::Number(*longitude),
        (ParseValue::Object(m), _) => m.get(name).cloned().unwrap_or(ParseValue::Null),
        _ => ParseValue::Null,
    }
}

/// A coordinate as upstream reads it unchecked, `point.longitude`: the number, or `null` for
/// anything else, which the database then refuses.
fn js_member_number(value: &ParseValue, name: &str) -> Bson {
    geo_number(&member(value, name))
}

fn geo_number(value: &ParseValue) -> Bson {
    match value {
        ParseValue::Number(n) => Bson::Double(*n),
        _ => Bson::Null,
    }
}

/// `value / by`, which coerces: `"100" / 6371` is a distance and `true / 3959` is a tiny one.
fn scaled(value: &ParseValue, by: f64) -> Bson {
    Bson::Double(parse_rust_core::js_number::to_number(value) / by)
}

/// An operand upstream hands the database as it arrived. Only the scalar shapes are kept; the
/// database refuses anything that is not a number either way.
fn raw_scalar(value: &ParseValue) -> Bson {
    match value {
        ParseValue::Number(n) => Bson::Double(*n),
        ParseValue::String(s) => Bson::String(s.clone()),
        ParseValue::Bool(b) => Bson::Boolean(*b),
        _ => Bson::Null,
    }
}

/// Reading a member of `null`, which JavaScript throws as a `TypeError` that upstream does not
/// catch: a bare 500, raised while the query is built.
fn null_member(name: &str) -> ParseError {
    ParseError::internal(format!(
        "TypeError: Cannot read properties of null (reading '{name}')"
    ))
}

/// `Number(value)` for the operands geo validation reads, where a non-number is `NaN`.
fn js_number(value: &ParseValue) -> f64 {
    match value {
        ParseValue::Number(n) => *n,
        _ => f64::NAN,
    }
}

/// Insert a logical operator without letting a second one of the same name overwrite the first.
///
/// A query document is a map, so two producers of `$or` at one level would collide and one would
/// silently vanish, which broadens the result set. That is not hypothetical here: pointer
/// permissions compose disjunctively and can arrive alongside a client's own `$or`. Combining
/// under `$and` is the only lowering that preserves both.
fn insert_logical(filter: &mut Document, key: &str, branches: Vec<Bson>) {
    // Two `$and`s at one level are the same conjunction, so their branch lists concatenate.
    if key == "$and" {
        if let Some(Bson::Array(mut existing)) = filter.remove("$and") {
            existing.extend(branches);
            filter.insert("$and", Bson::Array(existing));
            return;
        }
        filter.insert("$and", Bson::Array(branches));
        return;
    }

    let Some(existing) = filter.remove(key) else {
        filter.insert(key, Bson::Array(branches));
        return;
    };

    let mut conjuncts: Vec<Bson> = match filter.remove("$and") {
        Some(Bson::Array(items)) => items,
        Some(other) => vec![other],
        None => Vec::new(),
    };
    let mut first = Document::new();
    first.insert(key, existing);
    let mut second = Document::new();
    second.insert(key, Bson::Array(branches));
    conjuncts.push(Bson::Document(first));
    conjuncts.push(Bson::Document(second));
    filter.insert("$and", Bson::Array(conjuncts));
}

/// Merge a new constraint into an existing filter entry for the same field.
fn merge_constraint(filter: &mut Document, key: String, entry: Bson) -> Result<(), ParseError> {
    match filter.remove(&key) {
        None => {
            filter.insert(key, entry);
        }
        Some(existing) => match (existing, entry) {
            // Two operator documents merge key-wise: `{$gt: 1}` plus `{$lt: 5}` is a range.
            (Bson::Document(mut a), Bson::Document(b)) => {
                for (k, v) in b {
                    a.insert(k, v);
                }
                filter.insert(key, Bson::Document(a));
            }
            // Anything involving a bare equality cannot merge: Mongo has no way to express
            // "equals 1 and equals 2", and silently keeping one would drop the other.
            _ => {
                return Err(ParseError::invalid_query(format!(
                    "conflicting constraints on field {key}"
                )))
            }
        },
    }
    Ok(())
}

/// Lower one comparison. Total over [`Comparison`], so adding a variant fails to compile here
/// rather than silently matching everything.
fn comparison_to_bson(schema: &ClassSchema, constraint: &Constraint) -> Result<Bson, ParseError> {
    // **Which converter an operand goes through is decided by the field, not by the operator**
    // (`MongoTransform.js:656-662`): `(inArray || isNestedKey) ? transformInteriorAtom :
    // transformTopLevelAtom`. An `Array`-typed field and a dotted key both hold *interior* values,
    // where a Pointer keeps its `__type` envelope instead of collapsing to `Class$id`.
    //
    // Using the top-level converter for everything is what made `{"who": {"$in": [<pointer>]}}` on
    // an array-of-pointers field answer 111 `a top-level Pointer is lowered by key, not by value`,
    // which is both a wrong answer to an ordinary `containedIn` and an internal sentence on the
    // wire. The stored elements carry the envelope, so the query operand has to as well or it
    // matches nothing even when it does not error.
    //
    // **There are three rules here, not one, and they disagree.** Reading only the constraint rule
    // and applying it everywhere is how shorthand equality on an `Array` field ended up interior
    // when upstream has it top-level:
    //
    // | position | rule | upstream |
    // |---|---|---|
    // | an operator inside a constraint document | `inArray \|\| isNestedKey` | `:660-662` |
    // | shorthand equality | `isNestedKey` **alone** | `:346-348` |
    // | `$all` | interior unconditionally | `:743` |
    //
    // The middle row looks like an oversight upstream and is not. The `Array` case never reaches
    // it: a non-array value on an `Array` field is taken by the `$all` wrap at `:341-343` above,
    // so by the time control arrives at `:346` the only array-field values left are arrays, and
    // those go top-level.
    let dotted = constraint.field.contains('.');
    let in_array = schema
        .field(&constraint.field)
        .is_some_and(|f| matches!(f, FieldType::Array));
    let constraint_position = if in_array || dotted {
        AtomPosition::Interior
    } else {
        AtomPosition::TopLevel
    };
    let shorthand_position = if dotted {
        AtomPosition::Interior
    } else {
        AtomPosition::TopLevel
    };
    // **Recognition happens here, not in the parser.** The operand arrives raw, with no `__type`
    // envelope interpreted at any depth, because which envelopes count depends on the field and
    // only this layer knows it. See `parse_rust_core::AtomPosition`.
    //
    // **`interior_query_atom_to_bson`, not `interior_value_to_bson`.** The two differ by the
    // nested-key guard, which belongs to writes alone: a query operand of `{"$regex": "^xy"}` is
    // what `containsAllStartingWith` sends, and refusing it with `INVALID_NESTED_KEY` turns a
    // legitimate query into a 121. Reaching for the write converter here is the same
    // shared-function mistake that put a compiled regex into a stored array, made in the opposite
    // direction: one function refused what the other must accept.
    let lower = |v: &ParseValue, position: AtomPosition| -> Result<Bson, ParseError> {
        let atom = recognize_atom(v.clone(), position);
        match position {
            AtomPosition::Interior => interior_query_atom_to_bson(&atom),
            AtomPosition::TopLevel => {
                // **The top-level position refuses a non-atom, and it is a different refusal from
                // the shorthand one.** `transformConstraint` wraps its chosen transform in
                // `transformer`, which turns `CannotTransform` into `bad atom: ${JSON.stringify}`
                // (`MongoTransform.js:663-669`). Shorthand equality reaches its own throw site
                // instead and says `You cannot use ${value} as a query parameter.` Same code, two
                // messages, decided by which of the two call sites the value arrived through.
                //
                // Note that the empty-collection exemption above does **not** apply here. That
                // exemption comes from `transformConstraint` returning early when the *constraint
                // document* has no keys, which says nothing about an operand: `{"$ne": {}}` is a
                // `bad atom: {}`. Measured at the pin.
                if matches!(atom, ParseValue::Object(_) | ParseValue::Array(_)) {
                    return Err(ParseError::invalid_json(format!(
                        "bad atom: {}",
                        atom.to_json()
                    )));
                }
                value_to_bson_for_query(schema, &constraint.field, &atom)
            }
        }
    };
    let value = |v: &ParseValue| -> Result<Bson, ParseError> { lower(v, constraint_position) };
    // `$in` and `$nin` flatten one level (`MongoTransform.js:721-735`): an element that is itself
    // an array contributes its own elements rather than nesting. Nothing else flattens.
    let flatten_each = |items: &Vec<ParseValue>| -> Result<Vec<Bson>, ParseError> {
        collect_deferring(items.iter().flat_map(|item| match item {
            ParseValue::Array(inner) => inner.iter().map(value).collect::<Vec<_>>(),
            other => vec![value(other)],
        }))
    };

    Ok(match &constraint.comparison {
        // **An empty collection is neither an atom nor an error, and it is answered before either
        // of the two arms below.** Upstream reaches shorthand equality only after
        // `transformConstraint` declines, and for `[]` or `{}` it does not decline: its key loop
        // simply does not run and it returns the empty answer document it started with
        // (`MongoTransform.js:672-676`, `:961`). So `{"tags": []}` and `{"meta": {}}` both lower to
        // `{field: {}}`, which is an **equality against an empty document**: it matches a row whose
        // field holds `{}` and nothing else. Not an absent constraint. An earlier version of this
        // note called it "matches every row", which is what an empty *constraint document* would
        // do if Mongo read it that way, and Mongo does not: probed against a live server, `{"meta":
        // {}}` returned only the row storing an empty object and `{"tags": []}` returned none.
        //
        // Order is the whole of it. Put this after the `$all` wrap and an empty object on an
        // `Array` field becomes `{$all: [{}]}`; lower it as an ordinary value and an empty array
        // becomes `{field: []}`, which matches only rows holding an empty array. Both narrow a
        // query upstream answers with everything. Measured at the pin.
        Comparison::Equal(ParseValue::Array(items)) if items.is_empty() => {
            Bson::Document(Document::new())
        }
        Comparison::Equal(ParseValue::Object(map)) if map.is_empty() => {
            Bson::Document(Document::new())
        }
        // **A non-array value equated with an Array-typed field means "the array contains it"**,
        // and upstream spells that out as `{$all: [transformInteriorAtom(value)]}`
        // (`MongoTransform.js:341-343`). For a scalar the wrap is equivalent to a bare equality,
        // because MongoDB already matches an array element against a scalar. For a **Pointer** it
        // is not equivalent at all: the interior transform keeps the `__type` envelope, which is
        // what an array of pointers actually stores, where the top-level path would try to lower
        // it to `"Class$id"` and refuse. `query.equalTo('tags', someObject)` errored with 111 here
        // for exactly that reason.
        Comparison::Equal(v)
            if matches!(schema.field(&constraint.field), Some(FieldType::Array))
                && !matches!(v, ParseValue::Array(_)) =>
        {
            operator("$all", Bson::Array(vec![lower(v, AtomPosition::Interior)?]))
        }
        // Shorthand equality takes the middle rule: the dotted-key test alone.
        //
        // **And in the top-level position it must be an atom.** `transformTopLevelAtom` returns
        // `CannotTransform` for a generic object or an array, and the caller turns that into
        // `INVALID_JSON` rather than a query (`MongoTransform.js:350-354`). The interior position
        // has no such refusal: its final arm is `return atom`, so a dotted key compares whatever it
        // was given.
        //
        // Accepting it instead is not a harmless extra: `{"meta": {"a": 1}}` upstream is a 107, and
        // here it was a query that ran and returned rows. A client testing for the error saw a
        // result set.
        Comparison::Equal(v) => {
            let atom = recognize_atom(v.clone(), shorthand_position);
            if shorthand_position == AtomPosition::TopLevel
                && matches!(atom, ParseValue::Object(_) | ParseValue::Array(_))
            {
                // `${value}` in a template literal, so an array joins on commas and any object
                // renders as `[object Object]`. `js_string` is the same coercion the `$regex`
                // path needs.
                return Err(ParseError::invalid_json(format!(
                    "You cannot use {} as a query parameter.",
                    parse_rust_core::js_number::to_ecma_display(&atom)
                )));
            }
            match shorthand_position {
                AtomPosition::Interior => interior_query_atom_to_bson(&atom)?,
                AtomPosition::TopLevel => {
                    value_to_bson_for_query(schema, &constraint.field, &atom)?
                }
            }
        }
        // Keeps the wrapper, which is what lets it share a field with another operator.
        Comparison::EqualOperator(v) => operator("$eq", value(v)?),
        Comparison::NotEqual(v) => operator("$ne", value(v)?),
        Comparison::GreaterThan(v) => operator("$gt", value(v)?),
        Comparison::GreaterThanOrEqual(v) => operator("$gte", value(v)?),
        Comparison::LessThan(v) => operator("$lt", value(v)?),
        Comparison::LessThanOrEqual(v) => operator("$lte", value(v)?),
        Comparison::In(items) => operator("$in", Bson::Array(flatten_each(items)?)),
        Comparison::NotIn(items) => operator("$nin", Bson::Array(flatten_each(items)?)),
        Comparison::Exists(b) => operator("$exists", Bson::Boolean(*b)),
        // `$all` maps its values through the *interior* atom transform, not the top-level one
        // (`MongoTransform.js:743`), so a nested pointer keeps its `__type` envelope here even
        // though the same pointer compared with `=` would collapse to `"Class$id"`.
        //
        // Upstream also raises `INVALID_JSON` `All $all values must be of regex type or none:
        // <values>` when some but not all of the values are regexes (`:746-751`). That is
        // reachable: an element is a regex when it is a `{"$regex": ...}` object, which is what
        // `containsAllStartingWith` sends. An earlier version of this comment called the branch
        // unreachable on the grounds that `ParseValue` has no regex variant, which is true of the
        // *variant* and irrelevant to the *shape*.
        Comparison::All(items) => {
            // Upstream maps every value first and checks the regexes after (`:743-751`). A NUL
            // in a pattern is refused only by the driver, later still, so it waits for the check.
            let mut lowered = Vec::with_capacity(items.len());
            let mut deferred = None;
            for item in items {
                match lower(item, AtomPosition::Interior) {
                    Ok(b) => lowered.push(b),
                    Err(e) if e.info.at_query => {
                        deferred.get_or_insert(e);
                    }
                    Err(e) => return Err(e),
                }
            }
            // `isAnyValueRegex` asks whether any value is a regex at all; `isAllValuesRegexOrNone`
            // asks whether they agree on being a **starts-with** regex, `/^\Q...\E/`
            // (`:143-169`). So a lone `^ba` is refused, every value a starts-with regex passes,
            // and a plain regex beside a plain value passes too, because neither starts with.
            let starts_with: Vec<Option<bool>> = items
                .iter()
                .map(|v| match v {
                    ParseValue::Object(m) => interior_regex(m).map(|p| is_starts_with_regex(&p)),
                    _ => None,
                })
                .collect();
            let any_regex = starts_with.iter().any(Option::is_some);
            let flags: Vec<bool> = starts_with.iter().map(|s| *s == Some(true)).collect();
            let all_or_none = match flags.as_slice() {
                [] => true,
                [only] => *only,
                [first, rest @ ..] => rest.iter().all(|f| f == first),
            };
            if any_regex && !all_or_none {
                // Upstream appends the values through JavaScript string concatenation, so the
                // message ends with the array rendered by `Array.prototype.join`
                // (`MongoTransform.js:746-751`). Dropping them made the message a prefix of
                // upstream's rather than upstream's.
                return Err(ParseError::invalid_json(format!(
                    "All $all values must be of regex type or none: {}",
                    items
                        .iter()
                        .map(js_join_element)
                        .collect::<Vec<_>>()
                        .join(",")
                )));
            }
            if let Some(e) = deferred {
                return Err(e);
            }
            operator("$all", Bson::Array(lowered))
        }
        // The pattern stays a **string**, not a compiled regex (`MongoTransform.js:755-761`), and
        // `$options` is a sibling key rather than a flag folded into it (`:773-775`). Compiling it
        // here would change the BSON type the driver sends.
        Comparison::Regex { pattern, options } => {
            let mut d = Document::new();
            d.insert("$regex", Bson::String(pattern.clone()));
            if let Some(options) = options {
                d.insert("$options", Bson::String(options.clone()));
            }
            Bson::Document(d)
        }
        // Lowered by `transform_where_as`, which knows whether the read is a count and where the
        // top level is.
        Comparison::Geo(pairs) => geo_to_bson(pairs, false)?,
        Comparison::Text(search) => text_to_bson(search)?,
    })
}

fn operator(op: &str, value: Bson) -> Bson {
    let mut d = Document::new();
    d.insert(op, value);
    Bson::Document(d)
}

/// `transformUpdate`: lower an update AST into a Mongo update document.
///
/// The operator mapping is `transformUpdateOperator` (`MongoTransform.js:974-1033`). Note the
/// asymmetry between `Add`/`AddUnique`, which wrap their values in `$each`, and `Remove`, which
/// does not: `$pullAll` takes a bare array.
pub fn transform_update(schema: &ClassSchema, update: &Update) -> Result<Document, ParseError> {
    let mut out = Document::new();

    for (key, op) in update {
        match op {
            UpdateValue::Set(value) => {
                // A Relation has no column; `field_to_column` returns `None` for it.
                if let Some((mongo_key, bson)) = field_to_column(schema, key, value)? {
                    push_op(&mut out, "$set", mongo_key, bson);
                }
            }
            UpdateValue::Increment(amount) => {
                push_op(
                    &mut out,
                    "$inc",
                    storage_key(schema, key),
                    to_bson_number(*amount),
                );
            }
            UpdateValue::SetOnInsert(value) => {
                // Through `field_to_column` like `Set`, because the value is an ordinary one and
                // a pointer written this way still belongs in its `_p_` column.
                if let Some((mongo_key, bson)) = field_to_column(schema, key, value)? {
                    push_op(&mut out, "$setOnInsert", mongo_key, bson);
                }
            }
            UpdateValue::Add(values) => {
                push_op(&mut out, "$push", storage_key(schema, key), each(values)?);
            }
            UpdateValue::AddUnique(values) => {
                push_op(
                    &mut out,
                    "$addToSet",
                    storage_key(schema, key),
                    each(values)?,
                );
            }
            UpdateValue::Remove(values) => {
                push_op(
                    &mut out,
                    "$pullAll",
                    storage_key(schema, key),
                    Bson::Array(interior_atoms(values)?),
                );
            }
            // The argument is the empty string, not `null` or `true`
            // (`MongoTransform.js:976-981`).
            UpdateValue::Unset => {
                push_op(
                    &mut out,
                    "$unset",
                    storage_key(schema, key),
                    Bson::String(String::new()),
                );
            }
        }
    }

    Ok(out)
}

fn interior_atoms(values: &[ParseValue]) -> Result<Vec<Bson>, ParseError> {
    values.iter().map(interior_value_to_bson).collect()
}

/// `{$each: [...]}`, the argument shape `$push` and `$addToSet` take.
fn each(values: &[ParseValue]) -> Result<Bson, ParseError> {
    let mut d = Document::new();
    d.insert("$each", Bson::Array(interior_atoms(values)?));
    Ok(Bson::Document(d))
}

/// Put one field under one Mongo update operator, creating the operator's sub-document once.
///
/// Order matters and is preserved on purpose: upstream assigns into `mongoUpdate[op][key]`
/// (`MongoTransform.js:524-530`), so an operator keeps the position of its first use rather than
/// moving to the end each time a field is added to it.
fn push_op(out: &mut Document, op: &str, key: String, value: Bson) {
    if let Ok(existing) = out.get_document_mut(op) {
        existing.insert(key, value);
        return;
    }
    let mut sub = Document::new();
    sub.insert(key, value);
    out.insert(op, sub);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_storage::FieldType;

    /// **The four columns whose stored form does not describe itself**, raised by declared type.
    ///
    /// The legacy `Bytes` row is the one no gate can reach: the data-fidelity differential writes
    /// through the SDK, which always produces BSON Binary, so a column holding the *string* form
    /// that an older parse-server wrote is only reachable by constructing the document. Since
    /// running against a database an existing deployment already populated is a requirement, the
    /// corpus that matters most is the one this project cannot generate for itself.
    #[test]
    fn ambiguous_columns_are_raised_by_their_declared_type() {
        let schema = ClassSchema::new("M")
            .with_field("pic", FieldType::File)
            .with_field("spot", FieldType::GeoPoint)
            .with_field("bin", FieldType::Bytes)
            .with_field("label", FieldType::String);

        let mut doc = Document::new();
        doc.insert("_id", "abc");
        doc.insert("pic", "avatar.png");
        doc.insert(
            "spot",
            Bson::Array(vec![Bson::Double(2.0), Bson::Double(1.0)]),
        );
        // The legacy shape: a base64 **string**, not BSON Binary. Deliberately *non-canonical*:
        // `AB==` is accepted by upstream's pattern and decodes to a byte whose re-encoding is
        // `AA==`, so a test using a canonical string like `aGk=` passes whether the string is
        // preserved or round-tripped through bytes and cannot tell the two apart.
        doc.insert("bin", "AB==");
        doc.insert("label", "avatar.png");

        let out = mongo_object_to_parse(&schema, &doc).expect("raise");
        assert!(
            matches!(out.get("pic"), Some(ParseValue::File { name, url: None }) if name == "avatar.png"),
            "{:?}",
            out.get("pic")
        );
        assert!(
            matches!(
                out.get("spot"),
                Some(ParseValue::GeoPoint { latitude, longitude })
                    if *latitude == 1.0 && *longitude == 2.0
            ),
            "{:?}",
            out.get("spot")
        );
        // The envelope, carrying the stored string exactly as written.
        assert_eq!(
            out.get("bin").map(ParseValue::to_json).as_deref(),
            Some(r#"{"__type":"Bytes","base64":"AB=="}"#),
            "a legacy Bytes string is preserved, not canonicalized"
        );
        // The control: an identical string in a `String` column stays a string, so the assertions
        // above are about the schema and not about the value.
        assert!(
            matches!(out.get("label"), Some(ParseValue::String(s)) if s == "avatar.png"),
            "{:?}",
            out.get("label")
        );

        // A `Bytes` column holding a string that is not valid base64 fails `isBase64Value` and
        // falls through to the ordinary raise rather than erroring, which is upstream's behavior.
        let mut doc = Document::new();
        doc.insert("_id", "abc");
        doc.insert("bin", "not base64!");
        let out = mongo_object_to_parse(&schema, &doc).expect("raise");
        assert!(
            matches!(out.get("bin"), Some(ParseValue::String(s)) if s == "not base64!"),
            "{:?}",
            out.get("bin")
        );
    }

    fn post_schema() -> ClassSchema {
        ClassSchema::new("Post")
            .with_field("title", FieldType::String)
            .with_field("views", FieldType::Number)
            .with_field(
                "author",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
    }

    fn map(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    #[test]
    fn renamed_keys_round_trip() {
        let s = post_schema();
        assert_eq!(storage_key(&s, "objectId"), "_id");
        assert_eq!(storage_key(&s, "createdAt"), "_created_at");
        assert_eq!(storage_key(&s, "updatedAt"), "_updated_at");
        assert_eq!(storage_key(&s, "title"), "title");
        assert_eq!(storage_key(&s, "author"), "_p_author");

        assert_eq!(untransform_key("_id").as_deref(), Some("objectId"));
        assert_eq!(untransform_key("_created_at").as_deref(), Some("createdAt"));
        assert_eq!(untransform_key("_p_author").as_deref(), Some("author"));
        assert_eq!(untransform_key("title"), None);
    }

    /// The rule Gate B exists to prove.
    #[test]
    fn integral_numbers_in_i32_range_store_as_int32() {
        assert_eq!(to_bson_number(0.0), Bson::Int32(0));
        assert_eq!(to_bson_number(42.0), Bson::Int32(42));
        assert_eq!(to_bson_number(-42.0), Bson::Int32(-42));
        assert_eq!(to_bson_number(i32::MAX as f64), Bson::Int32(i32::MAX));
        assert_eq!(to_bson_number(i32::MIN as f64), Bson::Int32(i32::MIN));
    }

    #[test]
    fn everything_else_stores_as_double() {
        assert_eq!(to_bson_number(1.5), Bson::Double(1.5));
        // Just past the i32 range, still integral.
        assert_eq!(
            to_bson_number(i32::MAX as f64 + 1.0),
            Bson::Double(i32::MAX as f64 + 1.0)
        );
        assert_eq!(to_bson_number(1e20), Bson::Double(1e20));
    }

    #[test]
    fn a_pointer_field_collapses_to_class_dollar_id() {
        let doc = parse_object_to_mongo_create(
            &post_schema(),
            &map(vec![(
                "author",
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "abc123".into(),
                },
            )]),
        )
        .expect("transform");
        assert_eq!(doc.get_str("_p_author").expect("_p_author"), "_User$abc123");
        assert!(
            !doc.contains_key("author"),
            "must not also store the raw key"
        );
    }

    /// UPSTREAM-QUIRK. A nested pointer keeps its full shape, because the collapse is a key
    /// transformation and an interior value has no key.
    #[test]
    fn a_nested_pointer_keeps_its_type_envelope() {
        let doc = parse_object_to_mongo_create(
            &post_schema(),
            &map(vec![(
                "tags",
                ParseValue::Array(vec![ParseValue::Pointer {
                    class_name: "Tag".into(),
                    object_id: "t1".into(),
                }]),
            )]),
        )
        .expect("transform");
        let arr = doc.get_array("tags").expect("tags");
        let nested = arr[0].as_document().expect("document");
        assert_eq!(nested.get_str("__type").expect("__type"), "Pointer");
        assert_eq!(nested.get_str("className").expect("className"), "Tag");
    }

    #[test]
    fn relation_values_are_dropped_not_stored() {
        let doc = parse_object_to_mongo_create(
            &post_schema(),
            &map(vec![
                ("title", ParseValue::String("x".into())),
                (
                    "comments",
                    ParseValue::Relation {
                        class_name: "Comment".into(),
                    },
                ),
            ]),
        )
        .expect("transform");
        assert!(doc.contains_key("title"));
        assert!(
            !doc.contains_key("comments"),
            "a Relation lives in a join table, not on the object"
        );
    }

    #[test]
    fn read_back_restores_keys_and_pointers() {
        let mut doc = Document::new();
        doc.insert("_id", "objid1");
        doc.insert("title", "hello");
        doc.insert("views", Bson::Int32(7));
        doc.insert("_p_author", "_User$abc123");
        doc.insert(
            "_created_at",
            Bson::DateTime(bson::DateTime::from_millis(1_700_000_000_000)),
        );

        let parsed = mongo_object_to_parse(&post_schema(), &doc).expect("untransform");
        assert!(matches!(parsed.get("objectId"), Some(ParseValue::String(s)) if s == "objid1"));
        assert!(matches!(parsed.get("views"), Some(ParseValue::Number(n)) if *n == 7.0));
        assert!(matches!(
            parsed.get("author"),
            Some(ParseValue::Pointer { class_name, object_id })
                if class_name == "_User" && object_id == "abc123"
        ));
        assert!(matches!(parsed.get("createdAt"), Some(ParseValue::Date(_))));
    }

    /// Regression: these used to be dropped here, which meant `raise_acl` never saw them and a
    /// stored ACL could never be returned to a client.
    #[test]
    fn permission_columns_survive_for_the_acl_rebuild() {
        let mut doc = Document::new();
        doc.insert("title", "x");
        doc.insert("_rperm", Bson::Array(vec![Bson::String("*".into())]));
        doc.insert("_wperm", Bson::Array(vec![]));
        doc.insert("_acl", Document::new());

        let parsed = mongo_object_to_parse(&post_schema(), &doc).expect("untransform");
        assert!(parsed.get("_rperm").is_some(), "raise_acl needs this");
        assert!(parsed.get("_wperm").is_some(), "raise_acl needs this");
        assert!(
            parsed.get("_acl").is_none(),
            "the legacy mirror is write-only and is dropped on read"
        );
    }

    #[test]
    fn internal_columns_survive_under_their_own_names() {
        // Login needs to read the hash. It must NOT come back as `password`, which is the name
        // upstream raises it under and the one a response filter then has to strip again.
        let mut doc = Document::new();
        doc.insert("_hashed_password", "$2b$10$abc");
        doc.insert("_session_token", "r:tok");
        let parsed = mongo_object_to_parse(&post_schema(), &doc).expect("untransform");
        assert!(parsed.get("_hashed_password").is_some());
        assert!(
            parsed.get("password").is_none(),
            "the hash must never be raised under a user-facing name"
        );
        // This one IS renamed, matching upstream.
        assert!(parsed.get("sessionToken").is_some());
    }

    #[test]
    fn an_unknown_underscore_key_is_refused_rather_than_passed_through() {
        let mut doc = Document::new();
        doc.insert("_mystery", "x"); // not in INTERNAL_COLUMNS
        let err = mongo_object_to_parse(&post_schema(), &doc).unwrap_err();
        assert!(err.message.contains("bad key in untransform"));
    }

    #[test]
    fn int64_and_int32_both_raise_to_one_number_type() {
        let mut doc = Document::new();
        doc.insert("a", Bson::Int32(1));
        doc.insert("b", Bson::Int64(2));
        doc.insert("c", Bson::Double(3.5));
        let parsed = mongo_object_to_parse(&post_schema(), &doc).expect("untransform");
        for (k, expected) in [("a", 1.0), ("b", 2.0), ("c", 3.5)] {
            assert!(matches!(parsed.get(k), Some(ParseValue::Number(n)) if *n == expected));
        }
    }
}

#[cfg(test)]
mod query_tree_tests {
    use super::*;
    use bson::doc;
    use parse_rust_storage::{Constraint, FieldType};

    fn post_schema() -> ClassSchema {
        ClassSchema::new("Post")
            .with_field("title", FieldType::String)
            .with_field("tags", FieldType::Array)
            .with_field(
                "author",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
    }

    fn map(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    fn eq(field: &str, value: &str) -> Query {
        Query::from_constraints(vec![Constraint::equal(
            field,
            ParseValue::String(value.into()),
        )])
    }

    #[test]
    fn a_disjunction_lowers_to_dollar_or() {
        let mut q = Query::new();
        q.push(Clause::Or(vec![eq("title", "a"), eq("title", "b")]));
        let out = transform_where(&post_schema(), &q).expect("lower");
        assert_eq!(out, doc! { "$or": [ { "title": "a" }, { "title": "b" } ] });
    }

    #[test]
    fn and_and_nor_lower_to_their_own_operators() {
        let mut q = Query::new();
        q.push(Clause::And(vec![eq("title", "a")]));
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "$and": [ { "title": "a" } ] }
        );

        let mut q = Query::new();
        q.push(Clause::Nor(vec![eq("title", "a")]));
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "$nor": [ { "title": "a" } ] }
        );
    }

    /// The key transform applies inside a branch exactly as it does at the top level. Getting this
    /// wrong makes a pointer permission's `$or` match nothing while looking correct.
    #[test]
    fn a_branch_gets_the_same_key_and_value_transform() {
        let author = ParseValue::Pointer {
            class_name: "_User".into(),
            object_id: "u1".into(),
        };
        let mut q = Query::new();
        q.push(Clause::Or(vec![
            Query::from_constraints(vec![Constraint::equal("author", author)]),
            Query::from_constraints(vec![Constraint::equal(
                "objectId",
                ParseValue::String("oid1".into()),
            )]),
        ]));
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "$or": [ { "_p_author": "_User$u1" }, { "_id": "oid1" } ] }
        );
    }

    /// A query document is a map, so two `$or`s at one level would collide. Losing one broadens
    /// the result set, which is an authorization failure rather than a cosmetic difference.
    #[test]
    fn two_disjunctions_at_one_level_combine_rather_than_overwrite() {
        let mut q = Query::new();
        q.push(Clause::Or(vec![eq("title", "a"), eq("title", "b")]));
        q.push(Clause::Or(vec![eq("title", "c"), eq("title", "d")]));
        let out = transform_where(&post_schema(), &q).expect("lower");

        assert!(
            !out.contains_key("$or"),
            "neither disjunction may survive alone"
        );
        let conjuncts = out.get_array("$and").expect("$and");
        assert_eq!(conjuncts.len(), 2);
        assert_eq!(
            conjuncts[0],
            Bson::Document(doc! { "$or": [ { "title": "a" }, { "title": "b" } ] })
        );
        assert_eq!(
            conjuncts[1],
            Bson::Document(doc! { "$or": [ { "title": "c" }, { "title": "d" } ] })
        );
    }

    #[test]
    fn two_conjunctions_at_one_level_concatenate() {
        let mut q = Query::new();
        q.push(Clause::And(vec![eq("title", "a")]));
        q.push(Clause::And(vec![eq("title", "b")]));
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "$and": [ { "title": "a" }, { "title": "b" } ] }
        );
    }

    /// An existing `$and` must absorb the collided pair rather than be replaced by it.
    #[test]
    fn a_collided_disjunction_joins_an_existing_conjunction() {
        let mut q = Query::new();
        q.push(Clause::And(vec![eq("title", "keep")]));
        q.push(Clause::Or(vec![eq("title", "a"), eq("title", "b")]));
        q.push(Clause::Or(vec![eq("title", "c"), eq("title", "d")]));
        let out = transform_where(&post_schema(), &q).expect("lower");
        let conjuncts = out.get_array("$and").expect("$and");
        assert_eq!(conjuncts.len(), 3, "the original conjunct must survive");
        assert_eq!(conjuncts[0], Bson::Document(doc! { "title": "keep" }));
    }

    #[test]
    fn repeated_constraints_on_one_field_still_merge() {
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "views".into(),
            comparison: Comparison::GreaterThan(ParseValue::Number(1.0)),
        });
        q.push_constraint(Constraint {
            field: "views".into(),
            comparison: Comparison::LessThan(ParseValue::Number(9.0)),
        });
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "views": { "$gt": 1, "$lt": 9 } }
        );
    }

    #[test]
    fn conflicting_equalities_on_one_field_are_an_error_not_a_silent_drop() {
        let mut q = Query::new();
        q.push_constraint(Constraint::equal("title", ParseValue::String("a".into())));
        q.push_constraint(Constraint::equal("title", ParseValue::String("b".into())));
        assert!(transform_where(&post_schema(), &q).is_err());
    }

    /// `$all` values go through the interior transform, so a nested pointer keeps its envelope.
    #[test]
    fn all_lowers_to_dollar_all_with_interior_atoms() {
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "tags".into(),
            comparison: Comparison::All(vec![
                ParseValue::String("a".into()),
                ParseValue::Pointer {
                    class_name: "Tag".into(),
                    object_id: "t1".into(),
                },
            ]),
        });
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "tags": { "$all": [
                "a",
                { "__type": "Pointer", "className": "Tag", "objectId": "t1" }
            ] } }
        );
    }

    /// **Which envelopes an operand may be rebuilt from is chosen by the field, not by the parser,
    /// and there are three rules rather than one.**
    ///
    /// This is the test the previous arrangement could not express, because the choice was made in
    /// `query_parse` where no schema exists. Picking one rule there is wrong in both directions,
    /// and the two directions fail differently: a top-level guess over-matches, an interior guess
    /// under-matches.
    ///
    /// A GeoPoint is the probe because it is on exactly one of the two lists. `transformInteriorAtom`
    /// recognizes Pointer, Date and Bytes (`MongoTransform.js:566-584`); `transformTopLevelAtom`
    /// recognizes every type (`:594-652`). So the same operand, with the same extra key, must be
    /// rebuilt in one position and compared whole in the other.
    #[test]
    fn the_atom_list_is_chosen_by_the_field_not_by_the_parser() {
        // As the parser now produces it: raw, no envelope interpreted, extra key intact.
        let raw_geo = || {
            ParseValue::Object(map(vec![
                ("__type", ParseValue::String("GeoPoint".into())),
                ("latitude", ParseValue::Number(1.0)),
                ("longitude", ParseValue::Number(2.0)),
                ("extra", ParseValue::Number(7.0)),
            ]))
        };
        let schema = ClassSchema::new("Place")
            .with_field("spot", FieldType::GeoPoint)
            .with_field("spots", FieldType::Array);

        // Top-level position: GeoPoint is on the list, so upstream rebuilds it from its declared
        // keys and `extra` is discarded. The stored form is the `[lng, lat]` pair.
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "spot".into(),
            comparison: Comparison::NotEqual(raw_geo()),
        });
        assert_eq!(
            transform_where(&schema, &q).expect("lower"),
            doc! { "spot": { "$ne": [2.0, 1.0] } },
            "a GeoPoint operand on a GeoPoint field is rebuilt, so the extra key cannot affect it"
        );

        // Interior position, reached here by the field being an Array. GeoPoint is **not** on the
        // interior list, so upstream leaves the object alone and compares it whole, `extra`
        // included. Recognizing it here would match a row upstream does not return.
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "spots".into(),
            comparison: Comparison::NotEqual(raw_geo()),
        });
        assert_eq!(
            transform_where(&schema, &q).expect("lower"),
            doc! { "spots": { "$ne": {
                "__type": "GeoPoint", "latitude": 1, "longitude": 2, "extra": 7
            } } },
            "an Array field takes the interior list, which has no GeoPoint on it"
        );
    }

    /// Shorthand equality follows the **dotted-key test alone**, not the constraint rule, and the
    /// two positions disagree about what is even allowed.
    ///
    /// `MongoTransform.js:346-348` is `key.includes('.') ? interior : topLevel`, with no `inArray`
    /// term, where the constraint rule at `:660-662` has one. That reads like an upstream oversight
    /// and is not: a non-array value on an `Array` field never reaches `:346`, because the `$all`
    /// wrap at `:341-343` takes it first.
    ///
    /// Every row below was measured against `transformWhere` at the pin, because the reasoning
    /// alone produced the wrong answer twice: an array under shorthand equality is not lowered
    /// top-level, it is **refused**, and an *empty* array is neither.
    #[test]
    fn shorthand_equality_refuses_what_is_not_an_atom() {
        let schema = ClassSchema::new("P")
            .with_field("tags", FieldType::Array)
            .with_field("meta", FieldType::Object);
        let lower = |field: &str, v: ParseValue| {
            let mut q = Query::new();
            q.push_constraint(Constraint {
                field: field.into(),
                comparison: Comparison::Equal(v),
            });
            transform_where(&schema, &q)
        };
        let obj = || ParseValue::Object(map(vec![("a", ParseValue::Number(1.0))]));

        // A generic object and a non-empty array are both `CannotTransform`, which the caller turns
        // into 107. The message renders the value the way a JS template literal does.
        for (field, value, rendered) in [
            ("meta", obj(), "[object Object]"),
            (
                "tags",
                ParseValue::Array(vec![ParseValue::Number(1.0)]),
                "1",
            ),
            (
                "meta",
                ParseValue::Array(vec![
                    ParseValue::Array(vec![ParseValue::Number(1.0), ParseValue::Number(2.0)]),
                    ParseValue::Number(3.0),
                ]),
                // JS flattens on the way to a string, so a nested array is not `1,2,3` by accident.
                "1,2,3",
            ),
            ("meta", ParseValue::Array(vec![obj()]), "[object Object]"),
        ] {
            let err = lower(field, value).expect_err("upstream refuses this");
            assert_eq!(err.code, parse_rust_core::ErrorCode::InvalidJson, "{err:?}");
            assert_eq!(
                err.message,
                format!("You cannot use {rendered} as a query parameter.")
            );
        }

        // The empty cases are answered before any of that, by a key loop that does not run. Both
        // spellings, on both field types, lower to `{field: {}}`, which is an equality against an
        // empty document rather than an absent constraint.
        for (field, value) in [
            ("tags", ParseValue::Array(Vec::new())),
            ("meta", ParseValue::Array(Vec::new())),
            ("tags", ParseValue::Object(ParseMap::new())),
            ("meta", ParseValue::Object(ParseMap::new())),
        ] {
            assert_eq!(
                lower(field, value).expect("an empty collection is not refused"),
                doc! { field: {} },
                "field {field}"
            );
        }

        // A dotted key takes the interior position, whose last arm is `return atom`. The same
        // object that is a 107 above is a legitimate comparison here.
        assert_eq!(
            lower("meta.a", obj()).expect("the interior position has no refusal"),
            doc! { "meta.a": { "a": 1 } }
        );

        // **`Relation` is not on the top-level list**, which is six tags and not seven.
        // `transformTopLevelAtom` has no `Relation` arm and no `RelationCoder`, so the envelope is
        // an ordinary object there and falls to the same refusal as any other one. Calling that
        // list "every Parse type" is wrong by exactly this entry, and this entry is reachable.
        let relation = ParseValue::Object(map(vec![
            ("__type", ParseValue::String("Relation".into())),
            ("className", ParseValue::String("X".into())),
        ]));
        let err = lower("meta", relation.clone()).expect_err("not an atom at the top level");
        assert_eq!(
            err.message,
            "You cannot use [object Object] as a query parameter."
        );
        // And under an operator, where the other throw site gives the other message.
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "meta".into(),
            comparison: Comparison::NotEqual(relation),
        });
        let err = transform_where(&schema, &q).expect_err("not an atom under an operator either");
        assert_eq!(
            err.message,
            r#"bad atom: {"__type":"Relation","className":"X"}"#
        );
    }

    /// The pattern stays a BSON string. A compiled regex is a different BSON type and a different
    /// set of supported flags.
    #[test]
    fn regex_lowers_to_a_string_pattern_and_a_string_options() {
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "title".into(),
            comparison: Comparison::Regex {
                pattern: "^foo".into(),
                options: Some("i".into()),
            },
        });
        let out = transform_where(&post_schema(), &q).expect("lower");
        assert_eq!(out, doc! { "title": { "$regex": "^foo", "$options": "i" } });
        assert!(matches!(
            out.get_document("title").expect("title").get("$regex"),
            Some(Bson::String(_))
        ));
    }

    #[test]
    fn regex_without_options_emits_no_options_key() {
        let mut q = Query::new();
        q.push_constraint(Constraint {
            field: "title".into(),
            comparison: Comparison::Regex {
                pattern: "^foo".into(),
                options: None,
            },
        });
        assert_eq!(
            transform_where(&post_schema(), &q).expect("lower"),
            doc! { "title": { "$regex": "^foo" } }
        );
    }

    #[test]
    fn an_empty_query_lowers_to_an_empty_document() {
        assert!(transform_where(&post_schema(), &Query::new())
            .expect("lower")
            .is_empty());
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;
    use bson::doc;
    use parse_rust_storage::FieldType;
    use parse_rust_storage::{Update, UpdateValue};

    fn session_schema() -> ClassSchema {
        ClassSchema::new("_Session")
            .with_field("sessionToken", FieldType::String)
            .with_field("expiresAt", FieldType::Date)
            .with_field("timesUsed", FieldType::Number)
            .with_field("counts", FieldType::Array)
            .with_field(
                "user",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
    }

    fn update(pairs: Vec<(&str, UpdateValue)>) -> Update {
        let mut u = Update::new();
        for (k, v) in pairs {
            u.insert(k.to_string(), v);
        }
        u
    }

    #[test]
    fn set_lowers_to_dollar_set_under_the_storage_key() {
        let out = transform_update(
            &session_schema(),
            &update(vec![
                (
                    "sessionToken",
                    UpdateValue::Set(ParseValue::String("r:tok".into())),
                ),
                (
                    "user",
                    UpdateValue::Set(ParseValue::Pointer {
                        class_name: "_User".into(),
                        object_id: "u1".into(),
                    }),
                ),
            ]),
        )
        .expect("lower");
        assert_eq!(
            out,
            doc! { "$set": { "_session_token": "r:tok", "_p_user": "_User$u1" } }
        );
    }

    #[test]
    fn increment_lowers_to_dollar_inc() {
        let out = transform_update(
            &session_schema(),
            &update(vec![("timesUsed", UpdateValue::Increment(1.0))]),
        )
        .expect("lower");
        // `times_used` has no leading underscore. That looks like a typo upstream and is not
        // (`MongoTransform.js:7-31`); a corrected name would be a column parse-server never reads.
        assert_eq!(out, doc! { "$inc": { "times_used": 1 } });
    }

    #[test]
    fn add_and_add_unique_wrap_their_values_in_each() {
        let out = transform_update(
            &session_schema(),
            &update(vec![(
                "counts",
                UpdateValue::Add(vec![ParseValue::Number(1.0), ParseValue::Number(2.0)]),
            )]),
        )
        .expect("lower");
        assert_eq!(out, doc! { "$push": { "counts": { "$each": [1, 2] } } });

        let out = transform_update(
            &session_schema(),
            &update(vec![(
                "counts",
                UpdateValue::AddUnique(vec![ParseValue::Number(1.0)]),
            )]),
        )
        .expect("lower");
        assert_eq!(out, doc! { "$addToSet": { "counts": { "$each": [1] } } });
    }

    /// The asymmetry worth a test: `$pullAll` takes a bare array, with no `$each` wrapper.
    #[test]
    fn remove_lowers_to_pull_all_with_no_each_wrapper() {
        let out = transform_update(
            &session_schema(),
            &update(vec![(
                "counts",
                UpdateValue::Remove(vec![ParseValue::Number(1.0)]),
            )]),
        )
        .expect("lower");
        assert_eq!(out, doc! { "$pullAll": { "counts": [1] } });
    }

    #[test]
    fn unset_lowers_to_the_empty_string_argument() {
        let out = transform_update(
            &session_schema(),
            &update(vec![("counts", UpdateValue::Unset)]),
        )
        .expect("lower");
        assert_eq!(out, doc! { "$unset": { "counts": "" } });
    }

    #[test]
    fn several_ops_group_under_their_operators_in_first_use_order() {
        let out = transform_update(
            &session_schema(),
            &update(vec![
                ("timesUsed", UpdateValue::Increment(1.0)),
                (
                    "sessionToken",
                    UpdateValue::Set(ParseValue::String("r:tok".into())),
                ),
                ("counts", UpdateValue::Add(vec![ParseValue::Number(1.0)])),
            ]),
        )
        .expect("lower");
        let keys: Vec<&str> = out.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["$inc", "$set", "$push"]);
    }

    /// A Relation lives in a join table, so an update naming one writes no column at all.
    #[test]
    fn a_relation_set_is_skipped_rather_than_stored() {
        let out = transform_update(
            &session_schema(),
            &update(vec![
                (
                    "members",
                    UpdateValue::Set(ParseValue::Relation {
                        class_name: "_User".into(),
                    }),
                ),
                (
                    "sessionToken",
                    UpdateValue::Set(ParseValue::String("r:tok".into())),
                ),
            ]),
        )
        .expect("lower");
        assert_eq!(out, doc! { "$set": { "_session_token": "r:tok" } });
    }

    /// A `_Session` row whose `expiresAt` is stored as a string never expires, because
    /// parse-server compares it as a Date.
    #[test]
    fn expires_at_is_coerced_to_a_bson_date_even_from_a_string() {
        let out = transform_update(
            &session_schema(),
            &update(vec![(
                "expiresAt",
                UpdateValue::Set(ParseValue::String("2026-08-14T13:34:33.581Z".into())),
            )]),
        )
        .expect("lower");
        let set = out.get_document("$set").expect("$set");
        assert!(
            matches!(set.get("expiresAt"), Some(Bson::DateTime(_))),
            "expiresAt must be a BSON Date, not a string"
        );
    }
}

#[cfg(test)]
mod session_and_relation_tests {
    use super::*;
    use parse_rust_storage::FieldType;

    fn session_schema() -> ClassSchema {
        ClassSchema::new("_Session")
            .with_field("sessionToken", FieldType::String)
            .with_field("expiresAt", FieldType::Date)
            .with_field("createdWith", FieldType::Object)
            .with_field("installationId", FieldType::String)
            .with_field("lastUsed", FieldType::Date)
            .with_field("timesUsed", FieldType::Number)
            .with_field(
                "user",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
    }

    fn map(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    /// Every `_Session` column, in both directions. A name that is wrong here produces a row
    /// parse-server reads as a session with no token, which fails open on nothing and fails closed
    /// on everything.
    #[test]
    fn session_columns_round_trip() {
        let schema = session_schema();
        let date = ParseDate::parse_iso("2026-08-14T13:34:33.581Z").expect("date");
        let row = map(vec![
            ("objectId", ParseValue::String("s000000001".into())),
            ("sessionToken", ParseValue::String("r:tok".into())),
            (
                "user",
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "u1".into(),
                },
            ),
            ("expiresAt", ParseValue::Date(date)),
            ("lastUsed", ParseValue::Date(date)),
            ("timesUsed", ParseValue::Number(3.0)),
            (
                "createdWith",
                ParseValue::Object(map(vec![("action", ParseValue::String("login".into()))])),
            ),
            ("installationId", ParseValue::String("inst1".into())),
        ]);

        let doc = parse_object_to_mongo_create(&schema, &row).expect("lower");
        assert_eq!(doc.get_str("_session_token").expect("token"), "r:tok");
        assert_eq!(doc.get_str("_p_user").expect("user"), "_User$u1");
        assert!(matches!(doc.get("expiresAt"), Some(Bson::DateTime(_))));
        assert!(matches!(doc.get("_last_used"), Some(Bson::DateTime(_))));
        assert!(doc.contains_key("times_used"), "no leading underscore");
        // Plain, no rename.
        assert!(doc.contains_key("createdWith"));
        assert!(doc.contains_key("installationId"));

        let back = mongo_object_to_parse(&schema, &doc).expect("raise");
        assert!(matches!(back.get("sessionToken"), Some(ParseValue::String(s)) if s == "r:tok"));
        assert!(matches!(
            back.get("user"),
            Some(ParseValue::Pointer { object_id, .. }) if object_id == "u1"
        ));
        assert!(matches!(back.get("lastUsed"), Some(ParseValue::Date(_))));
        assert!(matches!(back.get("timesUsed"), Some(ParseValue::Number(n)) if *n == 3.0));
        // UPSTREAM-QUIRK: `expiresAt` comes back as a full `{"__type":"Date"}` envelope while
        // `createdAt`, `updatedAt` and `lastUsed` come back as bare ISO strings
        // (`MongoTransform.js:1169-1187`). Both are `ParseValue::Date` here; the position-dependent
        // flattening happens once, at the response boundary, so there is one place to audit.
        assert!(matches!(back.get("expiresAt"), Some(ParseValue::Date(_))));
    }

    #[test]
    fn a_relation_field_is_synthesized_on_read_and_has_no_column() {
        let schema = ClassSchema::new("_Role")
            .with_field("name", FieldType::String)
            .with_field(
                "users",
                FieldType::Relation {
                    target_class: "_User".into(),
                },
            );

        let doc = parse_object_to_mongo_create(
            &schema,
            &map(vec![
                ("name", ParseValue::String("Admins".into())),
                (
                    "users",
                    ParseValue::Relation {
                        class_name: "_User".into(),
                    },
                ),
            ]),
        )
        .expect("lower");
        assert!(!doc.contains_key("users"), "a Relation has no column");

        let back = mongo_object_to_parse(&schema, &doc).expect("raise");
        assert!(matches!(
            back.get("users"),
            Some(ParseValue::Relation { class_name }) if class_name == "_User"
        ));
    }

    /// The synthesized Relation is spread *after* the document, so a stray stored key of the same
    /// name loses.
    #[test]
    fn a_stray_stored_column_does_not_beat_the_synthesized_relation() {
        let schema = ClassSchema::new("_Role").with_field(
            "users",
            FieldType::Relation {
                target_class: "_User".into(),
            },
        );
        let mut doc = Document::new();
        doc.insert("users", "leftover");
        let back = mongo_object_to_parse(&schema, &doc).expect("raise");
        assert!(matches!(
            back.get("users"),
            Some(ParseValue::Relation { class_name }) if class_name == "_User"
        ));
    }
}

#[cfg(test)]
mod eq_operator_tests {
    use super::*;
    use parse_rust_storage::{Clause, Comparison, Constraint, FieldType, Query};

    fn schema() -> ClassSchema {
        ClassSchema::new("Post")
            .with_field("views", FieldType::Number)
            .with_field("meta", FieldType::Object)
    }

    /// `containsAllStartingWith`, which is the SDK method behind `$all` full of `$regex` atoms
    /// (`ParseQuery.js:1162-1172`). `transformInteriorAtom` compiles each one into a real regular
    /// expression (`MongoTransform.js:580-581`); storing the `{"$regex": ...}` envelope as a
    /// subdocument instead matches nothing and answers 200, so nothing tells the caller the
    /// constraint was meaningless.
    #[test]
    fn an_all_of_regex_atoms_compiles_to_regular_expressions() {
        let mut regex = ParseMap::new();
        regex.insert(
            "$regex".to_string(),
            ParseValue::String("^\\Qba\\E".to_string()),
        );

        let mut query = Query::default();
        query.push(Clause::Field(Constraint {
            field: "tags".into(),
            comparison: Comparison::All(vec![ParseValue::Object(regex)]),
        }));

        let doc = transform_where(&schema(), &query).expect("lowers");
        let all = doc
            .get_document("tags")
            .expect("tags")
            .get_array("$all")
            .expect("$all");
        match &all[0] {
            Bson::RegularExpression(r) => {
                assert_eq!(r.pattern.as_str(), "^\\Qba\\E");
                // `new RegExp(atom.$regex)` passes no flags, so neither does this.
                assert_eq!(r.options.as_str(), "");
            }
            other => panic!("expected a regex, got {other:?}"),
        }
    }

    /// A regex atom with a NUL byte is an internal error the read path sanitizes, as upstream's is,
    /// and only once the `$all` check has passed: upstream's driver refuses it after that check.
    #[test]
    fn a_regex_atom_with_a_nul_byte_is_refused() {
        let all = |pattern: &str| {
            let mut regex = ParseMap::new();
            regex.insert(
                "$regex".to_string(),
                ParseValue::String(pattern.to_string()),
            );
            let mut query = Query::default();
            query.push(Clause::Field(Constraint {
                field: "tags".into(),
                comparison: Comparison::All(vec![ParseValue::Object(regex)]),
            }));
            transform_where(&schema(), &query).expect_err("refused")
        };

        let err = all("^\\Qa\0b\\E");
        assert_eq!(err.code, ParseError::internal("").code);
        // Raised by the query, not while building it, so the read path sanitizes it.
        assert!(!err.before_query().info.before_query);

        // Not a starts-with regex, so the `$all` check refuses it first.
        assert_eq!(all("a\0b").code, parse_rust_core::ErrorCode::InvalidJson);
    }

    /// A `$`-carrying nested key is refused on a write, and the query path still accepts one.
    ///
    /// Two properties in one test because they are the same decision seen from both sides. Putting
    /// the regex compile in the shared interior transform stored a BSON regular expression in an
    /// ordinary array, which `bson_to_parse_value` cannot decode, so the row became permanently
    /// unreadable and poisoned every query that returned it. Splitting the paths fixed the
    /// corruption; refusing the key is what matches upstream, whose `transformInteriorValue` throws
    /// `INVALID_NESTED_KEY` before any atom conversion (`MongoTransform.js:177-187`).
    ///
    /// This asserted only that the written value round-tripped, which was the safe half while the
    /// refusal was unimplemented. It now asserts the refusal itself.
    #[test]
    fn a_dollar_key_is_refused_on_a_write_and_accepted_on_a_query() {
        let mut regex = ParseMap::new();
        regex.insert("$regex".to_string(), ParseValue::String("^x".to_string()));
        let written = ParseValue::Array(vec![ParseValue::Object(regex.clone())]);

        let refused = interior_value_to_bson(&written).expect_err("a write must refuse it");
        assert_eq!(refused.code, parse_rust_core::ErrorCode::InvalidNestedKey);
        assert_eq!(
            refused.message,
            "Nested keys should not contain the '$' or '.' characters"
        );

        // A dotted key is the other half of the same rule.
        let mut dotted = ParseMap::new();
        dotted.insert("a.b".to_string(), ParseValue::Number(1.0));
        assert_eq!(
            interior_value_to_bson(&ParseValue::Object(dotted))
                .expect_err("a dotted key is refused too")
                .code,
            parse_rust_core::ErrorCode::InvalidNestedKey
        );

        // The query path must still compile it: that is what a constraint looks like, and it is
        // why the guard cannot live in a function the two share.
        let queried = interior_query_atom_to_bson(&ParseValue::Object(regex)).expect("compiles");
        assert!(
            matches!(queried, Bson::RegularExpression(_)),
            "a query atom still becomes a regex: {queried:?}"
        );
    }

    /// `RegExp.prototype.source` and the starts-with test, against values measured in Node.
    #[test]
    fn regex_source_and_starts_with_match_v8() {
        for (pattern, source, starts_with) in [
            ("[/]", "[/]", false),
            ("\\/", "\\/", false),
            ("a/b", "a\\/b", false),
            ("[\\]/]", "[\\]/]", false),
            ("^\\Qa/\\E", "^\\Qa\\/\\E", true),
            ("^\\Qa\\E", "^\\Qa\\E", true),
            ("x^\\Qa\\E/", "x^\\Qa\\E\\/", false),
            ("\\Q", "\\Q", false),
            ("a\nb", "a\\nb", false),
            ("", "(?:)", false),
            ("^\\Qa[/]\\E", "^\\Qa[/]\\E", true),
            ("^\\Qa\\/\\E", "^\\Qa\\/\\E", true),
            ("[[/]", "[[/]", false),
            ("^\\Qa\\E\\/x", "^\\Qa\\E\\/x", false),
            ("a[/^\\Qx\\E/]", "a[/^\\Qx\\E/]", true),
        ] {
            assert_eq!(js_regex_source(pattern), source, "{pattern:?}");
            assert_eq!(is_starts_with_regex(pattern), starts_with, "{pattern:?}");
        }
    }

    /// Upstream's all-or-none rule (`MongoTransform.js:143-169`, `:746-751`), which is about
    /// **starts-with** regexes, not regexes: the values must agree on being `/^\Q...\E/`, and a
    /// lone value must be one.
    #[test]
    fn an_all_mixing_regexes_and_plain_values_is_refused() {
        let regex = |pattern: &str| {
            let mut m = ParseMap::new();
            m.insert(
                "$regex".to_string(),
                ParseValue::String(pattern.to_string()),
            );
            ParseValue::Object(m)
        };
        let plain = || ParseValue::String("plain".to_string());
        let lower = |values: Vec<ParseValue>| {
            let mut query = Query::default();
            query.push(Clause::Field(Constraint {
                field: "tags".into(),
                comparison: Comparison::All(values),
            }));
            transform_where(&schema(), &query)
        };

        let refused = |values| lower(values).expect_err("refused").code;
        assert_eq!(
            refused(vec![regex("^\\Qba\\E"), plain()]),
            parse_rust_core::ErrorCode::InvalidJson
        );
        assert_eq!(
            refused(vec![regex("^ba")]),
            parse_rust_core::ErrorCode::InvalidJson
        );
        assert_eq!(
            refused(vec![regex("^\\Qba\\E"), regex("^ba")]),
            parse_rust_core::ErrorCode::InvalidJson
        );

        lower(vec![regex("^\\Qa\\E"), regex("^\\Qb\\E")]).expect("all starts-with");
        // Neither value is a starts-with regex, so they agree.
        lower(vec![regex("^ba"), plain()]).expect("none starts-with");
    }

    /// A bare objectId string against a Pointer field has to acquire the class prefix from the
    /// **schema**, since the string carries none (`MongoTransform.js:600-603`). Without it the
    /// comparison is against an unprefixed id, which matches no stored value.
    #[test]
    fn a_bare_object_id_is_prefixed_for_a_pointer_field() {
        let schema = ClassSchema::new("Comment").with_field(
            "author",
            FieldType::Pointer {
                target_class: "_User".to_string(),
            },
        );

        for comparison in [
            Comparison::Equal(ParseValue::String("abc123".into())),
            Comparison::NotEqual(ParseValue::String("abc123".into())),
            Comparison::In(vec![ParseValue::String("abc123".into())]),
        ] {
            let mut query = Query::default();
            query.push(Clause::Field(Constraint {
                field: "author".into(),
                comparison,
            }));
            let doc = transform_where(&schema, &query).expect("lowers");
            let rendered = format!("{doc:?}");
            assert!(
                rendered.contains("_User$abc123"),
                "the id must be prefixed with the declared target class: {rendered}"
            );
        }
    }

    /// The three types `transformInteriorAtom` does not recognise keep their `__type` envelope,
    /// because upstream's chain falls through to `return atom`. Converting them to their
    /// top-level storage forms is a stored-format divergence a mixed fleet reads as disagreement
    /// about the column's contents.
    #[test]
    fn a_nested_geopoint_is_stored_as_its_envelope_rather_than_a_coordinate_pair() {
        let nested = ParseValue::Array(vec![ParseValue::GeoPoint {
            latitude: 1.0,
            longitude: 2.0,
        }]);
        let Bson::Array(items) = interior_value_to_bson(&nested).expect("lowers") else {
            panic!("expected an array");
        };
        let doc = match &items[0] {
            Bson::Document(d) => d,
            other => panic!("a nested GeoPoint must stay an object, got {other:?}"),
        };
        assert_eq!(doc.get_str("__type").ok(), Some("GeoPoint"));
    }

    /// `equalTo` on an Array-typed field means "the array contains this", which upstream writes as
    /// `$all` with one element (`MongoTransform.js:341-343`). The Pointer case is the one that was
    /// broken: the top-level path refuses a Pointer by value, so this errored 111 rather than
    /// running the query the SDK asked for.
    #[test]
    fn equality_against_an_array_field_becomes_a_single_element_all() {
        let schema = ClassSchema::new("Post").with_field("tags", FieldType::Array);

        let mut query = Query::default();
        query.push(Clause::Field(Constraint {
            field: "tags".into(),
            comparison: Comparison::Equal(ParseValue::Pointer {
                class_name: "Tag".into(),
                object_id: "t1".into(),
            }),
        }));
        let doc = transform_where(&schema, &query).expect("a pointer against an array field");
        let all = doc
            .get_document("tags")
            .expect("tags")
            .get_array("$all")
            .expect("$all");
        // The interior form, so the envelope survives: an array of pointers stores the envelope
        // rather than the `Class$id` collapse, which is a key transformation.
        let Bson::Document(pointer) = &all[0] else {
            panic!("expected the pointer envelope, got {:?}", all[0]);
        };
        assert_eq!(pointer.get_str("__type").ok(), Some("Pointer"));
        assert_eq!(pointer.get_str("objectId").ok(), Some("t1"));

        // **An array value is refused, not lowered.** This assertion used to read "an array value
        // is left alone: it is an equality against the whole array", which is the inference the
        // shape invites and is not what upstream does. The `$all` wrap above is reached only for a
        // non-array value; an array falls through to `transformTopLevelAtom`, which cannot
        // transform it, and the caller raises 107 (`MongoTransform.js:346-354`). Measured at the
        // pin: `{tags: ["a"]}` answers `You cannot use a as a query parameter.`
        let mut query = Query::default();
        query.push(Clause::Field(Constraint {
            field: "tags".into(),
            comparison: Comparison::Equal(ParseValue::Array(vec![ParseValue::String("a".into())])),
        }));
        let err = transform_where(&schema, &query).expect_err("upstream refuses this");
        assert_eq!(err.code, parse_rust_core::ErrorCode::InvalidJson);
        assert_eq!(err.message, "You cannot use a as a query parameter.");
    }

    /// The layer the mixed-constraint rewrite was being undone at.
    ///
    /// `replaceEquality` turns `{"meta": {"foo": 1, "$gt": 0}}` into an `$eq` plus a `$gt`. If
    /// `$eq` lowers to a bare value the way ordinary equality does, the two constraints become
    /// `{meta: {foo: 1}}` and `{meta: {$gt: 0}}`, and merging them for one field rebuilds the very
    /// document the rewrite existed to take apart. The parse-level test cannot see that, because
    /// everything is still correct when it runs.
    #[test]
    fn an_eq_keeps_its_wrapper_and_composes_with_another_operator() {
        let mut query = Query::default();
        query.push(Clause::Field(Constraint {
            field: "views".into(),
            comparison: Comparison::EqualOperator(ParseValue::Number(5.0)),
        }));
        query.push(Clause::Field(Constraint {
            field: "views".into(),
            comparison: Comparison::GreaterThan(ParseValue::Number(1.0)),
        }));

        let doc = transform_where(&schema(), &query).expect("lowers");
        let views = doc
            .get_document("views")
            .expect("one document for the field");
        assert_eq!(
            views
                .get_i32("$eq")
                .or(views.get_f64("$eq").map(|v| v as i32))
                .ok(),
            Some(5)
        );
        assert!(
            views.contains_key("$gt"),
            "both operators survive: {views:?}"
        );
    }

    /// Bare equality still lowers to the value itself, with no wrapper. This is the half that must
    /// not change: upstream emits the raw value for the shorthand form.
    #[test]
    fn bare_equality_still_lowers_without_a_wrapper() {
        let mut query = Query::default();
        query.push(Clause::Field(Constraint {
            field: "views".into(),
            comparison: Comparison::Equal(ParseValue::Number(5.0)),
        }));

        let doc = transform_where(&schema(), &query).expect("lowers");
        assert!(
            doc.get_document("views").is_err(),
            "shorthand equality is a plain value, not an operator document: {doc:?}"
        );
    }

    // -----------------------------------------------------------------------------------------
    // Geo and $text
    // -----------------------------------------------------------------------------------------

    fn geo_query(field: &str, json: &str) -> Query {
        let pairs: Vec<(String, ParseValue)> =
            match serde_json::from_str::<serde_json::Value>(json).expect("json") {
                serde_json::Value::Object(m) => m
                    .into_iter()
                    .map(|(k, v)| (k, parse_rust_core::classify_raw(v).expect("raw")))
                    .collect(),
                _ => panic!("object"),
            };
        Query::from_constraints(vec![Constraint {
            field: field.into(),
            comparison: Comparison::Geo(pairs),
        }])
    }

    /// `$nearSphere` precedes `$maxDistance`, and a count rewrites it into `$geoWithin` using the
    /// raw distance (`MongoTransform.js:812-827`).
    #[test]
    fn near_sphere_lowers_for_a_find_and_rewrites_for_a_count() {
        let schema = ClassSchema::new("P").with_field("loc", FieldType::GeoPoint);
        let q = geo_query(
            "loc",
            r#"{"$nearSphere":{"__type":"GeoPoint","latitude":1,"longitude":2},"$maxDistance":0.5}"#,
        );
        let find = transform_where(&schema, &q).expect("find");
        assert_eq!(
            find.get_document("loc").expect("loc"),
            &doc! { "$nearSphere": [2.0, 1.0], "$maxDistance": 0.5 }
        );
        let count = transform_where_for_count(&schema, &q).expect("count");
        assert_eq!(
            count.get_document("loc").expect("loc"),
            &doc! { "$geoWithin": { "$centerSphere": [[2.0, 1.0], 0.5] } }
        );
    }

    #[test]
    fn a_distance_in_miles_or_kilometers_is_converted_to_radians() {
        let schema = ClassSchema::new("P").with_field("loc", FieldType::GeoPoint);
        let q = geo_query(
            "loc",
            r#"{"$nearSphere":{"__type":"GeoPoint","latitude":0,"longitude":0},"$maxDistanceInKilometers":6371}"#,
        );
        let find = transform_where(&schema, &q).expect("find");
        assert_eq!(
            find.get_document("loc")
                .expect("loc")
                .get_f64("$maxDistance")
                .ok(),
            Some(1.0)
        );
    }

    /// Structural refusals are 107 with upstream's message; an out-of-range point is the SDK's
    /// `TypeError`, a bare 500.
    #[test]
    fn geo_within_polygon_refusals_match_upstream() {
        let schema = ClassSchema::new("P").with_field("loc", FieldType::GeoPoint);
        let short = geo_query("loc", r#"{"$geoWithin":{"$polygon":[[0,0],[1,1]]}}"#);
        let e = transform_where(&schema, &short).expect_err("two points");
        assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidJson);
        assert_eq!(
            e.message,
            "bad $geoWithin value; $polygon should contain at least 3 GeoPoints"
        );
        let bad = geo_query(
            "loc",
            r#"{"$geoWithin":{"$polygon":[{"__type":"GeoPoint","latitude":100,"longitude":0},[0,0],[1,1]]}}"#,
        );
        let e = transform_where(&schema, &bad).expect_err("latitude 100");
        assert_eq!(e.code, parse_rust_core::ErrorCode::InternalServerError);
    }

    /// `$text` leaves its field and goes to the top of the filter, where Mongo requires it.
    #[test]
    fn text_is_lifted_to_the_top_level() {
        let schema = ClassSchema::new("P").with_field("subject", FieldType::String);
        let operand = parse_rust_core::classify_raw(
            serde_json::from_str(r#"{"$search":{"$term":"coffee","$caseSensitive":true}}"#)
                .expect("json"),
        )
        .expect("raw");
        let q = Query::from_constraints(vec![Constraint {
            field: "subject".into(),
            comparison: Comparison::Text(operand),
        }]);
        let out = transform_where(&schema, &q).expect("lower");
        assert_eq!(
            out,
            doc! { "$text": { "$search": "coffee", "$caseSensitive": true } }
        );
        let bad = parse_rust_core::classify_raw(serde_json::json!({"$search": {"$term": 5}}))
            .expect("raw");
        let q = Query::from_constraints(vec![Constraint {
            field: "subject".into(),
            comparison: Comparison::Text(bad),
        }]);
        assert_eq!(
            transform_where(&schema, &q)
                .expect_err("non-string term")
                .message,
            "bad $text: $term, should be string"
        );
    }
}
