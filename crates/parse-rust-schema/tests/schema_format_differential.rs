//! Our `_SCHEMA` type strings against what parse-server actually writes to MongoDB.
//!
//! Read from a real database rather than from the source, because `_SCHEMA` is shared with any
//! parse-server pointed at the same data and both of its failure modes are silent: an unknown key
//! becomes a phantom field, and an unknown type string becomes `undefined` with no error.
//!
//! `#[ignore]` because it needs node, the upstream checkout, and a MongoDB on 27017. Run via
//! `tools/test.sh`.

use std::collections::BTreeMap;
use std::process::Command;

use parse_rust_schema::storage_format::{field_type_to_storage, NON_FIELD_KEYS};
use parse_rust_schema::FieldType;

#[test]
#[ignore = "requires node, the upstream checkout, and MongoDB; run via tools/test.sh"]
fn our_schema_strings_match_what_parse_server_writes() {
    let oracle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/schema-format-oracle.js"
    );
    let out = Command::new("node")
        // Editors inject a debug bootloader through NODE_OPTIONS, which makes every node process
        // wait for a debugger and hang. A test must not inherit that.
        .env_remove("NODE_OPTIONS")
        .arg(oracle)
        .output()
        .expect("node must be on PATH; this test is #[ignore]d by default");
    assert!(
        out.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // parse-server writes warnings to stdout, so the payload is marked rather than assumed to
    // be the whole stream.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload = stdout
        .lines()
        .find_map(|l| l.strip_prefix("SCHEMA_JSON "))
        .unwrap_or_else(|| panic!("oracle emitted no SCHEMA_JSON line:\n{stdout}"));
    let doc: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(payload).expect("oracle emitted JSON");

    // What we would write for each probe field.
    let ours: BTreeMap<&str, String> = [
        ("aString", FieldType::String),
        ("aNumber", FieldType::Number),
        ("aBoolean", FieldType::Boolean),
        ("aDate", FieldType::Date),
        ("anArray", FieldType::Array),
        ("anObject", FieldType::Object),
        ("aGeoPoint", FieldType::GeoPoint),
        ("aFile", FieldType::File),
        ("aPolygon", FieldType::Polygon),
        ("someBytes", FieldType::Bytes),
        (
            "aPointer",
            FieldType::Pointer {
                target_class: "Target".into(),
            },
        ),
        (
            "aRelation",
            FieldType::Relation {
                target_class: "Target".into(),
            },
        ),
    ]
    .into_iter()
    .map(|(k, ty)| (k, field_type_to_storage(&ty)))
    .collect();

    let mut mismatches = Vec::new();
    for (field, expected) in &ours {
        match doc.get(*field).and_then(|v| v.as_str()) {
            Some(theirs) if theirs == expected => {}
            Some(theirs) => {
                mismatches.push(format!("  {field}: node {theirs:?}, rust {expected:?}"))
            }
            None => mismatches.push(format!(
                "  {field}: absent from the written _SCHEMA (rust would write {expected:?})"
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "_SCHEMA type strings diverge:\n{}",
        mismatches.join("\n")
    );

    // Default columns, measured rather than assumed. Three of the four ARE written into the
    // stored document; only `ACL` is not, because `mongoSchemaFieldsToParseSchemaFields` injects
    // it on read. An earlier draft of this test asserted all four were absent and was wrong.
    for (name, expected) in [
        ("objectId", "string"),
        ("createdAt", "date"),
        ("updatedAt", "date"),
    ] {
        assert_eq!(
            doc.get(name).and_then(|v| v.as_str()),
            Some(expected),
            "{name} must be stored, and as {expected:?}"
        );
    }
    assert!(
        !doc.contains_key("ACL"),
        "ACL is injected on read and must never be a stored _SCHEMA key: writing one would be \
         the phantom-column failure the rule forbids"
    );

    // Anything else parse-server writes that is not a field is a key we must know about, because
    // our own writer has to preserve it rather than dropping it on a rewrite.
    let known_defaults = ["objectId", "createdAt", "updatedAt"];
    let unexpected: Vec<&String> = doc
        .keys()
        .filter(|k| {
            !NON_FIELD_KEYS.contains(&k.as_str())
                && !ours.contains_key(k.as_str())
                && !known_defaults.contains(&k.as_str())
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "parse-server wrote _SCHEMA keys this project does not model: {unexpected:?}"
    );
}
