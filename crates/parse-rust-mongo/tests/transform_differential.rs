//! Our Parse-to-BSON transform against upstream's actual `MongoTransform`.
//!
//! `MongoTransform.js` is pure and its two directions are exported, so this compares against the
//! real function rather than against a reading of it. That is a stronger oracle than the spec
//! suite for this particular layer: the specs exercise the transform only through a running
//! server, so a type-level difference like Int32 versus Double is invisible to them.
//!
//! Comparison is in canonical Extended JSON, which is what makes BSON types visible at all.
//!
//! `#[ignore]` because it shells out to node and needs the upstream checkout. Run via
//! `tools/test.sh`.

use std::io::Write;
use std::process::{Command, Stdio};

use parse_rust_core::{ParseDate, ParseMap, ParseValue};
use parse_rust_mongo::transform::parse_object_to_mongo_create;
use parse_rust_storage::{ClassSchema, FieldType};

/// One differential case: the same input handed to both implementations.
struct Case {
    name: &'static str,
    schema: ClassSchema,
    object: ParseMap,
    /// The Parse-format object as the upstream function expects it.
    object_json: serde_json::Value,
}

fn m(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
    let mut map = ParseMap::new();
    for (k, v) in pairs {
        map.insert(k.to_string(), v);
    }
    map
}

/// Upstream takes `schema` as `{fields: {name: {type, targetClass}}}`.
fn schema_json(schema: &ClassSchema) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    for (name, ty) in &schema.fields {
        let mut entry = serde_json::Map::new();
        match ty {
            FieldType::Pointer { target_class } => {
                entry.insert("type".into(), "Pointer".into());
                entry.insert("targetClass".into(), target_class.clone().into());
            }
            other => {
                entry.insert("type".into(), other.to_wire_string().into());
            }
        }
        fields.insert(name.clone(), serde_json::Value::Object(entry));
    }
    serde_json::json!({ "fields": fields })
}

fn cases() -> Vec<Case> {
    let post = ClassSchema::new("Post")
        .with_field("title", FieldType::String)
        .with_field("views", FieldType::Number)
        .with_field("live", FieldType::Boolean)
        .with_field("when", FieldType::Date)
        .with_field("tags", FieldType::Array)
        .with_field("meta", FieldType::Object)
        .with_field(
            "author",
            FieldType::Pointer {
                target_class: "_User".into(),
            },
        );

    let iso = "2026-08-14T13:34:33.581Z";
    let date = ParseDate::parse_iso(iso).expect("test date");

    vec![
        Case {
            name: "strings and booleans",
            schema: post.clone(),
            object: m(vec![
                ("title", ParseValue::String("hello".into())),
                ("live", ParseValue::Bool(true)),
            ]),
            object_json: serde_json::json!({ "title": "hello", "live": true }),
        },
        Case {
            name: "integral number stores as Int32",
            schema: post.clone(),
            object: m(vec![("views", ParseValue::Number(7.0))]),
            object_json: serde_json::json!({ "views": 7 }),
        },
        Case {
            name: "zero stores as Int32",
            schema: post.clone(),
            object: m(vec![("views", ParseValue::Number(0.0))]),
            object_json: serde_json::json!({ "views": 0 }),
        },
        Case {
            name: "negative integral stores as Int32",
            schema: post.clone(),
            object: m(vec![("views", ParseValue::Number(-42.0))]),
            object_json: serde_json::json!({ "views": -42 }),
        },
        Case {
            name: "i32 boundary stores as Int32",
            schema: post.clone(),
            object: m(vec![("views", ParseValue::Number(i32::MAX as f64))]),
            object_json: serde_json::json!({ "views": i32::MAX }),
        },
        Case {
            name: "just past i32 stores as Double",
            schema: post.clone(),
            object: m(vec![("views", ParseValue::Number(i32::MAX as f64 + 1.0))]),
            object_json: serde_json::json!({ "views": i32::MAX as f64 + 1.0 }),
        },
        Case {
            name: "fractional stores as Double",
            schema: post.clone(),
            object: m(vec![("views", ParseValue::Number(1.5))]),
            object_json: serde_json::json!({ "views": 1.5 }),
        },
        Case {
            name: "date becomes a BSON date",
            schema: post.clone(),
            object: m(vec![("when", ParseValue::Date(date))]),
            object_json: serde_json::json!({ "when": { "__type": "Date", "iso": iso } }),
        },
        Case {
            name: "declared pointer collapses to Class$id",
            schema: post.clone(),
            object: m(vec![(
                "author",
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "abc123".into(),
                },
            )]),
            object_json: serde_json::json!({
                "author": { "__type": "Pointer", "className": "_User", "objectId": "abc123" }
            }),
        },
        Case {
            name: "array of scalars",
            schema: post.clone(),
            object: m(vec![(
                "tags",
                ParseValue::Array(vec![
                    ParseValue::String("a".into()),
                    ParseValue::Number(2.0),
                    ParseValue::Bool(false),
                ]),
            )]),
            object_json: serde_json::json!({ "tags": ["a", 2, false] }),
        },
        Case {
            name: "nested object keeps its shape",
            schema: post.clone(),
            object: m(vec![(
                "meta",
                ParseValue::Object(m(vec![
                    ("k", ParseValue::String("v".into())),
                    ("n", ParseValue::Number(3.0)),
                ])),
            )]),
            object_json: serde_json::json!({ "meta": { "k": "v", "n": 3 } }),
        },
        Case {
            name: "nested date inside an array",
            schema: post.clone(),
            object: m(vec![(
                "tags",
                ParseValue::Array(vec![ParseValue::Date(date)]),
            )]),
            object_json: serde_json::json!({
                "tags": [{ "__type": "Date", "iso": iso }]
            }),
        },
        Case {
            name: "nested pointer keeps its envelope",
            schema: post.clone(),
            object: m(vec![(
                "tags",
                ParseValue::Array(vec![ParseValue::Pointer {
                    class_name: "Tag".into(),
                    object_id: "t1".into(),
                }]),
            )]),
            object_json: serde_json::json!({
                "tags": [{ "__type": "Pointer", "className": "Tag", "objectId": "t1" }]
            }),
        },
        Case {
            name: "null",
            schema: post.clone(),
            object: m(vec![("title", ParseValue::Null)]),
            object_json: serde_json::json!({ "title": null }),
        },
        Case {
            name: "objectId is renamed to _id",
            schema: post.clone(),
            object: m(vec![("objectId", ParseValue::String("oid1".into()))]),
            object_json: serde_json::json!({ "objectId": "oid1" }),
        },
    ]
}

#[test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
fn our_transform_matches_upstreams() {
    let payload: Vec<serde_json::Value> = cases()
        .into_iter()
        .map(|c| {
            let doc = parse_object_to_mongo_create(&c.schema, &c.object)
                .unwrap_or_else(|e| panic!("{}: our transform failed: {e}", c.name));
            let ejson = bson::Bson::Document(doc)
                .into_canonical_extjson()
                .to_string();
            serde_json::json!({
                "name": c.name,
                "className": c.schema.class_name,
                "schema": schema_json(&c.schema),
                "object": c.object_json,
                "rustBson": ejson,
            })
        })
        .collect();

    let oracle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/mongo-transform-oracle.js"
    );
    let mut child = Command::new("node")
        // Editors inject a debug bootloader through NODE_OPTIONS, which makes every node process
        // wait for a debugger and hang. A test must not inherit that.
        .env_remove("NODE_OPTIONS")
        .arg(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node must be on PATH; this test is #[ignore]d by default");

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(
            serde_json::to_string(&payload)
                .expect("serialize")
                .as_bytes(),
        )
        .expect("write to node");

    let out = child.wait_with_output().expect("node ran");
    assert!(
        out.status.success(),
        "transform diverges from MongoTransform.\n{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    println!("{}", String::from_utf8_lossy(&out.stdout).trim());
}
