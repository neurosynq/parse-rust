//! The `_SCHEMA` document format.
//!
//! **This is the one place where a mistake breaks a mixed fleet silently rather than loudly**, so
//! it gets its own module and its own round-trip tests.
//!
//! A `_SCHEMA` document is `{_id: <className>, <field>: <short type string>, ...}` plus
//! `_metadata` and `_client_permissions`. The type strings are terse and lossy-looking but exact:
//! `parseFieldTypeToMongoFieldType` (`MongoSchemaCollection.js:126-152`) going down, and
//! `mongoFieldToParseSchemaField` (`:4-39`) coming back.
//!
//! Two hazards, both silent:
//!
//! - **Never add a key.** parse-server reads an unknown top-level `_SCHEMA` key as a phantom
//!   field, so a key parse-rust invents for bookkeeping becomes a real column on every
//!   parse-server node reading the same database.
//! - **Never invent a type string.** `mongoFieldToParseSchemaField` is a `switch` with **no
//!   default case**, so an unrecognised type falls off the end and the field's parsed entry
//!   becomes `undefined`, with no error anywhere.

use parse_rust_storage::FieldType;

/// Keys in a `_SCHEMA` document that are not fields (`nonFieldSchemaKeys`).
pub const NON_FIELD_KEYS: [&str; 3] = ["_id", "_metadata", "_client_permissions"];

/// Lower a field type to its `_SCHEMA` string.
///
/// Total on purpose: every variant is named, so adding a `FieldType` fails to compile here rather
/// than silently writing a string parse-server cannot read.
pub fn field_type_to_storage(ty: &FieldType) -> String {
    match ty {
        FieldType::Pointer { target_class } => format!("*{target_class}"),
        FieldType::Relation { target_class } => format!("relation<{target_class}>"),
        FieldType::Number => "number".into(),
        FieldType::String => "string".into(),
        FieldType::Boolean => "boolean".into(),
        FieldType::Date => "date".into(),
        FieldType::Object => "object".into(),
        FieldType::Array => "array".into(),
        FieldType::GeoPoint => "geopoint".into(),
        FieldType::File => "file".into(),
        FieldType::Bytes => "bytes".into(),
        FieldType::Polygon => "polygon".into(),
        // `ACL` is never written into `_SCHEMA`. Measured: parse-server stores `objectId`,
        // `createdAt` and `updatedAt` as ordinary keys but not `ACL`, because
        // `mongoSchemaFieldsToParseSchemaFields` injects it on read. Emitting a string here would
        // create precisely the phantom column the rule forbids, so this returns the empty string
        // and `write_schema_document` skips it. Asserted by the format differential.
        FieldType::Acl => String::new(),
    }
}

/// Raise a `_SCHEMA` string back to a field type.
///
/// `None` for anything unrecognised, mirroring upstream's missing default case. The caller
/// decides what to do with that: upstream produces an `undefined` field entry, which is the
/// behavior a mixed fleet has to survive.
pub fn storage_to_field_type(s: &str) -> Option<FieldType> {
    if let Some(target) = s.strip_prefix('*') {
        return Some(FieldType::Pointer {
            target_class: target.to_string(),
        });
    }
    if let Some(rest) = s.strip_prefix("relation<") {
        return rest.strip_suffix('>').map(|target| FieldType::Relation {
            target_class: target.to_string(),
        });
    }
    Some(match s {
        "number" => FieldType::Number,
        "string" => FieldType::String,
        "boolean" => FieldType::Boolean,
        "date" => FieldType::Date,
        // Upstream maps both `map` and `object` to Object. `map` is a legacy spelling that still
        // exists in old databases, which is exactly the kind of value a migration will meet.
        "map" | "object" => FieldType::Object,
        "array" => FieldType::Array,
        "geopoint" => FieldType::GeoPoint,
        "file" => FieldType::File,
        "bytes" => FieldType::Bytes,
        "polygon" => FieldType::Polygon,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_is_not_storable() {
        assert!(
            field_type_to_storage(&FieldType::Acl).is_empty(),
            "ACL must never be written into _SCHEMA"
        );
    }

    #[test]
    fn every_type_round_trips() {
        let types = [
            FieldType::Number,
            FieldType::String,
            FieldType::Boolean,
            FieldType::Date,
            FieldType::Object,
            FieldType::Array,
            FieldType::GeoPoint,
            FieldType::File,
            FieldType::Bytes,
            FieldType::Polygon,
            FieldType::Pointer {
                target_class: "_User".into(),
            },
            FieldType::Relation {
                target_class: "Post".into(),
            },
        ];
        for ty in types {
            let s = field_type_to_storage(&ty);
            assert_eq!(
                storage_to_field_type(&s).as_ref(),
                Some(&ty),
                "{ty:?} did not round trip through {s:?}"
            );
        }
    }

    /// The exact strings parse-server writes. If any of these changes, a parse-server node reading
    /// the same database sees a different schema.
    #[test]
    fn storage_strings_are_byte_exact() {
        assert_eq!(field_type_to_storage(&FieldType::String), "string");
        assert_eq!(field_type_to_storage(&FieldType::Number), "number");
        assert_eq!(field_type_to_storage(&FieldType::Boolean), "boolean");
        assert_eq!(field_type_to_storage(&FieldType::Date), "date");
        assert_eq!(field_type_to_storage(&FieldType::Object), "object");
        assert_eq!(field_type_to_storage(&FieldType::GeoPoint), "geopoint");
        assert_eq!(
            field_type_to_storage(&FieldType::Pointer {
                target_class: "_User".into()
            }),
            "*_User",
            "a pointer is an asterisk and the class name, with no separator"
        );
        assert_eq!(
            field_type_to_storage(&FieldType::Relation {
                target_class: "Post".into()
            }),
            "relation<Post>"
        );
    }

    #[test]
    fn the_legacy_map_spelling_still_reads() {
        // Old databases contain `map` where new ones contain `object`. A migration meets both.
        assert_eq!(storage_to_field_type("map"), Some(FieldType::Object));
        assert_eq!(storage_to_field_type("object"), Some(FieldType::Object));
    }

    /// The mechanism behind "never invent a type string".
    #[test]
    fn an_unknown_type_string_reads_as_nothing_rather_than_erroring() {
        assert_eq!(storage_to_field_type("vector"), None);
        assert_eq!(storage_to_field_type("Number"), None, "case matters");
        assert_eq!(storage_to_field_type(""), None);
        // A malformed relation is unrecognised rather than a Relation with a broken target.
        assert_eq!(storage_to_field_type("relation<unterminated"), None);
    }

    #[test]
    fn non_field_keys_are_the_upstream_set() {
        assert_eq!(NON_FIELD_KEYS, ["_id", "_metadata", "_client_permissions"]);
    }
}
