//! Field types, and the per-class shape a transform needs.
//!
//! This lives in `parse-rust-storage` rather than `parse-rust-schema` because both adapters need it to
//! lower a value, and the transform cannot be written without knowing which fields are Pointers.
//! `parse-rust-schema` will own inference, validation and CLP on top of these types.

use indexmap::IndexMap;

use parse_rust_core::{ClassLevelPermissions, ParseMap};

/// A Parse field type.
///
/// `Pointer` and `Relation` carry their target class because the wire form does
/// (`Pointer<_User>`), and because the Mongo transform needs the target to build the
/// `"<Class>$<id>"` storage form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    String,
    Number,
    Boolean,
    Date,
    Object,
    Array,
    GeoPoint,
    File,
    Bytes,
    Polygon,
    Pointer {
        target_class: String,
    },
    Relation {
        target_class: String,
    },
    /// Not a user-settable field type. `ACL` is a real column in the Parse schema, and
    /// `mongoSchemaFieldsToParseSchemaFields` injects it unconditionally.
    Acl,
}

impl FieldType {
    /// The wire rendering, which is part of the error-message contract.
    ///
    /// `typeToString` produces `Pointer<_User>` for parametric types
    /// (`SchemaController.js:697-705`), and that exact string appears inside
    /// `schema mismatch for <Class>.<field>; expected <expected> but got <got>`. Getting the
    /// rendering wrong changes an error a client may match on.
    pub fn to_wire_string(&self) -> String {
        match self {
            FieldType::String => "String".into(),
            FieldType::Number => "Number".into(),
            FieldType::Boolean => "Boolean".into(),
            FieldType::Date => "Date".into(),
            FieldType::Object => "Object".into(),
            FieldType::Array => "Array".into(),
            FieldType::GeoPoint => "GeoPoint".into(),
            FieldType::File => "File".into(),
            FieldType::Bytes => "Bytes".into(),
            FieldType::Polygon => "Polygon".into(),
            FieldType::Acl => "ACL".into(),
            FieldType::Pointer { target_class } => format!("Pointer<{target_class}>"),
            FieldType::Relation { target_class } => format!("Relation<{target_class}>"),
        }
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self, FieldType::Pointer { .. })
    }

    pub fn is_relation(&self) -> bool {
        matches!(self, FieldType::Relation { .. })
    }

    /// The class a parametric type points at.
    pub fn target_class(&self) -> Option<&str> {
        match self {
            FieldType::Pointer { target_class } | FieldType::Relation { target_class } => {
                Some(target_class)
            }
            _ => None,
        }
    }
}

/// The join collection backing one `Relation` field.
///
/// `_Join:<key>:<className>` (`DatabaseController.js:319-321`). Note the argument order: the key
/// comes first and the *owning* class second, so `_Role.users` is `_Join:users:_Role`. Getting it
/// backwards produces a collection parse-server will never read.
pub fn join_table_name(class_name: &str, key: &str) -> String {
    format!("_Join:{key}:{class_name}")
}

/// The fixed schema every join collection has.
///
/// Two string columns and nothing else (`DatabaseController.js:418-420`). Deliberately built
/// here rather than fetched: join collections have **no `_SCHEMA` row at all** upstream, and
/// writing one would add a class every parse-server node reading the database would then see.
pub fn join_schema(class_name: &str, key: &str) -> ClassSchema {
    ClassSchema::new(join_table_name(class_name, key))
        .with_field("relatedId", FieldType::String)
        .with_field("owningId", FieldType::String)
}

/// The shape of one class: what a transform needs to lower or raise a document.
///
/// Order-preserving, because `_SCHEMA` documents are compared in golden files and because the
/// order fields were added is the order upstream writes them.
#[derive(Debug, Clone, Default)]
pub struct ClassSchema {
    pub class_name: String,
    pub fields: IndexMap<String, FieldType>,
    /// `_metadata.class_permissions`, parsed.
    ///
    /// **`None` is not "public".** It is "the key is absent", which reads back as `defaultCLPS`,
    /// a fully public block *including* an `ACL` key that the present-but-partial case never
    /// carries (`MongoSchemaCollection.js:67-112`). The distinction is preserved rather than
    /// normalized, because normalizing either way rewrites a block parse-server reads.
    pub clp: Option<ClassLevelPermissions>,
    /// `_metadata.indexes`, round-tripped verbatim and never interpreted.
    pub indexes: Option<ParseMap>,
    /// `_metadata.fields_options`, round-tripped **as sent**. A schema body is decoded without
    /// interpreting a `__type` envelope, so an offset instant, unpadded base64 and any key the
    /// envelope does not declare all survive, which is what a parse-server node reading the same
    /// row expects. 0.2.0 stores `required` and `defaultValue` for fleet safety and does not
    /// enforce them.
    pub field_options: Option<ParseMap>,
}

impl ClassSchema {
    pub fn new(class_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            fields: IndexMap::new(),
            clp: None,
            indexes: None,
            field_options: None,
        }
    }

    pub fn with_clp(mut self, clp: ClassLevelPermissions) -> Self {
        self.clp = Some(clp);
        self
    }

    /// Every `Relation` field, with its target class.
    pub fn relation_fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().filter_map(|(name, ty)| match ty {
            FieldType::Relation { target_class } => Some((name.as_str(), target_class.as_str())),
            _ => None,
        })
    }

    pub fn with_field(mut self, name: impl Into<String>, ty: FieldType) -> Self {
        self.fields.insert(name.into(), ty);
        self
    }

    pub fn field(&self, name: &str) -> Option<&FieldType> {
        self.fields.get(name)
    }

    /// Is this field stored under a `_p_` prefix?
    ///
    /// Note the deliberate narrowness: only a *declared* Pointer field is prefixed. A pointer
    /// value written to a field the schema does not know about is not prefixed by
    /// `transformKey`, because that function consults the schema and nothing else.
    pub fn is_pointer_field(&self, name: &str) -> bool {
        self.field(name).is_some_and(FieldType::is_pointer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parametric_types_render_with_angle_brackets() {
        assert_eq!(
            FieldType::Pointer {
                target_class: "_User".into()
            }
            .to_wire_string(),
            "Pointer<_User>"
        );
        assert_eq!(
            FieldType::Relation {
                target_class: "Post".into()
            }
            .to_wire_string(),
            "Relation<Post>"
        );
        assert_eq!(FieldType::String.to_wire_string(), "String");
    }

    #[test]
    fn only_declared_pointer_fields_are_prefixed() {
        let s = ClassSchema::new("Post").with_field(
            "author",
            FieldType::Pointer {
                target_class: "_User".into(),
            },
        );
        assert!(s.is_pointer_field("author"));
        assert!(!s.is_pointer_field("undeclared"));
    }
}
