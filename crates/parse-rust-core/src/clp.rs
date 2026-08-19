//! Class-level permissions: the model, and nothing that evaluates it.
//!
//! CLP lives here rather than in `parse-rust-schema` for the same reason [`crate::acl`] does. It is
//! an authorization data model with a JSON encoding and no I/O, and both the schema crate (which
//! validates it) and the REST crate (which enforces it) need the type. Validation messages and
//! evaluation both live above this crate.
//!
//! Three shapes here are load-bearing, and each one fails as a security defect rather than as a
//! test failure if it is modelled the obvious way instead of upstream's way.
//!
//! **CLP is default-open.** `testPermissions` allows when `classPermissions[operation]` is
//! *falsy* (`SchemaController.js:1365-1382`): an absent operation entry means unrestricted, not
//! denied. That is why [`ClassLevelPermissions::op`] returns `Option<&OpPerm>` with `None`
//! meaning unrestricted, and why **[`OpPerm`] deliberately has no `Default` impl**. A `Default`
//! would be an empty entity set, which is deny-all, so a refactor that reached for
//! `unwrap_or_default()` would invert the rule and lock every existing database out.
//!
//! **The two entity grammars are not interchangeable.** Operations and `addField` accept
//! `pointerFields`, `*`, `requiresAuthentication`, `role:<name>` and an objectId
//! (`validatePermissionKey`, `SchemaController.js:218-235`). `protectedFields` accepts
//! `userField:<name>`, `*`, `authenticated`, `role:<name>` and an objectId
//! (`validateProtectedFieldsKey`, `:237-254`). One shared enum gets this wrong in both
//! directions, so there are two: [`OpEntity`] and [`PfEntity`].
//!
//! **The raw block is kept verbatim.** parse-rust must never rewrite a key it does not
//! understand back out of `_metadata.class_permissions`, because a parse-server node reading the
//! same database would see the key vanish. [`ClassLevelPermissions::raw`] is what gets written;
//! the parsed view is only ever read.

use indexmap::IndexMap;

use crate::value::{ParseMap, ParseValue};

/// The seven operations a CLP can restrict.
///
/// `addField` is one of them, and it is checked on every non-master write that introduces a key
/// the schema does not have (`DatabaseController.js:970-998`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Find,
    Count,
    Get,
    Create,
    Update,
    Delete,
    AddField,
}

impl Operation {
    /// The key as it appears in the CLP object, and in
    /// `Permission denied for action <op> on class <Class>.`
    pub fn as_key(self) -> &'static str {
        match self {
            Operation::Find => "find",
            Operation::Count => "count",
            Operation::Get => "get",
            Operation::Create => "create",
            Operation::Update => "update",
            Operation::Delete => "delete",
            Operation::AddField => "addField",
        }
    }

    /// Which of the two class-wide pointer-field arrays applies to this operation.
    ///
    /// `permissionField = ['get','find','count'].indexOf(operation) > -1 ? 'readUserFields' :
    /// 'writeUserFields'` (`SchemaController.js:1425-1429`). Note `addField` falls on the write
    /// side, which is what makes the create lockdown reachable.
    pub fn user_fields_key(self) -> UserFieldsKey {
        match self {
            Operation::Get | Operation::Find | Operation::Count => UserFieldsKey::Read,
            _ => UserFieldsKey::Write,
        }
    }

    pub const ALL: [Operation; 7] = [
        Operation::Find,
        Operation::Count,
        Operation::Get,
        Operation::Create,
        Operation::Update,
        Operation::Delete,
        Operation::AddField,
    ];

    pub fn from_key(key: &str) -> Option<Operation> {
        Operation::ALL.into_iter().find(|op| op.as_key() == key)
    }
}

/// Which class-wide pointer-field array an operation consults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserFieldsKey {
    Read,
    Write,
}

/// An entity key inside an operation's permission object.
///
/// `pointerFields` is not here: it is a sibling key whose value is an array of field names rather
/// than an entity granted `true`, and conflating the two is how a permission object stops being a
/// map from principal to grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OpEntity {
    /// `"*"`
    Public,
    /// `"requiresAuthentication"`. Not a principal: a predicate over the caller.
    RequiresAuthentication,
    /// `"role:<name>"`, stored without the prefix.
    Role(String),
    /// An objectId.
    User(String),
}

impl OpEntity {
    /// Total, so a `role:`-prefixed string can never end up in the `User` arm.
    ///
    /// That totality is the mitigation for the `role:` objectId collision: upstream has to guard
    /// it at two call sites with an explicit `startsWith` check (`Auth.js:195`, `:237`) precisely
    /// because its entity namespace is one flat untyped string space.
    pub fn parse(key: &str) -> Self {
        if key == "*" {
            OpEntity::Public
        } else if key == "requiresAuthentication" {
            OpEntity::RequiresAuthentication
        } else if let Some(name) = key.strip_prefix("role:") {
            OpEntity::Role(name.to_string())
        } else {
            OpEntity::User(key.to_string())
        }
    }

    pub fn as_key(&self) -> String {
        match self {
            OpEntity::Public => "*".to_string(),
            OpEntity::RequiresAuthentication => "requiresAuthentication".to_string(),
            OpEntity::Role(name) => format!("role:{name}"),
            OpEntity::User(id) => id.clone(),
        }
    }
}

/// An entity key inside `protectedFields`.
///
/// Note what is *not* shared with [`OpEntity`]: there is no `requiresAuthentication` (the
/// spelling here is `authenticated`) and no `pointerFields` (the spelling here is
/// `userField:<name>`). Upstream validates the two with two different functions and two different
/// key sets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PfEntity {
    /// `"*"`. Always applicable.
    Public,
    /// `"authenticated"`. Applicable only when the caller is a logged-in user.
    Authenticated,
    /// `"userField:<name>"`. Applicable when the named field on the *row* points at the caller,
    /// which cannot be known until the row has been read.
    UserField(String),
    /// `"role:<name>"`, stored without the prefix.
    Role(String),
    /// An objectId.
    User(String),
}

impl PfEntity {
    pub fn parse(key: &str) -> Self {
        if key == "*" {
            PfEntity::Public
        } else if key == "authenticated" {
            PfEntity::Authenticated
        } else if let Some(field) = key.strip_prefix("userField:") {
            PfEntity::UserField(field.to_string())
        } else if let Some(name) = key.strip_prefix("role:") {
            PfEntity::Role(name.to_string())
        } else {
            PfEntity::User(key.to_string())
        }
    }

    pub fn as_key(&self) -> String {
        match self {
            PfEntity::Public => "*".to_string(),
            PfEntity::Authenticated => "authenticated".to_string(),
            PfEntity::UserField(f) => format!("userField:{f}"),
            PfEntity::Role(name) => format!("role:{name}"),
            PfEntity::User(id) => id.clone(),
        }
    }
}

/// One operation's permission object.
///
/// **No `Default` impl, on purpose.** See the module note: an empty `OpPerm` is deny-all, and
/// absent is unrestricted, so the two must never be reachable from one another by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpPerm {
    /// Entities granted the operation. Only a literal `true` counts upstream
    /// (`SchemaController.js:367-396`); `false`, `0` and `"true"` are all `INVALID_JSON` at
    /// validation, so anything reaching here is a grant.
    pub entities: Vec<OpEntity>,
    /// `pointerFields`: the caller must be the value of one of these fields on the row.
    pub pointer_fields: Vec<String>,
}

impl OpPerm {
    // No `Default` impl, and the lint asking for one is wrong here. An empty `OpPerm` is
    // deny-all, while an *absent* one is unrestricted, so a `Default` would put deny-all one
    // `unwrap_or_default()` away from every call site that means unrestricted. That is the
    // inversion this module exists to prevent.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entities: Vec::new(),
            pointer_fields: Vec::new(),
        }
    }

    pub fn grants(&self, entity: &OpEntity) -> bool {
        self.entities.contains(entity)
    }
}

/// Class-level permissions.
///
/// Constructed from the stored `_metadata.class_permissions` object or from a
/// `POST`/`PUT /schemas` body. Both paths keep [`Self::raw`] verbatim so that writing the block
/// back cannot drop a key parse-rust does not model.
///
/// No `PartialEq`, because [`Self::raw`] holds [`ParseValue`]s and a derived comparison would
/// inherit that type's float hazards. Compare the rendered JSON if two blocks need comparing.
#[derive(Debug, Clone)]
pub struct ClassLevelPermissions {
    raw: ParseMap,
    ops: Vec<(Operation, OpPerm)>,
    protected_fields: IndexMap<PfEntity, Vec<String>>,
    read_user_fields: Vec<String>,
    write_user_fields: Vec<String>,
}

impl ClassLevelPermissions {
    /// Parse a CLP block. Unknown keys are preserved in [`Self::raw`] and otherwise ignored;
    /// rejecting them is the schema API's job, not the model's, because a block already in the
    /// database has to be readable even if it would fail validation today.
    pub fn from_map(raw: ParseMap) -> Self {
        let mut ops = Vec::new();
        for op in Operation::ALL {
            match raw.get(op.as_key()) {
                Some(ParseValue::Object(entry)) => ops.push((op, parse_op_perm(entry))),
                // A present but malformed entry denies. `testPermissions` allows only when
                // `classPermissions[operation]` is *falsy* (`SchemaController.js:1365-1382`), so
                // `{"find": true}`, `{"find": "x"}` and `{"find": []}` all deny upstream: the
                // value is truthy, so the short-circuit does not fire, and none of the lookups
                // that follow finds a grant on a non-object.
                //
                // Recording an empty `OpPerm` rather than skipping the key is what reproduces
                // that. Skipping would make the entry absent, which is unrestricted, and the
                // failure direction there is open. Not reachable through `PUT /schemas`, which
                // refuses a non-object operation value, but a block written straight into
                // `_SCHEMA` has to be read the way parse-server reads it.
                Some(other) if is_js_truthy(other) => ops.push((op, OpPerm::new())),
                // Falsy, so `!classPermissions[operation]` holds and the operation is
                // unrestricted, exactly as an absent key is.
                _ => {}
            }
        }

        let mut protected_fields = IndexMap::new();
        if let Some(ParseValue::Object(pf)) = raw.get("protectedFields") {
            for (key, value) in pf {
                if let ParseValue::Array(items) = value {
                    protected_fields.insert(PfEntity::parse(key), string_array(items));
                }
            }
        }

        Self {
            read_user_fields: raw
                .get("readUserFields")
                .map(string_array_of)
                .unwrap_or_default(),
            write_user_fields: raw
                .get("writeUserFields")
                .map(string_array_of)
                .unwrap_or_default(),
            ops,
            protected_fields,
            raw,
        }
    }

    /// The block exactly as it will be stored. Never derived from the parsed view.
    pub fn raw(&self) -> &ParseMap {
        &self.raw
    }

    /// The permission object for one operation.
    ///
    /// **`None` means unrestricted, not denied.** Every caller has to spell that out; the reason
    /// it cannot be `unwrap_or_default()` is the whole point of this module.
    pub fn op(&self, operation: Operation) -> Option<&OpPerm> {
        self.ops
            .iter()
            .find(|(o, _)| *o == operation)
            .map(|(_, p)| p)
    }

    pub fn protected_fields(&self) -> &IndexMap<PfEntity, Vec<String>> {
        &self.protected_fields
    }

    /// The class-wide pointer-field array for one operation, per
    /// `SchemaController.js:1425-1429`.
    pub fn user_fields(&self, operation: Operation) -> &[String] {
        match operation.user_fields_key() {
            UserFieldsKey::Read => &self.read_user_fields,
            UserFieldsKey::Write => &self.write_user_fields,
        }
    }

    pub fn read_user_fields(&self) -> &[String] {
        &self.read_user_fields
    }

    pub fn write_user_fields(&self) -> &[String] {
        &self.write_user_fields
    }

    /// The class's declared default ACL, if it has one that upstream would stamp on a create.
    ///
    /// `None` covers three cases that upstream's condition collapses (`RestWrite.js:379-384`):
    /// the `ACL` key is absent; its value is falsy, which is `schema?.classLevelPermissions?.ACL`
    /// failing its own truthiness test; or it is exactly the public ACL, which upstream skips
    /// because stamping `{"*": {"read": true, "write": true}}` on a row would only reproduce what
    /// an absent ACL already means.
    ///
    /// **That last comparison is `JSON.stringify` equality upstream, so it is key-order
    /// sensitive**, and [`is_the_public_acl`] reproduces the ordering rather than comparing
    /// structurally. A block whose keys arrived in the other order is *not* the public ACL as far
    /// as upstream is concerned, and it gets stamped.
    ///
    /// A truthy non-object is returned rather than filtered: upstream clones and assigns whatever
    /// it finds, and the resulting `ACL` value is then lowered by the same rule any client-supplied
    /// one is.
    pub fn default_acl(&self) -> Option<&ParseValue> {
        let acl = self.raw.get("ACL")?;
        if !is_js_truthy(acl) || is_the_public_acl(acl) {
            return None;
        }
        Some(acl)
    }

    /// Every pointer field that applies to an operation, per-op first then class-wide, deduped.
    ///
    /// Order is upstream's (`DatabaseController.js:1749-1764`) and matters, because the clauses
    /// are composed into an `$or` whose element order is observable in a compiled query.
    pub fn applicable_pointer_fields(&self, operation: Operation) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(perm) = self.op(operation) {
            for f in &perm.pointer_fields {
                if !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
        for f in self.user_fields(operation) {
            if !out.contains(f) {
                out.push(f.clone());
            }
        }
        out
    }
}

/// Is this value what `JSON.stringify` would render as `{"*":{"read":true,"write":true}}`?
///
/// The one comparison upstream makes by stringifying both sides
/// (`RestWrite.js:382-383`), which makes it **sensitive to key order**: a block spelled
/// `{"*":{"write":true,"read":true}}` stringifies differently and is therefore not the public ACL,
/// so upstream stamps it onto every new object. The observable result is the same permissions
/// either way, but the row carries `_rperm` and `_wperm` in one case and neither in the other, and
/// a mixed fleet has to agree on which.
///
/// Written as an ordered structural test rather than by building a JSON string. For this one
/// literal the two are the same predicate: a value stringifies to it exactly when it is an object
/// of one key `*` whose value is an object of two keys, `read` then `write`, both `true`. Anything
/// else, including `{"*":{"read":true,"write":true,"x":1}}` or `read: 1` instead of `read: true`,
/// renders a different string and is correctly not the public ACL.
fn is_the_public_acl(value: &ParseValue) -> bool {
    let ParseValue::Object(entries) = value else {
        return false;
    };
    let mut entries = entries.iter();
    let (Some(("*", ParseValue::Object(flags))), None) =
        (entries.next().map(|(k, v)| (k.as_str(), v)), entries.next())
    else {
        return false;
    };
    let mut flags = flags.iter();
    matches!(
        (
            flags.next().map(|(k, v)| (k.as_str(), v)),
            flags.next().map(|(k, v)| (k.as_str(), v)),
            flags.next(),
        ),
        (
            Some(("read", ParseValue::Bool(true))),
            Some(("write", ParseValue::Bool(true))),
            None,
        )
    )
}

/// JavaScript truthiness, which is what `!classPermissions[operation]` tests.
///
/// The trap is `Array`: an empty array is **truthy** in JavaScript, and empty-is-falsy is the
/// reflex a Rust reader brings. Everything with a `__type` envelope is an object on the JS side
/// and therefore truthy too, including empty `Bytes`.
///
/// Public because it is not a CLP concern in particular. Any port of an upstream `if (value)` or
/// `!value` needs it, and re-deriving the rule per call site is how the `Array` trap gets missed.
pub fn is_js_truthy(value: &ParseValue) -> bool {
    match value {
        ParseValue::Null => false,
        ParseValue::Bool(b) => *b,
        // `NaN`, `0` and `-0` are the falsy numbers.
        ParseValue::Number(n) => *n != 0.0 && !n.is_nan(),
        ParseValue::String(s) => !s.is_empty(),
        ParseValue::Array(_)
        | ParseValue::Object(_)
        | ParseValue::Date(_)
        | ParseValue::Pointer { .. }
        | ParseValue::GeoPoint { .. }
        | ParseValue::Bytes(_)
        | ParseValue::File { .. }
        | ParseValue::Polygon(_)
        | ParseValue::Relation { .. } => true,
    }
}

fn parse_op_perm(entry: &ParseMap) -> OpPerm {
    let mut perm = OpPerm::new();
    for (key, value) in entry {
        if key == "pointerFields" {
            if let ParseValue::Array(items) = value {
                perm.pointer_fields = string_array(items);
            }
            continue;
        }
        if matches!(value, ParseValue::Bool(true)) {
            perm.entities.push(OpEntity::parse(key));
        }
    }
    perm
}

fn string_array(items: &[ParseValue]) -> Vec<String> {
    items
        .iter()
        .filter_map(|v| match v {
            ParseValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn string_array_of(value: &ParseValue) -> Vec<String> {
    match value {
        ParseValue::Array(items) => string_array(items),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clp(json: &str) -> ClassLevelPermissions {
        let value = crate::decode::classify(
            serde_json::from_str(json).expect("test literal must be valid JSON"),
        )
        .expect("classify");
        match value {
            ParseValue::Object(m) => ClassLevelPermissions::from_map(m),
            _ => panic!("expected an object"),
        }
    }

    /// The single most consequential CLP semantic. If this ever asserts "denied", every existing
    /// database is locked out on upgrade.
    #[test]
    fn an_absent_operation_is_unrestricted_not_denied() {
        let c = clp(r#"{"find":{"*":true}}"#);
        assert!(c.op(Operation::Find).is_some());
        assert!(
            c.op(Operation::Update).is_none(),
            "absent means unrestricted, and the caller must be forced to say so"
        );
    }

    /// The other half of the same rule: present-but-empty is deny-all, and it must not be
    /// reachable from the absent case.
    #[test]
    fn a_present_but_empty_operation_grants_nobody() {
        let c = clp(r#"{"find":{}}"#);
        let perm = c.op(Operation::Find).expect("present");
        assert!(perm.entities.is_empty());
        assert!(!perm.grants(&OpEntity::Public));
    }

    /// The fail-open this closes. A block written straight into `_SCHEMA` can carry a non-object
    /// operation value, and upstream denies on every truthy one, because `testPermissions` only
    /// short-circuits to allow when the value is falsy.
    #[test]
    fn a_truthy_non_object_operation_denies_rather_than_being_absent() {
        for json in [
            r#"{"find":true}"#,
            r#"{"find":"x"}"#,
            r#"{"find":[]}"#,
            r#"{"find":["role:A"]}"#,
            r#"{"find":1}"#,
            r#"{"find":{"__type":"Date","iso":"2020-01-01T00:00:00.000Z"}}"#,
        ] {
            let c = clp(json);
            let perm = c
                .op(Operation::Find)
                .unwrap_or_else(|| panic!("{json} must be present, not absent"));
            assert!(perm.entities.is_empty(), "{json} must grant nobody");
            assert!(!perm.grants(&OpEntity::Public), "{json}");
        }
    }

    /// The other half, and the reason this cannot just be "anything non-object denies": a falsy
    /// value is what `!classPermissions[operation]` is testing for, so it is unrestricted.
    #[test]
    fn a_falsy_operation_value_is_unrestricted_like_an_absent_key() {
        for json in [
            r#"{"find":false}"#,
            r#"{"find":null}"#,
            r#"{"find":0}"#,
            r#"{"find":""}"#,
        ] {
            assert!(
                clp(json).op(Operation::Find).is_none(),
                "{json} must read as unrestricted"
            );
        }
    }

    /// The trap inside the trap. Rust reads an empty array as empty; JavaScript reads it as
    /// truthy, and the two answers are opposite permission decisions.
    #[test]
    fn js_truthiness_is_not_rust_emptiness() {
        assert!(is_js_truthy(&ParseValue::Array(Vec::new())));
        assert!(is_js_truthy(&ParseValue::Bytes(Vec::new())));
        assert!(is_js_truthy(&ParseValue::String("0".into())));
        assert!(!is_js_truthy(&ParseValue::String(String::new())));
        assert!(!is_js_truthy(&ParseValue::Number(0.0)));
        assert!(!is_js_truthy(&ParseValue::Number(-0.0)));
        assert!(!is_js_truthy(&ParseValue::Number(f64::NAN)));
        assert!(is_js_truthy(&ParseValue::Number(-1.0)));
    }

    #[test]
    fn only_literal_true_is_a_grant() {
        let c = clp(r#"{"find":{"*":false,"role:A":true,"abc":0,"def":"true"}}"#);
        let perm = c.op(Operation::Find).expect("present");
        assert_eq!(perm.entities, vec![OpEntity::Role("A".into())]);
    }

    #[test]
    fn pointer_fields_is_not_an_entity() {
        let c = clp(r#"{"find":{"pointerFields":["owner"],"*":true}}"#);
        let perm = c.op(Operation::Find).expect("present");
        assert_eq!(perm.pointer_fields, vec!["owner".to_string()]);
        assert_eq!(perm.entities, vec![OpEntity::Public]);
    }

    #[test]
    fn the_two_entity_grammars_do_not_overlap() {
        // `requiresAuthentication` is an operation key and is an ordinary objectId under the
        // protectedFields grammar; `authenticated` is the reverse.
        assert_eq!(
            OpEntity::parse("requiresAuthentication"),
            OpEntity::RequiresAuthentication
        );
        assert_eq!(
            PfEntity::parse("requiresAuthentication"),
            PfEntity::User("requiresAuthentication".into())
        );
        assert_eq!(PfEntity::parse("authenticated"), PfEntity::Authenticated);
        assert_eq!(
            OpEntity::parse("authenticated"),
            OpEntity::User("authenticated".into())
        );
        assert_eq!(
            PfEntity::parse("userField:owner"),
            PfEntity::UserField("owner".into())
        );
        assert_eq!(
            OpEntity::parse("userField:owner"),
            OpEntity::User("userField:owner".into())
        );
    }

    /// The mitigation for the `role:` objectId collision: a `role:`-prefixed string cannot land
    /// in the `User` arm, so no ACL check can be tricked into granting a role.
    #[test]
    fn a_role_prefixed_key_can_never_parse_as_a_user() {
        assert_eq!(
            OpEntity::parse("role:Admin"),
            OpEntity::Role("Admin".into())
        );
        assert_eq!(
            PfEntity::parse("role:Admin"),
            PfEntity::Role("Admin".into())
        );
        for key in ["role:Admin", "role:", "role:with:colons"] {
            assert!(!matches!(OpEntity::parse(key), OpEntity::User(_)), "{key}");
            assert!(!matches!(PfEntity::parse(key), PfEntity::User(_)), "{key}");
        }
    }

    #[test]
    fn entity_keys_round_trip() {
        for key in ["*", "requiresAuthentication", "role:A", "abc123"] {
            assert_eq!(OpEntity::parse(key).as_key(), key);
        }
        for key in ["*", "authenticated", "userField:owner", "role:A", "abc123"] {
            assert_eq!(PfEntity::parse(key).as_key(), key);
        }
    }

    #[test]
    fn user_fields_split_by_operation_and_add_field_is_a_write() {
        let c = clp(r#"{"readUserFields":["r"],"writeUserFields":["w"]}"#);
        for op in [Operation::Get, Operation::Find, Operation::Count] {
            assert_eq!(c.user_fields(op), ["r".to_string()], "{op:?}");
        }
        for op in [
            Operation::Create,
            Operation::Update,
            Operation::Delete,
            Operation::AddField,
        ] {
            assert_eq!(c.user_fields(op), ["w".to_string()], "{op:?}");
        }
    }

    #[test]
    fn applicable_pointer_fields_is_per_op_then_class_wide_deduped() {
        let c = clp(r#"{"find":{"pointerFields":["owner","a"]},"readUserFields":["a","b"]}"#);
        assert_eq!(
            c.applicable_pointer_fields(Operation::Find),
            vec!["owner".to_string(), "a".to_string(), "b".to_string()]
        );
    }

    /// The rule that keeps a mixed fleet from losing configuration: a key parse-rust does not
    /// model survives the round trip.
    #[test]
    fn unmodelled_keys_survive_in_the_raw_block() {
        let c = clp(r#"{"find":{"*":true},"someFutureKey":{"x":1}}"#);
        assert!(c.raw().contains_key("someFutureKey"));
        assert!(c.raw().contains_key("find"));
    }

    #[test]
    fn protected_fields_parse_per_entity() {
        let c = clp(r#"{"protectedFields":{"*":["email"],"role:A":["email","phone"]}}"#);
        assert_eq!(
            c.protected_fields().get(&PfEntity::Public),
            Some(&vec!["email".to_string()])
        );
        assert_eq!(
            c.protected_fields()
                .get(&PfEntity::Role("A".into()))
                .map(Vec::len),
            Some(2)
        );
    }

    // -----------------------------------------------------------------------------------------
    // The declared default ACL
    // -----------------------------------------------------------------------------------------

    #[test]
    fn a_declared_acl_is_readable_and_an_absent_one_is_none() {
        assert!(clp(r#"{"find":{"*":true}}"#).default_acl().is_none());
        let c = clp(r#"{"ACL":{"currentUser":{"read":true,"write":true}}}"#);
        let ParseValue::Object(acl) = c.default_acl().expect("declared") else {
            panic!("expected an object");
        };
        assert!(acl.contains_key("currentUser"));
    }

    /// Upstream tests `schema?.classLevelPermissions?.ACL` for truthiness, so a falsy value is not
    /// a default ACL at all. Returning it instead would reach `lower_acl`, where a falsy value is
    /// dropped and the row is public anyway, but the two paths differ for `_Role`, whose ACL is a
    /// required column.
    #[test]
    fn a_falsy_declared_acl_is_not_a_default() {
        for literal in [
            r#"{"ACL":null}"#,
            r#"{"ACL":false}"#,
            r#"{"ACL":0}"#,
            r#"{"ACL":""}"#,
        ] {
            assert!(clp(literal).default_acl().is_none(), "{literal}");
        }
    }

    /// The public ACL is skipped, because stamping it would only restate what an absent ACL
    /// already means: a row every caller can read and write.
    #[test]
    fn the_public_acl_is_not_stamped() {
        assert!(clp(r#"{"ACL":{"*":{"read":true,"write":true}}}"#)
            .default_acl()
            .is_none());
    }

    /// **The comparison is `JSON.stringify` equality upstream and therefore key-order sensitive.**
    /// Every literal here grants exactly the same permissions as the public ACL, and upstream
    /// stamps every one of them, because none stringifies to the same bytes. Comparing
    /// structurally would skip them all and write no ACL columns where parse-server writes two,
    /// which a mixed fleet reading the same rows can see.
    #[test]
    fn a_reordered_or_extended_public_acl_is_still_stamped() {
        for literal in [
            r#"{"ACL":{"*":{"write":true,"read":true}}}"#,
            r#"{"ACL":{"*":{"read":true,"write":true,"delete":true}}}"#,
            r#"{"ACL":{"*":{"read":true}}}"#,
            r#"{"ACL":{"*":{"read":true,"write":true},"role:A":{"read":true}}}"#,
            r#"{"ACL":{"role:A":{"read":true},"*":{"read":true,"write":true}}}"#,
        ] {
            assert!(
                clp(literal).default_acl().is_some(),
                "{literal} does not stringify to the public ACL and must be stamped"
            );
        }
    }
}
