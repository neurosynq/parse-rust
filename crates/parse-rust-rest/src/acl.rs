//! ACL enforcement: the boundary between the `ACL` field a client sees and the `_rperm`/`_wperm`
//! columns storage holds.
//!
//! **The rule that must not be got wrong: absent permission columns mean public.**
//! `addReadACL` emits `_rperm: {$in: [null, '*', ...acl]}` and `null` in a Mongo `$in` matches a
//! document where the field is *missing*, which is how a row saved without an ACL stays readable.
//! Omitting the null silently hides every such row, and there is no error to notice.
//!
//! [`lower_acl`] is a port of `transformObjectACL` (`DatabaseController.js:93-110`) and keeps its
//! JavaScript semantics rather than reading the value as a principal map. Three of them are
//! observable in a stored row and each was a recorded divergence until 0.3.0: an array's indices
//! are principals, a flag is tested for truthiness rather than for `true`, and integer-like keys
//! enumerate first.

use parse_rust_core::{Acl, ErrorCode, ParseError, ParseMap, ParseValue};
use parse_rust_storage::{Comparison, Constraint};

/// Who a request is acting as, for ACL purposes.
///
/// An enum rather than an `Option<String>` so that "no ACL constraint at all" cannot be reached
/// by forgetting to set a field. `acl === undefined` as a master sentinel is the upstream shape
/// this deliberately does not copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclScope {
    /// Master or maintenance: no ACL constraint is applied at all.
    Unrestricted,
    /// A caller acting as nobody in particular.
    Anonymous,
    /// A logged-in user, with the transitive closure of their roles.
    ///
    /// **Roles are bare names here, with no `role:` prefix.** The prefix is added by
    /// [`AclScope::acl_group`] and by `AclScope::principals`, so there is exactly one place
    /// that knows the wire spelling. Construct through [`AclScope::user`] rather than by
    /// literal, so that a `role:`-prefixed objectId cannot reach `object_id`.
    User {
        object_id: String,
        roles: Vec<String>,
    },
}

impl AclScope {
    /// Build a user scope, refusing a `role:`-prefixed objectId.
    ///
    /// A user whose objectId began with `role:` would be granted that role by every ACL and CLP
    /// check, because the entity namespace is one flat string space on the wire. Upstream guards
    /// it at two session-resolution sites with the same code and message (`Auth.js:195`, `:237`);
    /// here the guard is at the one place a scope can be built.
    pub fn user(object_id: impl Into<String>, roles: Vec<String>) -> Result<Self, ParseError> {
        let object_id = object_id.into();
        if object_id.starts_with("role:") {
            return Err(ParseError::new(
                ErrorCode::InternalServerError,
                "Invalid object ID.",
            ));
        }
        Ok(AclScope::User { object_id, roles })
    }

    pub fn is_master(&self) -> bool {
        matches!(self, AclScope::Unrestricted)
    }

    pub fn user_id(&self) -> Option<&str> {
        match self {
            AclScope::User { object_id, .. } => Some(object_id),
            _ => None,
        }
    }

    /// Does the caller hold this role? The name is bare, with no `role:` prefix.
    pub fn has_role(&self, name: &str) -> bool {
        match self {
            AclScope::User { roles, .. } => roles.iter().any(|r| r == name),
            _ => false,
        }
    }

    /// Upstream's `aclGroup`: `['*']`, then every role as `role:<name>`, then the user's objectId
    /// (`RestWrite.js:190`, `RestQuery.js:427`, both `['*'].concat(roles, [user.id])`).
    ///
    /// Master is the empty list, because upstream never reaches a caller that consumes an
    /// `aclGroup` without first branching on `isMaster`.
    ///
    /// Order matters twice over. `addPointerPermissions` extracts the single user id by filtering
    /// out `role:` and `*` (`DatabaseController.js:1746-1748`), and the compiled `$in` array is
    /// snapshot-compared.
    pub fn acl_group(&self) -> Vec<String> {
        match self {
            AclScope::Unrestricted => Vec::new(),
            AclScope::Anonymous => vec!["*".to_string()],
            AclScope::User { object_id, roles } => {
                let mut out = Vec::with_capacity(roles.len() + 2);
                out.push("*".to_string());
                out.extend(roles.iter().map(|r| format!("role:{r}")));
                // Defensive, and unreachable through `AclScope::user`. A `role:`-prefixed
                // objectId that arrived by literal construction is dropped rather than emitted,
                // which costs the caller access to their own rows and grants nothing.
                if !object_id.starts_with("role:") {
                    out.push(object_id.clone());
                }
                out
            }
        }
    }

    /// The principals this caller matches in an `_rperm`/`_wperm` lookup.
    ///
    /// `null` first, then optionally a literal `'*'`, then the `aclGroup`
    /// (`DatabaseController.js:81`, `:88`).
    fn principals(&self, seed_public: bool) -> Vec<ParseValue> {
        // `null` matches a row with no permission column, i.e. a public row.
        let mut out = vec![ParseValue::Null];
        if seed_public {
            out.push(ParseValue::String("*".to_string()));
        }
        out.extend(self.acl_group().into_iter().map(ParseValue::String));
        out
    }

    /// The constraint to add to a read.
    ///
    /// `None` for [`AclScope::Unrestricted`], which is the only case where no constraint is
    /// applied. Returning `Option` makes the master case explicit at every call site instead of
    /// being the absence of a step.
    ///
    /// UPSTREAM-QUIRK: the emitted list carries `'*'` twice, once seeded by `addReadACL`
    /// (`DatabaseController.js:88`) and once already present in the `aclGroup`
    /// (`RestQuery.js:427`). A duplicate in an `$in` changes nothing, and removing it would make
    /// the compiled query differ from upstream's for no gain.
    pub fn read_constraint(&self) -> Option<Constraint> {
        match self {
            AclScope::Unrestricted => None,
            _ => Some(Constraint {
                field: "_rperm".to_string(),
                comparison: Comparison::In(self.principals(true)),
            }),
        }
    }

    /// The constraint to add to a write.
    ///
    /// Note the asymmetry with reads: `addWriteACL` omits `'*'` from the injected list, because
    /// `getUserAndRoleACL` already seeds it for every non-master caller. Reproduced rather than
    /// unified, since the two functions are not symmetric upstream and a caller path that builds
    /// its own list would behave differently.
    pub fn write_constraint(&self) -> Option<Constraint> {
        match self {
            AclScope::Unrestricted => None,
            _ => Some(Constraint {
                field: "_wperm".to_string(),
                comparison: Comparison::In(self.principals(false)),
            }),
        }
    }
}

/// Resolve a class's declared default ACL into the value a create should carry.
///
/// `RestWrite.js:445-451`. The declared block is copied, and if it names `currentUser` then the
/// caller's objectId gains a copy of that entry and the `currentUser` key is removed.
///
/// Three details are load-bearing and each fails silently if it is got wrong.
///
/// **`currentUser` is resolved, never stored.** An ACL containing the literal string
/// `currentUser` as a principal matches nobody, so the row is unreadable by everyone including
/// the user it was meant for, and the configuration reads as though it worked.
///
/// **An anonymous caller loses the entry rather than keeping it.** Upstream's `delete` is outside
/// the `if (this.auth.user?.id)` guard, so with no caller there is no substitute id and the key
/// simply goes. A class whose only declared entry is `currentUser` therefore produces an ACL with
/// no entries at all for an anonymous create, which is a row only master can read. That is
/// upstream's behavior and it is the restrictive direction.
///
/// **Key order is preserved, and it is not upstream's order.** The `_rperm` and `_wperm` arrays
/// are built by walking the ACL, so their element order comes from here, and a mixed fleet compares
/// stored rows. Substituting the caller's id in place of `currentUser` rather than appending would
/// reorder them, so the substitution appends as upstream's assignment does.
///
/// Insertion order is not the whole story. **The lowering enumerates a JavaScript object, so an
/// integer-like key sorts ahead of every string key regardless of insertion order**, and an
/// objectId of `1234567890` is integer-like. That ordering lives in [`lower_acl`], which is the
/// one place a principal map becomes a column.
pub fn default_acl_for_create(declared: &ParseValue, caller: Option<&str>) -> ParseValue {
    let ParseValue::Object(map) = declared else {
        // A truthy non-object is assigned verbatim upstream and lowered by the same rule any
        // client-supplied non-object ACL is: two empty columns, a master-only row.
        return declared.clone();
    };
    let mut acl = map.clone();
    let Some(current_user) = acl.get("currentUser").cloned() else {
        return ParseValue::Object(acl);
    };
    // `if (acl.currentUser)`: a falsy entry is left in place and not resolved, because upstream's
    // guard is truthiness rather than presence.
    if !parse_rust_core::is_js_truthy(&current_user) {
        return ParseValue::Object(acl);
    }
    if let Some(caller) = caller {
        acl.insert(caller.to_string(), current_user);
    }
    acl.shift_remove("currentUser");
    ParseValue::Object(acl)
}

/// Split an `ACL` field out of a row into the two storage columns.
///
/// Returns the row with `ACL` removed and the columns added. A row with no `ACL` gets no columns,
/// which is what makes it public.
///
/// **The test upstream applies is falsiness, not "is it an object"** (`DatabaseController.js:94-96`,
/// literally `if (!ACL) return result`). Everything truthy falls through to a `for...in` that reads
/// `.read` and `.write` off each entry, so a string, a number or a tagged value yields no
/// principals but **still writes both columns as empty arrays**, which is a master-only row.
/// Skipping the columns instead writes a row with no `_rperm`/`_wperm` at all, and an absent column
/// is public.
///
/// Getting this wrong is not a cosmetic divergence. Nothing type-checks `ACL` on either side, by
/// design (`SchemaController.js:1312-1315`), so `{"ACL":"x"}` reaches here from any client. The
/// consequential class is `_Role`: its required-column check tests presence and truthiness only, so
/// a non-object `ACL` would satisfy it and then produce a world-writable role that any caller can
/// add itself to.
///
/// **An entry of `null` is an error, not an empty entry.** `ACL[entry].read` on `null` throws a
/// `TypeError` out of the controller, before the adapter is called, so upstream answers a bare 500
/// and writes nothing, on every class and on create and update alike. Measured at the pin for
/// `{"*":null}` and `[null]`.
pub fn lower_acl(mut row: ParseMap) -> Result<ParseMap, ParseError> {
    let Some(acl_value) = row.shift_remove("ACL") else {
        return Ok(row);
    };
    if !parse_rust_core::is_js_truthy(&acl_value) {
        return Ok(row);
    }
    let (rperm, wperm) = acl_columns(&acl_value)?;
    row.insert(
        "_rperm".to_string(),
        ParseValue::Array(rperm.into_iter().map(ParseValue::String).collect()),
    );
    row.insert(
        "_wperm".to_string(),
        ParseValue::Array(wperm.into_iter().map(ParseValue::String).collect()),
    );
    Ok(row)
}

/// The `for...in` loop of `transformObjectACL`, over a truthy `ACL`.
///
/// `if (ACL[entry].read)` is a truthiness test, so `{"*":{"read":1}}` grants public read upstream
/// and must here. Reading only `true`, which is what this did, granted nobody.
fn acl_columns(value: &ParseValue) -> Result<(Vec<String>, Vec<String>), ParseError> {
    let mut rperm = Vec::new();
    let mut wperm = Vec::new();
    for (key, entry) in js_own_entries(value) {
        if matches!(entry, ParseValue::Null) {
            return Err(ParseError::internal(format!(
                "ACL entry {key:?} is null; upstream throws reading `.read` off it"
            )));
        }
        if js_member_truthy(entry, "read") {
            rperm.push(key.clone());
        }
        if js_member_truthy(entry, "write") {
            wperm.push(key);
        }
    }
    Ok((rperm, wperm))
}

/// `value[name]` is truthy, in JavaScript's terms.
///
/// Only a plain object can carry a member a client named. An array, a string, a number and every
/// tagged value answer `undefined` for `read` and `write`, because none of their own keys is
/// spelled that way.
fn js_member_truthy(value: &ParseValue, name: &str) -> bool {
    match value {
        ParseValue::Object(map) => map.get(name).is_some_and(parse_rust_core::is_js_truthy),
        _ => false,
    }
}

/// The own enumerable string keys `for...in` visits, with their values, in its order.
///
/// **Order is the point.** JavaScript enumerates an ordinary object's array-index keys first, in
/// ascending numeric order, and every other key after them in insertion order. A body naming
/// `zzz`, `10`, `2`, `aaa` stores `["2","10","zzz","aaa"]` upstream. The order reaches the stored
/// `_rperm` and `_wperm` arrays, which a mixed fleet compares, and no JavaScript probe can see it,
/// because an object literal and `JSON.parse` both reorder the same way.
///
/// An array enumerates its indices. Everything else enumerates nothing that matters here: a
/// string's indices name single characters, which carry no `read`, and a tagged value's members are
/// all scalars or arrays.
pub fn js_own_entries(value: &ParseValue) -> Vec<(String, &ParseValue)> {
    match value {
        ParseValue::Object(map) => {
            let mut indices: Vec<(u32, &String, &ParseValue)> = Vec::new();
            let mut rest: Vec<(String, &ParseValue)> = Vec::new();
            for (key, entry) in map {
                match array_index(key) {
                    Some(i) => indices.push((i, key, entry)),
                    None => rest.push((key.clone(), entry)),
                }
            }
            indices.sort_by_key(|(i, _, _)| *i);
            indices
                .into_iter()
                .map(|(_, key, entry)| (key.clone(), entry))
                .chain(rest)
                .collect()
        }
        ParseValue::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, entry)| (i.to_string(), entry))
            .collect(),
        _ => Vec::new(),
    }
}

/// An ECMAScript array index: the canonical decimal spelling of an integer from 0 to 2^32 - 2.
///
/// `"01"`, `"-1"` and `"4294967295"` are ordinary string keys and keep their insertion position.
/// Measured at the pin: a body naming `4294967294`, `4294967295`, `01`, `1`, `-1` stores
/// `["1","4294967294","4294967295","01","-1"]`.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    let n: u64 = key.parse().ok()?;
    (n < u64::from(u32::MAX)).then_some(n as u32)
}

/// An array `ACL`, as the object JavaScript sees once a principal is assigned onto it.
///
/// Upstream's owner stamp is `ACL[objectId] = {...}` on whatever `this.data.ACL` holds, and on an
/// array that adds a property beside the indices. The lowering then enumerates both. Building the
/// map keyed by index is what lets the owner join it the same way.
pub fn array_acl_as_object(items: &[ParseValue]) -> ParseMap {
    items
        .iter()
        .enumerate()
        .map(|(i, entry)| (i.to_string(), entry.clone()))
        .collect()
}

/// Rebuild the `ACL` field from the two storage columns, then drop them.
///
/// Reproduces `untransformObjectACL` exactly, including that both columns absent produce **no
/// `ACL` key at all** rather than `null` or `{}`.
pub fn raise_acl(mut row: ParseMap) -> ParseMap {
    let rperm = take_string_array(&mut row, "_rperm");
    let wperm = take_string_array(&mut row, "_wperm");

    let Some(acl) = Acl::from_perms(rperm.as_deref(), wperm.as_deref()) else {
        return row;
    };

    let mut map = ParseMap::new();
    for (principal, perms) in acl.iter() {
        if perms.is_empty() {
            continue;
        }
        let mut entry = ParseMap::new();
        // Only true flags are emitted. UPSTREAM-QUIRK, see `parse_rust_core::acl`.
        if perms.read {
            entry.insert("read".to_string(), ParseValue::Bool(true));
        }
        if perms.write {
            entry.insert("write".to_string(), ParseValue::Bool(true));
        }
        map.insert(principal.as_key(), ParseValue::Object(entry));
    }
    row.insert("ACL".to_string(), ParseValue::Object(map));
    row
}

fn take_string_array(row: &mut ParseMap, key: &str) -> Option<Vec<String>> {
    match row.shift_remove(key) {
        Some(ParseValue::Array(items)) => Some(
            items
                .into_iter()
                .filter_map(|v| match v {
                    ParseValue::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(row: ParseMap) -> ParseMap {
        lower_acl(row).expect("a non-null ACL lowers")
    }

    fn row(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    /// The single most important assertion in this module.
    #[test]
    fn the_read_constraint_includes_null_so_public_rows_stay_visible() {
        let c = AclScope::Anonymous
            .read_constraint()
            .expect("anonymous is constrained");
        assert_eq!(c.field, "_rperm");
        match c.comparison {
            Comparison::In(values) => {
                assert!(
                    values.iter().any(|v| matches!(v, ParseValue::Null)),
                    "null must be in the list, or every row saved without an ACL becomes invisible"
                );
                assert!(values
                    .iter()
                    .any(|v| matches!(v, ParseValue::String(s) if s == "*")));
            }
            other => panic!("expected In, got {other:?}"),
        }
    }

    fn columns(lowered: &ParseMap) -> (Vec<String>, Vec<String>) {
        let read = take_string_array(&mut lowered.clone(), "_rperm").expect("_rperm written");
        let write = take_string_array(&mut lowered.clone(), "_wperm").expect("_wperm written");
        (read, write)
    }

    fn lowered_json(json: &str) -> Result<ParseMap, ParseError> {
        let value = parse_rust_core::decode::classify(serde_json::from_str(json).expect("json"))
            .expect("classify");
        lower_acl(row(vec![("ACL", value)]))
    }

    /// **An array's indices are principals.** `[{"read":true}]` grants principal `"0"` upstream,
    /// because `for...in` over an array visits its indices. `[]` and `[1,2]` cannot tell the two
    /// readings apart, which is how 0.2.1's tests passed over this. Measured at the pin, as a
    /// client-supplied `ACL`, a `_User` update and a CLP-declared default.
    #[test]
    fn a_permission_bearing_array_grants_its_indices() {
        let lowered = lowered_json(r#"[{"read":true},{"write":true}]"#).expect("lowers");
        assert_eq!(columns(&lowered), (vec!["0".into()], vec!["1".into()]));
    }

    /// `if (ACL[entry].read)` is truthiness. `1`, `"yes"` and `[]` grant; `0`, `""` and `false`
    /// do not.
    #[test]
    fn a_flag_is_tested_for_truthiness_not_for_true() {
        let lowered = lowered_json(
            r#"{"a":{"read":1},"b":{"read":"yes"},"c":{"write":[]},"d":{"read":0,"write":""},"e":{"read":false}}"#,
        )
        .expect("lowers");
        assert_eq!(
            columns(&lowered),
            (vec!["a".into(), "b".into()], vec!["c".into()])
        );
    }

    /// Array-index keys first, ascending; everything else after them, in insertion order. The
    /// boundary is 2^32 - 2, and `01` and `-1` are ordinary keys.
    #[test]
    fn principals_enumerate_in_javascript_property_order() {
        let lowered = lowered_json(
            r#"{"zzz":{"read":true},"10":{"read":true},"2":{"read":true},"aaa":{"read":true}}"#,
        )
        .expect("lowers");
        assert_eq!(columns(&lowered).0, vec!["2", "10", "zzz", "aaa"]);

        let lowered = lowered_json(
            r#"{"4294967294":{"read":true},"4294967295":{"read":true},"01":{"read":true},"1":{"read":true},"-1":{"read":true}}"#,
        )
        .expect("lowers");
        assert_eq!(
            columns(&lowered).0,
            vec!["1", "4294967294", "4294967295", "01", "-1"]
        );
    }

    /// `null.read` throws upstream, before anything is written. Every other non-object entry
    /// simply has no `read`.
    #[test]
    fn a_null_entry_is_an_internal_error_and_nothing_else_is() {
        for json in [r#"{"*":null}"#, "[null]", r#"[{"read":true},null]"#] {
            let e = lowered_json(json).expect_err(json);
            assert_eq!(e.code, ErrorCode::InternalServerError, "{json}");
        }
        for json in [
            r#"{"*":"yes"}"#,
            r#"{"*":5}"#,
            r#"{"*":true}"#,
            r#"{"*":[]}"#,
            r#"["ab"]"#,
        ] {
            let lowered = lowered_json(json).expect(json);
            assert_eq!(columns(&lowered), (Vec::new(), Vec::new()), "{json}");
        }
    }

    /// The falsy-versus-not-an-object distinction, which is the whole of `lower_acl`'s contract.
    ///
    /// A truthy non-object must produce two empty arrays, which is a master-only row. Producing no
    /// columns instead is a public row, and on `_Role` that is a world-writable role any caller can
    /// add itself to, because the required-column check tests truthiness and stops there.
    #[test]
    fn a_truthy_non_object_acl_writes_empty_columns_rather_than_none() {
        for value in [
            ParseValue::String("x".into()),
            ParseValue::Number(1.0),
            ParseValue::Array(vec![]),
            ParseValue::Array(vec![ParseValue::String("*".into())]),
            ParseValue::Date(parse_rust_core::ParseDate::now()),
            ParseValue::Bool(true),
            ParseValue::Object(ParseMap::new()),
        ] {
            let lowered = lower(row(vec![("ACL", value.clone())]));
            for column in ["_rperm", "_wperm"] {
                assert!(
                    matches!(lowered.get(column), Some(ParseValue::Array(a)) if a.is_empty()),
                    "a truthy ACL must write an empty {column}, got {:?} for {value:?}",
                    lowered.get(column)
                );
            }
            assert!(!lowered.contains_key("ACL"));
        }
    }

    /// The other half. Falsy means no columns, which is a public row, and that is upstream's
    /// `if (!ACL) return result`.
    #[test]
    fn a_falsy_or_absent_acl_writes_no_columns() {
        for value in [
            ParseValue::Null,
            ParseValue::Bool(false),
            ParseValue::Number(0.0),
            ParseValue::String(String::new()),
        ] {
            let lowered = lower(row(vec![("ACL", value.clone())]));
            assert!(!lowered.contains_key("_rperm"), "falsy ACL: {value:?}");
            assert!(!lowered.contains_key("_wperm"), "falsy ACL: {value:?}");
        }
        let untouched = lower(row(vec![("title", ParseValue::String("x".into()))]));
        assert!(!untouched.contains_key("_rperm"));
        assert!(!untouched.contains_key("_wperm"));
    }

    #[test]
    fn master_applies_no_constraint_at_all() {
        assert!(AclScope::Unrestricted.read_constraint().is_none());
        assert!(AclScope::Unrestricted.write_constraint().is_none());
    }

    #[test]
    fn a_user_scope_carries_its_object_id() {
        let c = AclScope::user("u1", vec![])
            .expect("plain id")
            .read_constraint()
            .expect("constrained");
        match c.comparison {
            Comparison::In(values) => assert!(values
                .iter()
                .any(|v| matches!(v, ParseValue::String(s) if s == "u1"))),
            other => panic!("expected In, got {other:?}"),
        }
    }

    /// 0.1.0 emitted no `role:` entry at all, so a `role:Admins` entry in `_rperm` matched
    /// nobody and every role-protected row was invisible to its own members.
    #[test]
    fn a_role_entry_now_matches() {
        let scope = AclScope::user("u1", vec!["Admins".into(), "Editors".into()]).expect("scope");
        let c = scope.read_constraint().expect("constrained");
        match c.comparison {
            Comparison::In(values) => {
                let strings: Vec<&str> = values
                    .iter()
                    .filter_map(|v| match v {
                        ParseValue::String(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .collect();
                assert!(strings.contains(&"role:Admins"), "{strings:?}");
                assert!(strings.contains(&"role:Editors"), "{strings:?}");
                assert!(strings.contains(&"u1"));
            }
            other => panic!("expected In, got {other:?}"),
        }
    }

    /// Upstream order: `['*']`, then roles, then the user id. `addPointerPermissions` recovers
    /// the single user id by filtering the first two out, so the shape is load bearing.
    #[test]
    fn the_acl_group_is_star_then_roles_then_the_user() {
        let scope = AclScope::user("u1", vec!["A".into()]).expect("scope");
        assert_eq!(scope.acl_group(), vec!["*", "role:A", "u1"]);
        assert_eq!(AclScope::Anonymous.acl_group(), vec!["*"]);
        assert!(AclScope::Unrestricted.acl_group().is_empty());
    }

    #[test]
    fn accessors_answer_for_every_variant() {
        let scope = AclScope::user("u1", vec!["A".into()]).expect("scope");
        assert!(scope.has_role("A"));
        assert!(!scope.has_role("role:A"), "roles are stored bare");
        assert!(!scope.has_role("B"));
        assert_eq!(scope.user_id(), Some("u1"));
        assert!(!scope.is_master());
        assert!(AclScope::Unrestricted.is_master());
        assert_eq!(AclScope::Anonymous.user_id(), None);
        assert!(!AclScope::Anonymous.has_role("A"));
    }

    /// The `role:` objectId collision, guarded at the one place a scope can be built.
    #[test]
    fn a_role_prefixed_object_id_is_refused() {
        let e = AclScope::user("role:Admins", vec![]).unwrap_err();
        assert_eq!(e.code, parse_rust_core::ErrorCode::InternalServerError);
        assert_eq!(e.message, "Invalid object ID.");
    }

    #[test]
    fn acl_lowers_to_two_columns_and_raises_back() {
        let mut acl_map = ParseMap::new();
        let mut public = ParseMap::new();
        public.insert("read".into(), ParseValue::Bool(true));
        acl_map.insert("*".into(), ParseValue::Object(public));
        let mut owner = ParseMap::new();
        owner.insert("read".into(), ParseValue::Bool(true));
        owner.insert("write".into(), ParseValue::Bool(true));
        acl_map.insert("u1".into(), ParseValue::Object(owner));

        let lowered = lower(row(vec![
            ("title", ParseValue::String("x".into())),
            ("ACL", ParseValue::Object(acl_map)),
        ]));
        assert!(
            lowered.get("ACL").is_none(),
            "ACL must not be stored as a field"
        );
        assert!(matches!(lowered.get("_rperm"), Some(ParseValue::Array(a)) if a.len() == 2));
        assert!(matches!(lowered.get("_wperm"), Some(ParseValue::Array(a)) if a.len() == 1));

        let raised = raise_acl(lowered);
        assert!(raised.get("_rperm").is_none() && raised.get("_wperm").is_none());
        let ParseValue::Object(acl) = raised.get("ACL").expect("ACL restored") else {
            panic!("ACL should be an object");
        };
        assert!(acl.contains_key("*") && acl.contains_key("u1"));
    }

    /// UPSTREAM-QUIRK, reproduced end to end.
    #[test]
    fn a_false_flag_disappears_on_the_round_trip() {
        let mut entry = ParseMap::new();
        entry.insert("read".into(), ParseValue::Bool(true));
        entry.insert("write".into(), ParseValue::Bool(false));
        let mut acl_map = ParseMap::new();
        acl_map.insert("*".into(), ParseValue::Object(entry));

        let raised = raise_acl(lower(row(vec![("ACL", ParseValue::Object(acl_map))])));
        let ParseValue::Object(acl) = raised.get("ACL").expect("ACL") else {
            panic!()
        };
        let ParseValue::Object(star) = acl.get("*").expect("*") else {
            panic!()
        };
        assert!(star.contains_key("read"));
        assert!(
            !star.contains_key("write"),
            "the false key is dropped, matching untransformObjectACL"
        );
    }

    // -----------------------------------------------------------------------------------------
    // The CLP-declared default ACL
    // -----------------------------------------------------------------------------------------

    fn declared(json: &str) -> ParseValue {
        parse_rust_core::decode::classify(
            serde_json::from_str(json).expect("test literal must be valid JSON"),
        )
        .expect("classify")
    }

    /// What the resolved ACL looks like on the wire, after a round trip through the two columns.
    /// Asserted this way rather than on the intermediate map, because the columns are what the
    /// row actually carries and an entry that survives resolution but not lowering grants nothing.
    fn principals(acl: ParseValue) -> (Vec<String>, Vec<String>) {
        let mut carrier = ParseMap::new();
        carrier.insert("ACL".to_string(), acl);
        let lowered = lower(carrier);
        let read = take_string_array(&mut lowered.clone(), "_rperm").unwrap_or_default();
        let write = take_string_array(&mut lowered.clone(), "_wperm").unwrap_or_default();
        (read, write)
    }

    /// The headline case, and the one the release is named for: a class declared private, an
    /// object created by user A, and the caller's own id in both columns.
    #[test]
    fn current_user_resolves_to_the_callers_object_id() {
        let acl = default_acl_for_create(
            &declared(r#"{"currentUser":{"read":true,"write":true}}"#),
            Some("userA"),
        );
        let ParseValue::Object(map) = &acl else {
            panic!("expected an object")
        };
        assert!(
            !map.contains_key("currentUser"),
            "the literal key matches nobody and must not be stored"
        );
        assert_eq!(
            principals(acl),
            (vec!["userA".to_string()], vec!["userA".to_string()])
        );
    }

    /// **Both columns, not just `_rperm`.** They are written separately, so an implementation that
    /// resolved the read entry and dropped the write one would hide the row from user B and pass a
    /// read-only test while leaving it writable by everybody.
    #[test]
    fn a_read_only_declaration_produces_a_read_only_row() {
        let acl = default_acl_for_create(&declared(r#"{"currentUser":{"read":true}}"#), Some("u1"));
        assert_eq!(principals(acl), (vec!["u1".to_string()], Vec::new()));
    }

    /// With no caller there is no substitute id, and upstream's `delete` is outside the guard, so
    /// the entry goes. A class whose only declared entry is `currentUser` therefore yields an ACL
    /// with no principals at all for an anonymous create: readable by master and nobody else.
    #[test]
    fn an_anonymous_create_loses_the_current_user_entry_rather_than_keeping_it() {
        let acl = default_acl_for_create(
            &declared(r#"{"currentUser":{"read":true,"write":true}}"#),
            None,
        );
        let ParseValue::Object(map) = &acl else {
            panic!("expected an object")
        };
        assert!(map.is_empty(), "the literal key must not survive: {map:?}");
        assert_eq!(principals(acl), (Vec::new(), Vec::new()));
    }

    /// Entries other than `currentUser` are carried through untouched, and the caller's own entry
    /// is appended after them, which is where a JS property assignment puts a new key. The column
    /// order is observable in a stored row.
    #[test]
    fn other_entries_survive_and_the_caller_is_appended() {
        let acl = default_acl_for_create(
            &declared(
                r#"{"role:Admins":{"read":true,"write":true},"currentUser":{"read":true},"*":{"read":true}}"#,
            ),
            Some("u1"),
        );
        let (read, write) = principals(acl);
        assert_eq!(read, vec!["role:Admins", "*", "u1"]);
        assert_eq!(write, vec!["role:Admins"]);
    }

    /// An id already present is updated in place rather than moved to the end, which is what a
    /// JavaScript assignment to an existing key does.
    #[test]
    fn a_caller_already_named_keeps_its_position() {
        let acl = default_acl_for_create(
            &declared(
                r#"{"u1":{"read":true},"*":{"read":true},"currentUser":{"read":true,"write":true}}"#,
            ),
            Some("u1"),
        );
        let (read, write) = principals(acl);
        assert_eq!(read, vec!["u1", "*"]);
        assert_eq!(write, vec!["u1"], "the currentUser entry replaced it");
    }

    /// `if (acl.currentUser)` is truthiness, so a falsy entry is neither resolved nor deleted.
    #[test]
    fn a_falsy_current_user_entry_is_left_alone() {
        let acl = default_acl_for_create(&declared(r#"{"currentUser":null}"#), Some("u1"));
        let ParseValue::Object(map) = &acl else {
            panic!("expected an object")
        };
        assert!(map.contains_key("currentUser"));
        assert!(!map.contains_key("u1"));
    }

    /// A truthy non-object is assigned verbatim and lowered like any other truthy non-object ACL:
    /// two empty columns, which is a master-only row rather than a public one.
    #[test]
    fn a_truthy_non_object_declaration_yields_a_master_only_row() {
        let acl = default_acl_for_create(&declared(r#""nonsense""#), Some("u1"));
        assert!(matches!(&acl, ParseValue::String(s) if s == "nonsense"));
        let mut carrier = ParseMap::new();
        carrier.insert("ACL".to_string(), acl);
        let lowered = lower(carrier);
        for column in ["_rperm", "_wperm"] {
            assert!(matches!(lowered.get(column), Some(ParseValue::Array(a)) if a.is_empty()));
        }
    }

    #[test]
    fn a_row_with_no_acl_gets_no_columns_and_no_acl_key_back() {
        let lowered = lower(row(vec![("title", ParseValue::String("x".into()))]));
        assert!(lowered.get("_rperm").is_none());
        let raised = raise_acl(lowered);
        assert!(
            raised.get("ACL").is_none(),
            "absent columns produce no ACL key at all, not null and not an empty object"
        );
    }
}
