//! ACL enforcement: the boundary between the `ACL` field a client sees and the `_rperm`/`_wperm`
//! columns storage holds.
//!
//! **The rule that must not be got wrong: absent permission columns mean public.**
//! `addReadACL` emits `_rperm: {$in: [null, '*', ...acl]}` and `null` in a Mongo `$in` matches a
//! document where the field is *missing*, which is how a row saved without an ACL stays readable.
//! Omitting the null silently hides every such row, and there is no error to notice.

use parse_rust_core::{Acl, ErrorCode, ParseError, ParseMap, ParseValue, Permissions, Principal};
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
    /// (`RestWrite.js:184`, `RestQuery.js:427`, both `['*'].concat(roles, [user.id])`).
    ///
    /// Master is the empty list, because upstream never reaches a caller that consumes an
    /// `aclGroup` without first branching on `isMaster`.
    ///
    /// Order matters twice over. `addPointerPermissions` extracts the single user id by filtering
    /// out `role:` and `*` (`DatabaseController.js:1745-1747`), and the compiled `$in` array is
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

/// Split an `ACL` field out of a row into the two storage columns.
///
/// Returns the row with `ACL` removed and the columns added. A row with no `ACL` gets no columns,
/// which is what makes it public.
///
/// **The test upstream applies is falsiness, not "is it an object"** (`DatabaseController.js:94-96`,
/// literally `if (!ACL) return result`). Everything truthy falls through to a `for...in` that reads
/// `.read` and `.write` off each entry, so a string, a number or an array yields no principals but
/// **still writes both columns as empty arrays**, which is a master-only row. Skipping the columns
/// instead writes a row with no `_rperm`/`_wperm` at all, and an absent column is public.
///
/// Getting this wrong is not a cosmetic divergence. Nothing type-checks `ACL` on either side, by
/// design (`SchemaController.js:1312-1315`), so `{"ACL":"x"}` reaches here from any client. The
/// consequential class is `_Role`: its required-column check tests presence and truthiness only, so
/// a non-object `ACL` would satisfy it and then produce a world-writable role that any caller can
/// add itself to.
///
/// The update path applies the same test, in `lower_acl_into_update`. It did not until a review:
/// it tested for `null` alone, so `false`, `0` and `""` fell through and cleared both columns on a
/// row that already had permissions. Both paths now branch on truthiness, and the tests on each
/// side loop over the falsy values rather than checking one, because checking one is what let the
/// other three through.
pub fn lower_acl(mut row: ParseMap) -> ParseMap {
    let Some(acl_value) = row.shift_remove("ACL") else {
        return row;
    };
    if !parse_rust_core::is_js_truthy(&acl_value) {
        return row;
    }
    // `None` here is a truthy non-object, which upstream's loop walks and takes nothing from.
    let acl = acl_from_value(&acl_value).unwrap_or_default();
    let (rperm, wperm) = acl.to_perms();
    row.insert(
        "_rperm".to_string(),
        ParseValue::Array(rperm.into_iter().map(ParseValue::String).collect()),
    );
    row.insert(
        "_wperm".to_string(),
        ParseValue::Array(wperm.into_iter().map(ParseValue::String).collect()),
    );
    row
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

/// Read a client-supplied `ACL` value.
fn acl_from_value(value: &ParseValue) -> Option<Acl> {
    let ParseValue::Object(map) = value else {
        return None;
    };
    let mut acl = Acl::new();
    for (key, entry) in map {
        let ParseValue::Object(flags) = entry else {
            continue;
        };
        let flag = |name: &str| matches!(flags.get(name), Some(ParseValue::Bool(true)));
        acl.set(
            Principal::parse(key),
            Permissions {
                read: flag("read"),
                write: flag("write"),
            },
        );
    }
    Some(acl)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ParseValue::Bool(true),
            ParseValue::Object(ParseMap::new()),
        ] {
            let lowered = lower_acl(row(vec![("ACL", value.clone())]));
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
            let lowered = lower_acl(row(vec![("ACL", value.clone())]));
            assert!(!lowered.contains_key("_rperm"), "falsy ACL: {value:?}");
            assert!(!lowered.contains_key("_wperm"), "falsy ACL: {value:?}");
        }
        let untouched = lower_acl(row(vec![("title", ParseValue::String("x".into()))]));
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

        let lowered = lower_acl(row(vec![
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

        let raised = raise_acl(lower_acl(row(vec![("ACL", ParseValue::Object(acl_map))])));
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

    #[test]
    fn a_row_with_no_acl_gets_no_columns_and_no_acl_key_back() {
        let lowered = lower_acl(row(vec![("title", ParseValue::String("x".into()))]));
        assert!(lowered.get("_rperm").is_none());
        let raised = raise_acl(lowered);
        assert!(
            raised.get("ACL").is_none(),
            "absent columns produce no ACL key at all, not null and not an empty object"
        );
    }
}
