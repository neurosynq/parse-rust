//! ACL enforcement: the boundary between the `ACL` field a client sees and the `_rperm`/`_wperm`
//! columns storage holds.
//!
//! **The rule that must not be got wrong: absent permission columns mean public.**
//! `addReadACL` emits `_rperm: {$in: [null, '*', ...acl]}` and `null` in a Mongo `$in` matches a
//! document where the field is *missing*, which is how a row saved without an ACL stays readable.
//! Omitting the null silently hides every such row, and there is no error to notice.

use parse_rust_core::{Acl, ParseMap, ParseValue, Permissions, Principal};
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
    /// A logged-in user. Roles are out of scope for 0.1.0, so a `role:` entry never matches.
    User { object_id: String },
}

impl AclScope {
    /// The principals this caller matches, in upstream's order: `*` first, then the user id.
    fn principals(&self) -> Vec<ParseValue> {
        let mut out = vec![
            // `null` matches a row with no permission column, i.e. a public row.
            ParseValue::Null,
            ParseValue::String("*".to_string()),
        ];
        if let AclScope::User { object_id } = self {
            out.push(ParseValue::String(object_id.clone()));
        }
        out
    }

    /// The constraint to add to a read.
    ///
    /// `None` for [`AclScope::Unrestricted`], which is the only case where no constraint is
    /// applied. Returning `Option` makes the master case explicit at every call site instead of
    /// being the absence of a step.
    pub fn read_constraint(&self) -> Option<Constraint> {
        match self {
            AclScope::Unrestricted => None,
            _ => Some(Constraint {
                field: "_rperm".to_string(),
                comparison: Comparison::In(self.principals()),
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
                comparison: Comparison::In(self.principals()),
            }),
        }
    }
}

/// Split an `ACL` field out of a row into the two storage columns.
///
/// Returns the row with `ACL` removed and the columns added. A row with no `ACL` gets no columns,
/// which is what makes it public.
pub fn lower_acl(mut row: ParseMap) -> ParseMap {
    let Some(acl_value) = row.shift_remove("ACL") else {
        return row;
    };
    let Some(acl) = acl_from_value(&acl_value) else {
        return row;
    };
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

    #[test]
    fn master_applies_no_constraint_at_all() {
        assert!(AclScope::Unrestricted.read_constraint().is_none());
        assert!(AclScope::Unrestricted.write_constraint().is_none());
    }

    #[test]
    fn a_user_scope_carries_its_object_id() {
        let c = AclScope::User {
            object_id: "u1".into(),
        }
        .read_constraint()
        .expect("constrained");
        match c.comparison {
            Comparison::In(values) => assert!(values
                .iter()
                .any(|v| matches!(v, ParseValue::String(s) if s == "u1"))),
            other => panic!("expected In, got {other:?}"),
        }
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
