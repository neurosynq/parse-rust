//! Parse ACLs, and the storage form they lower to.
//!
//! An ACL is a map from principal to permissions. On the wire it is
//! `{"*":{"read":true},"role:Admin":{"read":true,"write":true}}`. In storage it is two arrays,
//! `_rperm` and `_wperm`, each listing the principals holding that permission.
//!
//! **UPSTREAM-QUIRK: the round trip is lossy, and this is Tier 1 bug-compatible.**
//! `untransformObjectACL` (`DatabaseController.js:385-406`) rebuilds the ACL from the two arrays
//! and only ever *sets* `read: true` or `write: true`. It never writes `false`. So an entry saved
//! as `{"read":true,"write":false}` reads back as `{"read":true}`, with the false key gone. A
//! client could depend on either shape, so reproduce it exactly and do not "fix" it.
//!
//! Two adjacent behaviors from the same function, both reproduced here:
//! - **Absent `_rperm` and `_wperm` produce no `ACL` key at all**, not `null` and not `{}`.
//!   The guard is `if (_rperm || _wperm)`.
//! - **An empty array is truthy in JavaScript**, so `_rperm: []` with no `_wperm` produces
//!   `"ACL": {}`, an empty object rather than an absent key. That asymmetry is easy to miss and
//!   easy to get wrong in Rust, where both are naturally `Option`/empty-`Vec`.

use indexmap::IndexMap;

/// Who a permission applies to.
///
/// `Other` exists because upstream does not validate that a non-`*`, non-`role:` principal is a
/// well-formed objectId. `RestWrite.js` writes the sentinel `*unresolved` into `_rperm` during
/// pointer-permission resolution and later matches on it, so a type that assumed "everything
/// else is an ObjectId" would either reject a real stored value or silently normalize it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Principal {
    /// `"*"`
    Public,
    /// `"role:<name>"`, stored without the prefix.
    Role(String),
    /// Anything else, kept verbatim. Usually an objectId.
    Other(String),
}

impl Principal {
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            Principal::Public
        } else if let Some(name) = s.strip_prefix("role:") {
            Principal::Role(name.to_string())
        } else {
            Principal::Other(s.to_string())
        }
    }

    pub fn as_key(&self) -> String {
        match self {
            Principal::Public => "*".to_string(),
            Principal::Role(name) => format!("role:{name}"),
            Principal::Other(s) => s.clone(),
        }
    }
}

/// Read and write flags for one principal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
}

impl Permissions {
    pub fn is_empty(&self) -> bool {
        !self.read && !self.write
    }
}

/// An ACL. Insertion-ordered, because the order of `_rperm` and `_wperm` is observable in
/// golden-file comparison even though it carries no meaning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Acl(IndexMap<Principal, Permissions>);

impl Acl {
    pub fn new() -> Self {
        Self(IndexMap::new())
    }

    pub fn set(&mut self, principal: Principal, perms: Permissions) {
        self.0.insert(principal, perms);
    }

    pub fn get(&self, principal: &Principal) -> Option<Permissions> {
        self.0.get(principal).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Principal, &Permissions)> {
        self.0.iter()
    }

    /// Lower to the storage form. An entry with neither permission appears in neither array,
    /// which is what makes the JSON round trip lossy.
    pub fn to_perms(&self) -> (Vec<String>, Vec<String>) {
        let mut rperm = Vec::new();
        let mut wperm = Vec::new();
        for (principal, perms) in &self.0 {
            if perms.read {
                rperm.push(principal.as_key());
            }
            if perms.write {
                wperm.push(principal.as_key());
            }
        }
        (rperm, wperm)
    }

    /// Rebuild from the storage form, reproducing `untransformObjectACL` exactly.
    ///
    /// Returns `None` when both columns are absent, which is the case that must produce no `ACL`
    /// key in the response rather than an empty one. `Some(empty Acl)` is the distinct case where
    /// a column is present but empty, which upstream renders as `"ACL": {}`.
    pub fn from_perms(rperm: Option<&[String]>, wperm: Option<&[String]>) -> Option<Acl> {
        if rperm.is_none() && wperm.is_none() {
            return None;
        }
        let mut acl = Acl::new();
        for entry in rperm.unwrap_or(&[]) {
            acl.0.entry(Principal::parse(entry)).or_default().read = true;
        }
        for entry in wperm.unwrap_or(&[]) {
            acl.0.entry(Principal::parse(entry)).or_default().write = true;
        }
        Some(acl)
    }

    /// The wire form. Only true flags are emitted, per the quirk above.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{");
        let mut first = true;
        for (principal, perms) in &self.0 {
            if perms.is_empty() {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            crate::value::write_json_string(&principal.as_key(), &mut out);
            out.push(':');
            out.push('{');
            match (perms.read, perms.write) {
                (true, true) => out.push_str(r#""read":true,"write":true"#),
                (true, false) => out.push_str(r#""read":true"#),
                (false, true) => out.push_str(r#""write":true"#),
                (false, false) => {}
            }
            out.push('}');
        }
        out.push('}');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Principal {
        Principal::parse(s)
    }

    #[test]
    fn principal_round_trips_every_shape() {
        for s in [
            "*",
            "role:Admin",
            "abc123",
            "*unresolved",
            "role:with:colons",
        ] {
            assert_eq!(Principal::parse(s).as_key(), s, "{s} did not round trip");
        }
        assert_eq!(p("*"), Principal::Public);
        assert_eq!(p("role:Admin"), Principal::Role("Admin".into()));
        // The sentinel must not be mistaken for the public principal or an objectId.
        assert_eq!(p("*unresolved"), Principal::Other("*unresolved".into()));
    }

    #[test]
    fn storage_round_trip_is_lossless() {
        let mut acl = Acl::new();
        acl.set(
            Principal::Public,
            Permissions {
                read: true,
                write: false,
            },
        );
        acl.set(
            Principal::Role("Admin".into()),
            Permissions {
                read: true,
                write: true,
            },
        );

        let (r, w) = acl.to_perms();
        assert_eq!(r, vec!["*", "role:Admin"]);
        assert_eq!(w, vec!["role:Admin"]);
        assert_eq!(Acl::from_perms(Some(&r), Some(&w)), Some(acl));
    }

    /// The Tier 1 quirk. This test exists so that "fixing" it fails loudly.
    #[test]
    fn upstream_quirk_false_flags_are_dropped_from_json() {
        let mut acl = Acl::new();
        acl.set(
            Principal::Public,
            Permissions {
                read: true,
                write: false,
            },
        );
        assert_eq!(acl.to_json(), r#"{"*":{"read":true}}"#);

        let mut both = Acl::new();
        both.set(
            Principal::Public,
            Permissions {
                read: true,
                write: true,
            },
        );
        assert_eq!(both.to_json(), r#"{"*":{"read":true,"write":true}}"#);

        let mut write_only = Acl::new();
        write_only.set(
            Principal::Public,
            Permissions {
                read: false,
                write: true,
            },
        );
        assert_eq!(write_only.to_json(), r#"{"*":{"write":true}}"#);
    }

    #[test]
    fn an_entry_with_no_permissions_disappears_entirely() {
        let mut acl = Acl::new();
        acl.set(Principal::Other("abc".into()), Permissions::default());
        assert_eq!(acl.to_json(), "{}");
        let (r, w) = acl.to_perms();
        assert!(r.is_empty() && w.is_empty());
    }

    #[test]
    fn absent_columns_and_empty_columns_are_different() {
        // Both absent: no ACL key at all in the response.
        assert_eq!(Acl::from_perms(None, None), None);
        // Present but empty: an empty ACL object, because [] is truthy in JavaScript.
        let empty: [String; 0] = [];
        assert_eq!(Acl::from_perms(Some(&empty), None), Some(Acl::new()));
        assert_eq!(
            Acl::from_perms(Some(&empty), None).map(|a| a.to_json()),
            Some("{}".to_string())
        );
    }

    #[test]
    fn merges_the_two_columns_per_principal() {
        let r = vec!["*".to_string(), "role:Admin".to_string()];
        let w = vec!["role:Admin".to_string()];
        let acl = Acl::from_perms(Some(&r), Some(&w)).unwrap();
        assert_eq!(
            acl.get(&Principal::Public),
            Some(Permissions {
                read: true,
                write: false
            })
        );
        assert_eq!(
            acl.get(&Principal::Role("Admin".into())),
            Some(Permissions {
                read: true,
                write: true
            })
        );
    }

    #[test]
    fn insertion_order_is_preserved_in_both_directions() {
        let r = vec!["z".to_string(), "a".to_string(), "m".to_string()];
        let acl = Acl::from_perms(Some(&r), None).unwrap();
        let (out, _) = acl.to_perms();
        assert_eq!(out, r, "order must not be sorted");
    }
}
