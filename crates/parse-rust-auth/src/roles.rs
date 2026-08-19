//! The role graph.
//!
//! A user's roles are the roles they belong to directly, plus every role that transitively
//! contains one of those. Upstream computes it in `Auth.prototype._loadRoles`
//! (`Auth.js:297-336`) and `_getAllRolesNamesForRoleIds` (`Auth.js:393-428`), and this is a port
//! of that, not a reimplementation of the idea.
//!
//! **Unauthenticated against storage, deliberately.** Upstream queries `_Role` under
//! `master(this.config)` in both directions (`Auth.js:283`, `:383`). It has to: the role names
//! are an input to every later ACL and CLP decision, so gating them on one would be circular.
//! What keeps that narrow is that nothing here takes a client query. The inputs are a user
//! objectId and a set of role objectIds this module produced itself, and the output is a list of
//! role names.
//!
//! **No cache, on purpose.** Upstream caches the expanded list per user with a 5 second TTL and
//! clears the whole role cache on any `_Role` write (`RestWrite.js:1565-1570`). The invalidation
//! is the load-bearing half: a cache that keeps the TTL and drops the invalidation serves stale
//! *authorization* for up to five seconds after a role membership is revoked, which is worse than
//! not caching at all. Adding one is 0.3.0 work and it lands with the invalidation or not at all.
//! Until then a request with deep role nesting issues two queries per level of the graph.
//!
//! **Relation reads go straight to the join collections.** `_Role.users` and `_Role.roles` are
//! `Relation` fields, which have no column at all: membership lives in `_Join:users:_Role` and
//! `_Join:roles:_Role`, whose documents are exactly `{relatedId, owningId}`
//! (`DatabaseController.js:418-420`, `:794-806`) and which have **no `_SCHEMA` row**. That is why
//! the schema comes from [`join_schema`] rather than from storage, and why nothing here ever
//! writes one.

use std::collections::HashSet;

use indexmap::IndexSet;

use parse_rust_core::{ParseError, ParseValue, Principal};
use parse_rust_schema::default_schema;
use parse_rust_storage::{
    join_schema, ClassSchema, Constraint, Query, QueryOptions, StorageAdapter,
};

const ROLE_CLASS: &str = "_Role";
/// `_Role.users`, backed by `_Join:users:_Role`.
const USERS_KEY: &str = "users";
/// `_Role.roles`, backed by `_Join:roles:_Role`.
const ROLES_KEY: &str = "roles";

/// A role name, **without** the `role:` prefix.
///
/// The prefix is the whole reason this is a newtype. Upstream's `_loadRoles` returns
/// `'role:' + r` (`Auth.js:329-331`) while `getRolesForUser` deals in bare names, so a
/// `Vec<String>` crossing between them carries no evidence of which form it holds. Getting that
/// wrong in the unprefixing direction is how a user whose objectId begins with `role:` comes to
/// match a role ACL entry, which is the collision upstream guards against separately at
/// `Auth.js:195` and `:237`.
///
/// This type holds the bare name. [`RoleName::to_principal`] is the only way to get the prefixed
/// form, and it produces a [`Principal`] rather than a `String`, so the prefixed spelling exists
/// in exactly one place.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The bare name, as stored in `_Role.name`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The ACL principal this role grants: `role:<name>`.
    pub fn to_principal(&self) -> Principal {
        Principal::Role(self.0.clone())
    }
}

/// Who is asking.
///
/// Upstream's short-circuit is `if (this.isMaster || this.isMaintenance || !this.user) return []`
/// (`Auth.js:253-256`). Modelling it as an argument rather than leaving it to the caller means
/// there is no way to call this "for the master key" and get a real role list back: every variant
/// is matched here, and three of them never reach storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolePrincipal<'a> {
    /// The master key. Bypasses roles entirely, because it bypasses everything roles feed.
    Master,
    /// The maintenance key. Same.
    Maintenance,
    /// No session. Note this is *not* Parse's anonymous auth provider, which produces a real
    /// `_User` and takes the `User` arm; it is the absence of a user.
    Anonymous,
    User(&'a str),
}

/// Every role a principal holds, direct and transitive, deduplicated.
///
/// The order is upstream's: direct role names first, in the order the `_Role` rows came back,
/// then each level of ancestors in turn. Duplicates are dropped on first sight, which is what
/// `[...new Set(names)]` does (`Auth.js:402`).
///
/// **The traversal cuts cycles, it does not reject them.** Upstream marks each role objectId into
/// `queriedRoles` as it builds the next frontier and filters the frontier against it
/// (`Auth.js:393-398`), so `A -> B -> A` terminates with both names and no error. A cycle check
/// that raised would be a behavior change, and no cycle check at all is an infinite loop. The
/// marking is the whole mechanism; see `a_cycle_terminates_and_returns_both_names`.
///
/// **Depth is unbounded and the cost is per level, not per role.** Each level is one read of the
/// join collection followed by one read of `_Role`, regardless of how wide the frontier is. A
/// per-role query would turn a wide role graph into a query storm.
pub async fn expand_roles<S: StorageAdapter>(
    storage: &S,
    principal: RolePrincipal<'_>,
) -> Result<Vec<RoleName>, ParseError> {
    let user_object_id = match principal {
        RolePrincipal::Master | RolePrincipal::Maintenance | RolePrincipal::Anonymous => {
            return Ok(Vec::new())
        }
        RolePrincipal::User(id) => id,
    };

    let role_schema = default_schema(ROLE_CLASS);

    // Direct membership: `getRolesForUser` queries `_Role` for `{users: <user pointer>}`
    // (`Auth.js:267-294`). An equal-to-pointer constraint on a Relation field is not a column
    // read; `reduceInRelation` turns it into `owningIds(className, key, [userId])`
    // (`DatabaseController.js:1050`, `:1036-1044`), which is a read of the join collection.
    let direct_ids = owning_ids(storage, USERS_KEY, &[user_object_id.to_string()]).await?;
    if direct_ids.is_empty() {
        return Ok(Vec::new());
    }
    let direct = fetch_roles(storage, &role_schema, &direct_ids).await?;
    if direct.is_empty() {
        return Ok(Vec::new());
    }

    let mut names: IndexSet<RoleName> = IndexSet::new();
    let mut frontier: Vec<String> = Vec::new();
    for role in direct {
        if let Some(name) = role.name {
            names.insert(RoleName(name));
        }
        frontier.push(role.object_id);
    }

    // `_getAllRolesNamesForRoleIds`. `queried` is upstream's `queriedRoles`, and filtering the
    // frontier against it is what makes a cyclic graph terminate.
    let mut queried: HashSet<String> = HashSet::new();
    loop {
        let ins: Vec<String> = frontier
            .into_iter()
            .filter(|id| queried.insert(id.clone()))
            .collect();
        if ins.is_empty() {
            break;
        }

        // `getRolesByIds` queries `_Role` for `{roles: {$in: <role pointers>}}` (`Auth.js:377`),
        // meaning the roles that CONTAIN these roles. Same reduction as above, against the other
        // join collection.
        let parent_ids = owning_ids(storage, ROLES_KEY, &ins).await?;
        if parent_ids.is_empty() {
            break;
        }
        let parents = fetch_roles(storage, &role_schema, &parent_ids).await?;
        if parents.is_empty() {
            break;
        }

        frontier = Vec::with_capacity(parents.len());
        for role in parents {
            if let Some(name) = role.name {
                names.insert(RoleName(name));
            }
            frontier.push(role.object_id);
        }
    }

    Ok(names.into_iter().collect())
}

/// A `_Role` row reduced to the two fields the traversal needs.
///
/// `name` is optional because a stored row can lack one; see [`fetch_roles`].
struct Role {
    object_id: String,
    name: Option<String>,
}

/// `DatabaseController.owningIds` (`:1036-1044`): the owning ids of every join document whose
/// `relatedId` is in the given set.
///
/// **No limit.** `QueryOptions::default()` carries Parse's 100-row page size, which is correct
/// for a client query and wrong here: a role with more than a hundred members would silently lose
/// the rest, and a silently short role list is an under-grant that looks exactly like a correct
/// deny. Upstream reads the join collection through the adapter directly, below the REST limit,
/// and iterates the `_Role` side with `query.each` (`RestQuery.js:318-348`) so neither side is
/// capped.
async fn owning_ids<S: StorageAdapter>(
    storage: &S,
    key: &str,
    related_ids: &[String],
) -> Result<Vec<String>, ParseError> {
    if related_ids.is_empty() {
        return Ok(Vec::new());
    }
    let schema = join_schema(ROLE_CLASS, key);
    let query = Query::from_constraints(vec![Constraint::one_of(
        "relatedId",
        related_ids
            .iter()
            .map(|id| ParseValue::String(id.clone()))
            .collect(),
    )]);
    let options = QueryOptions {
        limit: None,
        skip: None,
        order: Vec::new(),
        keys: Some(vec!["owningId".to_string()]),
        case_insensitive: false,
    };

    let rows = storage.find(&schema, &query, &options).await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| match row.get("owningId") {
            Some(ParseValue::String(id)) => Some(id.clone()),
            _ => None,
        })
        .collect())
}

/// Fetch `_Role` rows by objectId.
///
/// The schema is `default_schema("_Role")` rather than the stored one. Both fields read here,
/// `objectId` and `name`, are default columns of `_Role` (`SchemaController.js:64-69`) that a
/// client cannot redefine, and neither `users` nor `roles` has a column to raise. A `_Role` class
/// carrying extra application fields still reads correctly, because the stored form is
/// self-describing everywhere it matters.
///
/// A row whose `name` is missing or not a string contributes **its id but not a name**. Upstream
/// would push `undefined` and later produce the principal `role:undefined`, which is a phantom
/// role that an ACL could name. Dropping the name rather than reproducing that is a deliberate
/// difference, and it is the safe direction: keeping the id means no ancestor of such a row is
/// lost, so nothing is under-granted. The row is not reachable through any Parse API, because
/// `name` is a required write column of `_Role`.
async fn fetch_roles<S: StorageAdapter>(
    storage: &S,
    schema: &ClassSchema,
    object_ids: &[String],
) -> Result<Vec<Role>, ParseError> {
    if object_ids.is_empty() {
        return Ok(Vec::new());
    }
    let query = Query::from_constraints(vec![Constraint::one_of(
        "objectId",
        object_ids
            .iter()
            .map(|id| ParseValue::String(id.clone()))
            .collect(),
    )]);
    let options = QueryOptions {
        limit: None,
        skip: None,
        order: Vec::new(),
        keys: None,
        case_insensitive: false,
    };

    let rows = storage.find(schema, &query, &options).await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let object_id = match row.get("objectId") {
                Some(ParseValue::String(id)) => id.clone(),
                _ => return None,
            };
            let name = match row.get("name") {
                Some(ParseValue::String(name)) => Some(name.clone()),
                _ => None,
            };
            Some(Role { object_id, name })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeStorage;
    use parse_rust_storage::join_table_name;

    /// Build a role graph. `members` is user objectIds in `_Join:users:_Role`; `contains` is
    /// `(child, parent)` pairs, meaning the parent role's `roles` relation holds the child.
    fn graph(
        roles: &[(&str, &str)],
        members: &[(&str, &str)],
        contains: &[(&str, &str)],
    ) -> FakeStorage {
        let s = FakeStorage::new();
        for (object_id, name) in roles {
            s.insert_row(
                "_Role",
                vec![
                    ("objectId", ParseValue::String((*object_id).into())),
                    ("name", ParseValue::String((*name).into())),
                ],
            );
        }
        for (user, role) in members {
            s.insert_row(
                &join_table_name("_Role", "users"),
                vec![
                    ("relatedId", ParseValue::String((*user).into())),
                    ("owningId", ParseValue::String((*role).into())),
                ],
            );
        }
        for (child, parent) in contains {
            s.insert_row(
                &join_table_name("_Role", "roles"),
                vec![
                    ("relatedId", ParseValue::String((*child).into())),
                    ("owningId", ParseValue::String((*parent).into())),
                ],
            );
        }
        s
    }

    fn names(roles: &[RoleName]) -> Vec<&str> {
        roles.iter().map(RoleName::as_str).collect()
    }

    #[tokio::test]
    async fn master_maintenance_and_anonymous_never_reach_storage() {
        let s = graph(&[("r1", "Admins")], &[("u1", "r1")], &[]);
        for principal in [
            RolePrincipal::Master,
            RolePrincipal::Maintenance,
            RolePrincipal::Anonymous,
        ] {
            s.reset_find_count();
            let roles = expand_roles(&s, principal).await.expect("expand");
            assert!(roles.is_empty(), "{principal:?} must expand to no roles");
            assert_eq!(s.find_count(), 0, "{principal:?} must issue no query");
        }
    }

    #[tokio::test]
    async fn a_user_in_no_role_gets_an_empty_list() {
        let s = graph(&[("r1", "Admins")], &[("u1", "r1")], &[]);
        let roles = expand_roles(&s, RolePrincipal::User("u2"))
            .await
            .expect("expand");
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn direct_membership_resolves_through_the_join_collection() {
        let s = graph(
            &[("r1", "Admins"), ("r2", "Editors"), ("r3", "Nobody")],
            &[("u1", "r1"), ("u1", "r2"), ("u2", "r3")],
            &[],
        );
        let roles = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        assert_eq!(names(&roles), vec!["Admins", "Editors"]);
    }

    /// The direction is upward: a member of the inner role gains the names of every role that
    /// contains it. Getting this backwards grants the wrong set and is not caught by a
    /// single-level test.
    #[tokio::test]
    async fn transitive_membership_walks_upward_not_downward() {
        // Admins contains Moderators contains Members. A Member is only a Member.
        let s = graph(
            &[("r1", "Members"), ("r2", "Moderators"), ("r3", "Admins")],
            &[("member", "r1"), ("admin", "r3")],
            &[("r1", "r2"), ("r2", "r3")],
        );

        let roles = expand_roles(&s, RolePrincipal::User("member"))
            .await
            .expect("expand");
        assert_eq!(names(&roles), vec!["Members", "Moderators", "Admins"]);

        let roles = expand_roles(&s, RolePrincipal::User("admin"))
            .await
            .expect("expand");
        assert_eq!(
            names(&roles),
            vec!["Admins"],
            "containment does not flow downward"
        );
    }

    /// The cycle break. Upstream marks ids into `queriedRoles` and filters the next frontier
    /// against it, so this terminates with both names and no error. A cycle check that raised
    /// would be a behavior change; a missing one would hang this test forever.
    #[tokio::test]
    async fn a_cycle_terminates_and_returns_both_names() {
        let s = graph(
            &[("a", "Alpha"), ("b", "Beta")],
            &[("u1", "a")],
            &[("a", "b"), ("b", "a")],
        );
        let roles = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        assert_eq!(names(&roles), vec!["Alpha", "Beta"]);
    }

    #[tokio::test]
    async fn a_self_referential_role_terminates() {
        let s = graph(&[("a", "Alpha")], &[("u1", "a")], &[("a", "a")]);
        let roles = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        assert_eq!(names(&roles), vec!["Alpha"]);
    }

    /// The failure this exists to catch is a silent under-grant: `QueryOptions::default()` caps
    /// at 100 rows, so a user in more than a hundred roles would lose the rest and the request
    /// would look like a correct deny.
    #[tokio::test]
    async fn more_than_a_hundred_roles_are_all_returned() {
        let ids: Vec<String> = (0..250).map(|i| format!("role{i:04}")).collect();
        let roles: Vec<(&str, &str)> = ids.iter().map(|id| (id.as_str(), id.as_str())).collect();
        let members: Vec<(&str, &str)> = ids.iter().map(|id| ("u1", id.as_str())).collect();
        let s = graph(&roles, &members, &[]);

        let resolved = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        assert_eq!(
            resolved.len(),
            250,
            "the default page size of 100 must not reach the join or role reads"
        );
    }

    /// One read of the join collection and one of `_Role` per level, regardless of how many roles
    /// are in the frontier. A per-role query would turn a wide graph into a query storm.
    #[tokio::test]
    async fn the_query_count_is_per_level_not_per_role() {
        // Twenty roles at the bottom, all contained by one role at the top.
        let mut roles: Vec<(String, String)> = (0..20)
            .map(|i| (format!("r{i:02}"), format!("Role{i:02}")))
            .collect();
        roles.push(("top".to_string(), "Top".to_string()));
        let role_refs: Vec<(&str, &str)> = roles
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let members: Vec<(&str, &str)> = roles[..20]
            .iter()
            .map(|(a, _)| ("u1", a.as_str()))
            .collect();
        let contains: Vec<(&str, &str)> = roles[..20]
            .iter()
            .map(|(a, _)| (a.as_str(), "top"))
            .collect();

        let s = graph(&role_refs, &members, &contains);
        s.reset_find_count();
        let resolved = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        assert_eq!(resolved.len(), 21);
        // Level 0: join read + role read. Level 1: join read + role read. Level 2: join read
        // returns nothing and stops. Nothing scales with the twenty-role frontier.
        assert_eq!(s.find_count(), 5);
    }

    #[tokio::test]
    async fn a_role_reachable_by_two_paths_appears_once() {
        // Both Editors and Reviewers are contained by Staff.
        let s = graph(
            &[("r1", "Editors"), ("r2", "Reviewers"), ("r3", "Staff")],
            &[("u1", "r1"), ("u1", "r2")],
            &[("r1", "r3"), ("r2", "r3")],
        );
        let roles = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        assert_eq!(names(&roles), vec!["Editors", "Reviewers", "Staff"]);
    }

    #[tokio::test]
    async fn a_role_row_with_no_name_contributes_its_ancestors_but_no_principal() {
        let s = FakeStorage::new();
        s.insert_row(
            "_Role",
            vec![("objectId", ParseValue::String("broken".into()))],
        );
        s.insert_row(
            "_Role",
            vec![
                ("objectId", ParseValue::String("parent".into())),
                ("name", ParseValue::String("Parent".into())),
            ],
        );
        s.insert_row(
            &join_table_name("_Role", "users"),
            vec![
                ("relatedId", ParseValue::String("u1".into())),
                ("owningId", ParseValue::String("broken".into())),
            ],
        );
        s.insert_row(
            &join_table_name("_Role", "roles"),
            vec![
                ("relatedId", ParseValue::String("broken".into())),
                ("owningId", ParseValue::String("parent".into())),
            ],
        );

        let roles = expand_roles(&s, RolePrincipal::User("u1"))
            .await
            .expect("expand");
        // No phantom principal from the nameless row, and the ancestor is still found.
        assert_eq!(names(&roles), vec!["Parent"]);
    }

    #[test]
    fn a_role_name_holds_the_bare_name_and_prefixes_only_on_request() {
        let r = RoleName::new("Admins");
        assert_eq!(r.as_str(), "Admins");
        assert_eq!(r.to_principal(), Principal::Role("Admins".into()));
        assert_eq!(r.to_principal().as_key(), "role:Admins");
    }

    /// A role whose name itself begins with `role:` must not double-prefix or unprefix. The
    /// newtype holds the bare name, so `role:role:x` is the only correct rendering.
    #[test]
    fn a_role_named_like_a_principal_is_not_unwrapped() {
        let r = RoleName::new("role:Admins");
        assert_eq!(r.as_str(), "role:Admins");
        assert_eq!(r.to_principal().as_key(), "role:role:Admins");
    }
}
