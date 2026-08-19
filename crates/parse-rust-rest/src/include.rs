//! `include`: expanding pointers into the objects they point at.
//!
//! The algorithm is upstream's (`RestQuery.js:241-258` for path expansion, `:1057-1288` for
//! execution). Every prefix of every dotted path is materialized and the paths are sorted by
//! depth, so a parent resolves before its children. Per level, the pointers at that path are
//! collected and grouped by target class, and **one query is issued per target class per level**
//! rather than one per pointer.
//!
//! The part that is not an optimization: **the nested query is a full read against the target
//! class with the caller's own scope**, so the target class's CLP, its object ACLs and its
//! protected fields all apply. Grafting a row in without that is the classic Parse data leak,
//! because the caller is authorized for the class holding the pointer and not for the class it
//! points at. This module deliberately does not fetch anything; it collects and grafts, and the
//! pipeline owns the read.
//!
//! `include=*` is out of scope for 0.2.0 and is refused at parse time. See
//! [`crate::query_parse::parse_include`].

use indexmap::IndexMap;
use parse_rust_core::{ParseMap, ParseValue};

/// Pointers found at one path, grouped by target class, in encounter order.
///
/// Insertion-ordered so the generated `$in` array is deterministic and diffable against
/// upstream's.
pub type PointersByClass = IndexMap<String, Vec<String>>;

/// Collect every pointer at `path`, walking through arrays.
pub fn collect_pointers(results: &[ParseMap], path: &[String]) -> PointersByClass {
    let mut out: PointersByClass = IndexMap::new();
    for row in results {
        collect_from_value(&ParseValue::Object(row.clone()), path, &mut out);
    }
    out
}

fn collect_from_value(value: &ParseValue, path: &[String], out: &mut PointersByClass) {
    // An array is walked before the path is consumed, at every depth, which is how a path
    // reaches into an array of pointers and into an array of expanded objects alike
    // (`RestQuery.js:1296-1298`).
    if let ParseValue::Array(items) = value {
        for item in items {
            collect_from_value(item, path, out);
        }
        return;
    }
    match (path.split_first(), value) {
        (
            None,
            ParseValue::Pointer {
                class_name,
                object_id,
            },
        ) => {
            let ids = out.entry(class_name.clone()).or_default();
            if !ids.contains(object_id) {
                ids.push(object_id.clone());
            }
        }
        (None, _) => {}
        (Some((head, rest)), ParseValue::Object(map)) => {
            if let Some(next) = map.get(head) {
                collect_from_value(next, rest, out);
            }
        }
        _ => {}
    }
}

/// Replace the pointers at `path` with the fetched objects.
///
/// `replacePointers` (`RestQuery.js:1324-1356`). An unresolved pointer is **dropped**, not left
/// as a pointer: inside an array the element disappears, and at a scalar key the key becomes
/// absent. That is how a pointer to a row the caller cannot read stops being evidence that the
/// row exists.
pub fn graft(results: &mut [ParseMap], path: &[String], fetched: &IndexMap<String, ParseMap>) {
    for row in results.iter_mut() {
        graft_into_map(row, path, fetched);
    }
}

fn graft_into_map(map: &mut ParseMap, path: &[String], fetched: &IndexMap<String, ParseMap>) {
    let Some((head, rest)) = path.split_first() else {
        return;
    };
    let Some(current) = map.shift_remove(head) else {
        return;
    };
    // A pointer that did not resolve leaves the key absent rather than null.
    if let Some(value) = graft_value(current, rest, fetched) {
        map.insert(head.clone(), value);
    }
    // `shift_remove` moved the key to the end of the map. Reinsertion above restores the value
    // but not the position; key order within one object is not part of the wire contract for a
    // rewritten key, and preserving it would mean rebuilding the map for every result.
}

fn graft_value(
    value: ParseValue,
    path: &[String],
    fetched: &IndexMap<String, ParseMap>,
) -> Option<ParseValue> {
    // Arrays first, at every depth, mirroring `findPointers`. An element that does not resolve is
    // dropped from the array rather than left behind as a pointer.
    if let ParseValue::Array(items) = value {
        return Some(ParseValue::Array(
            items
                .into_iter()
                .filter_map(|item| graft_value(item, path, fetched))
                .collect(),
        ));
    }
    match (path.split_first(), value) {
        (None, ParseValue::Pointer { object_id, .. }) => fetched
            .get(&object_id)
            .map(|row| ParseValue::Object(row.clone())),
        (None, other) => Some(other),
        (Some((head, rest)), ParseValue::Object(mut map)) => {
            if let Some(inner) = map.shift_remove(head) {
                if let Some(replaced) = graft_value(inner, rest, fetched) {
                    map.insert(head.clone(), replaced);
                }
            }
            Some(ParseValue::Object(map))
        }
        (Some(_), other) => Some(other),
    }
}

/// Shape a fetched row for grafting: `__type` and `className`, and the `_User` stripping.
///
/// An included `_User` loses `sessionToken` and `authData` for a non-master caller
/// (`RestQuery.js:1269-1275`). Note this is on top of the target class's own
/// `filterSensitiveData`, not instead of it.
pub fn shape_included(row: &mut ParseMap, class_name: &str, is_master: bool) {
    row.insert(
        "__type".to_string(),
        ParseValue::String("Object".to_string()),
    );
    row.insert(
        "className".to_string(),
        ParseValue::String(class_name.to_string()),
    );
    if class_name == "_User" && !is_master {
        row.shift_remove("sessionToken");
        row.shift_remove("authData");
    }
}

/// The `keys` an included query inherits (`RestQuery.js:1196-1214`).
///
/// Keep only keys whose leading components match the path, then take the component at the path's
/// depth. `None` means the include is unprojected.
pub fn keys_for_path(keys: &[String], path: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for key in keys {
        let parts: Vec<&str> = key.split('.').collect();
        if !path
            .iter()
            .enumerate()
            .all(|(i, p)| parts.get(i).is_some_and(|k| k == p))
        {
            continue;
        }
        if let Some(next) = parts.get(path.len()) {
            let next = (*next).to_string();
            if !out.contains(&next) {
                out.push(next);
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The `excludeKeys` an included query inherits (`RestQuery.js:1216-1234`).
///
/// Deliberately a second function rather than a parameter on the first: the terminating condition
/// differs, `i == keyPath.length - 1` here against `i < keyPath.length` for `keys`, so a shared
/// implementation would have to be wrong for one of them.
pub fn exclude_keys_for_path(exclude_keys: &[String], path: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for key in exclude_keys {
        let parts: Vec<&str> = key.split('.').collect();
        if !path
            .iter()
            .enumerate()
            .all(|(i, p)| parts.get(i).is_some_and(|k| k == p))
        {
            continue;
        }
        if path.len() == parts.len().saturating_sub(1) {
            if let Some(next) = parts.get(path.len()) {
                let next = (*next).to_string();
                if !out.contains(&next) {
                    out.push(next);
                }
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The extra include paths `keys` and `excludeKeys` force (`RestQuery.js:148-183`).
///
/// A dotted projection needs its parent included, because the projection only ever names the
/// first component of a path on the class being queried. `a.b.c` therefore forces `a.b`.
pub fn paths_forced_by_projection(keys: &[String], exclude_keys: &[String]) -> Vec<String> {
    keys.iter()
        .chain(exclude_keys.iter())
        .filter(|k| k.contains('.'))
        .filter_map(|k| k.rsplit_once('.').map(|(head, _)| head.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pointer(class: &str, id: &str) -> ParseValue {
        ParseValue::Pointer {
            class_name: class.to_string(),
            object_id: id.to_string(),
        }
    }

    fn row(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    #[test]
    fn pointers_group_by_class_and_dedupe() {
        let results = vec![
            row(vec![("author", pointer("_User", "u1"))]),
            row(vec![("author", pointer("_User", "u1"))]),
            row(vec![("author", pointer("Robot", "r1"))]),
        ];
        let found = collect_pointers(&results, &["author".to_string()]);
        assert_eq!(found.get("_User"), Some(&vec!["u1".to_string()]));
        assert_eq!(found.get("Robot"), Some(&vec!["r1".to_string()]));
    }

    #[test]
    fn pointers_inside_arrays_are_found() {
        let results = vec![row(vec![(
            "editors",
            ParseValue::Array(vec![pointer("_User", "u1"), pointer("_User", "u2")]),
        )])];
        let found = collect_pointers(&results, &["editors".to_string()]);
        assert_eq!(
            found.get("_User"),
            Some(&vec!["u1".to_string(), "u2".to_string()])
        );
    }

    #[test]
    fn a_nested_path_reaches_through_an_expanded_parent() {
        let results = vec![row(vec![(
            "author",
            ParseValue::Object(row(vec![("company", pointer("Company", "c1"))])),
        )])];
        let found = collect_pointers(&results, &["author".to_string(), "company".to_string()]);
        assert_eq!(found.get("Company"), Some(&vec!["c1".to_string()]));
    }

    #[test]
    fn a_resolved_pointer_is_replaced_and_an_unresolved_one_disappears() {
        let mut results = vec![
            row(vec![
                ("objectId", ParseValue::String("p1".into())),
                ("author", pointer("_User", "u1")),
            ]),
            row(vec![
                ("objectId", ParseValue::String("p2".into())),
                ("author", pointer("_User", "hidden")),
            ]),
        ];
        let mut fetched = IndexMap::new();
        fetched.insert(
            "u1".to_string(),
            row(vec![("objectId", ParseValue::String("u1".into()))]),
        );
        graft(&mut results, &["author".to_string()], &fetched);
        assert!(matches!(
            results[0].get("author"),
            Some(ParseValue::Object(_))
        ));
        assert!(
            results[1].get("author").is_none(),
            "a pointer the caller cannot read is dropped, not left as a pointer"
        );
    }

    #[test]
    fn an_unresolved_pointer_inside_an_array_is_filtered_out() {
        let mut results = vec![row(vec![(
            "editors",
            ParseValue::Array(vec![pointer("_User", "u1"), pointer("_User", "hidden")]),
        )])];
        let mut fetched = IndexMap::new();
        fetched.insert(
            "u1".to_string(),
            row(vec![("objectId", ParseValue::String("u1".into()))]),
        );
        graft(&mut results, &["editors".to_string()], &fetched);
        match results[0].get("editors") {
            Some(ParseValue::Array(items)) => assert_eq!(items.len(), 1),
            other => panic!("expected an array, got {other:?}"),
        }
    }

    #[test]
    fn an_included_user_loses_its_session_token_for_a_non_master_caller() {
        let mut r = row(vec![
            ("sessionToken", ParseValue::String("r:t".into())),
            ("authData", ParseValue::Object(ParseMap::new())),
        ]);
        shape_included(&mut r, "_User", false);
        assert!(r.get("sessionToken").is_none());
        assert!(r.get("authData").is_none());
        assert!(matches!(r.get("__type"), Some(ParseValue::String(s)) if s == "Object"));
        assert!(matches!(r.get("className"), Some(ParseValue::String(s)) if s == "_User"));

        let mut r = row(vec![("sessionToken", ParseValue::String("r:t".into()))]);
        shape_included(&mut r, "_User", true);
        assert!(r.get("sessionToken").is_some());
    }

    #[test]
    fn projections_rewrite_per_path() {
        let keys = vec!["author.name".to_string(), "title".to_string()];
        assert_eq!(
            keys_for_path(&keys, &["author".to_string()]),
            Some(vec!["name".to_string()])
        );
        assert_eq!(keys_for_path(&keys, &["other".to_string()]), None);

        // The exclude rule stops one level shallower than the keys rule.
        let excludes = vec!["author.company.name".to_string()];
        assert_eq!(
            exclude_keys_for_path(&excludes, &["author".to_string()]),
            None
        );
        assert_eq!(
            exclude_keys_for_path(&excludes, &["author".to_string(), "company".to_string()]),
            Some(vec!["name".to_string()])
        );
    }

    #[test]
    fn a_dotted_projection_forces_its_parent_include() {
        assert_eq!(
            paths_forced_by_projection(&["a.b.c".to_string(), "d".to_string()], &[]),
            vec!["a.b".to_string()]
        );
        assert_eq!(
            paths_forced_by_projection(&[], &["x.y".to_string()]),
            vec!["x".to_string()]
        );
    }
}
