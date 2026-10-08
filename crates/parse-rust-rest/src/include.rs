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
    let mut seen: IndexMap<String, indexmap::IndexSet<String>> = IndexMap::new();
    let Some((head, rest)) = path.split_first() else {
        return PointersByClass::new();
    };
    for row in results {
        if let Some(next) = row.get(head) {
            collect_from_value(next, rest, &mut seen);
        }
    }
    seen.into_iter()
        .map(|(class, ids)| (class, ids.into_iter().collect()))
        .collect()
}

fn collect_from_value(
    value: &ParseValue,
    path: &[String],
    out: &mut IndexMap<String, indexmap::IndexSet<String>>,
) {
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
        (None, _) => {
            if let Some((class_name, object_id)) = pointer_parts(value) {
                out.entry(class_name.to_string())
                    .or_default()
                    .insert(object_id.to_string());
            }
        }
        (Some((head, rest)), ParseValue::Object(map)) => {
            if let Some(next) = map.get(head) {
                collect_from_value(next, rest, out);
            }
        }
        _ => {}
    }
}

/// The class and id of a pointer, in either of the forms one arrives in.
///
/// A pointer at a schema-typed field decodes as [`ParseValue::Pointer`]. One stored inside an
/// array or a plain object has no column type to decode it by, so it reads back as the plain
/// `{"__type":"Pointer",...}` object it was stored as. Upstream tests `__type == 'Pointer'` on plain
/// JSON (`RestQuery.js:1305`, `:1336`), so both are pointers to it, and an include through an array
/// of pointers expands. A plain one without a string class or id is not collected.
fn pointer_parts(value: &ParseValue) -> Option<(&str, &str)> {
    match value {
        ParseValue::Pointer {
            class_name,
            object_id,
        } => Some((class_name, object_id)),
        ParseValue::Object(map) if is_plain_pointer(map) => {
            match (map.get("className"), map.get("objectId")) {
                (Some(ParseValue::String(c)), Some(ParseValue::String(id))) => Some((c, id)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_plain_pointer(map: &ParseMap) -> bool {
    matches!(map.get("__type"), Some(ParseValue::String(t)) if t == "Pointer")
}

/// Replace the pointers at `path` with the fetched objects.
///
/// `replacePointers` (`RestQuery.js:1324-1356`). An unresolved pointer is **dropped**, not left
/// as a pointer: inside an array the element disappears, and at a scalar key the key becomes
/// absent. That is how a pointer to a row the caller cannot read stops being evidence that the
/// row exists.
pub fn graft(
    results: &mut [ParseMap],
    path: &[String],
    fetched: &IndexMap<String, ParseMap>,
    budget: &mut GraftBudget,
) -> Result<(), parse_rust_core::ParseError> {
    let sizes: IndexMap<&str, usize> = fetched
        .iter()
        .map(|(id, row)| (id.as_str(), ParseValue::object_json_len(row)))
        .collect();
    let mut grafting = Grafting {
        fetched,
        sizes: &sizes,
        budget,
    };
    for row in results.iter_mut() {
        if grafting.budget.exceeded {
            break;
        }
        graft_into_map(row, path, &mut grafting);
    }
    if grafting.budget.exceeded {
        // Upstream serializes the whole response at once, and one past what a JavaScript string
        // can hold is a thrown error and the generic 500. Every pointer occurrence here is a copy
        // of its row, so without a bound one request could ask for more memory than the process
        // has, and failing an allocation ends the process rather than the request.
        return Err(parse_rust_core::ParseError::internal(
            "included rows exceed the response budget".to_string(),
        ));
    }
    Ok(())
}

/// How much one request's includes may graft, in bytes of JSON, across every path.
pub struct GraftBudget {
    remaining: usize,
    exceeded: bool,
}

impl GraftBudget {
    /// 128 MiB of included JSON per request.
    pub const DEFAULT: usize = 128 * 1024 * 1024;

    pub fn new(bytes: usize) -> Self {
        Self {
            remaining: bytes,
            exceeded: false,
        }
    }

    /// Spend `bytes`, or record that the budget is gone.
    fn spend(&mut self, bytes: usize) -> bool {
        match self.remaining.checked_sub(bytes) {
            Some(left) if !self.exceeded => {
                self.remaining = left;
                true
            }
            _ => {
                self.exceeded = true;
                false
            }
        }
    }
}

struct Grafting<'a> {
    fetched: &'a IndexMap<String, ParseMap>,
    sizes: &'a IndexMap<&'a str, usize>,
    budget: &'a mut GraftBudget,
}

impl Grafting<'_> {
    /// The fetched row for `id`, copied if the budget allows. `Some(None)` is a pointer that
    /// resolves to nothing; `None` is the budget running out.
    fn row(&mut self, id: &str) -> Option<Option<ParseValue>> {
        let Some(row) = self.fetched.get(id) else {
            return Some(None);
        };
        let size = self.sizes.get(id).copied().unwrap_or_default();
        self.budget
            .spend(size)
            .then(|| Some(ParseValue::Object(row.clone())))
    }
}

fn graft_into_map(map: &mut ParseMap, path: &[String], grafting: &mut Grafting<'_>) {
    let Some((head, rest)) = path.split_first() else {
        return;
    };
    replace_in_place(map, head, |current| graft_value(current, rest, grafting));
}

/// Replace one key's value where it stands, or remove the key if the replacement is `None`.
///
/// **In place, because key order is part of the contract.** Upstream's `replacePointers` rebuilds
/// the object key by key with the replaced value at the original position (`RestQuery.js:1324-1356`),
/// and an unresolved pointer becomes `undefined`, which `JSON.stringify` drops. Removing and
/// re-inserting the key, which this did, moved every included field to the end of its object; the
/// benchmark correctness gate found it on a four-pointer `include`.
fn replace_in_place(
    map: &mut ParseMap,
    key: &str,
    f: impl FnOnce(ParseValue) -> Option<ParseValue>,
) {
    let Some(index) = map.get_index_of(key) else {
        return;
    };
    let current = std::mem::replace(&mut map[index], ParseValue::Null);
    match f(current) {
        Some(value) => map[index] = value,
        None => {
            map.shift_remove_index(index);
        }
    }
}

fn graft_value(
    value: ParseValue,
    path: &[String],
    grafting: &mut Grafting<'_>,
) -> Option<ParseValue> {
    // Arrays first, at every depth, mirroring `findPointers`. An element that does not resolve is
    // dropped from the array rather than left behind as a pointer.
    if let ParseValue::Array(items) = value {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            if grafting.budget.exceeded {
                break;
            }
            if let Some(v) = graft_value(item, path, grafting) {
                out.push(v);
            }
        }
        return Some(ParseValue::Array(out));
    }
    match (path.split_first(), value) {
        (None, ParseValue::Pointer { object_id, .. }) => grafting.row(&object_id).flatten(),
        // `replace[object.objectId]`: a plain pointer resolves by its id alone, and one whose id
        // matches nothing, or that has none, becomes `undefined` and is dropped.
        (None, ParseValue::Object(map)) if is_plain_pointer(&map) => match map.get("objectId") {
            Some(ParseValue::String(id)) => grafting.row(id).flatten(),
            _ => None,
        },
        (None, other) => Some(other),
        (Some((head, rest)), ParseValue::Object(mut map)) => {
            replace_in_place(&mut map, head, |inner| graft_value(inner, rest, grafting));
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
    // An included row is a REST read's result, so its server timestamps are bare strings, as they
    // are at the top level (`MongoTransform.js:1172-1187`). Each included row passes through here
    // at its own depth, so nested includes are flattened too.
    crate::guard::flatten_top_level_dates(row);
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
    fn an_included_row_has_bare_string_timestamps() {
        let date =
            parse_rust_core::ParseDate::from_timestamp_millis(1_728_051_862_287).expect("date");
        let mut fetched = row(vec![
            ("objectId", ParseValue::String("t1".into())),
            ("createdAt", ParseValue::Date(date)),
            ("updatedAt", ParseValue::Date(date)),
            ("when", ParseValue::Date(date)),
        ]);
        shape_included(&mut fetched, "Target", false);
        for key in ["createdAt", "updatedAt"] {
            assert!(
                matches!(fetched.get(key), Some(ParseValue::String(s)) if s == "2024-10-04T14:24:22.287Z"),
                "{key}"
            );
        }
        assert!(
            matches!(fetched.get("when"), Some(ParseValue::Date(_))),
            "a user Date stays typed"
        );
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

    /// How a pointer inside an array comes back from storage: no column type, so a plain object.
    fn plain_pointer(class: &str, id: &str) -> ParseValue {
        ParseValue::Object(row(vec![
            ("__type", ParseValue::String("Pointer".into())),
            ("className", ParseValue::String(class.into())),
            ("objectId", ParseValue::String(id.into())),
        ]))
    }

    #[test]
    fn a_stored_array_of_pointers_is_collected_and_grafted() {
        let mut results = vec![row(vec![(
            "refs",
            ParseValue::Array(vec![
                plain_pointer("Target", "t1"),
                plain_pointer("Target", "gone"),
                ParseValue::String("not a pointer".into()),
            ]),
        )])];
        let path = ["refs".to_string()];
        let found = collect_pointers(&results, &path);
        assert_eq!(
            found.get("Target"),
            Some(&vec!["t1".to_string(), "gone".to_string()])
        );

        let mut fetched = IndexMap::new();
        fetched.insert(
            "t1".to_string(),
            row(vec![("objectId", ParseValue::String("t1".into()))]),
        );
        graft(
            &mut results,
            &path,
            &fetched,
            &mut GraftBudget::new(GraftBudget::DEFAULT),
        )
        .expect("within budget");
        let Some(ParseValue::Array(items)) = results[0].get("refs") else {
            panic!("refs is still an array");
        };
        // The resolved one is the object, the unresolved one is dropped, the rest is untouched.
        assert_eq!(items.len(), 2);
        assert!(
            matches!(&items[0], ParseValue::Object(m) if matches!(m.get("objectId"), Some(ParseValue::String(id)) if id == "t1"))
        );
        assert!(matches!(&items[1], ParseValue::String(s) if s == "not a pointer"));
    }

    /// Every occurrence is a copy of its row, so the total is bounded, and running out is an error
    /// rather than an allocation the process cannot survive.
    #[test]
    fn grafting_past_the_budget_is_refused() {
        let pointers: Vec<ParseValue> = (0..10).map(|_| plain_pointer("Target", "t1")).collect();
        let mut results = vec![row(vec![("refs", ParseValue::Array(pointers))])];
        let mut fetched = IndexMap::new();
        fetched.insert(
            "t1".to_string(),
            row(vec![("blob", ParseValue::String("x".repeat(1000)))]),
        );
        let path = ["refs".to_string()];
        let mut small = GraftBudget::new(5_000);
        assert!(graft(&mut results, &path, &fetched, &mut small).is_err());
        let mut results = vec![row(vec![(
            "refs",
            ParseValue::Array(vec![plain_pointer("Target", "t1")]),
        )])];
        let mut ample = GraftBudget::new(GraftBudget::DEFAULT);
        assert!(graft(&mut results, &path, &fetched, &mut ample).is_ok());
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
        graft(
            &mut results,
            &["author".to_string()],
            &fetched,
            &mut GraftBudget::new(GraftBudget::DEFAULT),
        )
        .expect("within budget");
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
        graft(
            &mut results,
            &["editors".to_string()],
            &fetched,
            &mut GraftBudget::new(GraftBudget::DEFAULT),
        )
        .expect("within budget");
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
