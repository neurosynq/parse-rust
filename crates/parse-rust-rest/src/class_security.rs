//! `enforceRoleSecurity`: the classes a client may not address at all.
//!
//! This lives in the pipeline crate rather than in a route handler, and the layer is the point.
//! Upstream calls it from both `rest.js` entry points **and** from the `RestQuery` constructor
//! (`RestQuery.js:54`), and the include path builds a `RestQuery` (`RestQuery.js:1250-1258`), so
//! an included read is checked too. A router-level copy is checked on the request a client sent
//! and not on the reads that request fans out into, which is the same defect the `_Session`
//! narrowing had.

use parse_rust_core::{ErrorCode, ErrorDetail, ParseError};

/// Classes a client may not address, reproduced from `enforceRoleSecurity`
/// (`SharedRest.js:14-55`).
///
/// Note what is **not** here. `_Role` and `_Session` are absent upstream despite a stale comment
/// on the function saying otherwise: role reads and writes go through ordinary CLP plus ACL.
/// `_User` is absent too. The two additions below are stated rather than silent.
pub fn enforce_class_security(
    class_name: &str,
    privileged: bool,
    operation: &str,
    detail: ErrorDetail,
) -> Result<(), ParseError> {
    if privileged {
        return Ok(());
    }

    // `_Installation`, and only for two of the five operations. The message says `installation
    // collection` in lower case rather than naming the class, which is upstream's string.
    if class_name == "_Installation" && matches!(operation, "delete" | "find") {
        return Err(ParseError::permission_denied(
            ErrorCode::OperationForbidden,
            format!(
                "Clients aren't allowed to perform the {operation} operation on the installation collection."
            ),
            detail,
        ));
    }

    let forbidden = MASTER_ONLY_CLASSES.contains(&class_name)
        || class_name.starts_with("_Join:")
        // **Two deliberate additions, both fail-closed over a subsystem that does not exist yet.**
        //
        // A `_Session` write reaches `RestWrite.handleSession` upstream (`RestWrite.js:1221-1292`),
        // which never stores the client's body: it mints a real session for the authenticated
        // caller and refuses a client-chosen `sessionToken`, `user`, `expiresAt` or `createdWith`.
        // parse-rust has no such stage, so allowing the write would let any client insert a
        // `_Session` row carrying a token of its choosing, which is account takeover rather than a
        // missing feature. `DELETE /sessions/:objectId` is served by its own narrowed path.
        //
        // A `_User` **create or delete** reaches stages parse-rust does not have. `transformUser`
        // on a create validates the username, generates one when absent, enforces the private ACL
        // and mints a session, so a create through this route would produce a user with no
        // username and no session; signup is `POST /users`. A delete additionally has to revoke
        // the user's sessions, which is not wired here.
        //
        // **Update is allowed**, because it is what `user.save()` on an existing user compiles to
        // in every SDK, and the stages it needs do exist: the password is hashed by
        // `prepare_user_write`, `_hashed_password` and every other reserved key are refused before
        // the body is decoded, uniqueness is enforced by the `username` and `email` unique indexes,
        // and the ACL written at signup already restricts the row to its owner. The password-change
        // followup, revoking sessions and minting a replacement, is handled by the route.
        || (class_name == crate::pipeline::SESSION_CLASS && matches!(operation, "create" | "update" | "delete"))
        || (class_name == crate::pipeline::USER_CLASS
            && matches!(operation, "create" | "delete"));

    if forbidden {
        return Err(ParseError::permission_denied(
            ErrorCode::OperationForbidden,
            format!(
                "Clients aren't allowed to perform the {operation} operation on the {class_name} collection."
            ),
            detail,
        ));
    }
    Ok(())
}

/// `classesWithMasterOnlyAccess` (`SharedRest.js:1-10`), in upstream's order.
const MASTER_ONLY_CLASSES: [&str; 8] = [
    "_JobStatus",
    "_PushStatus",
    "_Hooks",
    "_GlobalConfig",
    "_GraphQLConfig",
    "_JobSchedule",
    "_Audience",
    "_Idempotency",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `enableSanitizedErrorResponse: true`, the upstream default.
    const WITHHELD: ErrorDetail = ErrorDetail::Withheld;
    /// `enableSanitizedErrorResponse: false`. The detailed strings are contract under it.
    const DISCLOSED: ErrorDetail = ErrorDetail::Disclosed;

    /// Upstream's `auth.isMaster` gate. A bool rather than a credential type, because this
    /// function is below the layer that knows how a caller proved it.
    const CLIENT: bool = false;
    const MASTER: bool = true;

    #[test]
    fn role_and_session_reads_are_no_longer_denylisted() {
        // 0.1.0's substitute for CLP. Both classes now go through ordinary CLP plus ACL, and
        // `_Session` additionally through the owner narrowing.
        assert!(enforce_class_security("_Role", CLIENT, "find", WITHHELD).is_ok());
        assert!(enforce_class_security("_Role", CLIENT, "create", WITHHELD).is_ok());
        assert!(enforce_class_security("_Session", CLIENT, "find", WITHHELD).is_ok());
        assert!(enforce_class_security("_Session", CLIENT, "get", WITHHELD).is_ok());
    }

    #[test]
    fn the_master_only_list_is_upstreams() {
        for class in MASTER_ONLY_CLASSES {
            let e = enforce_class_security(class, CLIENT, "find", DISCLOSED).unwrap_err();
            assert_eq!(e.code, ErrorCode::OperationForbidden);
            assert_eq!(
                e.message,
                format!("Clients aren't allowed to perform the find operation on the {class} collection.")
            );
            // The regime a stock deployment runs: same code, no reason.
            let withheld = enforce_class_security(class, CLIENT, "find", WITHHELD).unwrap_err();
            assert_eq!(withheld.code, ErrorCode::OperationForbidden);
            assert_eq!(withheld.message, "Permission denied");
            assert!(enforce_class_security(class, MASTER, "find", WITHHELD).is_ok());
        }
    }

    #[test]
    fn installation_is_restricted_on_two_operations_only() {
        for op in ["delete", "find"] {
            let e = enforce_class_security("_Installation", CLIENT, op, DISCLOSED).unwrap_err();
            assert_eq!(
                e.message,
                format!(
                    "Clients aren't allowed to perform the {op} operation on the installation collection."
                ),
                "the message names the collection in lower case, not the class"
            );
            assert_eq!(
                enforce_class_security("_Installation", CLIENT, op, WITHHELD)
                    .unwrap_err()
                    .message,
                "Permission denied"
            );
        }
        for op in ["get", "create", "update"] {
            assert!(enforce_class_security("_Installation", CLIENT, op, WITHHELD).is_ok());
        }
    }

    #[test]
    fn join_tables_are_never_client_addressable() {
        let e = enforce_class_security("_Join:users:_Role", CLIENT, "find", WITHHELD).unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
    }

    /// The two additions, and the reason each exists.
    #[test]
    fn session_and_user_writes_are_refused_but_reads_are_not() {
        // `_Session` is closed to clients on every write. There is no stage that could make one
        // safe: the token is the credential, so a client-authored row is a forged credential.
        for op in ["create", "update", "delete"] {
            assert_eq!(
                enforce_class_security(crate::pipeline::SESSION_CLASS, CLIENT, op, WITHHELD)
                    .unwrap_err()
                    .code,
                ErrorCode::OperationForbidden,
                "_Session/{op}"
            );
        }

        // `_User` is closed to a client create and delete, and **open to update**, which is what
        // `user.save()` on an existing user compiles to in every SDK. The row's own ACL is what
        // stops one user saving another's; the class guard is not carrying that weight.
        for op in ["create", "delete"] {
            assert_eq!(
                enforce_class_security(crate::pipeline::USER_CLASS, CLIENT, op, WITHHELD)
                    .unwrap_err()
                    .code,
                ErrorCode::OperationForbidden,
                "_User/{op}"
            );
        }
        assert!(
            enforce_class_security(crate::pipeline::USER_CLASS, CLIENT, "update", WITHHELD).is_ok(),
            "a client may save its own user row"
        );

        for class in [crate::pipeline::SESSION_CLASS, crate::pipeline::USER_CLASS] {
            for op in ["find", "get"] {
                assert!(
                    enforce_class_security(class, CLIENT, op, WITHHELD).is_ok(),
                    "{class}/{op}"
                );
            }
            // Master is exempt, which is what lets the dashboard write both.
            assert!(enforce_class_security(class, MASTER, "create", WITHHELD).is_ok());
        }
    }
}
