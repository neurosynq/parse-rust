//! `accountLockout`, the failed-login counter and the lock it trips (`AccountLockout.js`).
//!
//! **The two columns are the contract, not this code.** `_failed_login_count` and
//! `_account_lockout_expires_at` live on the `_User` row, and a parse-server node behind the same
//! load balancer reads the same two, so a failed login here has to count there. That is the whole
//! reason this is implemented rather than declined: a lock that one node in a fleet ignores is a
//! lock an attacker can route around.
//!
//! Upstream's `unlockOnPasswordReset` has nothing to hook into here, because there is no password
//! reset flow, so it is accepted and has no effect.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use parse_rust_core::{ErrorCode, ParseDate, ParseError, ParseValue};
use parse_rust_storage::{ClassSchema, Comparison, Constraint, Query, StorageAdapter, UpdateValue};

/// `accountLockout` (`Options/Definitions.js:55-60`, validated at `Config.js:400-424`).
#[derive(Debug, Clone, PartialEq)]
pub struct AccountLockout {
    /// Minutes, greater than 0 and at most 99999. Not necessarily whole.
    pub duration: f64,
    /// Failed attempts that lock the account, 1 to 999.
    pub threshold: u32,
    pub unlock_on_password_reset: bool,
}

impl AccountLockout {
    /// Upstream's validation, with its messages, which are what an operator sees at boot.
    pub fn validate(&self) -> Result<(), String> {
        if !(self.duration > 0.0 && self.duration <= 99999.0) {
            return Err(
                "Account lockout duration should be greater than 0 and less than 100000".into(),
            );
        }
        if !(1..=999).contains(&self.threshold) {
            return Err(
                "Account lockout threshold should be an integer greater than 0 and less than 1000"
                    .into(),
            );
        }
        Ok(())
    }

    /// The refusal, `OBJECT_NOT_FOUND` with the duration as JavaScript prints it.
    fn locked(&self) -> ParseError {
        ParseError::new(
            ErrorCode::ObjectNotFound,
            format!(
                "Your account is locked due to multiple failed login attempts. Please try again \
                 after {} minute(s)",
                parse_rust_core::js_number::to_ecma_string(self.duration)
            ),
        )
    }
}

/// One login attempt per account at a time, in this process.
///
/// The lockout is specified as a sequence of attempts, and this lock is what makes concurrent
/// attempts on one account count as that sequence: it is held from before the password compare to
/// after the bookkeeping, so a client sending in sequence sees exactly what it saw without it. It
/// does not span a fleet; two nodes still race each other on the same two columns.
///
/// Keyed by username alone, so two apps in one process that share a username serialize each other's
/// logins. That costs time and decides nothing.
pub async fn serialize_attempts(username: &str) -> tokio::sync::OwnedMutexGuard<()> {
    static GATES: Mutex<Option<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = Mutex::new(None);
    let gate = {
        // A poisoned map only means another thread panicked while holding it; the map itself is
        // still a valid cache of weak handles, so recover it rather than refuse every login.
        let mut guard = GATES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let gates = guard.get_or_insert_with(HashMap::new);
        // Drop entries whose last holder has gone, so the map tracks logins in flight rather than
        // every username ever tried.
        if gates.len() > 1024 {
            gates.retain(|_, weak| weak.strong_count() > 0);
        }
        match gates.get(username).and_then(Weak::upgrade) {
            Some(gate) => gate,
            None => {
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                gates.insert(username.to_string(), Arc::downgrade(&gate));
                gate
            }
        }
    };
    gate.lock_owned().await
}

/// `handleLoginAttempt`: run after the password has been compared, whichever way it went.
///
/// A locked account is refused even with the right password. Otherwise a success resets the count,
/// and a failure increments it atomically and reads the post-image, which is the count that decides
/// (`AccountLockout.js:104-120`): at the threshold the lock is set and the attempt is reported as
/// an ordinary failure, past it the attempt is refused as locked.
pub async fn handle_login_attempt<S: StorageAdapter>(
    storage: &S,
    schema: &ClassSchema,
    policy: &AccountLockout,
    username: &str,
    login_successful: bool,
) -> Result<(), ParseError> {
    let by_username = || {
        Query::from_constraints(vec![Constraint::equal(
            "username",
            ParseValue::String(username.to_string()),
        )])
    };
    let threshold = ParseValue::Number(f64::from(policy.threshold));

    // `_notLocked` (`AccountLockout.js:80-97`).
    let mut locked = by_username();
    locked.push_constraint(Constraint {
        field: "_account_lockout_expires_at".into(),
        comparison: Comparison::GreaterThan(ParseValue::Date(ParseDate::now())),
    });
    locked.push_constraint(Constraint {
        field: "_failed_login_count".into(),
        comparison: Comparison::GreaterThanOrEqual(threshold.clone()),
    });
    if storage
        .count(
            schema,
            &locked,
            &parse_rust_storage::CountOptions::default(),
        )
        .await?
        > 0
    {
        return Err(policy.locked());
    }

    if login_successful {
        let mut reset = parse_rust_storage::Update::new();
        reset.insert(
            "_failed_login_count".into(),
            UpdateValue::Set(ParseValue::Number(0.0)),
        );
        storage.update(schema, &by_username(), &reset).await?;
        return Ok(());
    }

    let mut increment = parse_rust_storage::Update::new();
    increment.insert("_failed_login_count".into(), UpdateValue::Increment(1.0));
    let Some(row) = storage
        .update_one_returning(schema, &by_username(), &increment)
        .await?
    else {
        return Ok(());
    };
    let count = match row.get("_failed_login_count") {
        Some(ParseValue::Number(n)) => *n,
        _ => return Ok(()),
    };
    if count < f64::from(policy.threshold) {
        return Ok(());
    }

    // `_setLockoutExpiration`, conditional on the count so a concurrent reset is not overwritten
    // (`AccountLockout.js:45-72`).
    let duration_ms = (policy.duration * 60.0 * 1000.0) as i64;
    let mut lock = by_username();
    lock.push_constraint(Constraint {
        field: "_failed_login_count".into(),
        comparison: Comparison::GreaterThanOrEqual(threshold),
    });
    let mut expires = parse_rust_storage::Update::new();
    expires.insert(
        "_account_lockout_expires_at".into(),
        UpdateValue::Set(ParseValue::Date(ParseDate::now().plus_millis(duration_ms))),
    );
    storage.update(schema, &lock, &expires).await?;

    if count > f64::from(policy.threshold) {
        return Err(policy.locked());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(duration: f64, threshold: u32) -> AccountLockout {
        AccountLockout {
            duration,
            threshold,
            unlock_on_password_reset: false,
        }
    }

    /// `Config.js:400-424`: the bounds are exclusive at 0 and inclusive at 99999 for the duration,
    /// inclusive at both ends for the threshold, and the two messages are upstream's.
    #[test]
    fn validation_bounds_and_messages_are_upstreams() {
        for ok in [policy(0.05, 1), policy(99999.0, 999), policy(1.0, 3)] {
            assert_eq!(ok.validate(), Ok(()), "{ok:?}");
        }
        let duration =
            "Account lockout duration should be greater than 0 and less than 100000".to_string();
        for bad in [0.0, -1.0, 99999.5, 100000.0, f64::NAN, f64::INFINITY] {
            assert_eq!(policy(bad, 3).validate(), Err(duration.clone()), "{bad}");
        }
        let threshold =
            "Account lockout threshold should be an integer greater than 0 and less than 1000"
                .to_string();
        for bad in [0, 1000] {
            assert_eq!(policy(1.0, bad).validate(), Err(threshold.clone()), "{bad}");
        }
    }

    /// Two attempts on one account never overlap; attempts on two accounts do. The second half is
    /// what keeps the gate from serializing every login on the server.
    #[tokio::test]
    async fn attempts_on_one_account_are_serialized_and_others_are_not() {
        let first = serialize_attempts("gate-a").await;
        let same = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            serialize_attempts("gate-a"),
        )
        .await;
        assert!(same.is_err(), "a second attempt on the account must wait");
        let other = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            serialize_attempts("gate-b"),
        )
        .await;
        assert!(other.is_ok(), "another account must not wait");
        drop(first);
        let after = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            serialize_attempts("gate-a"),
        )
        .await;
        assert!(
            after.is_ok(),
            "the account is free once the first attempt ends"
        );
    }

    /// The duration is concatenated into the message as JavaScript prints a number
    /// (`AccountLockout.js:91-94`), so a whole number has no decimal point and a fraction keeps
    /// exactly its shortest form.
    #[test]
    fn the_locked_message_prints_the_duration_as_javascript_does() {
        for (duration, printed) in [(1.0, "1"), (5.0, "5"), (0.05, "0.05"), (1.5, "1.5")] {
            let err = policy(duration, 3).locked();
            assert_eq!(err.code, ErrorCode::ObjectNotFound);
            assert_eq!(
                err.message,
                format!(
                    "Your account is locked due to multiple failed login attempts. Please try \
                     again after {printed} minute(s)"
                )
            );
        }
    }
}
