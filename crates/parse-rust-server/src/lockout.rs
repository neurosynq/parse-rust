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
