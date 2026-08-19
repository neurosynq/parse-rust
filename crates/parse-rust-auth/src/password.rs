//! Password hashing.
//!
//! Upstream is `src/password.js`: `bcrypt.hash(password, 10)`, using `bcryptjs` by default and
//! `@node-rs/bcrypt` when it can be required.
//!
//! **The cost factor and the output format are interop contract, not implementation detail.** A
//! `_User` row written by parse-rust must be loginable by parse-server and the reverse, on the
//! same database. That is a mixed-fleet requirement, and it is the kind of thing that looks fine
//! until a second server exists. `tests/bcrypt_interop.rs` checks both directions against Node.
//!
//! **Both functions are async and hash on the blocking pool, and that is not a style choice.**
//! bcrypt at cost 10 is tens of milliseconds of pure CPU with no await points in it. Run inline on
//! a tokio worker it parks that thread outright, and both entry points are reachable without
//! credentials: `POST /users` hashes on every signup and `POST /login` verifies for any known
//! username. As many concurrent requests as there are workers therefore stops the runtime polling
//! anything at all, including `/health`, and a single `/batch` of signups is one request that does
//! it. `spawn_blocking` puts the work on a bounded pool instead, which turns that into ordinary
//! queueing. Upstream has the property for free, because its bcrypt binding hands off to libuv's
//! threadpool rather than running on the event loop.
//!
//! This does not remove the need for login rate limiting. It removes the case where one caller
//! takes the process down without needing volume.

use parse_rust_core::ParseError;

/// Upstream's cost factor (`password.js`, `bcrypt.hash(password, 10)`).
///
/// Not raised. A higher cost would be better practice and would produce hashes parse-server can
/// still verify, but it would change login latency in a way an operator did not ask for, and the
/// benchmark story would then be comparing different work. Revisit deliberately, not silently.
pub const BCRYPT_COST: u32 = 10;

/// Hash a password for storage in `_User._hashed_password`.
///
/// Takes an owned `String` because the work moves to another thread. The caller already owns one
/// at both call sites.
pub async fn hash(password: String) -> Result<String, ParseError> {
    run_blocking(move || bcrypt::hash(&password, BCRYPT_COST))
        .await?
        .map_err(|e| {
            // `ParseError::internal` keeps this off the wire entirely: upstream's bcrypt failure
            // is a rejected promise carrying a plain `Error`, so a client gets the generic 500 and
            // this text reaches the log. `kind_of` is still narrow, because a log line must not
            // carry the password either.
            ParseError::internal(format!("password hashing failed: {}", kind_of(&e)))
        })
}

/// Verify a password against a stored hash.
///
/// Returns `false` rather than an error for a malformed or empty hash, matching upstream:
/// `compare` resolves `false` when either side is falsy rather than throwing
/// (`password.js:24-29`). A stored hash that cannot be parsed is a failed login, not a 500.
///
/// A panic or a shutdown in the blocking pool also reads as `false`. A failed login is the
/// fail-closed answer, and it is the same answer this returns for every other way the comparison
/// cannot be completed.
pub async fn verify(password: String, hashed: String) -> bool {
    if password.is_empty() || hashed.is_empty() {
        return false;
    }
    matches!(
        run_blocking(move || bcrypt::verify(&password, &hashed)).await,
        Ok(Ok(true))
    )
}

/// Upstream's fixed dummy hash, for timing normalization (`password.js:33`).
///
/// **The value is irrelevant and the cost is the point.** A login that fails before reaching bcrypt
/// returns in microseconds while one that reaches it pays the full cost factor, and that difference
/// is measurable over the network. It answers "does this account exist" without any response body
/// saying so, which is exactly what the single shared `Invalid username/password.` message exists
/// to prevent. The message alone does not close the oracle; this does.
///
/// Cost factor 10, matching upstream's, because a dummy compare cheaper than the real one leaks the
/// difference just as well.
pub const DUMMY_HASH: &str = "$2b$10$Wd1gvrMYPnQv5pHBbXCwCehxXmJSEzRqNON0ev98L6JJP5296S35i";

/// Pay the bcrypt cost without having a hash to check, and discard the answer.
///
/// Called on every login path that fails before a real comparison: no such user, and a user with no
/// usable stored hash. Both are `false` regardless, so the result is deliberately dropped.
///
/// An empty password still short-circuits, because [`verify`] short-circuits and upstream's
/// `compare` does the same on a falsy input (`password.js:24-29`). The two branches stay
/// indistinguishable from each other, which is what matters.
pub async fn verify_dummy(password: String) {
    let _ = verify(password, DUMMY_HASH.to_string()).await;
}

/// How many bcrypt calls may run at once.
///
/// **`spawn_blocking` alone is not a bound.** Tokio's blocking pool defaults to 512 threads, so
/// moving the work off the async workers stops it starving the reactor and does nothing to stop
/// hundreds of cost-10 hashes running in parallel. An anonymous flood of signups is exactly that
/// shape: bcrypt is deliberately expensive, and an unbounded number of them is a CPU exhaustion
/// primitive that needs no credentials.
///
/// Sized to the machine, with a floor of one, because bcrypt is CPU-bound and more concurrent
/// hashes than cores makes every one of them slower without completing any sooner. Work over the
/// limit queues on the semaphore rather than being refused: a queued login is slow, a refused one
/// is an outage, and the queue is what makes the cost bounded rather than the client count.
static BCRYPT_PERMITS: std::sync::LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        let cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        std::sync::Arc::new(tokio::sync::Semaphore::new(cores.max(1)))
    });

/// Run one bcrypt call on the blocking pool, under the concurrency bound.
///
/// The outer `Result` is the join result. It fails only if the task panicked or the runtime is
/// shutting down, neither of which is a client's doing, so it renders as the generic 500 rather
/// than naming bcrypt on the wire.
///
/// The permit is acquired before the task is spawned and held until it finishes, so the bound is
/// on bcrypt calls in flight rather than on tasks queued. `acquire` fails only if the semaphore is
/// closed, which nothing does.
async fn run_blocking<T, F>(f: F) -> Result<T, ParseError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // **The permit moves into the blocking closure, and that placement is the whole bound.** Held
    // by this future instead, it is released the moment the future is dropped, which is what a
    // client disconnecting mid-request does. The `spawn_blocking` task is *not* cancelled by that:
    // bcrypt keeps running to completion on the pool with its permit already returned. An
    // anonymous caller who connects and disconnects in a loop then accumulates as many concurrent
    // hashes as they like, which is the exact exhaustion the semaphore was added to prevent, with
    // the semaphore in place and reporting itself satisfied.
    //
    // Owned by the closure, the permit is released when bcrypt returns, so the bound is on work in
    // flight rather than on callers still waiting for it.
    let permit = std::sync::Arc::clone(&BCRYPT_PERMITS)
        .acquire_owned()
        .await
        .map_err(|_| ParseError::internal("password hashing is unavailable"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|_| ParseError::internal("password hashing task did not complete"))
}

fn kind_of(e: &bcrypt::BcryptError) -> &'static str {
    match e {
        bcrypt::BcryptError::CostNotAllowed(_) => "cost not allowed",
        bcrypt::BcryptError::InvalidHash(_) => "invalid hash",
        _ => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips() {
        let h = hash("hunter2".into()).await.expect("hash");
        assert!(verify("hunter2".into(), h.clone()).await);
        assert!(!verify("hunter3".into(), h).await);
    }

    #[tokio::test]
    async fn uses_upstreams_cost_factor() {
        let h = hash("x".into()).await.expect("hash");
        // bcrypt encodes the cost in the third field: $2b$10$...
        let cost = h.split('$').nth(2).expect("cost field");
        assert_eq!(
            cost, "10",
            "cost must match upstream's bcrypt.hash(password, 10)"
        );
    }

    #[tokio::test]
    async fn empty_inputs_are_a_failed_login_not_an_error() {
        let h = hash("x".into()).await.expect("hash");
        assert!(!verify("".into(), h).await);
        assert!(!verify("x".into(), "".into()).await);
    }

    #[tokio::test]
    async fn a_corrupt_stored_hash_fails_login_rather_than_panicking() {
        // A row written by something else, or truncated in transit. Must not take down a worker.
        assert!(!verify("x".into(), "not-a-bcrypt-hash".into()).await);
        assert!(!verify("x".into(), "$2b$10$tooshort".into()).await);
    }

    /// The reason both functions are async: hashing must not park the worker it runs on.
    ///
    /// **This needs a second task to be a test at all.** An earlier version hashed on a
    /// `current_thread` runtime and asserted only the result, which passes identically with
    /// `spawn_blocking` removed: with nothing else waiting to run, a parked worker is
    /// unobservable. One worker thread plus a competing task is the smallest arrangement that
    /// tells the two implementations apart.
    ///
    /// With `spawn_blocking`, `hash` yields at its first poll and the spawned task reaches the
    /// flag while bcrypt runs on the blocking pool. Run inline, the first poll would carry bcrypt
    /// to completion and the flag would still be false.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn hashing_yields_the_worker_instead_of_parking_it() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        tokio::spawn(async move { flag.store(true, Ordering::SeqCst) });

        let h = hash("hunter2".into()).await.expect("hash");
        assert!(
            ran.load(Ordering::SeqCst),
            "another task must be able to run while a password is being hashed"
        );
        assert!(verify("hunter2".into(), h).await);
    }
}
