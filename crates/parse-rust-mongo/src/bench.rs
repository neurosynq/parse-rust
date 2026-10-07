//! Per-request database time, for the benchmark harness. Compiled only with the
//! `bench-instrumentation` feature.
//!
//! **The boundary is the driver's command monitoring** (the benchmark design, section
//! 8.2): a command's interval runs from `CommandStarted` to `CommandSucceeded` or `CommandFailed`,
//! paired by request id. That covers the network and the database's own execution and excludes
//! the Parse-to-BSON transform and the post-processing on either side, which are server work and
//! are where a difference between the two servers would be. It is the same boundary parse-server
//! gets from `monitorCommands`, so the two are measured alike.
//!
//! **Attribution is by task.** The server wraps each request in [`scope`], which sets a
//! task-local. A command a request issues fires its started event on that request's own task and
//! sees it. Heartbeats and connection handshakes run on the driver's background tasks, see no
//! task-local, and so belong to no request, which is the right answer for them without a list.
//!
//! **Not yet measured on either side: connection-pool wait.** It sits outside a command's interval
//! on both targets, so the two agree; at concurrency 1 on a warm pool it is negligible, and the
//! contended workloads where it would matter are later work. The report says so.
//!
//! Overlapping commands are accumulated as a union of intervals, never a sum, so parallel round
//! trips cannot report more database time than the request spent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use mongodb::event::command::CommandEvent;

/// What one request spent in the database.
#[derive(Debug, Default, Clone)]
pub struct DbSummary {
    pub micros: u64,
    pub ops: u64,
    /// One normalized shape per command, `<command> <collection> <filter keys>`, for the
    /// query-shape fixtures.
    pub shapes: Vec<String>,
}

#[derive(Default)]
struct Tally {
    intervals: Mutex<Vec<(Instant, Instant)>>,
    ops: Mutex<u64>,
    shapes: Mutex<Vec<String>>,
}

tokio::task_local! {
    static REQUEST: Arc<Tally>;
}

/// Commands in flight: request id to (started, the request it belongs to).
type InFlight = Mutex<HashMap<i32, (Instant, Arc<Tally>)>>;

fn in_flight() -> &'static InFlight {
    static IN_FLIGHT: OnceLock<InFlight> = OnceLock::new();
    IN_FLIGHT.get_or_init(Mutex::default)
}

/// Run `f` as one request, and report what it spent in the database.
pub async fn scope<F: std::future::Future>(f: F) -> (F::Output, DbSummary) {
    let tally = Arc::new(Tally::default());
    let out = REQUEST.scope(tally.clone(), f).await;
    let mut intervals = tally
        .intervals
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    intervals.sort_by_key(|(start, _)| *start);
    let mut micros = 0u128;
    let mut current: Option<(Instant, Instant)> = None;
    for (start, end) in intervals {
        current = match current {
            Some((s, e)) if start <= e => Some((s, e.max(end))),
            Some((s, e)) => {
                micros += e.duration_since(s).as_micros();
                Some((start, end))
            }
            None => Some((start, end)),
        };
    }
    if let Some((s, e)) = current {
        micros += e.duration_since(s).as_micros();
    }
    let summary = DbSummary {
        micros: u64::try_from(micros).unwrap_or(u64::MAX),
        ops: tally.ops.lock().map(|v| *v).unwrap_or(0),
        shapes: tally.shapes.lock().map(|v| v.clone()).unwrap_or_default(),
    };
    (out, summary)
}

/// The command event handler installed on the client.
pub fn on_command(event: CommandEvent) {
    match event {
        CommandEvent::Started(started) => {
            let Ok(tally) = REQUEST.try_with(Arc::clone) else {
                return;
            };
            if let Ok(mut ops) = tally.ops.lock() {
                *ops += 1;
            }
            if let Ok(mut shapes) = tally.shapes.lock() {
                shapes.push(shape(&started.command_name, &started.command));
            }
            if let Ok(mut map) = in_flight().lock() {
                map.insert(started.request_id, (Instant::now(), tally));
            }
        }
        CommandEvent::Succeeded(done) => close(done.request_id),
        CommandEvent::Failed(failed) => close(failed.request_id),
        _ => {}
    }
}

fn close(request_id: i32) {
    let entry = in_flight()
        .lock()
        .ok()
        .and_then(|mut m| m.remove(&request_id));
    if let Some((start, tally)) = entry {
        if let Ok(mut v) = tally.intervals.lock() {
            v.push((start, Instant::now()));
        }
    }
}

/// `<command> <collection> <filter key structure>`, with every value replaced by its type. The
/// structure is what a query-shape fixture pins; the values are the corpus's business.
fn shape(name: &str, command: &bson::Document) -> String {
    let collection = command.get_str(name).unwrap_or("");
    // An update or delete carries its filter inside its first statement.
    let statement = ["updates", "deletes"]
        .iter()
        .find_map(|k| command.get_array(*k).ok())
        .and_then(|a| a.first())
        .and_then(|s| s.as_document());
    let filter = ["filter", "q", "query", "pipeline"]
        .iter()
        .find_map(|k| {
            command
                .get(*k)
                .or_else(|| statement.and_then(|s| s.get(*k)))
        })
        .map(skeleton)
        .unwrap_or_default();
    format!("{name} {collection} {filter}")
}

fn skeleton(value: &bson::Bson) -> String {
    match value {
        bson::Bson::Document(d) => {
            let inner: Vec<String> = d
                .iter()
                .map(|(k, v)| format!("{k}:{}", skeleton(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        bson::Bson::Array(items) => {
            let inner: Vec<String> = items.iter().map(skeleton).collect();
            format!("[{}]", inner.join(","))
        }
        other => format!("{:?}", other.element_type()).to_lowercase(),
    }
}
