//! Serialise model ownership across overlapping analysis/cancellation requests.
use std::sync::{Condvar, Mutex};
use std::time::Duration;

struct Session {
    id: String,
    needs_cleanup: bool,
}

#[derive(Default)]
pub struct AnalysisModel {
    session: Mutex<Option<Session>>,
    changed: Condvar,
}

impl AnalysisModel {
    pub fn run<T>(
        &self,
        id: &str,
        cancelled: impl Fn() -> bool,
        operation: impl FnOnce(&mut bool) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut slot = self.session.lock().map_err(|_| "AI session unavailable")?;
        loop {
            if cancelled() {
                return Err("Analysis cancelled.".into());
            }
            if slot.as_ref().is_none_or(|session| session.id == id) {
                break;
            }
            slot = self
                .changed
                .wait_timeout(slot, Duration::from_millis(100))
                .map_err(|_| "AI session unavailable")?
                .0;
        }
        let session = slot.get_or_insert_with(|| Session {
            id: id.into(),
            needs_cleanup: false,
        });
        // Hold the lock during model operations: finish cannot unload a runner
        // while it is being loaded or used, and a new analysis waits for cleanup.
        operation(&mut session.needs_cleanup)
    }

    pub fn finish(
        &self,
        id: &str,
        cleanup: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut slot = self.session.lock().map_err(|_| "AI session unavailable")?;
        if !slot.as_ref().is_some_and(|session| session.id == id) {
            return Ok(());
        }
        let result = if slot.as_ref().unwrap().needs_cleanup {
            cleanup()
        } else {
            Ok(())
        };
        *slot = None;
        self.changed.notify_all();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use std::thread;

    #[test]
    fn failed_static_analysis_releases_preloaded_model() {
        let state = AnalysisModel::default();
        state
            .run(
                "a",
                || false,
                |dirty| {
                    *dirty = true;
                    Ok(())
                },
            )
            .unwrap();
        let mut unloaded = false;
        state
            .finish("a", || {
                unloaded = true;
                Ok(())
            })
            .unwrap();
        assert!(unloaded);
    }

    #[test]
    fn already_unloaded_model_is_not_unloaded_twice() {
        let state = AnalysisModel::default();
        state
            .run(
                "a",
                || false,
                |dirty| {
                    *dirty = false;
                    Ok(())
                },
            )
            .unwrap();
        state
            .finish("a", || panic!("AI completion already released the model"))
            .unwrap();
    }

    #[test]
    fn stale_finish_cannot_unload_new_analysis() {
        let state = AnalysisModel::default();
        state
            .run(
                "new",
                || false,
                |dirty| {
                    *dirty = true;
                    Ok(())
                },
            )
            .unwrap();
        state.finish("old", || panic!("stale cleanup")).unwrap();
        state.finish("new", || Ok(())).unwrap();
    }

    #[test]
    fn cancelled_waiter_does_not_take_model_ownership() {
        let state = AnalysisModel::default();
        state.run("a", || false, |_| Ok(())).unwrap();
        assert!(state
            .run::<()>("b", || true, |_| panic!("cancelled warmup"))
            .is_err());
        state.finish("a", || Ok(())).unwrap();
    }

    #[test]
    fn next_analysis_waits_for_cleanup() {
        let state = Arc::new(AnalysisModel::default());
        state
            .run(
                "a",
                || false,
                |dirty| {
                    *dirty = true;
                    Ok(())
                },
            )
            .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let next = Arc::clone(&state);
        let worker = thread::spawn(move || {
            next.run(
                "b",
                || false,
                |_| {
                    started_tx.send(()).unwrap();
                    Ok(())
                },
            )
        });
        assert!(started_rx.recv_timeout(Duration::from_millis(30)).is_err());
        state
            .finish("a", || {
                assert!(started_rx.try_recv().is_err());
                Ok(())
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap().unwrap();
        state.finish("b", || Ok(())).unwrap();
    }
}
