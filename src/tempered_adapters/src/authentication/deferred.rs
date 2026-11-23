//! Work a public route does after it has answered.
//!
//! Password-reset initiation and signup answer the same whether or not the
//! address has an account. What they do next does depend on it: look the
//! account up, store a token, send a mail. Done inline, that work makes a
//! real account's answer slower, so the response time says which addresses
//! are registered. `Deferred` runs it after the response instead, so the
//! request does the same work either way.
//!
//! The queue is bounded: these routes are open to anyone, and an unbounded
//! spawn would let a flood of requests pile up sends without limit. When it
//! is full, a job is dropped and logged rather than run inline, since
//! running it inline would bring the timing back exactly when the server is
//! busy. The user asks again.
//!
//! A job that is queued when the process stops is lost. For these mails
//! that is acceptable: the user requests another.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;

/// How many deferred jobs a slot keeps in flight before it drops new ones.
pub const MAX_DEFERRED_JOBS: usize = 64;

/// A bounded runner for work done after the response.
#[derive(Clone)]
pub(crate) struct Deferred {
    permits: Arc<Semaphore>,
}

impl Default for Deferred {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_DEFERRED_JOBS)),
        }
    }
}

impl Deferred {
    /// Run `job` in the background, or drop it (logged as `what`) if
    /// [`MAX_DEFERRED_JOBS`] are already in flight.
    pub(crate) fn run<F>(&self, what: &'static str, job: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        match self.permits.clone().try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(async move {
                    job.await;
                    drop(permit);
                });
            }
            Err(_) => tracing::warn!(job = what, "too many deferred jobs in flight; dropped"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_full_queue_drops_new_jobs_instead_of_running_them() {
        let deferred = Deferred::default();
        let (release, wait) = tokio::sync::watch::channel(false);
        for _ in 0..MAX_DEFERRED_JOBS {
            let mut wait = wait.clone();
            deferred.run("blocker", async move {
                let _ = wait.wait_for(|go| *go).await;
            });
        }
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        deferred.run("extra", async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        release.send(true).unwrap();
        tokio::task::yield_now().await;
        // Drain: once every blocker finished, all permits are back.
        let _all = deferred
            .permits
            .acquire_many(MAX_DEFERRED_JOBS as u32)
            .await
            .unwrap();
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_job_runs_after_the_caller_returns() {
        let deferred = Deferred::default();
        let (done, rx) = tokio::sync::oneshot::channel();
        deferred.run("job", async move {
            done.send(()).unwrap();
        });
        rx.await.unwrap();
    }
}
