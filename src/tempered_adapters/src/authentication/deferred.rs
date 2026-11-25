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
//! that is acceptable: the user requests another. An app that wants them
//! on its own executor or job system sets a [`DeferredRunner`]; one that
//! must not lose a mail can also have its `EmailClient::send_mail` put the
//! message on a durable queue instead of sending it.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use tokio::sync::Semaphore;

/// A job the library runs after a response (a reset or signup mail).
pub type DeferredJob = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Runs the library's after-the-response jobs, instead of `tokio::spawn`
/// (see `CredentialScheme::deferred_runner`). `what` names the job for
/// logs. The bound on jobs in flight still applies before a job gets here.
pub trait DeferredRunner: Send + Sync {
    fn run(&self, what: &'static str, job: DeferredJob);
}

/// How many deferred jobs a slot keeps in flight before it drops new ones.
pub const MAX_DEFERRED_JOBS: usize = 64;

/// A bounded runner for work done after the response.
#[derive(Clone)]
pub(crate) struct Deferred {
    permits: Arc<Semaphore>,
    /// Shared by every clone, so a runner set on the scheme reaches the
    /// slots made before it was set.
    runner: Arc<OnceLock<Arc<dyn DeferredRunner>>>,
}

impl Default for Deferred {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_DEFERRED_JOBS)),
            runner: Arc::default(),
        }
    }
}

impl Deferred {
    /// Hand jobs to `runner` from now on. Set once; a second runner is
    /// ignored (and logged).
    pub(crate) fn set_runner(&self, runner: Arc<dyn DeferredRunner>) {
        if self.runner.set(runner).is_err() {
            tracing::warn!("a deferred runner was already set; keeping the first");
        }
    }

    /// Run `job` in the background, or drop it (logged as `what`) if
    /// [`MAX_DEFERRED_JOBS`] are already in flight.
    pub(crate) fn run<F>(&self, what: &'static str, job: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        match self.permits.clone().try_acquire_owned() {
            Ok(permit) => {
                let job = Box::pin(async move {
                    job.await;
                    drop(permit);
                });
                match self.runner.get() {
                    Some(runner) => runner.run(what, job),
                    None => {
                        tokio::spawn(job);
                    }
                }
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
