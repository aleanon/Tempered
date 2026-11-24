//! Argon2id password hashing for user stores, bounded and configurable.
//!
//! Each hash or verification takes about 19 MiB and tens of milliseconds of
//! CPU on a blocking thread. Without a bound, a login flood fills tokio's
//! blocking pool (512 threads by default, so about 10 GiB) and every other
//! blocking task waits behind it. [`Argon2Hasher`] admits a fixed number of
//! hashes at once; the rest wait their turn as cheap futures, not threads.

use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version,
    password_hash::{PasswordHasher, SaltString, rand_core},
};
use secrecy::{ExposeSecret, Secret};
use tempered_core::Password;
use tokio::sync::{OnceCell, Semaphore};

/// Argon2id cost parameters. The default is the OWASP minimum (19 MiB,
/// two passes, one lane).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory per hash, in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Argon2Params {
    fn to_params(self) -> Result<Params, String> {
        Params::new(self.memory_kib, self.iterations, self.parallelism, None)
            .map_err(|e| e.to_string())
    }
}

/// What a verification found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordVerdict {
    /// The password does not match.
    Mismatch,
    /// The password matches. `needs_rehash` is set when the stored hash was
    /// made with other parameters (or another algorithm) than the hasher's
    /// current ones: the store should hash the password again and save it.
    Match { needs_rehash: bool },
}

/// Argon2id hashing with a bound on how many hashes run at once.
///
/// Cloning is cheap and shares the bound, so one hasher (and its clones)
/// limits a whole store. Verification reads the parameters from the stored
/// hash, so changing [`Argon2Params`] keeps old hashes working;
/// [`PasswordVerdict::Match`] says when one should be upgraded.
#[derive(Clone)]
pub struct Argon2Hasher {
    params: Argon2Params,
    permits: Arc<Semaphore>,
    /// A hash of a throwaway password with this hasher's parameters, made on
    /// first use, for the "no such user" path (see [`Self::verify_nothing`]).
    dummy: Arc<OnceCell<Secret<String>>>,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new(Argon2Params::default())
    }
}

impl Argon2Hasher {
    /// A hasher with `params`, running at most as many hashes at once as
    /// the machine has cores.
    ///
    /// # Panics
    ///
    /// If `params` are outside what Argon2 accepts (for example less than
    /// 8 KiB of memory per lane): a configuration error, caught at startup.
    pub fn new(params: Argon2Params) -> Self {
        if let Err(e) = params.to_params() {
            panic!("invalid Argon2 parameters {params:?}: {e}");
        }
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        Self {
            params,
            permits: Arc::new(Semaphore::new(cores)),
            dummy: Arc::new(OnceCell::new()),
        }
    }

    /// Run at most `max` hashes at once (memory use is about `max` × the
    /// memory parameter).
    ///
    /// # Panics
    ///
    /// If `max` is 0: no password could ever be checked.
    pub fn max_concurrent(mut self, max: usize) -> Self {
        assert!(max > 0, "Argon2Hasher::max_concurrent must be at least 1");
        self.permits = Arc::new(Semaphore::new(max));
        self
    }

    /// The parameters new hashes are made with.
    pub fn params(&self) -> Argon2Params {
        self.params
    }

    /// Hash `password` with a fresh salt. `Err` only if the hashing task
    /// failed.
    pub async fn hash(&self, password: &Password) -> Result<Secret<String>, String> {
        let params = self.params.to_params()?;
        let password = password.clone();
        self.run(move || {
            let salt = SaltString::generate(rand_core::OsRng);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password(password.as_ref().expose_secret().as_bytes(), &salt)
                .map(|h| Secret::from(h.to_string()))
                .map_err(|e| e.to_string())
        })
        .await
    }

    /// Check `password` against `stored`. `Err` only for a stored hash that
    /// does not parse or a hashing task that failed, never for a mismatch.
    pub async fn verify(
        &self,
        stored: &Secret<String>,
        password: &Password,
    ) -> Result<PasswordVerdict, String> {
        let current = self.params;
        let stored = stored.clone();
        let password = password.clone();
        self.run(move || {
            let hash = PasswordHash::new(stored.expose_secret()).map_err(|e| e.to_string())?;
            // The verifier takes the algorithm and costs from the hash itself.
            match Argon2::default()
                .verify_password(password.as_ref().expose_secret().as_bytes(), &hash)
            {
                Ok(()) => Ok(PasswordVerdict::Match {
                    needs_rehash: !made_with(&hash, current),
                }),
                Err(argon2::password_hash::Error::Password) => Ok(PasswordVerdict::Mismatch),
                Err(e) => Err(e.to_string()),
            }
        })
        .await
    }

    /// Spend the time of a verification without a stored hash, so a store's
    /// "no such user" path takes as long as its "wrong password" path and
    /// response time does not reveal which addresses are registered.
    pub async fn verify_nothing(&self, password: &Password) {
        let dummy = self
            .dummy
            .get_or_try_init(|| async {
                let throwaway = Password::try_from(Secret::from("not-a-real-password".to_string()))
                    .expect("the throwaway password is valid");
                self.hash(&throwaway).await
            })
            .await;
        match dummy {
            Ok(dummy) => {
                let _ = self.verify(&dummy.clone(), password).await;
            }
            Err(e) => tracing::error!(error = %e, "could not make the timing dummy hash"),
        }
    }

    /// Run `job` on the blocking pool once a permit is free.
    async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        // The semaphore is never closed, so acquiring only waits.
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let span = tracing::Span::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            span.in_scope(job)
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

/// Whether `hash` is Argon2id with exactly the `current` costs.
fn made_with(hash: &PasswordHash<'_>, current: Argon2Params) -> bool {
    if hash.algorithm != Algorithm::Argon2id.ident() {
        return false;
    }
    match Params::try_from(hash) {
        Ok(p) => {
            p.m_cost() == current.memory_kib
                && p.t_cost() == current.iterations
                && p.p_cost() == current.parallelism
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn password(s: &str) -> Password {
        Password::try_from(Secret::from(s.to_string())).unwrap()
    }

    /// Small costs keep the tests fast; Argon2 accepts 8 KiB per lane.
    fn cheap() -> Argon2Params {
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[tokio::test]
    async fn a_hash_verifies_and_a_wrong_password_does_not() {
        let hasher = Argon2Hasher::new(cheap());
        let hash = hasher.hash(&password("correct horse")).await.unwrap();
        assert_eq!(
            hasher.verify(&hash, &password("correct horse")).await,
            Ok(PasswordVerdict::Match {
                needs_rehash: false
            })
        );
        assert_eq!(
            hasher.verify(&hash, &password("wrong horse!")).await,
            Ok(PasswordVerdict::Mismatch)
        );
    }

    #[tokio::test]
    async fn a_hash_from_other_params_verifies_and_asks_for_a_rehash() {
        let old = Argon2Hasher::new(cheap());
        let hash = old.hash(&password("correct horse")).await.unwrap();

        let new = Argon2Hasher::new(Argon2Params {
            iterations: 2,
            ..cheap()
        });
        assert_eq!(
            new.verify(&hash, &password("correct horse")).await,
            Ok(PasswordVerdict::Match { needs_rehash: true })
        );
    }

    #[tokio::test]
    async fn a_hash_that_does_not_parse_is_an_error() {
        let hasher = Argon2Hasher::new(cheap());
        let result = hasher
            .verify(
                &Secret::from("not-a-phc".to_string()),
                &password("whatever1"),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_more_than_max_concurrent_hashes_run_at_once() {
        let hasher = Argon2Hasher::new(cheap()).max_concurrent(2);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let hasher = hasher.clone();
                let (running, peak) = (running.clone(), peak.clone());
                tokio::spawn(async move {
                    hasher
                        .run(move || {
                            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            running.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .await
                })
            })
            .collect();
        for job in jobs {
            job.await.unwrap().unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[should_panic(expected = "invalid Argon2 parameters")]
    fn parameters_argon2_refuses_panic_at_startup() {
        Argon2Hasher::new(Argon2Params {
            memory_kib: 1,
            ..cheap()
        });
    }
}
