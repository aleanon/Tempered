//! Rate limits on the routes an attacker would hammer.
//!
//! Each limited route belongs to a [`RateLimitGroup`]. A group has a limit
//! per account (the address being logged in to, reset or mailed; or the
//! logged-in user) and per client address, each a count per fixed window.
//! Over either, the route answers `429 Too Many Requests` with
//! `Retry-After` and does nothing else. Every attempt counts, whether it
//! succeeds or not, so the answer does not reveal whether an account exists
//! or a password was right.
//!
//! A per-account limit is also a way to lock an account out for a window
//! by failing on purpose. The defaults keep that window short (15 minutes
//! for logins) and the client limits catch one source trying many accounts.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use http::{StatusCode, request::Parts};
use secrecy::ExposeSecret;
use tempered_core::{Email, RateLimitStore};

use crate::endpoints::{ClientAddr, EndpointResponse, RouteId, error_response};

/// A route group that shares one set of counters.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RateLimitGroup {
    /// Password and passkey logins, and OAuth starts.
    Login,
    /// 2FA codes, at login and at elevation.
    SecondFactor,
    /// `/elevate` (re-entering the password).
    Elevate,
    /// Password reset: asking for a link and using one.
    PasswordReset,
    /// What sends a verification mail: signup and resend.
    VerificationMail,
}

impl RateLimitGroup {
    fn of(route: RouteId) -> Option<Self> {
        use RouteId::*;
        Some(match route {
            Login | PasskeyLoginStart | PasskeyLoginFinish | OAuthStart => Self::Login,
            Verify2Fa | VerifyElevation2Fa => Self::SecondFactor,
            Elevate => Self::Elevate,
            PasswordResetInitiate | PasswordResetComplete => Self::PasswordReset,
            Signup | ResendVerification => Self::VerificationMail,
            _ => return None,
        })
    }

    fn key(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::SecondFactor => "second_factor",
            Self::Elevate => "elevate",
            Self::PasswordReset => "password_reset",
            Self::VerificationMail => "verification_mail",
        }
    }
}

/// At most `max` attempts per `window_seconds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub max: u64,
    pub window_seconds: u64,
}

impl Limit {
    /// `max` attempts per `window_seconds`.
    ///
    /// # Panics
    ///
    /// If either is 0.
    pub const fn new(max: u64, window_seconds: u64) -> Self {
        assert!(
            max > 0 && window_seconds > 0,
            "a rate limit needs a count and a window"
        );
        Self {
            max,
            window_seconds,
        }
    }
}

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;

/// The limits per group. [`Default`] is a starting point:
///
/// | group | per account | per client |
/// |---|---|---|
/// | login | 10 / 15 min | 100 / 15 min |
/// | second factor | 10 / 15 min | 100 / 15 min |
/// | elevate | 10 / 15 min | 100 / 15 min |
/// | password reset | 5 / hour | 30 / hour |
/// | verification mail | 5 / hour | 30 / hour |
///
/// Client limits are per IP address (per /64 for IPv6, which one host
/// usually holds whole). Many users behind one NAT share one.
#[derive(Clone, Debug)]
pub struct RateLimits {
    per_account: HashMap<RateLimitGroup, Limit>,
    per_client: HashMap<RateLimitGroup, Limit>,
}

impl Default for RateLimits {
    fn default() -> Self {
        use RateLimitGroup::*;
        let short = (Limit::new(10, 15 * MINUTE), Limit::new(100, 15 * MINUTE));
        let mail = (Limit::new(5, HOUR), Limit::new(30, HOUR));
        let all = [
            (Login, short),
            (SecondFactor, short),
            (Elevate, short),
            (PasswordReset, mail),
            (VerificationMail, mail),
        ];
        Self {
            per_account: all.iter().map(|(g, (a, _))| (*g, *a)).collect(),
            per_client: all.iter().map(|(g, (_, c))| (*g, *c)).collect(),
        }
    }
}

impl RateLimits {
    /// No limits at all; add them with the setters.
    pub fn none() -> Self {
        Self {
            per_account: HashMap::new(),
            per_client: HashMap::new(),
        }
    }

    /// Set (or with `None`, remove) `group`'s per-account limit.
    pub fn per_account(mut self, group: RateLimitGroup, limit: Option<Limit>) -> Self {
        match limit {
            Some(limit) => self.per_account.insert(group, limit),
            None => self.per_account.remove(&group),
        };
        self
    }

    /// Set (or with `None`, remove) `group`'s per-client limit.
    pub fn per_client(mut self, group: RateLimitGroup, limit: Option<Limit>) -> Self {
        match limit {
            Some(limit) => self.per_client.insert(group, limit),
            None => self.per_client.remove(&group),
        };
        self
    }
}

type ClientOf = dyn Fn(&Parts) -> Option<IpAddr> + Send + Sync;

/// Counts attempts in a [`RateLimitStore`] and refuses the ones over the
/// [`RateLimits`]. Turn it on with
/// [`CredentialScheme::rate_limited`](crate::authentication::credential_scheme::CredentialScheme::rate_limited).
///
/// The client address comes from the request's [`ClientAddr`] extension,
/// which the axum adapter sets from the connection. Behind a reverse proxy
/// that is the proxy's address; use
/// [`client_address`](Self::client_address) to read the header your proxy
/// sets instead (only one it overwrites: a client can send any
/// `X-Forwarded-For` it likes).
///
/// If the store fails, the attempt is let through and the error logged: an
/// outage of the counter store should not take logins down with it.
#[derive(Clone)]
pub struct RateLimiter {
    store: Arc<dyn RateLimitStore>,
    limits: Arc<RateLimits>,
    client: Arc<ClientOf>,
}

impl RateLimiter {
    /// The default limits, counted in `store`.
    pub fn new(store: impl RateLimitStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            limits: Arc::new(RateLimits::default()),
            client: Arc::new(|parts: &Parts| parts.extensions.get::<ClientAddr>().map(|c| c.0)),
        }
    }

    /// Use these limits instead of the defaults.
    pub fn limits(mut self, limits: RateLimits) -> Self {
        self.limits = Arc::new(limits);
        self
    }

    /// Read the client's address with `client` (for example from the header
    /// a trusted proxy sets). `None` skips the per-client limits.
    pub fn client_address(
        mut self,
        client: impl Fn(&Parts) -> Option<IpAddr> + Send + Sync + 'static,
    ) -> Self {
        self.client = Arc::new(client);
        self
    }

    /// Count this attempt at `route`; `Err` is the 429 to answer with.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn check(
        &self,
        route: RouteId,
        parts: &Parts,
        account: Option<&Email>,
    ) -> Result<(), EndpointResponse> {
        let Some(group) = RateLimitGroup::of(route) else {
            return Ok(());
        };
        if let Some(limit) = self.limits.per_client.get(&group)
            && let Some(addr) = (self.client)(parts)
        {
            let key = format!("{}:client:{}", group.key(), client_key(addr));
            self.count(&key, *limit).await?;
        }
        if let Some(limit) = self.limits.per_account.get(&group)
            && let Some(email) = account
        {
            let key = format!("{}:account:{}", group.key(), email.as_ref().expose_secret());
            self.count(&key, *limit).await?;
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    async fn count(&self, key: &str, limit: Limit) -> Result<(), EndpointResponse> {
        match self.store.hit(key, limit.window_seconds).await {
            Ok(window) if window.count > limit.max => Err(too_many(window.resets_in_seconds)),
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::error!(error = %e, "rate limit store failed; letting the attempt through");
                Ok(())
            }
        }
    }
}

/// The key a client address counts under: the address itself, or for IPv6
/// its /64 (one host or home network usually holds a whole /64, so per
/// address it could step around the limit).
fn client_key(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0).to_string() + "/64"
            }
        },
    }
}

fn too_many(retry_after: u64) -> EndpointResponse {
    let mut response = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many attempts; try again later",
    );
    response.headers_mut().insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from(retry_after),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::HashMapRateLimitStore;
    use secrecy::Secret;

    fn parts_from(addr: Option<&str>) -> Parts {
        let (mut parts, ()) = http::Request::new(()).into_parts();
        if let Some(addr) = addr {
            parts.extensions.insert(ClientAddr(addr.parse().unwrap()));
        }
        parts
    }

    fn email(s: &str) -> Email {
        Email::try_from(Secret::new(s.to_string())).unwrap()
    }

    fn limiter(limits: RateLimits) -> RateLimiter {
        RateLimiter::new(HashMapRateLimitStore::new()).limits(limits)
    }

    #[tokio::test]
    async fn the_attempt_over_the_account_limit_gets_429_with_retry_after() {
        let limiter =
            limiter(RateLimits::none().per_account(RateLimitGroup::Login, Some(Limit::new(2, 60))));
        let alice = email("alice@example.com");
        let parts = parts_from(None);
        for _ in 0..2 {
            assert!(
                limiter
                    .check(RouteId::Login, &parts, Some(&alice))
                    .await
                    .is_ok()
            );
        }
        let refused = limiter
            .check(RouteId::Login, &parts, Some(&alice))
            .await
            .unwrap_err();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = refused.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry));

        // Another account is not affected, and neither are unlimited routes.
        let bob = email("bob@example.com");
        assert!(
            limiter
                .check(RouteId::Login, &parts, Some(&bob))
                .await
                .is_ok()
        );
        assert!(
            limiter
                .check(RouteId::Logout, &parts, Some(&alice))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn one_client_trying_many_accounts_hits_the_client_limit() {
        let limiter =
            limiter(RateLimits::none().per_client(RateLimitGroup::Login, Some(Limit::new(3, 60))));
        let parts = parts_from(Some("203.0.113.7"));
        for i in 0..3 {
            let who = email(&format!("user{i}@example.com"));
            assert!(
                limiter
                    .check(RouteId::Login, &parts, Some(&who))
                    .await
                    .is_ok()
            );
        }
        let who = email("user9@example.com");
        assert!(
            limiter
                .check(RouteId::Login, &parts, Some(&who))
                .await
                .is_err()
        );
        // Another client is fine.
        let other = parts_from(Some("198.51.100.1"));
        assert!(
            limiter
                .check(RouteId::Login, &other, Some(&who))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn routes_in_one_group_share_a_count() {
        let limiter = limiter(
            RateLimits::none()
                .per_account(RateLimitGroup::VerificationMail, Some(Limit::new(1, 60))),
        );
        let alice = email("alice@example.com");
        let parts = parts_from(None);
        assert!(
            limiter
                .check(RouteId::Signup, &parts, Some(&alice))
                .await
                .is_ok()
        );
        assert!(
            limiter
                .check(RouteId::ResendVerification, &parts, Some(&alice))
                .await
                .is_err()
        );
    }

    #[test]
    fn ipv6_clients_count_per_64_and_mapped_v4_as_v4() {
        let a = client_key("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = client_key("2001:db8:1:2:bbbb::9".parse().unwrap());
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:1:2::/64");
        assert_eq!(
            client_key("::ffff:203.0.113.7".parse().unwrap()),
            "203.0.113.7"
        );
    }
}
