//! Route buckets ([`Routers`]) + the elevation appliers the auto-wiring uses.

use crate::IntoStatusMessage;
use axum::{Router, routing::post};
use tempered_core::{AuthValidator, HttpElevationScheme, SupportsElevation};

/// Applies the elevated-token middleware to a router. See [`apply_elevated_validation`].
pub type ElevatedLayerFn<Scheme> = fn(Router<Scheme>, Scheme) -> Router<Scheme>;

/// Registers the logout route at a path. See [`register_logout_with_elevation`].
pub type LogoutRegisterFn<Scheme> = fn(Router<Scheme>, &str) -> Router<Scheme>;

pub struct Routers<Scheme> {
    pub main_router: Router<Scheme>,
    pub validated_router: Router<Scheme>,
    pub elevated_router: Option<Router<Scheme>>,
    /// Applies the elevated-token middleware to [`Self::elevated_router`] at
    /// build time. Stored as a plain `fn` so the base build (which lacks the
    /// `HttpElevationScheme` bound) can call it; the bound is only required to
    /// *take* the pointer, which the elevation builder methods do. See
    /// [`apply_elevated_validation`].
    pub elevated_layer: Option<ElevatedLayerFn<Scheme>>,
    /// Registers the logout route. When elevation is configured this is swapped
    /// for the elevation-aware variant (which also revokes the elevated token),
    /// again via a `fn` pointer so the base `logout_route` can install it without
    /// the `HttpElevationScheme` bound. `None` → plain logout. See
    /// [`register_logout_with_elevation`].
    pub logout_register: Option<LogoutRegisterFn<Scheme>>,
}

impl<Scheme> Routers<Scheme>
where
    Scheme: Clone + Send + Sync + 'static,
{
    /// Empty buckets, no elevation hooks — the starting point for auto-wiring.
    pub fn empty() -> Self {
        Routers {
            main_router: Router::new(),
            validated_router: Router::new(),
            elevated_router: None,
            elevated_layer: None,
            logout_register: None,
        }
    }
}

/// Layer the elevated-token validation middleware over `router`.
///
/// Used as a `fn` pointer stored in [`Routers::elevated_layer`]: the elevation
/// builder methods (which carry the `HttpElevationScheme` bound) hand this to the
/// base build, which can then protect the elevated bucket without naming the
/// bound itself.
pub fn apply_elevated_validation<S>(router: Router<S>, scheme: S) -> Router<S>
where
    S: HttpElevationScheme + SupportsElevation + Clone + Send + Sync + 'static,
    S::ElevatedValidator: AuthValidator<RequestParts = http::request::Parts>,
    <S::ElevatedValidator as AuthValidator>::Error: IntoStatusMessage,
{
    router.layer(axum::middleware::from_fn_with_state(
        scheme,
        crate::middleware::validate_elevated_token::<S>,
    ))
}

/// Register the elevation-aware logout route (revokes the elevated token too).
///
/// Stored as a `fn` pointer in [`Routers::logout_register`] by the elevation
/// builder methods so the base `logout_route` installs the right handler.
pub fn register_logout_with_elevation<S>(validated: Router<S>, logout_path: &str) -> Router<S>
where
    S: HttpElevationScheme + SupportsElevation + Clone + Send + Sync + 'static,
{
    validated.route(logout_path, post(crate::routes::logout_with_elevation::<S>))
}
