//! Slot-driven route auto-wiring.
//!
//! `auth_service` reads the capabilities the scheme declared (`supports_*`) and
//! wires the matching routes with default paths, at the right authz level. Rust
//! can't introspect trait impls, so each *slot-gated* capability has a `Wire<Cap>`
//! trait with two non-overlapping impls — disabled slot (`()`) = no-op, enabled
//! slot = wires the route (the capability bound holds there). The *always-on*
//! capabilities (registration, password change, account deletion) are wired from
//! the scheme's runtime `RouteFlags` in [`WireCore`]. [`AutoWire`] drives them all.

use axum::{
    Router,
    routing::{delete, get, post},
};
use tempered_adapters::authentication::api_key_scheme::ApiKeyScheme;
use tempered_adapters::authentication::credential_scheme::{
    Authz, CredentialScheme, Elevation, EmailVerify, OAuth, Passkeys, PasswordReset, TwoFa,
};
use tempered_adapters::authentication::token_strategy::TokenStrategy;
use tempered_core::{
    AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, HttpElevationScheme,
    HttpOAuth2Scheme, RequiresEmailVerification, SupportsAccountDeletion,
    SupportsElevation, SupportsOAuth2, SupportsPasskeys, SupportsPasswordChange,
    SupportsPasswordReset, SupportsRegistration, SupportsTwoFactor,
};
use crate::IntoStatusMessage;

use crate::route_config::{Routers, apply_elevated_validation, register_logout_with_elevation};

/// Per-route path overrides. `None` → the route's default path.
#[derive(Default)]
pub struct PathOverrides {
    pub login: Option<String>,
    pub logout: Option<String>,
    pub verify_token: Option<String>,
    pub signup: Option<String>,
    pub verify_2fa: Option<String>,
    pub change_password: Option<String>,
    pub delete_account: Option<String>,
    pub elevate: Option<String>,
    pub verify_elevated_token: Option<String>,
    pub password_reset_initiate: Option<String>,
    pub password_reset_complete: Option<String>,
    pub verify_email: Option<String>,
    pub oauth_start: Option<String>,
    pub oauth_callback: Option<String>,
    pub passkey_prefix: Option<String>,
}

fn or<'a>(o: &'a Option<String>, default: &'a str) -> &'a str {
    o.as_deref().unwrap_or(default)
}

// ============================================================================
// Always-on core + runtime-flagged capabilities
// ============================================================================

/// Wires the always-present routes (login/logout/verify-token) and the runtime-
/// flagged always-on capabilities (signup, change-password, account-deletion).
pub trait WireCore: Sized {
    fn wire_core(&self, routers: Routers<Self>, o: &PathOverrides) -> Routers<Self>;
}

impl<U, T, F, L, R, M, O, K> WireCore for CredentialScheme<U, T, F, L, R, M, O, K>
where
    Self: HttpAuthenticationScheme<LogoutOutput = String>
        + SupportsRegistration
        + SupportsPasswordChange
        + SupportsAccountDeletion,
    <Self as AuthenticationScheme>::AuthError: IntoStatusMessage,
    <Self as SupportsRegistration>::RegistrationError: IntoStatusMessage,
    <Self as SupportsPasswordChange>::PasswordChangeError: IntoStatusMessage,
    <Self as SupportsAccountDeletion>::AccountDeletionError: IntoStatusMessage,
    T: TokenStrategy,
{
    fn wire_core(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        // Login (public) + verify-token (login-gated).
        routers.main_router = routers
            .main_router
            .route(or(&o.login, "/login"), post(crate::routes::login::<Self>));
        routers.validated_router = routers.validated_router.route(
            or(&o.verify_token, "/verify-token"),
            post(crate::routes::verify_token::<Self>),
        );

        // Logout (login-gated); elevation-aware variant if elevation set the hook.
        let logout_path = or(&o.logout, "/logout");
        routers.validated_router = match routers.logout_register {
            Some(register) => register(routers.validated_router, logout_path),
            None => routers
                .validated_router
                .route(logout_path, post(crate::routes::logout::<Self>)),
        };

        // Signup (opt-in via supports_registration).
        if self.route_flags().registration {
            routers.main_router = routers.main_router.route(
                or(&o.signup, "/signup"),
                post(crate::routes::signup::<Self>),
            );
        }

        // Password change / account deletion — login or elevation gated, or off.
        routers = wire_sensitive(
            routers,
            self.route_flags().password_change,
            &o.change_password,
            "/change-password",
            "/elevated/change-password",
            |r, path| r.route(path, post(crate::routes::change_password::<Self>)),
        );
        routers = wire_sensitive(
            routers,
            self.route_flags().account_deletion,
            &o.delete_account,
            "/delete-account",
            "/elevated/delete-account",
            |r, path| r.route(path, delete(crate::routes::delete_account::<Self>)),
        );

        routers
    }
}

/// Place a sensitive-op route on the validated or elevated bucket per its [`Authz`].
/// The path override (if any) applies to whichever level the op is at.
fn wire_sensitive<S>(
    mut routers: Routers<S>,
    authz: Option<Authz>,
    override_path: &Option<String>,
    login_default: &str,
    elevated_default: &str,
    add: impl Fn(Router<S>, &str) -> Router<S>,
) -> Routers<S>
where
    S: Clone + Send + Sync + 'static,
{
    match authz {
        None => {}
        Some(Authz::Login) => {
            let path = or(override_path, login_default);
            routers.validated_router = add(routers.validated_router, path);
        }
        Some(Authz::Elevated) => {
            let path = or(override_path, elevated_default);
            routers.elevated_router = Some(add(routers.elevated_router.unwrap_or_default(), path));
        }
    }
    routers
}

// ============================================================================
// Slot-gated capabilities (non-overlapping impls: () = no-op, real = wire)
// ============================================================================

macro_rules! wire_slot_trait {
    ($trait:ident, $method:ident) => {
        pub trait $trait: Sized {
            fn $method(&self, routers: Routers<Self>, o: &PathOverrides) -> Routers<Self>;
        }
    };
}

wire_slot_trait!(WireTwoFa, wire_2fa);
wire_slot_trait!(WireElevation, wire_elevation);
wire_slot_trait!(WirePasswordReset, wire_password_reset);
wire_slot_trait!(WireEmailVerify, wire_email_verify);
wire_slot_trait!(WireOAuth, wire_oauth);
wire_slot_trait!(WirePasskeys, wire_passkeys);

// ---- 2FA -------------------------------------------------------------------

impl<U, T, L, R, M, O, K> WireTwoFa for CredentialScheme<U, T, (), L, R, M, O, K>
where
    Self: HttpAuthenticationScheme,
{
    fn wire_2fa(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}

impl<U, T, St, E, L, R, M, O, K> WireTwoFa for CredentialScheme<U, T, TwoFa<St, E>, L, R, M, O, K>
where
    Self: HttpAuthenticationScheme + SupportsTwoFactor,
    <Self as SupportsTwoFactor>::TwoFactorError: IntoStatusMessage,
{
    fn wire_2fa(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        routers.main_router = routers.main_router.route(
            or(&o.verify_2fa, "/verify-2fa"),
            post(crate::routes::verify_2fa::<Self>),
        );
        routers
    }
}

// ---- Elevation -------------------------------------------------------------

impl<U, T, F, R, M, O, K> WireElevation for CredentialScheme<U, T, F, (), R, M, O, K>
where
    Self: HttpAuthenticationScheme,
{
    fn wire_elevation(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}

impl<U, T, F, TE, R, M, O, K> WireElevation
    for CredentialScheme<U, T, F, Elevation<TE>, R, M, O, K>
where
    Self: HttpElevationScheme,
    <Self as AuthenticationScheme>::Validator:
        AuthValidator<RequestParts = http::request::Parts>,
    <<Self as AuthenticationScheme>::Validator as AuthValidator>::Error: IntoStatusMessage,
    <Self as SupportsElevation>::ElevatedValidator:
        AuthValidator<RequestParts = http::request::Parts>,
    <<Self as SupportsElevation>::ElevatedValidator as AuthValidator>::Error: IntoStatusMessage,
    TE: TokenStrategy,
{
    fn wire_elevation(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        // `/elevate` (become elevated) needs a normal session → validated bucket.
        routers.validated_router = routers.validated_router.route(
            or(&o.elevate, "/elevate"),
            post(crate::routes::elevate::<Self>),
        );
        // verify-elevated + the elevated bucket's middleware/logout hook.
        let elevated = routers.elevated_router.unwrap_or_default().route(
            or(&o.verify_elevated_token, "/elevated/verify-token"),
            post(crate::routes::verify_elevated_token::<Self>),
        );
        routers.elevated_router = Some(elevated);
        routers
            .elevated_layer
            .get_or_insert(apply_elevated_validation::<Self>);
        routers
            .logout_register
            .get_or_insert(register_logout_with_elevation::<Self>);
        routers
    }
}

// ---- Password reset --------------------------------------------------------

impl<U, T, F, L, M, O, K> WirePasswordReset for CredentialScheme<U, T, F, L, (), M, O, K>
where
    Self: HttpAuthenticationScheme,
{
    fn wire_password_reset(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}

impl<U, T, F, L, P, E, M, O, K> WirePasswordReset
    for CredentialScheme<U, T, F, L, PasswordReset<P, E>, M, O, K>
where
    Self: HttpAuthenticationScheme + SupportsPasswordReset,
{
    fn wire_password_reset(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        routers.main_router = routers
            .main_router
            .route(
                or(&o.password_reset_initiate, "/password-reset/initiate"),
                post(crate::routes::initiate_password_reset::<Self>),
            )
            .route(
                or(&o.password_reset_complete, "/password-reset/complete"),
                post(crate::routes::complete_password_reset::<Self>),
            );
        routers
    }
}

// ---- Email verification ----------------------------------------------------

impl<U, T, F, L, R, O, K> WireEmailVerify for CredentialScheme<U, T, F, L, R, (), O, K>
where
    Self: HttpAuthenticationScheme,
{
    fn wire_email_verify(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}

impl<U, T, F, L, R, V, E, O, K> WireEmailVerify
    for CredentialScheme<U, T, F, L, R, EmailVerify<V, E>, O, K>
where
    Self: HttpAuthenticationScheme + RequiresEmailVerification,
    <Self as RequiresEmailVerification>::EmailVerificationError: IntoStatusMessage,
{
    fn wire_email_verify(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        routers.main_router = routers.main_router.route(
            or(&o.verify_email, "/verify-email"),
            post(crate::routes::verify_email::<Self>),
        );
        routers
    }
}

// ---- OAuth -----------------------------------------------------------------

impl<U, T, F, L, R, M, K> WireOAuth for CredentialScheme<U, T, F, L, R, M, (), K>
where
    Self: HttpAuthenticationScheme,
{
    fn wire_oauth(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}

impl<U, T, F, L, R, M, ST, ID, HC, K> WireOAuth
    for CredentialScheme<U, T, F, L, R, M, OAuth<ST, ID, HC>, K>
where
    Self: HttpOAuth2Scheme,
    <Self as SupportsOAuth2>::OAuth2Error: IntoStatusMessage,
{
    fn wire_oauth(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        routers.main_router = routers
            .main_router
            .route(
                or(&o.oauth_start, "/oauth/{provider}/start"),
                get(crate::routes::oauth_start::<Self>),
            )
            .route(
                or(&o.oauth_callback, "/oauth/{provider}/callback"),
                get(crate::routes::oauth_callback::<Self>),
            );
        routers
    }
}

// ---- Passkeys --------------------------------------------------------------

impl<U, T, F, L, R, M, O> WirePasskeys for CredentialScheme<U, T, F, L, R, M, O, ()>
where
    Self: HttpAuthenticationScheme,
{
    fn wire_passkeys(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}

impl<U, T, F, L, R, M, O, CS, ChS, V> WirePasskeys
    for CredentialScheme<U, T, F, L, R, M, O, Passkeys<CS, ChS, V>>
where
    Self: HttpAuthenticationScheme + SupportsPasskeys,
    <Self as SupportsPasskeys>::PasskeyError: IntoStatusMessage,
{
    fn wire_passkeys(&self, mut routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        let prefix = or(&o.passkey_prefix, "/passkey");
        routers.main_router = routers
            .main_router
            .route(
                &format!("{prefix}/register/start"),
                post(crate::routes::passkey_register_start::<Self>),
            )
            .route(
                &format!("{prefix}/register/finish"),
                post(crate::routes::passkey_register_finish::<Self>),
            )
            .route(
                &format!("{prefix}/login/start"),
                post(crate::routes::passkey_login_start::<Self>),
            )
            .route(
                &format!("{prefix}/login/finish"),
                post(crate::routes::passkey_login_finish::<Self>),
            );
        routers
    }
}

// ============================================================================
// AutoWire — call them all in order
// ============================================================================

/// Wires every route the scheme declared. Elevation runs first so it can install
/// the elevated-bucket middleware hook + elevation-aware logout before core wires
/// logout and the elevation-gated sensitive routes.
///
/// Implemented per scheme family (rather than as a blanket over the `Wire*`
/// traits) so a scheme with no credential routes — [`ApiKeyScheme`] — can wire
/// nothing while still being served by `auth_service`.
pub trait AutoWire: Sized {
    fn auto_wire(&self, routers: Routers<Self>, o: &PathOverrides) -> Routers<Self>;
}

impl<U, T, F, L, R, M, O, K> AutoWire for CredentialScheme<U, T, F, L, R, M, O, K>
where
    Self: WireCore
        + WireElevation
        + WireTwoFa
        + WirePasswordReset
        + WireEmailVerify
        + WireOAuth
        + WirePasskeys,
{
    fn auto_wire(&self, routers: Routers<Self>, o: &PathOverrides) -> Routers<Self> {
        let routers = self.wire_elevation(routers, o);
        let routers = self.wire_core(routers, o);
        let routers = self.wire_2fa(routers, o);
        let routers = self.wire_password_reset(routers, o);
        let routers = self.wire_email_verify(routers, o);
        let routers = self.wire_oauth(routers, o);
        self.wire_passkeys(routers, o)
    }
}

/// API-key schemes have no credential routes (no login/logout/signup, 2FA,
/// elevation, password reset, OAuth, or passkeys) to auto-wire. `auth_service`
/// still serves static assets and protects the validated bucket with the
/// scheme's key validator, so
/// `auth_service(api_key_scheme, assets).validated_router(..)` works exactly as
/// it does for a JWT scheme. Key *issuance* is app-specific (it needs an owner
/// and scopes), so it stays a caller-supplied route rather than an auto-wired one.
impl<S, I> AutoWire for ApiKeyScheme<S, I>
where
    S: Clone + Send + Sync + 'static,
    I: Clone + Send + Sync + 'static,
{
    fn auto_wire(&self, routers: Routers<Self>, _o: &PathOverrides) -> Routers<Self> {
        routers
    }
}
