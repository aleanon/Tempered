//! Composing multiple authentication schemes into one, the library's way.
//!
//! `auth_service<S>` takes exactly ONE scheme. To offer several methods in a
//! single app (e.g. a JWT session cookie *or* an API key header on the same
//! endpoints), you implement the scheme/validator traits on your own enum and
//! control dispatch yourself. The library intentionally ships no composite.
//!
//! This file is a DESIGN SKELETON. The real `SessionScheme` / `ApiKeyScheme`
//! referenced below do not exist yet (see `docs/AUTH_SCHEMES_PLAN.md`), so the
//! illustrative implementation lives in a `#[cfg(any())]` module that is never
//! compiled — it documents the intended shape without breaking `cargo build
//! --examples`. Promote it to real code as the schemes land.
//!
//! It exists to pin down two ergonomics decisions early:
//!   1. How `Credentials` disambiguates across schemes (serde tag convention).
//!   2. Where the multi-validator "try in order" logic lives (the user's
//!      `AuthValidator` impl on the validator enum).

fn main() {
    println!(
        "Design skeleton only — see the `#[cfg(any())] mod composed` block in \
         this file and docs/AUTH_SCHEMES_PLAN.md (Phase 5)."
    );
}

// ---------------------------------------------------------------------------
// Never compiled (always-false cfg). Faithful sketch of the intended impls.
// ---------------------------------------------------------------------------
#[cfg(any())]
mod composed {
    use async_trait::async_trait;
    use serde::Deserialize;
    use tempered_core::{
        AuthRequest, AuthValidator, AuthenticationScheme, HttpAuthenticationScheme, LoginOutcome,
        ResponseBuilder, ResponseBuilderError,
    };

    // Stand-ins for the schemes from Phases 1–4. Each must expose its Token,
    // Validator, Claims and error types as public, nameable types so they can
    // be wrapped here.
    use tempered_adapters::authentication::jwt_scheme::{JwtAuthError, JwtScheme, JwtToken};
    use tempered_adapters::authentication::session_scheme::{SessionId, SessionScheme};
    use tempered_adapters::authentication::api_key_scheme::{ApiKeyId, ApiKeyScheme};

    // Concrete store generics elided as `..` for readability.
    type Jwt = JwtScheme</* .. */>;
    type Session = SessionScheme</* .. */>;
    type ApiKey = ApiKeyScheme</* .. */>;

    // === The composed scheme ===============================================
    #[derive(Clone)]
    pub enum MyScheme {
        Jwt(Jwt),
        Session(Session),
        ApiKey(ApiKey),
    }

    // Unified associated types: one enum variant per inner scheme.
    #[derive(Clone)]
    pub enum MyToken {
        Jwt(JwtToken),
        Session(SessionId),
        ApiKey(ApiKeyId),
    }

    // DECISION 1: internally-tagged on a `method` field. Clearer parse errors
    // than `#[serde(untagged)]`, and no ambiguous matching. The client sends
    // e.g. `{"method":"password","email":"..","password":".."}`.
    #[derive(Deserialize)]
    #[serde(tag = "method", rename_all = "snake_case")]
    pub enum MyCredentials {
        Password(<Jwt as AuthenticationScheme>::Credentials),
        // API keys are presented in a header, not posted to /login, so they
        // need no login-credentials variant — only a validator (below).
    }

    #[derive(Clone)]
    pub enum MyClaims {
        Jwt(<<Jwt as AuthenticationScheme>::Validator as AuthValidator>::Claims),
        Session(<<Session as AuthenticationScheme>::Validator as AuthValidator>::Claims),
        ApiKey(<<ApiKey as AuthenticationScheme>::Validator as AuthValidator>::Claims),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum MyAuthError {
        #[error(transparent)]
        Jwt(#[from] JwtAuthError),
        // .. Session / ApiKey error variants
    }

    // === The composed validator (DECISION 2 lives here) ====================
    #[derive(Clone)]
    pub struct MyValidator {
        jwt: <Jwt as AuthenticationScheme>::Validator,
        session: <Session as AuthenticationScheme>::Validator,
        api_key: <ApiKey as AuthenticationScheme>::Validator,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("no authentication method matched")]
    pub struct NoMethodMatched;

    #[async_trait]
    impl AuthValidator for MyValidator {
        type Claims = MyClaims;
        // Rule 2 from the plan: every inner validator uses the same RequestParts,
        // which is what makes trying them in sequence possible.
        type RequestParts = http::request::Parts;
        type Error = NoMethodMatched;

        async fn validate(&self, parts: &Self::RequestParts) -> Result<MyClaims, Self::Error> {
            // YOU control precedence and which error surfaces. Order matters:
            // cheapest / most-specific first. Here: header-based API key, then
            // the two cookie-based schemes.
            if let Ok(c) = self.api_key.validate(parts).await {
                return Ok(MyClaims::ApiKey(c));
            }
            if let Ok(c) = self.jwt.validate(parts).await {
                return Ok(MyClaims::Jwt(c));
            }
            if let Ok(c) = self.session.validate(parts).await {
                return Ok(MyClaims::Session(c));
            }
            Err(NoMethodMatched)
        }
    }

    // === Scheme + HTTP delivery dispatch ===================================
    #[async_trait]
    impl AuthenticationScheme for MyScheme {
        type Token = MyToken;
        type LogoutOutput = String;
        type Validator = MyValidator;
        type Credentials = MyCredentials;
        type AuthError = MyAuthError;

        async fn login(
            &self,
            creds: Self::Credentials,
        ) -> Result<LoginOutcome<Self::Token>, Self::AuthError> {
            // Credentials shape selects the scheme.
            match (self, creds) {
                (MyScheme::Jwt(s), MyCredentials::Password(c)) => match s.login(c).await? {
                    LoginOutcome::Success(t) => Ok(LoginOutcome::Success(MyToken::Jwt(t))),
                    LoginOutcome::Requires2Fa { email, attempt_id } => {
                        Ok(LoginOutcome::Requires2Fa { email, attempt_id })
                    }
                },
                // .. Session login, etc.
                _ => todo!("unsupported (scheme, credentials) combination"),
            }
        }

        async fn logout(&self, token: &Self::Token) -> Result<Self::LogoutOutput, Self::AuthError> {
            match (self, token) {
                (MyScheme::Jwt(s), MyToken::Jwt(t)) => Ok(s.logout(t).await?),
                _ => todo!(),
            }
        }

        fn validator(&self) -> &Self::Validator {
            // MyScheme stores a prebuilt MyValidator (constructed once, like the
            // build() step does for JwtScheme). Field elided in this sketch.
            todo!("return &self.validator")
        }
    }

    impl HttpAuthenticationScheme for MyScheme {
        fn create_login_response<B: ResponseBuilder>(
            &self,
            builder: B,
            outcome: LoginOutcome<Self::Token>,
        ) -> Result<B::Response, ResponseBuilderError> {
            // Delegate to the inner scheme that owns the token variant, so each
            // keeps its own delivery (JWT cookie, session cookie, key in body).
            match (self, outcome) {
                (MyScheme::Jwt(s), LoginOutcome::Success(MyToken::Jwt(t))) => {
                    s.create_login_response(builder, LoginOutcome::Success(t))
                }
                _ => todo!(),
            }
        }

        fn create_logout_response<B: ResponseBuilder>(
            &self,
            builder: B,
            cookie_name: Option<String>,
        ) -> Result<B::Response, ResponseBuilderError> {
            match self {
                MyScheme::Jwt(s) => s.create_logout_response(builder, cookie_name),
                _ => todo!(),
            }
        }

        fn extract_token_from_request<R: AuthRequest>(&self, req: &R) -> Option<Self::Token> {
            match self {
                MyScheme::Jwt(s) => s.extract_token_from_request(req).map(MyToken::Jwt),
                _ => todo!(),
            }
        }
    }
}
