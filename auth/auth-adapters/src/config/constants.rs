use std::sync::LazyLock;

use crate::config::settings::AuthServiceSetting;

pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const JWT_ELEVATED_SECRET_ENV_VAR: &str = "JWT_ELEVATED_SECRET";
    pub const AUTH_SERVICE_ALLOWED_ORIGINS_ENV_VAR: &str = "AUTH_SERVICE_ALLOWED_ORIGINS";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME";
    pub const POSTMARK_AUTH_TOKEN_ENV_VAR: &str = "POSTMARK_AUTH_TOKEN";
}

pub const JWT_COOKIE_NAME: LazyLock<&'static str> = LazyLock::new(|| {
    let cookie_name = AuthServiceSetting::load().auth.jwt.cookie_name.clone();
    Box::leak(cookie_name.into_boxed_str())
});
pub static JWT_ELEVATED_COOKIE_NAME: LazyLock<&'static str> = LazyLock::new(|| {
    let cookie_name = AuthServiceSetting::load()
        .auth
        .elevated_jwt
        .cookie_name
        .clone();
    Box::leak(cookie_name.into_boxed_str())
});

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
    pub mod email_client {
        use std::time::Duration;

        pub const BASE_URL: &str = "https://api.postmarkapp.com/";
        pub const SENDER: &str = "bogdan@codeiron.io";
        pub const TIMEOUT: Duration = std::time::Duration::from_secs(10);
    }
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
    pub mod email_client {
        use std::time::Duration;

        pub const SENDER: &str = "test@email.com";
        pub const TIMEOUT: Duration = std::time::Duration::from_millis(200);
    }
}
