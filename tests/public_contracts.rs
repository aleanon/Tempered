//! The store contracts are usable from outside the crate (feature
//! `testing`), as a third-party store would use them.
#![cfg(feature = "testing")]

#[tokio::test]
async fn an_outside_store_can_run_the_contracts() {
    tempered::testing::session_store(tempered::HashMapSessionStore::new()).await;
    tempered::testing::refresh_token_store(tempered::HashMapRefreshTokenStore::new()).await;
    tempered::testing::totp_store(tempered::HashMapTotpStore::new()).await;
}
