//! The store contracts are usable from outside the crate (feature
//! `testing`), as a third-party store would use them.
#![cfg(feature = "testing")]

#[tokio::test]
async fn an_outside_store_can_run_the_contracts() {
    tempered::testing::session_store(tempered::HashMapSessionStore::new()).await;
    tempered::testing::refresh_token_store(tempered::HashMapRefreshTokenStore::new()).await;
    // A store that needs real accounts gets them from the contract helper.
    let users = tempered::HashMapUserStore::new();
    let ids = tempered::testing::accounts(&users, ["a@example.com", "b@example.com"]).await;
    tempered::testing::totp_store(tempered::HashMapTotpStore::new(), ids).await;
}
