//! One test function per port, run against every implementation of it, so
//! the in-memory and the production stores answer the same assertions.

#![allow(dead_code)]

use secrecy::Secret;
use tempered_core::{Email, SessionId, SessionStore, SessionStoreError};

pub(crate) fn email(address: &str) -> Email {
    Email::try_from(Secret::new(address.to_string())).unwrap()
}

/// [`SessionStore`]: lookup, single and per-user deletion, the revocation
/// count, and the credential lock.
pub(crate) async fn session_store(store: impl SessionStore) {
    let alice = email("alice@example.com");
    let bob = email("bob@example.com");

    let a1 = SessionId::new();
    let a2 = SessionId::new();
    let b1 = SessionId::new();
    store
        .create_session(a1.clone(), alice.clone())
        .await
        .unwrap();
    store
        .create_session(a2.clone(), alice.clone())
        .await
        .unwrap();
    store.create_session(b1.clone(), bob.clone()).await.unwrap();
    assert_eq!(store.get_session(&a1).await.unwrap(), alice);
    assert!(matches!(
        store.get_session(&SessionId::new()).await,
        Err(SessionStoreError::SessionNotFound)
    ));
    store.touch_session(&a1).await.unwrap();
    assert_eq!(store.get_session(&a1).await.unwrap(), alice);

    // One session.
    store.delete_session(&a2).await.unwrap();
    assert!(store.get_session(&a2).await.is_err());
    assert!(matches!(
        store.delete_session(&a2).await,
        Err(SessionStoreError::SessionNotFound)
    ));

    // All of one user's, counted.
    assert_eq!(store.revocation_count(&alice).await.unwrap(), 0);
    store.delete_all_for_user(&alice).await.unwrap();
    assert!(store.get_session(&a1).await.is_err());
    assert_eq!(store.get_session(&b1).await.unwrap(), bob);
    assert_eq!(store.revocation_count(&alice).await.unwrap(), 1);
    store.delete_all_for_user(&alice).await.unwrap();
    assert_eq!(store.revocation_count(&alice).await.unwrap(), 2);
    assert_eq!(store.revocation_count(&bob).await.unwrap(), 0);

    // The credential lock.
    assert!(!store.is_user_locked(&alice).await.unwrap());
    assert!(store.try_lock_user(&alice, "one", 10).await.unwrap());
    assert!(!store.try_lock_user(&alice, "two", 10).await.unwrap());
    assert!(store.is_user_locked(&alice).await.unwrap());
    assert!(!store.is_user_locked(&bob).await.unwrap());
    store.unlock_user(&alice, "two").await.unwrap();
    assert!(store.is_user_locked(&alice).await.unwrap());
    store.unlock_user(&alice, "one").await.unwrap();
    assert!(!store.is_user_locked(&alice).await.unwrap());
}

/// [`OAuthStateStore`]: a stored request comes back exactly once.
pub(crate) async fn oauth_state_store(store: impl tempered_core::OAuthStateStore) {
    use secrecy::ExposeSecret;
    use tempered_core::{OAuthStateStoreError, PendingAuthorization};

    store
        .store_state(
            "s1".to_string(),
            PendingAuthorization {
                provider: "google".to_string(),
                code_verifier: Secret::new("verifier-1".to_string()),
            },
        )
        .await
        .unwrap();

    let found = store.consume_state("s1").await.unwrap();
    assert_eq!(found.provider, "google");
    assert_eq!(found.code_verifier.expose_secret(), "verifier-1");
    assert!(matches!(
        store.consume_state("s1").await,
        Err(OAuthStateStoreError::UnknownState)
    ));
    assert!(matches!(
        store.consume_state("never-stored").await,
        Err(OAuthStateStoreError::UnknownState)
    ));
}

/// [`ChallengeStore`]: single-use ceremonies, and dropping one user's.
pub(crate) async fn challenge_store(store: impl tempered_core::ChallengeStore) {
    use tempered_core::{CeremonyId, CeremonyState, ChallengeStoreError, PendingCeremony};

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let ceremony = |user: Option<&Email>, state: &[u8]| PendingCeremony {
        user: user.cloned(),
        state: CeremonyState(state.to_vec()),
    };
    let id = |s: &str| CeremonyId(s.to_string());

    store
        .store_ceremony(id("c1"), ceremony(Some(&alice), b"\x00state-1\xff"))
        .await
        .unwrap();
    let found = store.consume_ceremony(&id("c1")).await.unwrap();
    assert_eq!(found.user, Some(alice.clone()));
    assert_eq!(found.state, CeremonyState(b"\x00state-1\xff".to_vec()));
    assert!(matches!(
        store.consume_ceremony(&id("c1")).await,
        Err(ChallengeStoreError::ChallengeNotFound)
    ));

    // Dropping Alice's leaves Bob's and the usernameless one.
    store
        .store_ceremony(id("a1"), ceremony(Some(&alice), b"a1"))
        .await
        .unwrap();
    store
        .store_ceremony(id("a2"), ceremony(Some(&alice), b"a2"))
        .await
        .unwrap();
    store
        .store_ceremony(id("b1"), ceremony(Some(&bob), b"b1"))
        .await
        .unwrap();
    store
        .store_ceremony(id("n1"), ceremony(None, b"n1"))
        .await
        .unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    assert!(store.consume_ceremony(&id("a1")).await.is_err());
    assert!(store.consume_ceremony(&id("a2")).await.is_err());
    assert_eq!(
        store.consume_ceremony(&id("b1")).await.unwrap().user,
        Some(bob)
    );
    assert_eq!(store.consume_ceremony(&id("n1")).await.unwrap().user, None);
}

/// [`EmailVerificationTokenStore`]: single-use tokens, the verified mark,
/// and forgetting one address.
pub(crate) async fn email_verification_token_store(
    store: impl tempered_core::EmailVerificationTokenStore,
) {
    use tempered_core::{EmailVerificationStoreError, EmailVerificationToken};

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");

    let token = EmailVerificationToken::new();
    store
        .store_pending_verification(token.clone(), alice.clone())
        .await
        .unwrap();
    assert_eq!(store.consume_token(&token).await.unwrap(), alice);
    assert!(matches!(
        store.consume_token(&token).await,
        Err(EmailVerificationStoreError::TokenNotFound)
    ));

    assert!(!store.is_verified(&alice).await.unwrap());
    store.mark_verified(&alice).await.unwrap();
    assert!(store.is_verified(&alice).await.unwrap());

    // Forgetting Alice clears her mark and her pending tokens, not Bob's.
    let alices = EmailVerificationToken::new();
    let bobs = EmailVerificationToken::new();
    store
        .store_pending_verification(alices.clone(), alice.clone())
        .await
        .unwrap();
    store
        .store_pending_verification(bobs.clone(), bob.clone())
        .await
        .unwrap();
    store.mark_verified(&bob).await.unwrap();
    store.forget_email(&alice).await.unwrap();
    store.forget_email(&alice).await.unwrap();
    assert!(!store.is_verified(&alice).await.unwrap());
    assert!(store.consume_token(&alices).await.is_err());
    assert!(store.is_verified(&bob).await.unwrap());
    assert_eq!(store.consume_token(&bobs).await.unwrap(), bob);
}
