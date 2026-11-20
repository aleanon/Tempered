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
