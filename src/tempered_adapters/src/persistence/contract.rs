//! Contract tests for the store ports: one `async fn` per port, which
//! exercises a store against the behaviour the port's docs promise
//! (atomicity, single use, owner scoping, ...). The built-in stores run
//! them in their own tests; a store of your own can too (feature
//! `testing`):
//!
//! ```ignore
//! #[tokio::test]
//! async fn my_session_store_meets_the_contract() {
//!     tempered::testing::session_store(MySessionStore::connect().await).await;
//! }
//! ```
//!
//! Each one panics with an assertion on the first broken promise. Give it
//! an empty store: it creates users, sessions and so on under fixed test
//! addresses.

#![allow(dead_code)]

use secrecy::Secret;
use tempered_core::{Email, SessionId, SessionRecord, SessionStore, SessionStoreError};

/// A test address.
pub fn email(address: &str) -> Email {
    Email::try_from(Secret::new(address.to_string())).unwrap()
}

/// [`SessionStore`]: lookup, single and per-user deletion, the revocation
/// count, and the credential lock.
pub async fn session_store(store: impl SessionStore) {
    let alice = email("alice@example.com");
    let bob = email("bob@example.com");

    let a1 = SessionId::new();
    let a2 = SessionId::new();
    let b1 = SessionId::new();
    let record = |email: &Email, created_at| SessionRecord {
        email: email.clone(),
        created_at,
        scope: "__Host-session".to_string(),
        last_seen: None,
        user_agent: None,
    };
    store
        .create_session(a1.clone(), record(&alice, 100))
        .await
        .unwrap();
    store
        .create_session(a2.clone(), record(&alice, 200))
        .await
        .unwrap();
    store
        .create_session(b1.clone(), record(&bob, 300))
        .await
        .unwrap();
    // The record comes back as stored, creation time included.
    assert_eq!(store.get_session(&a1).await.unwrap(), record(&alice, 100));
    assert!(matches!(
        store.get_session(&SessionId::new()).await,
        Err(SessionStoreError::SessionNotFound)
    ));
    // Touching extends the expiry, not the age.
    let seen = tempered_core::SessionSeen {
        at: 500,
        user_agent: Some("Firefox"),
    };
    assert_eq!(
        store.touch_session(&a1, seen).await.unwrap(),
        record(&alice, 100)
    );
    // The visit is recorded; the first device stays.
    let later = tempered_core::SessionSeen {
        at: 600,
        user_agent: Some("curl"),
    };
    store.touch_session(&a1, later).await.unwrap();
    let touched = store.get_session(&a1).await.unwrap();
    assert_eq!(touched.last_seen, Some(600));
    assert_eq!(touched.user_agent.as_deref(), Some("Firefox"));
    assert_eq!(touched.created_at, 100);

    // A user's list holds their live sessions only.
    let mut listed: Vec<u64> = store
        .list_for_user(&alice)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, r)| r.created_at)
        .collect();
    listed.sort_unstable();
    assert_eq!(listed, [100, 200]);
    assert!(matches!(
        store.touch_session(&SessionId::new(), seen).await,
        Err(SessionStoreError::SessionNotFound)
    ));

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
    assert_eq!(store.get_session(&b1).await.unwrap().email, bob);
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
pub async fn oauth_state_store(store: impl tempered_core::OAuthStateStore) {
    use secrecy::ExposeSecret;
    use tempered_core::{OAuthStateStoreError, PendingAuthorization};

    store
        .store_state(
            "s1".to_string(),
            PendingAuthorization {
                provider: "google".to_string(),
                code_verifier: Secret::new("verifier-1".to_string()),
                nonce: Some(Secret::new("nonce-1".to_string())),
                link_to: Some(email("linker@example.com")),
            },
        )
        .await
        .unwrap();

    let found = store.consume_state("s1").await.unwrap();
    assert_eq!(found.provider, "google");
    assert_eq!(found.code_verifier.expose_secret(), "verifier-1");
    assert_eq!(found.nonce.unwrap().expose_secret(), "nonce-1");
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
pub async fn challenge_store(store: impl tempered_core::ChallengeStore) {
    use tempered_core::{
        CeremonyId, CeremonyKind, CeremonyState, ChallengeStoreError, PendingCeremony,
    };

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let ceremony = |user: Option<&Email>, state: &[u8]| PendingCeremony {
        // A usernameless ceremony is a login; one with a user, an enrolment.
        kind: if user.is_some() {
            CeremonyKind::Registration
        } else {
            CeremonyKind::Authentication
        },
        user: user.cloned(),
        state: CeremonyState(state.to_vec()),
    };
    let id = |s: &str| CeremonyId(s.to_string());

    store
        .store_ceremony(id("c1"), ceremony(Some(&alice), b"\x00state-1\xff"))
        .await
        .unwrap();
    let found = store.consume_ceremony(&id("c1")).await.unwrap();
    assert_eq!(found.kind, CeremonyKind::Registration);
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
pub async fn email_verification_token_store(
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

/// [`TokenEpochStore`](tempered_core::TokenEpochStore): the cutoff only
/// ever rises, per user, and the credential lock.
pub async fn token_epoch_store(store: impl tempered_core::TokenEpochStore) {
    let alice = email("alice@example.com");
    let bob = email("bob@example.com");

    assert_eq!(store.min_valid_iat(&alice).await.unwrap(), None);
    store.revoke_before(&alice, 100).await.unwrap();
    assert_eq!(store.min_valid_iat(&alice).await.unwrap(), Some(100));
    // An older cutoff (a slower instance's revocation) never lowers it.
    store.revoke_before(&alice, 90).await.unwrap();
    assert_eq!(store.min_valid_iat(&alice).await.unwrap(), Some(100));
    store.revoke_before(&alice, 120).await.unwrap();
    assert_eq!(store.min_valid_iat(&alice).await.unwrap(), Some(120));
    assert_eq!(store.min_valid_iat(&bob).await.unwrap(), None);

    // The lock: one holder at a time; only the holder releases it.
    assert!(!store.is_user_locked(&alice).await.unwrap());
    assert!(store.try_lock_user(&alice, "a", 10).await.unwrap());
    assert!(!store.try_lock_user(&alice, "b", 10).await.unwrap());
    assert!(store.is_user_locked(&alice).await.unwrap());
    assert!(!store.is_user_locked(&bob).await.unwrap());
    store.unlock_user(&alice, "b").await.unwrap();
    assert!(store.is_user_locked(&alice).await.unwrap());
    store.unlock_user(&alice, "a").await.unwrap();
    assert!(!store.is_user_locked(&alice).await.unwrap());
}

/// [`TwoFaCodeStore`](tempered_core::TwoFaCodeStore) with the default cap
/// of 5: single use, the per-account guessing budget (which a new code does
/// not reset), and success clearing it.
pub async fn two_fa_code_store(store: impl tempered_core::TwoFaCodeStore) {
    use tempered_core::{TwoFaAttemptId, TwoFaCode, TwoFaCodeStoreError};

    let wrong = |right: &TwoFaCode| {
        let flipped = if right.as_str() == "000000" {
            "000001"
        } else {
            "000000"
        };
        TwoFaCode::parse(flipped.to_string()).unwrap()
    };
    let issue = |user: &Email| {
        let (attempt, code) = (TwoFaAttemptId::new(), TwoFaCode::new());
        let user = user.clone();
        let store = &store;
        async move {
            store
                .store_code(user, attempt.clone(), code.clone())
                .await
                .unwrap();
            (attempt, code)
        }
    };
    let alice = email("alice@example.com");
    let bob = email("bob@example.com");

    // Single use.
    let (attempt, code) = issue(&alice).await;
    assert_eq!(
        store
            .get_login_attempt_id_and_two_fa_code(&alice)
            .await
            .unwrap(),
        (attempt.clone(), code.clone())
    );
    store.redeem_code(&alice, &attempt, &code).await.unwrap();
    assert_eq!(
        store.redeem_code(&alice, &attempt, &code).await,
        Err(TwoFaCodeStoreError::UserNotFound)
    );

    // Another login attempt's id does not redeem the code.
    let (attempt, code) = issue(&alice).await;
    assert_eq!(
        store
            .redeem_code(&alice, &TwoFaAttemptId::new(), &code)
            .await,
        Err(TwoFaCodeStoreError::InvalidAttemptId)
    );
    store.redeem_code(&alice, &attempt, &code).await.unwrap();

    // Two wrong guesses, then a fresh login: the budget carries over, so
    // two more fail and the fifth hits the cap.
    let (attempt, code) = issue(&alice).await;
    for _ in 0..2 {
        assert_eq!(
            store.redeem_code(&alice, &attempt, &wrong(&code)).await,
            Err(TwoFaCodeStoreError::Invalid2FACode)
        );
    }
    let (attempt, code) = issue(&alice).await;
    for _ in 0..2 {
        assert_eq!(
            store.redeem_code(&alice, &attempt, &wrong(&code)).await,
            Err(TwoFaCodeStoreError::Invalid2FACode)
        );
    }
    assert_eq!(
        store.redeem_code(&alice, &attempt, &wrong(&code)).await,
        Err(TwoFaCodeStoreError::TooManyAttempts)
    );
    // The code is gone, and a code issued later in the window is refused too.
    assert!(
        store
            .get_login_attempt_id_and_two_fa_code(&alice)
            .await
            .is_err()
    );
    let (attempt, code) = issue(&alice).await;
    assert_eq!(
        store.redeem_code(&alice, &attempt, &code).await,
        Err(TwoFaCodeStoreError::TooManyAttempts)
    );

    // Bob's budget is his own, and a success clears it.
    let (attempt, code) = issue(&bob).await;
    for _ in 0..4 {
        let _ = store.redeem_code(&bob, &attempt, &wrong(&code)).await;
    }
    store.redeem_code(&bob, &attempt, &code).await.unwrap();
    let (attempt, code) = issue(&bob).await;
    assert_eq!(
        store.redeem_code(&bob, &attempt, &wrong(&code)).await,
        Err(TwoFaCodeStoreError::Invalid2FACode)
    );
    store.redeem_code(&bob, &attempt, &code).await.unwrap();

    // Deleting a pending code; deleting none is reported.
    issue(&bob).await;
    store.delete(&bob).await.unwrap();
    assert_eq!(
        store.delete(&bob).await,
        Err(TwoFaCodeStoreError::UserNotFound)
    );
}

/// [`UserStore`](tempered_core::UserStore): one account per address,
/// password checks, and `UserNotFound` from every update of a missing
/// account.
pub async fn user_store(store: impl tempered_core::UserStore) {
    use tempered_core::{Password, User, UserStoreError, ValidatedUser};

    let password = |p: &str| Password::try_from(Secret::new(p.to_string())).unwrap();
    let alice = email("alice@example.com");
    let nobody = email("nobody@example.com");

    store
        .add_user(User::new(alice.clone(), password("alices-password"), false))
        .await
        .unwrap();
    assert_eq!(
        store
            .add_user(User::new(alice.clone(), password("another-password"), true))
            .await,
        Err(UserStoreError::UserAlreadyExists)
    );
    assert_eq!(
        store
            .authenticate_user(&alice, &password("alices-password"))
            .await,
        Ok(ValidatedUser::No2Fa(alice.clone()))
    );
    assert!(
        store
            .authenticate_user(&alice, &password("wrong-password"))
            .await
            .is_err()
    );
    assert!(
        store
            .authenticate_user(&nobody, &password("alices-password"))
            .await
            .is_err()
    );

    // Updates change only what they say.
    store
        .set_new_password(&alice, password("a-new-password"))
        .await
        .unwrap();
    store.set_requires_2fa(&alice, true).await.unwrap();
    assert_eq!(
        store
            .authenticate_user(&alice, &password("a-new-password"))
            .await,
        Ok(ValidatedUser::Requires2Fa(alice.clone()))
    );
    assert!(
        store
            .authenticate_user(&alice, &password("alices-password"))
            .await
            .is_err()
    );

    // A missing account is reported, never silently "updated".
    assert_eq!(
        store
            .set_new_password(&nobody, password("a-new-password"))
            .await,
        Err(UserStoreError::UserNotFound)
    );
    assert_eq!(
        store.set_requires_2fa(&nobody, true).await,
        Err(UserStoreError::UserNotFound)
    );
    assert_eq!(
        store.delete_user(&nobody).await,
        Err(UserStoreError::UserNotFound)
    );

    store.delete_user(&alice).await.unwrap();
    assert_eq!(
        store.get_user(&alice).await.map(|_| ()),
        Err(UserStoreError::UserNotFound)
    );
    assert_eq!(
        store
            .set_new_password(&alice, password("a-new-password"))
            .await,
        Err(UserStoreError::UserNotFound)
    );

    // An email change keeps the account (password and all), and refuses a
    // taken address.
    let moved = email("alice@moved.example.com");
    let taken = email("taken@example.com");
    store
        .add_user(User::new(
            taken.clone(),
            password("someone-elses-pw"),
            false,
        ))
        .await
        .unwrap();
    store
        .add_user(User::new(
            email("carol@example.com"),
            password("carols-password"),
            false,
        ))
        .await
        .unwrap();
    let carol = email("carol@example.com");
    assert_eq!(
        store.change_email(&carol, &taken).await,
        Err(UserStoreError::UserAlreadyExists)
    );
    assert_eq!(
        store.change_email(&nobody, &moved).await,
        Err(UserStoreError::UserNotFound)
    );
    let carols_id = store.get_user(&carol).await.unwrap().id;
    store.change_email(&carol, &moved).await.unwrap();
    assert!(store.get_user(&carol).await.is_err());
    // The id stays with the account, and finds it at its new address.
    assert_eq!(store.get_user(&moved).await.unwrap().id, carols_id);
    assert_eq!(store.get_user_by_id(&carols_id).await.unwrap().email, moved);
    assert_eq!(
        store
            .get_user_by_id(&tempered_core::UserId::new())
            .await
            .unwrap_err(),
        UserStoreError::UserNotFound
    );
    assert!(
        store
            .authenticate_user(&moved, &password("carols-password"))
            .await
            .is_ok()
    );
}

/// [`PasswordResetTokenStore`]: single-use tokens, and dropping every token
/// of one address.
pub async fn password_reset_token_store(store: impl tempered_core::PasswordResetTokenStore) {
    use tempered_core::{PasswordResetToken, PasswordResetTokenStoreError};

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");

    let token = PasswordResetToken::new();
    store
        .store_token(token.clone(), alice.clone())
        .await
        .unwrap();
    assert_eq!(store.get_email_for_token(&token).await.unwrap(), alice);
    assert_eq!(store.consume_token(&token).await.unwrap(), alice);
    assert!(matches!(
        store.consume_token(&token).await,
        Err(PasswordResetTokenStoreError::TokenNotFound)
    ));
    assert!(matches!(
        store.get_email_for_token(&token).await,
        Err(PasswordResetTokenStoreError::TokenNotFound)
    ));

    let deleted = PasswordResetToken::new();
    store
        .store_token(deleted.clone(), alice.clone())
        .await
        .unwrap();
    store.delete_token(&deleted).await.unwrap();
    assert!(store.consume_token(&deleted).await.is_err());

    // Dropping Alice's tokens takes all of them, and none of Bob's.
    let first = PasswordResetToken::new();
    let second = PasswordResetToken::new();
    let bobs = PasswordResetToken::new();
    store
        .store_token(first.clone(), alice.clone())
        .await
        .unwrap();
    store
        .store_token(second.clone(), alice.clone())
        .await
        .unwrap();
    store.store_token(bobs.clone(), bob.clone()).await.unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    assert!(store.consume_token(&first).await.is_err());
    assert!(store.consume_token(&second).await.is_err());
    assert_eq!(store.consume_token(&bobs).await.unwrap(), bob);

    // A token stored after the purge works again.
    let later = PasswordResetToken::new();
    store
        .store_token(later.clone(), alice.clone())
        .await
        .unwrap();
    assert_eq!(store.consume_token(&later).await.unwrap(), alice);
}

/// [`OAuthIdentityStore`]: links never move between accounts, and one
/// account's links can be removed.
pub async fn oauth_identity_store(store: impl tempered_core::OAuthIdentityStore) {
    use tempered_core::OAuthIdentityStoreError;

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let link = |provider: &str, subject: &str, to: &Email| {
        store.link_identity(provider.to_string(), subject.to_string(), to.clone())
    };

    assert_eq!(store.find_email("google", "g-1").await.unwrap(), None);
    assert!(!store.has_identity_for_email(&alice).await.unwrap());

    link("google", "g-1", &alice).await.unwrap();
    link("google", "g-1", &alice).await.unwrap(); // idempotent
    assert_eq!(
        store.find_email("google", "g-1").await.unwrap(),
        Some(alice.clone())
    );
    assert!(store.has_identity_for_email(&alice).await.unwrap());
    // Same subject at another provider is another identity.
    assert_eq!(store.find_email("github", "g-1").await.unwrap(), None);

    assert!(matches!(
        link("google", "g-1", &bob).await,
        Err(OAuthIdentityStoreError::AlreadyLinked)
    ));
    assert_eq!(
        store.find_email("google", "g-1").await.unwrap(),
        Some(alice.clone())
    );

    link("github", "h-1", &alice).await.unwrap();
    link("github", "h-2", &bob).await.unwrap();
    store.unlink_all_for_email(&alice).await.unwrap();
    store.unlink_all_for_email(&alice).await.unwrap();
    assert!(!store.has_identity_for_email(&alice).await.unwrap());
    assert_eq!(store.find_email("google", "g-1").await.unwrap(), None);
    assert_eq!(store.find_email("github", "h-1").await.unwrap(), None);
    assert_eq!(
        store.find_email("github", "h-2").await.unwrap(),
        Some(bob.clone())
    );
    // Unlinked, the identity can be linked again (to a new account).
    link("google", "g-1", &bob).await.unwrap();

    // A user's links, and unlinking one provider.
    let mut listed = store.list_for_user(&bob).await.unwrap();
    listed.sort();
    assert_eq!(
        listed,
        [
            ("github".to_string(), "h-2".to_string()),
            ("google".to_string(), "g-1".to_string())
        ]
    );
    assert!(
        !store.unlink(&alice, "github").await.unwrap(),
        "not alice's"
    );
    assert!(store.unlink(&bob, "github").await.unwrap());
    assert!(!store.unlink(&bob, "github").await.unwrap());
    assert_eq!(store.find_email("github", "h-2").await.unwrap(), None);
    assert_eq!(
        store.find_email("google", "g-1").await.unwrap(),
        Some(bob.clone())
    );

    // An email change moves the links.
    let moved = email("bob@new.example.com");
    store.reassign(&bob, &moved).await.unwrap();
    assert_eq!(
        store.find_email("google", "g-1").await.unwrap(),
        Some(moved)
    );
}

/// [`PasskeyCredentialStore`]: insert-only ids, the sign-count rule, and
/// removing one owner's credentials.
pub async fn passkey_credential_store(store: impl tempered_core::PasskeyCredentialStore) {
    use tempered_core::{CredentialId, PasskeyCredential, PasskeyStoreError};

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let cred = |id: &str, owner: &Email, count: u32| PasskeyCredential {
        credential_id: CredentialId(id.to_string()),
        credential_data: vec![0, 1, 2, 255],
        sign_count: count,
        owner: owner.clone(),
        name: None,
    };
    let id = |s: &str| CredentialId(s.to_string());

    store.add_credential(cred("a1", &alice, 5)).await.unwrap();
    let found = store.get_credential(&id("a1")).await.unwrap();
    assert_eq!(found.owner, alice);
    assert_eq!(found.sign_count, 5);
    assert_eq!(found.credential_data, vec![0, 1, 2, 255]);
    assert!(matches!(
        store.get_credential(&id("nope")).await,
        Err(PasskeyStoreError::CredentialNotFound)
    ));

    // Insert-only, for any owner.
    assert!(matches!(
        store.add_credential(cred("a1", &bob, 0)).await,
        Err(PasskeyStoreError::CredentialAlreadyExists)
    ));
    assert_eq!(store.get_credential(&id("a1")).await.unwrap().owner, alice);

    // The counter must advance; data is replaced only when given.
    store
        .update_after_authentication(&id("a1"), 6, None)
        .await
        .unwrap();
    let found = store.get_credential(&id("a1")).await.unwrap();
    assert_eq!(found.sign_count, 6);
    assert_eq!(found.credential_data, vec![0, 1, 2, 255]);
    for stale in [6, 3] {
        assert!(matches!(
            store
                .update_after_authentication(&id("a1"), stale, Some(vec![9]))
                .await,
            Err(PasskeyStoreError::SignCountNotAdvanced)
        ));
    }
    store
        .update_after_authentication(&id("a1"), 7, Some(vec![7, 7]))
        .await
        .unwrap();
    let found = store.get_credential(&id("a1")).await.unwrap();
    assert_eq!((found.sign_count, found.credential_data), (7, vec![7, 7]));
    assert!(matches!(
        store
            .update_after_authentication(&id("nope"), 1, None)
            .await,
        Err(PasskeyStoreError::CredentialNotFound)
    ));

    // No counter at all: 0 stays 0.
    store.add_credential(cred("a0", &alice, 0)).await.unwrap();
    store
        .update_after_authentication(&id("a0"), 0, None)
        .await
        .unwrap();
    // A large counter survives the round trip.
    store
        .update_after_authentication(&id("a0"), u32::MAX, None)
        .await
        .unwrap();
    assert_eq!(
        store.get_credential(&id("a0")).await.unwrap().sign_count,
        u32::MAX
    );

    store.add_credential(cred("b1", &bob, 0)).await.unwrap();
    let mut alices: Vec<String> = store
        .list_for_user(&alice)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.credential_id.0)
        .collect();
    alices.sort();
    assert_eq!(alices, ["a0", "a1"]);

    store.delete_all_for_user(&alice).await.unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    assert!(store.list_for_user(&alice).await.unwrap().is_empty());
    assert!(store.get_credential(&id("a1")).await.is_err());
    assert_eq!(store.get_credential(&id("b1")).await.unwrap().owner, bob);

    // Rename and delete, owner-scoped.
    assert!(
        !store
            .rename_credential(&alice, &id("b1"), Some("x".into()))
            .await
            .unwrap()
    );
    assert!(
        store
            .rename_credential(&bob, &id("b1"), Some("phone".into()))
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_credential(&id("b1"))
            .await
            .unwrap()
            .name
            .as_deref(),
        Some("phone")
    );
    assert!(!store.delete_credential(&alice, &id("b1")).await.unwrap());
    assert!(store.delete_credential(&bob, &id("b1")).await.unwrap());
    assert!(store.get_credential(&id("b1")).await.is_err());

    // An email change moves the credentials.
    store.add_credential(cred("c1", &alice, 0)).await.unwrap();
    let moved = email("alice@new.example.com");
    store.reassign(&alice, &moved).await.unwrap();
    assert!(store.list_for_user(&alice).await.unwrap().is_empty());
    assert_eq!(store.get_credential(&id("c1")).await.unwrap().owner, moved);
}

/// [`ApiKeyStore`]: lookup by prefix, per-owner listing, revocation.
pub async fn api_key_store(store: impl tempered_core::ApiKeyStore) {
    use tempered_core::{ApiKeyId, ApiKeyRecord, ApiKeyStoreError};

    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let record = |prefix: &str, owner: &Email, scopes: &[&str]| ApiKeyRecord {
        id: ApiKeyId::new(),
        prefix: prefix.to_string(),
        secret_hash: format!("hash-of-{prefix}"),
        owner: owner.clone(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        created_at: 1000,
        expires_at: Some(5000),
        last_used_at: None,
    };

    let a1 = record("pa1", &alice, &["read", "write"]);
    let a2 = record("pa2", &alice, &[]);
    let b1 = record("pb1", &bob, &["read"]);
    for r in [&a1, &a2, &b1] {
        store.create_key(r.clone()).await.unwrap();
    }

    let found = store.find_by_prefix("pa1").await.unwrap();
    assert_eq!(found.id, a1.id);
    assert_eq!(found.secret_hash, "hash-of-pa1");
    assert_eq!(found.owner, alice);
    assert_eq!(found.scopes, ["read", "write"]);
    assert!(matches!(
        store.find_by_prefix("nope").await,
        Err(ApiKeyStoreError::NotFound)
    ));

    let mut listed: Vec<String> = store
        .list_for_user(&alice)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.prefix)
        .collect();
    listed.sort();
    assert_eq!(listed, ["pa1", "pa2"]);

    // A prefix is never reused: the second record is refused, the first kept.
    assert!(matches!(
        store.create_key(record("pa1", &bob, &[])).await,
        Err(ApiKeyStoreError::PrefixTaken)
    ));
    assert_eq!(store.find_by_prefix("pa1").await.unwrap().owner, alice);

    // Only the owner revokes a key; anyone else is told it does not exist.
    assert!(matches!(
        store.revoke_key(&bob, &a1.id).await,
        Err(ApiKeyStoreError::NotFound)
    ));
    assert!(store.find_by_prefix("pa1").await.is_ok());
    store.revoke_key(&alice, &a1.id).await.unwrap();
    assert!(store.find_by_prefix("pa1").await.is_err());
    assert!(matches!(
        store.revoke_key(&alice, &a1.id).await,
        Err(ApiKeyStoreError::NotFound)
    ));
    assert_eq!(store.list_for_user(&alice).await.unwrap().len(), 1);
    assert_eq!(store.find_by_prefix("pb1").await.unwrap().owner, bob);

    // Deleting an owner's keys takes all of theirs and none of Bob's.
    store.create_key(record("pa3", &alice, &[])).await.unwrap();
    store.delete_all_for_owner(&alice).await.unwrap();
    store.delete_all_for_owner(&alice).await.unwrap();
    assert!(store.list_for_user(&alice).await.unwrap().is_empty());
    assert!(store.find_by_prefix("pa2").await.is_err());
    assert_eq!(store.find_by_prefix("pb1").await.unwrap().owner, bob);

    // Times survive the round trip, and a use is recorded.
    let found = store.find_by_prefix("pb1").await.unwrap();
    assert_eq!(
        (found.created_at, found.expires_at, found.last_used_at),
        (1000, Some(5000), None)
    );
    store.record_use(&found.id, 2000).await.unwrap();
    assert_eq!(
        store.find_by_prefix("pb1").await.unwrap().last_used_at,
        Some(2000)
    );
    let listed = store.list_for_user(&bob).await.unwrap();
    assert_eq!(listed[0].last_used_at, Some(2000));

    // An email change moves the keys.
    let moved = email("bob@new.example.com");
    store.reassign(&bob, &moved).await.unwrap();
    assert!(store.list_for_user(&bob).await.unwrap().is_empty());
    assert_eq!(store.find_by_prefix("pb1").await.unwrap().owner, moved);
}

/// Hits count up within a window, keys are separate, and a window ends.
pub async fn rate_limit_store(store: impl tempered_core::RateLimitStore) {
    let first = store.hit("login:a@example.com", 60).await.unwrap();
    assert_eq!(first.count, 1);
    assert!((1..=60).contains(&first.resets_in_seconds));
    assert_eq!(store.hit("login:a@example.com", 60).await.unwrap().count, 2);
    // Another key starts at one.
    assert_eq!(store.hit("login:b@example.com", 60).await.unwrap().count, 1);

    // Concurrent hits are all counted, each once.
    let (a, b, c, d, e) = tokio::join!(
        store.hit("burst", 60),
        store.hit("burst", 60),
        store.hit("burst", 60),
        store.hit("burst", 60),
        store.hit("burst", 60),
    );
    let mut counts = [a, b, c, d, e].map(|r| r.unwrap().count);
    counts.sort_unstable();
    assert_eq!(counts, [1, 2, 3, 4, 5]);

    // A window ends, and the count starts again.
    store.hit("short", 1).await.unwrap();
    store.hit("short", 1).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(store.hit("short", 1).await.unwrap().count, 1);
}

/// Pending and active secrets, single-use steps and recovery codes.
pub async fn totp_store(store: impl tempered_core::TotpStore) {
    use secrecy::{ExposeSecret, Secret};
    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let secret = |b: u8| Secret::new(vec![b; 20]);
    let code = |b: u8| [b; 32];

    // Nothing to start with; activating without a pending secret does nothing.
    assert!(store.active(&alice).await.unwrap().is_none());
    assert!(!store.activate(&alice, 1, vec![]).await.unwrap());
    assert!(
        !store.use_step(&alice, 1).await.unwrap(),
        "no active secret"
    );

    // Pending is not active until activated.
    store.set_pending(&alice, secret(1)).await.unwrap();
    assert_eq!(
        store
            .pending(&alice)
            .await
            .unwrap()
            .unwrap()
            .expose_secret(),
        &vec![1; 20]
    );
    assert!(store.active(&alice).await.unwrap().is_none());
    assert!(
        store
            .activate(&alice, 100, vec![code(1), code(2)])
            .await
            .unwrap()
    );
    assert_eq!(
        store.active(&alice).await.unwrap().unwrap().expose_secret(),
        &vec![1; 20]
    );
    assert!(store.pending(&alice).await.unwrap().is_none());

    // Steps move forward only; the activation step is used.
    assert!(!store.use_step(&alice, 100).await.unwrap());
    assert!(store.use_step(&alice, 101).await.unwrap());
    assert!(!store.use_step(&alice, 101).await.unwrap(), "replay");
    assert!(!store.use_step(&alice, 99).await.unwrap(), "earlier step");

    // A new pending secret leaves the active one working.
    store.set_pending(&alice, secret(2)).await.unwrap();
    assert_eq!(
        store.active(&alice).await.unwrap().unwrap().expose_secret(),
        &vec![1; 20]
    );

    // Recovery codes work once each, and only for their owner.
    assert!(!store.use_recovery_code(&bob, &code(1)).await.unwrap());
    assert!(store.use_recovery_code(&alice, &code(1)).await.unwrap());
    assert!(!store.use_recovery_code(&alice, &code(1)).await.unwrap());
    store
        .replace_recovery_codes(&alice, vec![code(3)])
        .await
        .unwrap();
    assert!(
        !store.use_recovery_code(&alice, &code(2)).await.unwrap(),
        "replaced"
    );
    assert!(store.use_recovery_code(&alice, &code(3)).await.unwrap());

    // Deleting forgets everything, and is idempotent.
    store.set_pending(&bob, secret(9)).await.unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    store.delete_all_for_user(&alice).await.unwrap();
    assert!(store.active(&alice).await.unwrap().is_none());
    assert!(store.pending(&alice).await.unwrap().is_none());
    assert!(
        store.pending(&bob).await.unwrap().is_some(),
        "other users untouched"
    );

    // An email change moves the secrets.
    let moved = email("bob@new.example.com");
    store.reassign(&bob, &moved).await.unwrap();
    assert!(store.pending(&bob).await.unwrap().is_none());
    assert!(store.pending(&moved).await.unwrap().is_some());
}

/// Single use, reuse revoking the family, logout and revoke-all, expiry.
pub async fn refresh_token_store(store: impl tempered_core::RefreshTokenStore) {
    use tempered_core::{RefreshRecord, RefreshTokenStoreError};
    let alice = email("alice@example.com");
    let bob = email("bob@example.com");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let record = |who: &Email, family: &str| RefreshRecord {
        email: who.clone(),
        family: family.to_string(),
        expires_at: now + 600,
    };

    // Used once.
    store.create([1; 32], record(&alice, "f1")).await.unwrap();
    assert_eq!(store.redeem(&[1; 32]).await.unwrap(), record(&alice, "f1"));
    assert!(matches!(
        store.redeem(&[9; 32]).await,
        Err(RefreshTokenStoreError::NotFound)
    ));

    // Its successor in the family works, until the old one is presented
    // again: that revokes the family, successor included.
    store.create([2; 32], record(&alice, "f1")).await.unwrap();
    store.create([3; 32], record(&alice, "f2")).await.unwrap();
    assert!(matches!(
        store.redeem(&[1; 32]).await,
        Err(RefreshTokenStoreError::Reused { email }) if email == alice
    ));
    assert!(matches!(
        store.redeem(&[2; 32]).await,
        Err(RefreshTokenStoreError::NotFound)
    ));
    // Another family of the same user is untouched.
    assert!(store.redeem(&[3; 32]).await.is_ok());

    // Logout revokes one family.
    store.create([4; 32], record(&alice, "f3")).await.unwrap();
    store.revoke_family("f3").await.unwrap();
    store.revoke_family("never-issued").await.unwrap();
    assert!(store.redeem(&[4; 32]).await.is_err());
    // A rotation in flight at the revocation cannot bring the family back.
    assert!(matches!(
        store.create([11; 32], record(&alice, "f3")).await,
        Err(RefreshTokenStoreError::NotFound)
    ));
    assert!(store.redeem(&[11; 32]).await.is_err());

    // Revoke-all takes every family of one user, and only theirs.
    store.create([5; 32], record(&alice, "f4")).await.unwrap();
    store.create([6; 32], record(&alice, "f5")).await.unwrap();
    store.create([7; 32], record(&bob, "f6")).await.unwrap();
    store.revoke_all_for_user(&alice).await.unwrap();
    assert!(store.redeem(&[5; 32]).await.is_err());
    assert!(store.redeem(&[6; 32]).await.is_err());
    assert!(store.redeem(&[7; 32]).await.is_ok());
    assert!(
        store.create([12; 32], record(&alice, "f4")).await.is_err(),
        "revoked by revoke-all"
    );

    // An expired token is refused.
    let expired = RefreshRecord {
        expires_at: now - 1,
        ..record(&bob, "f7")
    };
    store.create([10; 32], expired).await.unwrap();
    assert!(matches!(
        store.redeem(&[10; 32]).await,
        Err(RefreshTokenStoreError::NotFound)
    ));
}

/// Single use, one pending change per account, expiry.
pub async fn email_change_store(store: impl tempered_core::EmailChangeStore) {
    use tempered_core::EmailChangeStoreError;
    let alice = email("alice@example.com");
    let new = email("alice@new.example.com");
    store
        .create([1; 32], alice.clone(), new.clone(), 600)
        .await
        .unwrap();
    // Peeking does not use it.
    for _ in 0..2 {
        assert_eq!(
            store.peek(&[1; 32]).await.unwrap(),
            (alice.clone(), new.clone())
        );
    }
    assert_eq!(
        store.consume(&[1; 32]).await.unwrap(),
        (alice.clone(), new.clone())
    );
    assert!(matches!(
        store.consume(&[1; 32]).await,
        Err(EmailChangeStoreError::NotFound)
    ));

    // A newer request for the account replaces the older one.
    store
        .create([2; 32], alice.clone(), email("first@example.com"), 600)
        .await
        .unwrap();
    store
        .create([3; 32], alice.clone(), email("second@example.com"), 600)
        .await
        .unwrap();
    assert!(store.consume(&[2; 32]).await.is_err());
    assert_eq!(
        store.consume(&[3; 32]).await.unwrap().1,
        email("second@example.com")
    );

    // Expired.
    store
        .create([4; 32], alice.clone(), new.clone(), 1)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(store.consume(&[4; 32]).await.is_err());
}
