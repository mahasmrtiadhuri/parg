use ed25519_dalek::SigningKey;
use ledger_service::{Error, Fault, Ledger};
use parg_protocol::*;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::sync::{Barrier, OnceCell};
use uuid::Uuid;
static SCHEMA: OnceCell<()> = OnceCell::const_new();
struct Fixture {
    ledger: Ledger,
    key: SigningKey,
    intent: Intent,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("PARG_TEST_DATABASE_URL").expect("Set PARG_TEST_DATABASE_URL to a disposable PostgreSQL database; integration tests never silently skip");
        let pool = PgPoolOptions::new()
            .max_connections(24)
            .connect(&url)
            .await
            .unwrap();
        SCHEMA
            .get_or_init(|| async {
                sqlx::raw_sql(include_str!("../schema.sql"))
                    .execute(&pool)
                    .await
                    .unwrap();
            })
            .await;
        let key = SigningKey::from_bytes(&[7; 32]);
        let now = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let ledger = Ledger::new(
            pool,
            Uuid::from_u128(77),
            vec![KeyEpoch {
                epoch_id: 1,
                public_key: hex::encode(key.verifying_key().as_bytes()),
                valid_from: now - 3600,
                valid_until: now + 3600,
            }],
        )
        .unwrap();
        let intent = Intent {
            op_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            target_service_id: ledger.target,
            source_account_id: Uuid::new_v4(),
            dest_account_id: Uuid::new_v4(),
            amount_units: 100,
        };
        ledger
            .seed(
                intent.principal_id,
                intent.source_account_id,
                intent.dest_account_id,
            )
            .await
            .unwrap();
        Self {
            ledger,
            key,
            intent,
        }
    }
    async fn signed(&self, i: &Intent) -> Commit {
        let ch = self.ledger.challenge(i, i.principal_id, 60).await.unwrap();
        let request = Authorize {
            intent: i.clone(),
            nonce: ch.nonce,
        };
        let s = self.ledger.snapshot(&request).await.unwrap();
        let payload = s.authorize(&request, 1).unwrap();
        Commit {
            intent: i.clone(),
            receipt: Receipt::sign(payload, &self.key).unwrap(),
        }
    }
    async fn balance(&self, id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT balance FROM accounts WHERE account_id=$1")
            .bind(id)
            .fetch_one(&self.ledger.pool)
            .await
            .unwrap()
    }
}
#[tokio::test]
async fn happy_path_and_exact_retry() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    let a = f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    let b = f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    assert_eq!(a, b);
    assert_eq!((a.source_balance, a.dest_balance), (9900, 10100));
    assert_eq!(f.balance(f.intent.source_account_id).await, 9900);
}
#[tokio::test]
async fn tampered_amount_and_destination_fail() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    let mut bad = c.clone();
    bad.intent.amount_units += 1;
    assert!(matches!(
        f.ledger.commit(&bad, f.intent.principal_id).await,
        Err(Error::Signature)
    ));
    bad = c;
    bad.receipt.payload.intent.dest_account_id = Uuid::new_v4();
    assert!(matches!(
        f.ledger.commit(&bad, f.intent.principal_id).await,
        Err(Error::Signature)
    ));
    assert_eq!(f.balance(f.intent.source_account_id).await, 10000);
}
#[tokio::test]
async fn stale_unspent_receipt_rejected_and_reauthorized() {
    let f = Fixture::new().await;
    let stale = f.signed(&f.intent).await;
    let mut other = f.intent.clone();
    other.op_id = Uuid::new_v4();
    let other = f.signed(&other).await;
    f.ledger
        .commit(&other, f.intent.principal_id)
        .await
        .unwrap();
    assert!(matches!(
        f.ledger.commit(&stale, f.intent.principal_id).await,
        Err(Error::Stale)
    ));
    let fresh = f.signed(&f.intent).await;
    f.ledger
        .commit(&fresh, f.intent.principal_id)
        .await
        .unwrap();
    assert_eq!(f.balance(f.intent.source_account_id).await, 9800);
}
#[tokio::test]
async fn reauthorization_after_unknown_commit_returns_cached() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    let first = f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    let renewed = f.signed(&f.intent).await;
    assert_ne!(
        c.receipt.payload.digest().unwrap(),
        renewed.receipt.payload.digest().unwrap()
    );
    assert_eq!(
        first,
        f.ledger
            .commit(&renewed, f.intent.principal_id)
            .await
            .unwrap()
    );
}
#[tokio::test]
async fn conflicting_operation_id_rejected() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    let mut changed = f.intent.clone();
    changed.amount_units += 1;
    let signed = f.signed(&changed).await;
    assert!(matches!(
        f.ledger.commit(&signed, f.intent.principal_id).await,
        Err(Error::Conflict)
    ));
}
#[tokio::test]
async fn sixteen_concurrent_exact_retries_debit_once() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = vec![];
    for _ in 0..16 {
        let l = f.ledger.clone();
        let c = c.clone();
        let b = barrier.clone();
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            l.commit(&c, c.intent.principal_id).await.unwrap()
        }));
    }
    let mut outcomes = vec![];
    for t in tasks {
        outcomes.push(t.await.unwrap());
    }
    assert!(outcomes.iter().all(|o| o == &outcomes[0]));
    assert_eq!(f.balance(f.intent.source_account_id).await, 9900);
}
#[tokio::test]
async fn independent_resources_both_commit() {
    let a = Fixture::new().await;
    let b = Fixture::new().await;
    let ac = a.signed(&a.intent).await;
    let bc = b.signed(&b.intent).await;
    let (x, y) = tokio::join!(
        a.ledger.commit(&ac, a.intent.principal_id),
        b.ledger.commit(&bc, b.intent.principal_id)
    );
    assert!(x.is_ok() && y.is_ok());
}
#[tokio::test]
async fn opposite_transfers_one_commit_one_stale() {
    let f = Fixture::new().await;
    let a = f.signed(&f.intent).await;
    let mut reverse = f.intent.clone();
    reverse.op_id = Uuid::new_v4();
    std::mem::swap(&mut reverse.source_account_id, &mut reverse.dest_account_id);
    let b = f.signed(&reverse).await;
    let (x, y) = tokio::join!(
        f.ledger.commit(&a, f.intent.principal_id),
        f.ledger.commit(&b, f.intent.principal_id)
    );
    assert!(matches!(
        (&x, &y),
        (Ok(_), Err(Error::Stale)) | (Err(Error::Stale), Ok(_))
    ));
    assert_eq!(
        f.balance(f.intent.source_account_id).await + f.balance(f.intent.dest_account_id).await,
        20000
    );
}
#[tokio::test]
async fn shared_principal_limit_serializes_disjoint_accounts() {
    let f = Fixture::new().await;
    let mut i = f.intent.clone();
    i.op_id = Uuid::new_v4();
    i.source_account_id = Uuid::new_v4();
    i.dest_account_id = Uuid::new_v4();
    f.ledger
        .seed(i.principal_id, i.source_account_id, i.dest_account_id)
        .await
        .unwrap();
    let a = f.signed(&f.intent).await;
    let b = f.signed(&i).await;
    let (x, y) = tokio::join!(
        f.ledger.commit(&a, i.principal_id),
        f.ledger.commit(&b, i.principal_id)
    );
    assert!(matches!(
        (&x, &y),
        (Ok(_), Err(Error::Stale)) | (Err(Error::Stale), Ok(_))
    ));
}
#[tokio::test]
async fn rollback_restores_all_state_at_both_failpoints() {
    for fault in [Fault::AfterDebit, Fault::BeforeCommit] {
        let f = Fixture::new().await;
        let c = f.signed(&f.intent).await;
        assert!(matches!(
            f.ledger
                .commit_with_fault(&c, f.intent.principal_id, fault)
                .await,
            Err(Error::Injected)
        ));
        assert_eq!(f.balance(f.intent.source_account_id).await, 10000);
        assert_eq!(f.balance(f.intent.dest_account_id).await, 10000);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE op_id=$1")
            .bind(f.intent.op_id)
            .fetch_one(&f.ledger.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    }
}
#[tokio::test]
async fn forged_signature_and_wrong_target_fail() {
    let f = Fixture::new().await;
    let mut c = f.signed(&f.intent).await;
    c.receipt =
        Receipt::sign(c.receipt.payload.clone(), &SigningKey::from_bytes(&[9; 32])).unwrap();
    assert!(matches!(
        f.ledger.commit(&c, f.intent.principal_id).await,
        Err(Error::Signature)
    ));
    let mut i = f.intent.clone();
    i.target_service_id = Uuid::new_v4();
    assert!(matches!(
        f.ledger.challenge(&i, i.principal_id, 60).await,
        Err(Error::Unauthorized)
    ));
}
#[tokio::test]
async fn wrong_principal_cannot_read_cached_result() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    assert!(matches!(
        f.ledger.commit(&c, Uuid::new_v4()).await,
        Err(Error::Unauthorized)
    ));
}
#[tokio::test]
async fn expired_epoch_is_rejected() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    let old = Ledger::new(
        f.ledger.pool.clone(),
        f.ledger.target,
        vec![KeyEpoch {
            epoch_id: 1,
            public_key: hex::encode(f.key.verifying_key().as_bytes()),
            valid_from: 0,
            valid_until: 1,
        }],
    )
    .unwrap();
    assert!(matches!(
        old.commit(&c, f.intent.principal_id).await,
        Err(Error::Signature)
    ));
}
#[tokio::test]
async fn key_rotation_accepts_overlap_and_rejects_unknown() {
    let f = Fixture::new().await;
    let key2 = SigningKey::from_bytes(&[8; 32]);
    let now = f.ledger.now().await.unwrap();
    let epochs = vec![
        KeyEpoch {
            epoch_id: 1,
            public_key: hex::encode(f.key.verifying_key().as_bytes()),
            valid_from: 0,
            valid_until: now + 60,
        },
        KeyEpoch {
            epoch_id: 2,
            public_key: hex::encode(key2.verifying_key().as_bytes()),
            valid_from: now - 1,
            valid_until: now + 3600,
        },
    ];
    let l = Ledger::new(f.ledger.pool.clone(), f.ledger.target, epochs).unwrap();
    let mut c = f.signed(&f.intent).await;
    c.receipt.payload.epoch_id = 2;
    c.receipt = Receipt::sign(c.receipt.payload, &key2).unwrap();
    l.commit(&c, f.intent.principal_id).await.unwrap();
    let mut i = f.intent.clone();
    i.op_id = Uuid::new_v4();
    let mut unknown = f.signed(&i).await;
    unknown.receipt.payload.epoch_id = 3;
    unknown.receipt = Receipt::sign(unknown.receipt.payload, &key2).unwrap();
    assert!(matches!(
        l.commit(&unknown, i.principal_id).await,
        Err(Error::Signature)
    ));
}
#[tokio::test]
async fn process_restart_preserves_replay_protection() {
    let f = Fixture::new().await;
    let c = f.signed(&f.intent).await;
    let first = f.ledger.commit(&c, f.intent.principal_id).await.unwrap();
    let reopened = PgPoolOptions::new()
        .connect(&std::env::var("PARG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let now = f.ledger.now().await.unwrap();
    let l = Ledger::new(
        reopened,
        f.ledger.target,
        vec![KeyEpoch {
            epoch_id: 1,
            public_key: hex::encode(f.key.verifying_key().as_bytes()),
            valid_from: 0,
            valid_until: now + 3600,
        }],
    )
    .unwrap();
    assert_eq!(first, l.commit(&c, f.intent.principal_id).await.unwrap());
}
#[tokio::test]
async fn over_limit_policy_and_ledger_both_deny() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE policy_limits SET max_daily=50,version=version+1 WHERE principal_id=$1")
        .bind(f.intent.principal_id)
        .execute(&f.ledger.pool)
        .await
        .unwrap();
    let ch = f
        .ledger
        .challenge(&f.intent, f.intent.principal_id, 60)
        .await
        .unwrap();
    let a = Authorize {
        intent: f.intent.clone(),
        nonce: ch.nonce.clone(),
    };
    let s = f.ledger.snapshot(&a).await.unwrap();
    assert!(s.authorize(&a, 1).is_err());
    let p = ReceiptPayload {
        epoch_id: 1,
        policy_version: 1,
        challenge: ch,
        intent: f.intent.clone(),
    };
    let c = Commit {
        intent: f.intent.clone(),
        receipt: Receipt::sign(p, &f.key).unwrap(),
    };
    assert!(matches!(
        f.ledger.commit(&c, f.intent.principal_id).await,
        Err(Error::Denied)
    ));
}
#[tokio::test]
async fn expiry_checked_after_waiting_for_account_lock() {
    let f = Fixture::new().await;
    let mut ch = f
        .ledger
        .challenge(&f.intent, f.intent.principal_id, 60)
        .await
        .unwrap();
    let now = f.ledger.now().await.unwrap();
    ch.expiry = now + 1;
    sqlx::query("UPDATE issued_challenges SET payload=$2 WHERE nonce=$1")
        .bind(&ch.nonce)
        .bind(serde_json::to_value(&ch).unwrap())
        .execute(&f.ledger.pool)
        .await
        .unwrap();
    let c = Commit {
        intent: f.intent.clone(),
        receipt: Receipt::sign(
            ReceiptPayload {
                epoch_id: 1,
                policy_version: 1,
                challenge: ch,
                intent: f.intent.clone(),
            },
            &f.key,
        )
        .unwrap(),
    };
    let mut blocker = f.ledger.pool.begin().await.unwrap();
    sqlx::query("SELECT account_id FROM accounts WHERE account_id=$1 FOR UPDATE")
        .bind(f.intent.source_account_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let l = f.ledger.clone();
    let task = tokio::spawn(async move { l.commit(&c, c.intent.principal_id).await });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Expired)));
}
