//! Authoritative PostgreSQL ledger. Every mutator uses operation -> accounts -> limit -> challenge lock order.
use parg_protocol::*;
use rand::RngCore;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Unauthorized,
    Signature,
    Expired,
    Stale,
    Conflict,
    Denied,
    Storage(sqlx::Error),
    Injected,
}
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Storage(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}
impl std::error::Error for Error {}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Signature => "invalid_receipt",
            Self::Expired => "expired_receipt",
            Self::Stale => "stale_state",
            Self::Conflict => "operation_conflict",
            Self::Denied => "policy_denied",
            Self::Storage(_) => "storage_unavailable",
            Self::Injected => "injected_failure",
        }
    }
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone)]
pub struct Ledger {
    pub pool: PgPool,
    pub target: Uuid,
    keys: Vec<KeyEpoch>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    AfterDebit,
    BeforeCommit,
}

impl Ledger {
    pub fn new(
        pool: PgPool,
        target: Uuid,
        keys: Vec<KeyEpoch>,
    ) -> std::result::Result<Self, &'static str> {
        let mut ids = HashSet::new();
        if keys.is_empty() {
            return Err("empty trusted keyring");
        }
        for k in &keys {
            k.key()?;
            if k.valid_from >= k.valid_until || !ids.insert(k.epoch_id) {
                return Err("invalid or duplicate key epoch");
            }
        }
        Ok(Self { pool, target, keys })
    }
    pub async fn migrate(&self) -> Result<()> {
        sqlx::raw_sql(include_str!("../schema.sql"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn now(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await?,
        )
    }
    pub async fn seed(&self, principal: Uuid, source: Uuid, dest: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for id in [source, dest] {
            sqlx::query("INSERT INTO accounts(account_id,owner_id,balance) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(id).bind(principal).bind(10_000i64).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO policy_limits(principal_id,max_daily,window_day) VALUES($1,50000,$2) ON CONFLICT DO NOTHING").bind(principal).bind(self.now().await?.div_euclid(86400)).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    fn validate(&self, i: &Intent, principal: Uuid) -> Result<()> {
        i.validate().map_err(Error::Invalid)?;
        if i.principal_id != principal || i.target_service_id != self.target {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    async fn resources(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        i: &Intent,
    ) -> Result<(
        sqlx::postgres::PgRow,
        sqlx::postgres::PgRow,
        sqlx::postgres::PgRow,
    )> {
        let (lo, hi) = if i.source_account_id < i.dest_account_id {
            (i.source_account_id, i.dest_account_id)
        } else {
            (i.dest_account_id, i.source_account_id)
        };
        let a = sqlx::query("SELECT * FROM accounts WHERE account_id=$1 FOR UPDATE")
            .bind(lo)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(Error::Denied)?;
        let b = sqlx::query("SELECT * FROM accounts WHERE account_id=$1 FOR UPDATE")
            .bind(hi)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(Error::Denied)?;
        let limit = sqlx::query("SELECT * FROM policy_limits WHERE principal_id=$1 FOR UPDATE")
            .bind(i.principal_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(Error::Denied)?;
        let (src, dst) = if lo == i.source_account_id {
            (a, b)
        } else {
            (b, a)
        };
        if src.get::<Uuid, _>("owner_id") != i.principal_id {
            return Err(Error::Unauthorized);
        }
        Ok((src, dst, limit))
    }
    pub async fn challenge(&self, i: &Intent, principal: Uuid, ttl: i64) -> Result<Challenge> {
        self.validate(i, principal)?;
        if !(1..=300).contains(&ttl) {
            return Err(Error::Invalid("TTL must be 1..300 seconds"));
        }
        let mut tx = self.pool.begin().await?;
        let (src, dst, mut limit) = self.resources(&mut tx, i).await?;
        let now = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
        )
        .fetch_one(&mut *tx)
        .await?;
        if limit.get::<i64, _>("window_day") != now.div_euclid(86400) {
            limit=sqlx::query("UPDATE policy_limits SET spent=0,window_day=$2,version=version+1 WHERE principal_id=$1 RETURNING *").bind(principal).bind(now.div_euclid(86400)).fetch_one(&mut *tx).await?;
        }
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let c = Challenge {
            nonce: hex::encode(random),
            expiry: now + ttl,
            intent_digest: hex::encode(i.digest()),
            source_version: src.get::<i64, _>("version") as u64,
            dest_version: dst.get::<i64, _>("version") as u64,
            limit_version: limit.get::<i64, _>("version") as u64,
        };
        sqlx::query("INSERT INTO issued_challenges(nonce,principal_id,intent_digest,payload) VALUES($1,$2,$3,$4)").bind(&c.nonce).bind(principal).bind(&c.intent_digest).bind(serde_json::to_value(&c).map_err(|_|Error::Invalid("challenge encoding"))?).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(c)
    }
    /// Authenticated policy-core-only read; never accepts worker-supplied balances.
    pub async fn snapshot(&self, a: &Authorize) -> Result<Snapshot> {
        self.validate(&a.intent, a.intent.principal_id)?;
        let mut tx = self.pool.begin().await?;
        let (src, dst, limit) = self.resources(&mut tx, &a.intent).await?;
        let row = sqlx::query("SELECT * FROM issued_challenges WHERE nonce=$1")
            .bind(&a.nonce)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Denied)?;
        if row.get::<Uuid, _>("principal_id") != a.intent.principal_id
            || row.get::<String, _>("intent_digest") != hex::encode(a.intent.digest())
        {
            return Err(Error::Denied);
        }
        let c: Challenge = serde_json::from_value(row.get("payload"))
            .map_err(|_| Error::Invalid("stored challenge"))?;
        let now = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
        )
        .fetch_one(&mut *tx)
        .await?;
        let snapshot = Snapshot {
            challenge: c,
            source_balance: src.get::<i64, _>("balance") as u64,
            dest_balance: dst.get::<i64, _>("balance") as u64,
            spent: limit.get::<i64, _>("spent") as u64,
            daily_limit: limit.get::<i64, _>("max_daily") as u64,
            current_source_version: src.get::<i64, _>("version") as u64,
            current_dest_version: dst.get::<i64, _>("version") as u64,
            current_limit_version: limit.get::<i64, _>("version") as u64,
            window_day: limit.get("window_day"),
            now,
        };
        tx.commit().await?;
        Ok(snapshot)
    }
    pub async fn commit(&self, c: &Commit, principal: Uuid) -> Result<Outcome> {
        self.commit_with_fault(c, principal, Fault::None).await
    }
    /// Failure injection is a library test facility, never an HTTP route or environment switch.
    pub async fn commit_with_fault(
        &self,
        c: &Commit,
        principal: Uuid,
        fault: Fault,
    ) -> Result<Outcome> {
        self.validate(&c.intent, principal)?;
        if c.intent != c.receipt.payload.intent {
            return Err(Error::Signature);
        }
        let epoch = self
            .keys
            .iter()
            .find(|k| k.epoch_id == c.receipt.payload.epoch_id)
            .ok_or(Error::Signature)?;
        c.receipt
            .verify(&epoch.key().map_err(|_| Error::Signature)?)
            .map_err(|_| Error::Signature)?;
        let digest = hex::encode(c.intent.digest());
        let receipt_digest = hex::encode(c.receipt.payload.digest().map_err(Error::Invalid)?);
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='3s'")
            .execute(&mut *tx)
            .await?;
        // Unique insertion waits for concurrent claimants. Aborts remove both the claim and all mutations.
        let claim=sqlx::query("INSERT INTO operations(op_id,principal_id,intent_digest,receipt_digest) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING op_id").bind(c.intent.op_id).bind(principal).bind(&digest).bind(&receipt_digest).fetch_optional(&mut *tx).await?;
        if claim.is_none() {
            let row = sqlx::query(
                "SELECT principal_id,intent_digest,outcome FROM operations WHERE op_id=$1",
            )
            .bind(c.intent.op_id)
            .fetch_one(&mut *tx)
            .await?;
            if row.get::<Uuid, _>("principal_id") != principal
                || row.get::<String, _>("intent_digest") != digest
            {
                return Err(Error::Conflict);
            }
            let value: Option<serde_json::Value> = row.get("outcome");
            let outcome =
                serde_json::from_value(value.ok_or(Error::Invalid("incomplete operation"))?)
                    .map_err(|_| Error::Invalid("stored outcome"))?;
            tx.commit().await?;
            return Ok(outcome);
        }
        let (src, dst, limit) = self.resources(&mut tx, &c.intent).await?;
        let row = sqlx::query(
            "SELECT payload,intent_digest FROM issued_challenges WHERE nonce=$1 FOR UPDATE",
        )
        .bind(&c.receipt.payload.challenge.nonce)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::Denied)?;
        let stored: Challenge = serde_json::from_value(row.get("payload"))
            .map_err(|_| Error::Invalid("stored challenge"))?;
        if stored != c.receipt.payload.challenge || row.get::<String, _>("intent_digest") != digest
        {
            return Err(Error::Denied);
        }
        let now = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
        )
        .fetch_one(&mut *tx)
        .await?;
        if now >= stored.expiry {
            return Err(Error::Expired);
        }
        if now < epoch.valid_from
            || now >= epoch.valid_until
            || c.receipt.payload.policy_version != POLICY_VERSION
        {
            return Err(Error::Signature);
        }
        if src.get::<i64, _>("version") as u64 != stored.source_version
            || dst.get::<i64, _>("version") as u64 != stored.dest_version
            || limit.get::<i64, _>("version") as u64 != stored.limit_version
            || limit.get::<i64, _>("window_day") != now.div_euclid(86400)
        {
            return Err(Error::Stale);
        }
        let amount = c.intent.amount_units;
        let source = (src.get::<i64, _>("balance") as u64)
            .checked_sub(amount)
            .ok_or(Error::Denied)?;
        let dest = (dst.get::<i64, _>("balance") as u64)
            .checked_add(amount)
            .filter(|v| *v <= MAX_UNITS)
            .ok_or(Error::Denied)?;
        let spent = (limit.get::<i64, _>("spent") as u64)
            .checked_add(amount)
            .filter(|v| *v <= limit.get::<i64, _>("max_daily") as u64)
            .ok_or(Error::Denied)?;
        let sv = src
            .get::<i64, _>("version")
            .checked_add(1)
            .ok_or(Error::Denied)?;
        let dv = dst
            .get::<i64, _>("version")
            .checked_add(1)
            .ok_or(Error::Denied)?;
        let lv = limit
            .get::<i64, _>("version")
            .checked_add(1)
            .ok_or(Error::Denied)?;
        sqlx::query("UPDATE accounts SET balance=$2,version=$3 WHERE account_id=$1")
            .bind(c.intent.source_account_id)
            .bind(source as i64)
            .bind(sv)
            .execute(&mut *tx)
            .await?;
        if fault == Fault::AfterDebit {
            tx.rollback().await?;
            return Err(Error::Injected);
        }
        sqlx::query("UPDATE accounts SET balance=$2,version=$3 WHERE account_id=$1")
            .bind(c.intent.dest_account_id)
            .bind(dest as i64)
            .bind(dv)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE policy_limits SET spent=$2,version=$3 WHERE principal_id=$1")
            .bind(principal)
            .bind(spent as i64)
            .bind(lv)
            .execute(&mut *tx)
            .await?;
        // Deleting the challenge is consumption; rollback restores it, commit leaves no reusable nonce.
        sqlx::query("DELETE FROM issued_challenges WHERE nonce=$1")
            .bind(&stored.nonce)
            .execute(&mut *tx)
            .await?;
        let outcome = Outcome {
            op_id: c.intent.op_id,
            source_balance: source,
            dest_balance: dest,
            source_version: sv as u64,
            dest_version: dv as u64,
            limit_version: lv as u64,
        };
        sqlx::query(
            "UPDATE operations SET outcome=$2,committed_at=clock_timestamp() WHERE op_id=$1",
        )
        .bind(c.intent.op_id)
        .bind(serde_json::to_value(&outcome).map_err(|_| Error::Invalid("outcome encoding"))?)
        .execute(&mut *tx)
        .await?;
        if fault == Fault::BeforeCommit {
            tx.rollback().await?;
            return Err(Error::Injected);
        }
        tx.commit().await?;
        Ok(outcome)
    }
}
