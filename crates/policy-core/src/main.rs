//! Separate process signing service. This implementation does not claim hardware attestation.
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use parg_protocol::*;
use rand::RngCore;
use std::{env, fs, path::Path, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use uuid::Uuid;
struct App {
    key: SigningKey,
    epoch: u64,
    ledger: String,
    core_token: String,
    worker_token: String,
    principal: Uuid,
    client: reqwest::Client,
}
async fn authorize(
    State(s): State<Arc<App>>,
    headers: HeaderMap,
    Json(a): Json<Authorize>,
) -> Result<Json<Receipt>, (StatusCode, Json<serde_json::Value>)> {
    let fail = |status, code| (status, Json(serde_json::json!({"error":code})));
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|t| t.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bool::from(bearer.as_bytes().ct_eq(s.worker_token.as_bytes()))
        || a.intent.principal_id != s.principal
    {
        return Err(fail(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let response = s
        .client
        .post(format!("{}/internal/snapshot", s.ledger))
        .bearer_auth(&s.core_token)
        .json(&a)
        .send()
        .await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"))?;
    if !response.status().is_success() {
        return Err(fail(StatusCode::FORBIDDEN, "authority_denied"));
    }
    let snapshot: Snapshot = response.json().await.map_err(|_| {
        fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_authority_response",
        )
    })?;
    let payload = snapshot
        .authorize(&a, s.epoch)
        .map_err(|_| fail(StatusCode::FORBIDDEN, "policy_denied"))?;
    Ok(Json(Receipt::sign(payload, &s.key).map_err(|_| {
        fail(StatusCode::BAD_REQUEST, "invalid_request")
    })?))
}
fn read_key(path: &str) -> anyhow::Result<SigningKey> {
    let raw = fs::read(path)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed file must contain exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
fn keygen(private: &str, public: &str) -> anyhow::Result<()> {
    if !Path::new(private).exists() {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(private)?;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        file.write_all(&seed)?;
        file.sync_all()?;
    }
    let key = read_key(private)?;
    if Path::new(public).exists() {
        let existing: Vec<KeyEpoch> = serde_json::from_slice(&fs::read(public)?)?;
        anyhow::ensure!(
            existing
                .iter()
                .any(|k| k.epoch_id == 1
                    && k.public_key == hex::encode(key.verifying_key().as_bytes())),
            "existing keyring does not match seed; refusing replacement"
        );
        println!("Existing matching key material preserved.");
        return Ok(());
    }
    let keyring = vec![KeyEpoch {
        epoch_id: 1,
        public_key: hex::encode(key.verifying_key().as_bytes()),
        valid_from: 0,
        valid_until: 4_102_444_800,
    }];
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    use std::io::Write;
    let mut out = options.open(public)?;
    out.write_all(&serde_json::to_vec_pretty(&keyring)?)?;
    out.sync_all()?;
    println!("Created policy key and public keyring; private key was not printed.");
    Ok(())
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("keygen") {
        anyhow::ensure!(
            args.len() == 4,
            "usage: policy-core keygen PRIVATE_SEED PUBLIC_KEYRING"
        );
        return keygen(&args[2], &args[3]);
    }
    let worker_token = env::var("PARG_WORKER_TOKEN")?;
    let core_token = env::var("PARG_CORE_TOKEN")?;
    anyhow::ensure!(
        worker_token.len() >= 32 && core_token.len() >= 32 && worker_token != core_token,
        "distinct service tokens of at least 32 characters required"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let state = App {
        key: read_key(&env::var("PARG_SIGNING_KEY")?)?,
        epoch: env::var("PARG_EPOCH")
            .unwrap_or_else(|_| "1".into())
            .parse()?,
        ledger: env::var("PARG_LEDGER_URL")?,
        core_token,
        worker_token,
        principal: env::var("PARG_PRINCIPAL_ID")?.parse()?,
        client,
    };
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status":"ok","isolation":"process-only"})) }),
        )
        .route("/v1/authorize", post(authorize))
        .layer(DefaultBodyLimit::max(16384))
        .with_state(Arc::new(state));
    let bind = env::var("PARG_POLICY_BIND").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("policy-core listening at {bind}; trusted-host mode");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
