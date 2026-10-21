use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ledger_service::{Error, Ledger};
use parg_protocol::*;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::{env, sync::Arc};
use subtle::ConstantTimeEq;
use uuid::Uuid;

struct App {
    ledger: Ledger,
    worker_token: String,
    core_token: String,
    principal: Uuid,
}
fn token(headers: &HeaderMap, expected: &str) -> Result<(), Error> {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if bool::from(provided.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}
struct ApiError(Error);
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Signature => StatusCode::UNAUTHORIZED,
            Error::Conflict | Error::Stale => StatusCode::CONFLICT,
            Error::Denied => StatusCode::FORBIDDEN,
            Error::Expired | Error::Invalid(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"error":self.0.code()}))).into_response()
    }
}
async fn challenge(
    State(s): State<Arc<App>>,
    headers: HeaderMap,
    Json(i): Json<Intent>,
) -> Result<Json<Challenge>, ApiError> {
    token(&headers, &s.worker_token)?;
    Ok(Json(s.ledger.challenge(&i, s.principal, 60).await?))
}
async fn commit(
    State(s): State<Arc<App>>,
    headers: HeaderMap,
    Json(c): Json<Commit>,
) -> Result<Json<Outcome>, ApiError> {
    token(&headers, &s.worker_token)?;
    Ok(Json(s.ledger.commit(&c, s.principal).await?))
}
async fn snapshot(
    State(s): State<Arc<App>>,
    headers: HeaderMap,
    Json(a): Json<Authorize>,
) -> Result<Json<Snapshot>, ApiError> {
    token(&headers, &s.core_token)?;
    Ok(Json(s.ledger.snapshot(&a).await?))
}
async fn health(State(s): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    s.ledger.now().await?;
    Ok(Json(
        json!({"status":"ok","model":"trusted-host-prototype"}),
    ))
}
fn required(name: &str) -> anyhow::Result<String> {
    let s = env::var(name)?;
    anyhow::ensure!(s.len() >= 32, "{name} must have at least 32 characters");
    Ok(s)
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&env::var("PARG_DATABASE_URL")?)
        .await?;
    let target = env::var("PARG_TARGET_ID")?.parse()?;
    let principal = env::var("PARG_PRINCIPAL_ID")?.parse()?;
    let keys: Vec<KeyEpoch> = serde_json::from_slice(&std::fs::read(env::var("PARG_KEYRING")?)?)?;
    let ledger = Ledger::new(pool, target, keys).map_err(anyhow::Error::msg)?;
    ledger.migrate().await?;
    if env::var("PARG_DEMO_SEED").as_deref() == Ok("1") {
        ledger
            .seed(
                principal,
                env::var("PARG_SOURCE_ID")?.parse()?,
                env::var("PARG_DEST_ID")?.parse()?,
            )
            .await?;
    }
    let worker_token = required("PARG_WORKER_TOKEN")?;
    let core_token = required("PARG_CORE_TOKEN")?;
    anyhow::ensure!(
        worker_token != core_token,
        "worker and policy-core tokens must differ"
    );
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/challenges", post(challenge))
        .route("/v1/commit", post(commit))
        .route("/internal/snapshot", post(snapshot))
        .layer(DefaultBodyLimit::max(16384))
        .with_state(Arc::new(App {
            ledger,
            worker_token,
            core_token,
            principal,
        }));
    let bind = env::var("PARG_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("ledger-service listening at {bind}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
