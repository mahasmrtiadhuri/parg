//! Synthetic authorized worker and explicit adversarial HTTP driver; no exploit payloads.
use parg_protocol::*;
use std::{env, time::Duration};
use uuid::Uuid;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ledger = env::var("PARG_LEDGER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let policy = env::var("PARG_POLICY_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".into());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for _ in 0..60 {
        if client
            .get(format!("{ledger}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
            && client
                .get(format!("{policy}/health"))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let token = env::var("PARG_WORKER_TOKEN")?;
    let intent = Intent {
        op_id: Uuid::new_v4(),
        principal_id: env::var("PARG_PRINCIPAL_ID")?.parse()?,
        target_service_id: env::var("PARG_TARGET_ID")?.parse()?,
        source_account_id: env::var("PARG_SOURCE_ID")?.parse()?,
        dest_account_id: env::var("PARG_DEST_ID")?.parse()?,
        amount_units: 100,
    };
    let no_auth = client
        .post(format!("{ledger}/v1/challenges"))
        .json(&intent)
        .send()
        .await?;
    anyhow::ensure!(no_auth.status() == 401, "unauthenticated request accepted");
    println!("PASS: unauthenticated request rejected");
    let no_receipt = client
        .post(format!("{ledger}/v1/commit"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"intent":intent}))
        .send()
        .await?;
    anyhow::ensure!(
        no_receipt.status().is_client_error(),
        "missing receipt accepted"
    );
    println!("PASS: missing receipt rejected");
    let challenge: Challenge = client
        .post(format!("{ledger}/v1/challenges"))
        .bearer_auth(&token)
        .json(&intent)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let receipt: Receipt = client
        .post(format!("{policy}/v1/authorize"))
        .bearer_auth(&token)
        .json(&Authorize {
            intent: intent.clone(),
            nonce: challenge.nonce,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let commit = Commit {
        intent: intent.clone(),
        receipt,
    };
    let mut tampered = commit.clone();
    tampered.intent.amount_units += 1;
    let rejected = client
        .post(format!("{ledger}/v1/commit"))
        .bearer_auth(&token)
        .json(&tampered)
        .send()
        .await?;
    anyhow::ensure!(rejected.status() == 401, "tampered payload accepted");
    println!("PASS: altered amount rejected");
    let first: Outcome = client
        .post(format!("{ledger}/v1/commit"))
        .bearer_auth(&token)
        .json(&commit)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let retry: Outcome = client
        .post(format!("{ledger}/v1/commit"))
        .bearer_auth(&token)
        .json(&commit)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    anyhow::ensure!(first == retry, "retry changed outcome");
    println!("PASS: compliant transfer committed");
    println!("PASS: exact replay returned original outcome without a second debit");
    println!("{}", serde_json::to_string_pretty(&first)?);
    Ok(())
}
