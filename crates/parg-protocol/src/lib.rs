//! PARG v1: explicit canonical bytes; no native struct layout is a wire format.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const POLICY_VERSION: u64 = 1;
pub const MAX_UNITS: u64 = 1_000_000_000_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub op_id: Uuid,
    pub principal_id: Uuid,
    pub target_service_id: Uuid,
    pub source_account_id: Uuid,
    pub dest_account_id: Uuid,
    pub amount_units: u64,
}
impl Intent {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.op_id.get_version_num() != 4 || self.op_id.get_variant() != uuid::Variant::RFC4122 {
            return Err("operation ID must be an RFC4122 UUIDv4");
        }
        if self.source_account_id == self.dest_account_id {
            return Err("self transfers are unsupported");
        }
        if self.amount_units == 0 || self.amount_units > MAX_UNITS {
            return Err("amount outside supported range");
        }
        Ok(())
    }
    /// Stable across retries and reauthorizations. All monetary values are demo credits.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = b"PARGINT1".to_vec();
        for id in [
            self.op_id,
            self.principal_id,
            self.target_service_id,
            self.source_account_id,
            self.dest_account_id,
        ] {
            out.extend(id.as_bytes());
        }
        out.extend((self.amount_units as u128).to_be_bytes());
        out
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: String,
    pub expiry: i64,
    pub intent_digest: String,
    pub source_version: u64,
    pub dest_version: u64,
    pub limit_version: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPayload {
    pub epoch_id: u64,
    pub policy_version: u64,
    pub challenge: Challenge,
    pub intent: Intent,
}
impl ReceiptPayload {
    pub fn canonical(&self) -> Result<[u8; 224], &'static str> {
        self.intent.validate()?;
        let nonce = hex::decode(&self.challenge.nonce).map_err(|_| "invalid nonce")?;
        if nonce.len() != 32 {
            return Err("nonce must be 32 bytes");
        }
        if self.challenge.intent_digest != hex::encode(self.intent.digest()) {
            return Err("intent binding mismatch");
        }
        let mut out = Vec::with_capacity(224);
        out.extend(b"PARG-V01");
        for value in [1u64, self.epoch_id, self.policy_version] {
            out.extend(value.to_be_bytes());
        }
        out.extend(nonce);
        out.extend(self.challenge.expiry.to_be_bytes());
        for id in [
            self.intent.op_id,
            self.intent.principal_id,
            self.intent.target_service_id,
            self.intent.source_account_id,
            self.intent.dest_account_id,
        ] {
            out.extend(id.as_bytes());
        }
        out.extend((self.intent.amount_units as u128).to_be_bytes());
        for version in [
            self.challenge.source_version,
            self.challenge.dest_version,
            self.challenge.limit_version,
        ] {
            out.extend(version.to_be_bytes());
        }
        out.extend(self.intent.digest());
        out.try_into().map_err(|_| "invalid canonical size")
    }
    pub fn digest(&self) -> Result<[u8; 32], &'static str> {
        Ok(*blake3::hash(&self.canonical()?).as_bytes())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub payload: ReceiptPayload,
    pub signature: String,
}
impl Receipt {
    pub fn sign(payload: ReceiptPayload, key: &SigningKey) -> Result<Self, &'static str> {
        let signature = hex::encode(key.sign(&payload.digest()?).to_bytes());
        Ok(Self { payload, signature })
    }
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), &'static str> {
        let bytes = hex::decode(&self.signature).map_err(|_| "invalid signature encoding")?;
        let signature = Signature::from_slice(&bytes).map_err(|_| "invalid signature length")?;
        key.verify_strict(&self.payload.digest()?, &signature)
            .map_err(|_| "signature rejected")
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorize {
    pub intent: Intent,
    pub nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub intent: Intent,
    pub receipt: Receipt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub challenge: Challenge,
    pub source_balance: u64,
    pub dest_balance: u64,
    pub spent: u64,
    pub daily_limit: u64,
    pub current_source_version: u64,
    pub current_dest_version: u64,
    pub current_limit_version: u64,
    pub window_day: i64,
    pub now: i64,
}
impl Snapshot {
    pub fn authorize(
        &self,
        request: &Authorize,
        epoch: u64,
    ) -> Result<ReceiptPayload, &'static str> {
        request.intent.validate()?;
        if request.nonce != self.challenge.nonce
            || self.challenge.intent_digest != hex::encode(request.intent.digest())
        {
            return Err("challenge scope mismatch");
        }
        if self.now >= self.challenge.expiry {
            return Err("challenge expired");
        }
        if self.window_day != self.now.div_euclid(86400) {
            return Err("limit window stale");
        }
        if self.challenge.source_version != self.current_source_version
            || self.challenge.dest_version != self.current_dest_version
            || self.challenge.limit_version != self.current_limit_version
        {
            return Err("state version stale");
        }
        if self.source_balance < request.intent.amount_units
            || self
                .dest_balance
                .checked_add(request.intent.amount_units)
                .filter(|v| *v <= MAX_UNITS)
                .is_none()
            || self
                .spent
                .checked_add(request.intent.amount_units)
                .filter(|v| *v <= self.daily_limit)
                .is_none()
        {
            return Err("policy denied");
        }
        Ok(ReceiptPayload {
            epoch_id: epoch,
            policy_version: POLICY_VERSION,
            challenge: self.challenge.clone(),
            intent: request.intent.clone(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub op_id: Uuid,
    pub source_balance: u64,
    pub dest_balance: u64,
    pub source_version: u64,
    pub dest_version: u64,
    pub limit_version: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEpoch {
    pub epoch_id: u64,
    pub public_key: String,
    pub valid_from: i64,
    pub valid_until: i64,
}
impl KeyEpoch {
    pub fn key(&self) -> Result<VerifyingKey, &'static str> {
        let raw = hex::decode(&self.public_key).map_err(|_| "invalid public key")?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| "public key must be 32 bytes")?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid public key")?;
        if key.is_weak() {
            return Err("weak public key");
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent() -> Intent {
        Intent {
            op_id: Uuid::parse_str("a0a1a2a3-a4a5-46a7-a8a9-aaabacadaeaf").unwrap(),
            principal_id: Uuid::from_bytes([0xb0; 16]),
            target_service_id: Uuid::from_bytes([0xc0; 16]),
            source_account_id: Uuid::from_bytes([0xd0; 16]),
            dest_account_id: Uuid::from_bytes([0xe0; 16]),
            amount_units: 1_000_000,
        }
    }
    fn payload() -> ReceiptPayload {
        let i = intent();
        ReceiptPayload {
            epoch_id: 42,
            policy_version: 1,
            challenge: Challenge {
                nonce: hex::encode((1u8..=32u8).collect::<Vec<_>>()),
                expiry: 1_800_000_000,
                intent_digest: hex::encode(i.digest()),
                source_version: 14,
                dest_version: 8,
                limit_version: 3,
            },
            intent: i,
        }
    }
    #[test]
    fn fixed_width_offsets() {
        let p = payload();
        let b = p.canonical().unwrap();
        assert_eq!(b.len(), 224);
        assert_eq!(&b[..8], b"PARG-V01");
        assert_eq!(&b[16..24], 42u64.to_be_bytes());
        assert_eq!(&b[152..168], 1_000_000u128.to_be_bytes());
        assert_eq!(&b[192..], p.intent.digest());
    }
    #[test]
    fn signatures_bind_every_byte() {
        let p = payload();
        let key = SigningKey::from_bytes(&[7; 32]);
        let receipt = Receipt::sign(p.clone(), &key).unwrap();
        receipt.verify(&key.verifying_key()).unwrap();
        for n in 0..224 {
            let mut b = p.canonical().unwrap();
            b[n] ^= 1;
            let signature =
                Signature::from_slice(&hex::decode(&receipt.signature).unwrap()).unwrap();
            assert!(key
                .verifying_key()
                .verify_strict(blake3::hash(&b).as_bytes(), &signature)
                .is_err());
        }
    }
    #[test]
    fn intent_identity_survives_reauthorization() {
        let p = payload();
        let mut q = p.clone();
        q.epoch_id += 1;
        q.challenge.nonce = hex::encode([9; 32]);
        q.challenge.source_version += 1;
        assert_eq!(p.intent.digest(), q.intent.digest());
        assert_ne!(p.digest().unwrap(), q.digest().unwrap());
    }
    #[test]
    fn reject_unsupported_inputs() {
        let mut i = intent();
        i.amount_units = 0;
        assert!(i.validate().is_err());
        i.amount_units = MAX_UNITS + 1;
        assert!(i.validate().is_err());
        i.amount_units = 1;
        i.dest_account_id = i.source_account_id;
        assert!(i.validate().is_err());
    }
    #[test]
    fn reject_bad_nonce_and_binding() {
        let mut p = payload();
        p.challenge.nonce = "00".into();
        assert!(p.canonical().is_err());
        p.challenge.nonce = hex::encode([0; 32]);
        p.challenge.intent_digest = "00".into();
        assert!(p.canonical().is_err());
    }
    #[test]
    fn json_rejects_unknown_fields() {
        let mut value = serde_json::to_value(intent()).unwrap();
        value["currency"] = serde_json::json!("USD");
        assert!(serde_json::from_value::<Intent>(value).is_err());
    }
    #[test]
    fn independent_golden_bytes() {
        let p = payload();
        let expected = include_str!("../golden.hex").trim();
        assert_eq!(hex::encode(p.canonical().unwrap()), expected);
    }
}
