CREATE TABLE IF NOT EXISTS accounts (
 account_id UUID PRIMARY KEY, owner_id UUID NOT NULL,
 balance BIGINT NOT NULL CHECK(balance BETWEEN 0 AND 1000000000000),
 version BIGINT NOT NULL DEFAULT 1 CHECK(version > 0)
);
CREATE TABLE IF NOT EXISTS policy_limits (
 principal_id UUID PRIMARY KEY, spent BIGINT NOT NULL DEFAULT 0 CHECK(spent >= 0),
 max_daily BIGINT NOT NULL CHECK(max_daily BETWEEN 1 AND 1000000000000),
 window_day BIGINT NOT NULL, version BIGINT NOT NULL DEFAULT 1 CHECK(version > 0)
);
CREATE TABLE IF NOT EXISTS issued_challenges (
 nonce TEXT PRIMARY KEY CHECK(length(nonce)=64),
 principal_id UUID NOT NULL, intent_digest TEXT NOT NULL,
 payload JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
 op_id UUID PRIMARY KEY, principal_id UUID NOT NULL,
 intent_digest TEXT NOT NULL, receipt_digest TEXT NOT NULL,
 outcome JSONB, committed_at TIMESTAMPTZ
);
