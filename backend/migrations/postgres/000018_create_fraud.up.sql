-- ============================================================
-- Domain 16: Fraud & Financial Crime Detection
-- ============================================================

-- Fraud detection rules / patterns
CREATE TABLE IF NOT EXISTS fraud_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    category        TEXT NOT NULL CHECK (category IN (
                        'aml','card_fraud','account_takeover','insider_threat',
                        'swift_fraud','wire_fraud','identity_theft','money_laundering')),
    rule_type       TEXT NOT NULL CHECK (rule_type IN ('threshold','pattern','velocity','ml_score','watchlist')),
    conditions      JSONB NOT NULL DEFAULT '{}',   -- rule logic: field, operator, value
    risk_score      INT NOT NULL DEFAULT 50 CHECK (risk_score BETWEEN 0 AND 100),
    is_active       BOOL DEFAULT TRUE,
    triggered_count BIGINT DEFAULT 0,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fraud_rules_tenant        ON fraud_rules (tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_fraud_rules_tenant_cat    ON fraud_rules (tenant_id, category);

-- Monitored transactions (banking events)
CREATE TABLE IF NOT EXISTS fraud_transactions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    transaction_id  TEXT NOT NULL,                -- external TXN ID from CBS/SWIFT
    channel         TEXT NOT NULL CHECK (channel IN (
                        'swift','wire','card','atm','online','mobile','internal','sepa')),
    amount          NUMERIC(20,4) NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'USD',
    sender_account  TEXT,
    sender_entity   TEXT,
    receiver_account TEXT,
    receiver_entity TEXT,
    country_origin  TEXT,
    country_dest    TEXT,
    metadata        JSONB DEFAULT '{}',
    fraud_score     INT DEFAULT 0 CHECK (fraud_score BETWEEN 0 AND 100),
    status          TEXT DEFAULT 'pending' CHECK (status IN ('pending','cleared','flagged','blocked','under_review')),
    flagged_by      TEXT[],                       -- rule IDs that triggered
    transacted_at   TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_fraud_txn_tenant         ON fraud_transactions (tenant_id, transacted_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_txn_tenant_status  ON fraud_transactions (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_fraud_txn_score          ON fraud_transactions (tenant_id, fraud_score DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_txn_sender         ON fraud_transactions (tenant_id, sender_account);
CREATE INDEX IF NOT EXISTS idx_fraud_txn_receiver       ON fraud_transactions (tenant_id, receiver_account);

-- Fraud signals: individual indicators raised against a transaction
CREATE TABLE IF NOT EXISTS fraud_signals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    transaction_id  UUID REFERENCES fraud_transactions(id) ON DELETE CASCADE,
    rule_id         UUID REFERENCES fraud_rules(id) ON DELETE SET NULL,
    signal_type     TEXT NOT NULL,               -- rule category + type
    description     TEXT NOT NULL,
    risk_contribution INT NOT NULL DEFAULT 10,   -- how much this signal adds to score
    evidence        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fraud_signals_txn    ON fraud_signals (transaction_id);
CREATE INDEX IF NOT EXISTS idx_fraud_signals_tenant ON fraud_signals (tenant_id, created_at DESC);

-- Fraud cases: investigated fraud incidents (one or many transactions)
CREATE TABLE IF NOT EXISTS fraud_cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    case_number     TEXT NOT NULL,               -- human-readable: FRD-2026-00001
    title           TEXT NOT NULL,
    category        TEXT NOT NULL CHECK (category IN (
                        'aml','card_fraud','account_takeover','insider_threat',
                        'swift_fraud','wire_fraud','identity_theft','money_laundering')),
    severity        TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','under_review','escalated','sar_filed','closed_confirmed','closed_false_positive')),
    assigned_to     UUID,
    transaction_ids UUID[],                      -- linked transactions
    total_amount    NUMERIC(20,4),               -- total suspicious amount
    currency        TEXT DEFAULT 'USD',
    sar_required    BOOL DEFAULT FALSE,          -- Suspicious Activity Report required
    sar_filed_at    TIMESTAMPTZ,
    notes           TEXT,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fraud_cases_tenant        ON fraud_cases (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_cases_tenant_status ON fraud_cases (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_fraud_cases_number        ON fraud_cases (tenant_id, case_number);

-- Watchlist: entities under AML/fraud surveillance
CREATE TABLE IF NOT EXISTS fraud_watchlist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('account','person','entity','ip','device','country','swift_bic')),
    entity_value    TEXT NOT NULL,
    reason          TEXT NOT NULL,
    list_type       TEXT NOT NULL CHECK (list_type IN ('internal','sanctions','pep','adverse_media','custom')),
    severity        TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    is_active       BOOL DEFAULT TRUE,
    expires_at      TIMESTAMPTZ,
    added_by        UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, entity_type, entity_value, list_type)
);

CREATE INDEX IF NOT EXISTS idx_fraud_watchlist_tenant ON fraud_watchlist (tenant_id, entity_type, is_active);
CREATE INDEX IF NOT EXISTS idx_fraud_watchlist_value  ON fraud_watchlist (tenant_id, entity_value);
