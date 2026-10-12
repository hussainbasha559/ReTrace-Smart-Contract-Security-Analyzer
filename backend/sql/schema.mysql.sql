-- ReTrace schema for MySQL 8.x (generated from Alembic migration 0001; verified on MySQL 8.0).
-- Prefer 'alembic upgrade head'. Use this script only if you cannot run Alembic.
-- Create the database first:  CREATE DATABASE evm_security CHARACTER SET utf8mb4;  USE evm_security;

CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 0001

CREATE TABLE users (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    name VARCHAR(100) NOT NULL, 
    email VARCHAR(254) NOT NULL, 
    password_hash VARCHAR(255) NOT NULL, 
    `role` VARCHAR(10) NOT NULL, 
    is_active BOOL NOT NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    last_login_at DATETIME, 
    PRIMARY KEY (id), 
    CONSTRAINT ck_users_role CHECK (role in ('user','admin')), 
    UNIQUE (email)
);

CREATE TABLE audit_logs (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    actor_user_id INTEGER, 
    action VARCHAR(60) NOT NULL, 
    resource_type VARCHAR(30) NOT NULL, 
    resource_id VARCHAR(64), 
    outcome VARCHAR(15) NOT NULL, 
    timestamp DATETIME NOT NULL, 
    request_id VARCHAR(36), 
    PRIMARY KEY (id), 
    FOREIGN KEY(actor_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_audit_actor ON audit_logs (actor_user_id);

CREATE INDEX ix_audit_timestamp ON audit_logs (timestamp);

CREATE TABLE projects (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    owner_user_id INTEGER NOT NULL, 
    project_name VARCHAR(120) NOT NULL, 
    description TEXT, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE CASCADE, 
    CONSTRAINT uq_projects_owner_name UNIQUE (owner_user_id, project_name)
);

CREATE TABLE usage_events (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    owner_user_id INTEGER NOT NULL, 
    event_type VARCHAR(40) NOT NULL, 
    resource_type VARCHAR(30) NOT NULL, 
    resource_id INTEGER, 
    quantity INTEGER NOT NULL, 
    duration_ms INTEGER, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX ix_usage_owner_created ON usage_events (owner_user_id, created_at);

CREATE INDEX ix_usage_type ON usage_events (event_type);

CREATE TABLE user_sessions (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    user_id INTEGER NOT NULL, 
    token_hash VARCHAR(64) NOT NULL, 
    csrf_token VARCHAR(64) NOT NULL, 
    created_at DATETIME NOT NULL, 
    expires_at DATETIME NOT NULL, 
    last_seen_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
    UNIQUE (token_hash)
);

CREATE INDEX ix_user_sessions_expires ON user_sessions (expires_at);

CREATE INDEX ix_user_sessions_user ON user_sessions (user_id);

CREATE TABLE uploaded_files (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    owner_user_id INTEGER NOT NULL, 
    project_id INTEGER, 
    original_filename VARCHAR(255) NOT NULL, 
    generated_storage_key VARCHAR(64) NOT NULL, 
    file_size INTEGER NOT NULL, 
    file_hash VARCHAR(64) NOT NULL, 
    detected_input_type VARCHAR(30) NOT NULL, 
    upload_status VARCHAR(20) NOT NULL, 
    created_at DATETIME NOT NULL, 
    deleted_at DATETIME, 
    PRIMARY KEY (id), 
    FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE CASCADE, 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE SET NULL, 
    UNIQUE (generated_storage_key)
);

CREATE INDEX ix_files_hash ON uploaded_files (file_hash);

CREATE INDEX ix_files_owner_created ON uploaded_files (owner_user_id, created_at);

CREATE TABLE scans (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    owner_user_id INTEGER NOT NULL, 
    project_id INTEGER, 
    uploaded_file_id INTEGER, 
    scan_type VARCHAR(30) NOT NULL, 
    target_identifier VARCHAR(80) NOT NULL, 
    target_name VARCHAR(255), 
    network_name VARCHAR(50), 
    scan_status VARCHAR(12) NOT NULL, 
    run_decompiler BOOL NOT NULL, 
    run_mythril BOOL NOT NULL, 
    input_bytes INTEGER NOT NULL, 
    verdict VARCHAR(30), 
    attempts INTEGER NOT NULL, 
    created_at DATETIME NOT NULL, 
    started_at DATETIME, 
    completed_at DATETIME, 
    duration_ms INTEGER, 
    analyzer_version VARCHAR(40) NOT NULL, 
    error_summary TEXT, 
    PRIMARY KEY (id), 
    CONSTRAINT ck_scans_status CHECK (scan_status in ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED')), 
    FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE CASCADE, 
    FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE SET NULL, 
    FOREIGN KEY(uploaded_file_id) REFERENCES uploaded_files (id) ON DELETE SET NULL
);

CREATE INDEX ix_scans_file ON scans (uploaded_file_id);

CREATE INDEX ix_scans_owner_created ON scans (owner_user_id, created_at);

CREATE INDEX ix_scans_owner_status ON scans (owner_user_id, scan_status);

CREATE TABLE ai_analysis (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    owner_user_id INTEGER NOT NULL, 
    scan_id INTEGER NOT NULL, 
    provider VARCHAR(40) NOT NULL, 
    model_name VARCHAR(80), 
    analysis_type VARCHAR(30) NOT NULL, 
    status VARCHAR(15) NOT NULL, 
    result_summary VARCHAR(500), 
    result_text TEXT, 
    token_usage INTEGER, 
    prompt_tokens INTEGER, 
    completion_tokens INTEGER, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE CASCADE, 
    FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_ai_owner_created ON ai_analysis (owner_user_id, created_at);

CREATE INDEX ix_ai_scan ON ai_analysis (scan_id);

CREATE TABLE scan_reports (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    scan_id INTEGER NOT NULL, 
    report_kind VARCHAR(30) NOT NULL, 
    report_format VARCHAR(10) NOT NULL, 
    storage_key VARCHAR(64) NOT NULL, 
    report_hash VARCHAR(64) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
    UNIQUE (storage_key)
);

CREATE INDEX ix_reports_scan ON scan_reports (scan_id);

CREATE TABLE vulnerabilities (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    scan_id INTEGER NOT NULL, 
    category VARCHAR(120) NOT NULL, 
    title VARCHAR(200) NOT NULL, 
    swc_id VARCHAR(20), 
    source VARCHAR(20) NOT NULL, 
    severity VARCHAR(15) NOT NULL, 
    confidence_label VARCHAR(20) NOT NULL, 
    verification_status VARCHAR(30) NOT NULL, 
    reentrancy_related BOOL NOT NULL, 
    program_counter INTEGER, 
    opcode_evidence JSON, 
    description TEXT NOT NULL, 
    remediation TEXT NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_vuln_category_severity ON vulnerabilities (category, severity);

CREATE INDEX ix_vuln_scan ON vulnerabilities (scan_id);

INSERT INTO alembic_version (version_num) VALUES ('0001');

