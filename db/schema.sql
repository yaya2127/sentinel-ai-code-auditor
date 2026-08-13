-- ============================================================================
-- SentinelAI - Autonomous Agentic AI Code Security Auditor
-- Enterprise Database Schema
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Repository Audit Scans Table
CREATE TABLE IF NOT EXISTS audit_scans (
    scan_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_name VARCHAR(128) NOT NULL,
    branch VARCHAR(64) NOT NULL DEFAULT 'main',
    total_files_scanned INT NOT NULL DEFAULT 0,
    total_lines_of_code INT NOT NULL DEFAULT 0,
    risk_score INT NOT NULL DEFAULT 0, -- 0 (Secure) to 100 (Critical Risk)
    status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED', -- 'IN_PROGRESS', 'COMPLETED', 'FAILED'
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Security Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES audit_scans(scan_id) ON DELETE CASCADE,
    file_path VARCHAR(256) NOT NULL,
    line_number INT NOT NULL,
    vuln_type VARCHAR(64) NOT NULL, -- 'SQL_INJECTION', 'HARDCODED_SECRET', 'XSS', 'BUFFER_OVERFLOW', 'UNHANDLED_EXCEPTION'
    severity VARCHAR(32) NOT NULL,  -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    cwe_id VARCHAR(32) NOT NULL,     -- e.g., 'CWE-89', 'CWE-798', 'CWE-79'
    vulnerable_snippet TEXT NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    remediated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity, scan_id);

-- 3. AI Generated Fix Patches Table
CREATE TABLE IF NOT EXISTS code_patches (
    patch_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vuln_id UUID REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    file_path VARCHAR(256) NOT NULL,
    original_code TEXT NOT NULL,
    patched_code TEXT NOT NULL,
    unified_diff TEXT NOT NULL,
    applied BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Auto-Generated Unit Tests Table
CREATE TABLE IF NOT EXISTS generated_tests (
    test_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES audit_scans(scan_id) ON DELETE CASCADE,
    target_function VARCHAR(128) NOT NULL,
    test_framework VARCHAR(32) NOT NULL, -- 'pytest', 'jest', 'testing'
    test_code TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
