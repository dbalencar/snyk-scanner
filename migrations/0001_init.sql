CREATE TABLE scans (
    scan_id          UUID PRIMARY KEY,
    git_url          TEXT NOT NULL,
    ref              TEXT NOT NULL,
    org_id           TEXT,
    status           TEXT NOT NULL DEFAULT 'pending',  -- pending | in_progress | completed | failed
    expected_units   INT NOT NULL DEFAULT 0,
    completed_units  INT NOT NULL DEFAULT 0,
    overall_summary  JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at     TIMESTAMPTZ
);

CREATE TABLE scan_units (
    id            BIGSERIAL PRIMARY KEY,
    scan_id       UUID NOT NULL REFERENCES scans(scan_id),
    project_path  TEXT NOT NULL,
    scan_type     TEXT NOT NULL,        -- sca | sast | iac | container
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | completed | failed | skipped
    object_key    TEXT,
    vuln_summary  JSONB,
    snyk_cli_version TEXT,
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    UNIQUE (scan_id, project_path, scan_type)
);

CREATE INDEX idx_scan_units_scan_id ON scan_units(scan_id);
CREATE INDEX idx_scans_status ON scans(status);
