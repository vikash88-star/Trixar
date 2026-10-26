CREATE TABLE assets (
  id SERIAL PRIMARY KEY,
  hostname TEXT UNIQUE NOT NULL,
  ip INET,
  criticality INT CHECK (criticality BETWEEN 1 AND 5) DEFAULT 2
);

CREATE TABLE alerts (
  id BIGSERIAL PRIMARY KEY,
  source_id TEXT UNIQUE,            -- ID from Wazuh, prevents duplicates
  received_at TIMESTAMPTZ DEFAULT now(),
  rule_id TEXT,
  rule_desc TEXT,
  severity INT,                     -- Wazuh level 0-15
  src_ip INET,
  asset_id INT REFERENCES assets(id),
  technique_id TEXT,                -- e.g. T1110
  tactic TEXT,
  enrichment JSONB DEFAULT '{}',    -- flexible reputation data
  priority_score REAL,
  fp_probability REAL,
  ai_summary TEXT,
  status TEXT DEFAULT 'new'
);

CREATE INDEX idx_alerts_score ON alerts (priority_score DESC);
CREATE INDEX idx_alerts_technique ON alerts (technique_id);

