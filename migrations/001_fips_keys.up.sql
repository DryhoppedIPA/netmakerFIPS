-- File: migrations/001_fips_keys.up.sql

-- 1) Update nodes table
ALTER TABLE nodes 
    ALTER COLUMN public_key TYPE VARCHAR(89);

-- 2) Update hosts table
ALTER TABLE hosts 
    ALTER COLUMN public_key TYPE VARCHAR(89);

-- 3) Update extclients table
ALTER TABLE extclients 
    ALTER COLUMN public_key TYPE VARCHAR(89),
    ALTER COLUMN private_key TYPE VARCHAR(89);

-- 4) Add indexes for performance (if not already present)
CREATE INDEX IF NOT EXISTS idx_nodes_public_key ON nodes(public_key);
CREATE INDEX IF NOT EXISTS idx_hosts_public_key ON hosts(public_key);
CREATE INDEX IF NOT EXISTS idx_extclients_public_key ON extclients(public_key); 