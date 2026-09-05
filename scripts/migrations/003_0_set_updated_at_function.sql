-- Compatibility migration for databases that run numbered migrations without
-- first applying the fresh-install DB_SCHEMA.sql baseline.

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
