-- Directory fields synced in from Rally (Prismonian's HR/directory
-- system) — display name, office building/suite, department, phone,
-- and network ID. All five are plain, nullable text: admin/CLI-managed
-- only (there's no self-service edit path for any of them, unlike
-- full_name/description/theme), and no uniqueness constraint on
-- network_id, same reasoning as email in migration 001 — this is
-- directory data handed to Passport, not a lookup key Passport itself
-- enforces uniqueness on.
ALTER TABLE userdata ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE userdata ADD COLUMN IF NOT EXISTS office_location TEXT;
ALTER TABLE userdata ADD COLUMN IF NOT EXISTS department TEXT;
ALTER TABLE userdata ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE userdata ADD COLUMN IF NOT EXISTS network_id TEXT;
