-- Enforces "at least one enabled admin must always exist" at the database
-- level. Same idea as Global-Admin-Account-System's "last remaining
-- sysadmin" trigger, simplified to this fork's flat two-tier role: the
-- qualifying condition is just `role = 'admin' AND disabled = false` —
-- there's no second full-capability rank to also check.
--
-- Application code (src/routes/users.js, scripts/passport-cli.js) also
-- checks this before acting, but only a DB-level trigger sees every code
-- path atomically: two concurrent requests can both read "more than one
-- admin left" before either one's change commits, and together leave
-- zero — permanently locking everyone out of administration.
--
-- Takes a fixed advisory lock before counting, so two concurrent
-- admin-removing changes serialize against a single lock rather than
-- against each other's row locks (which, for the specific case of the
-- last two admins being changed at once, would otherwise deadlock).

CREATE OR REPLACE FUNCTION enforce_min_one_admin() RETURNS trigger AS $$
DECLARE
  remaining INTEGER;
  was_qualifying BOOLEAN;
  still_qualifying BOOLEAN;
BEGIN
  was_qualifying := (OLD.role = 'admin' AND OLD.disabled = false);
  IF NOT was_qualifying THEN
    RETURN COALESCE(NEW, OLD);
  END IF;

  IF TG_OP = 'DELETE' THEN
    still_qualifying := false;
  ELSE
    still_qualifying := (NEW.role = 'admin' AND NEW.disabled = false);
  END IF;
  IF still_qualifying THEN
    RETURN NEW;
  END IF;

  -- This row was a qualifying admin and, after this change, won't be —
  -- confirm at least one other one exists before allowing it.
  PERFORM pg_advisory_xact_lock(847362951);
  SELECT count(*) INTO remaining FROM userdata
    WHERE role = 'admin' AND disabled = false AND uid <> OLD.uid;
  IF remaining = 0 THEN
    RAISE EXCEPTION 'Cannot remove the last remaining admin account';
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_min_one_admin ON userdata;
CREATE TRIGGER trg_enforce_min_one_admin
  BEFORE UPDATE OR DELETE ON userdata
  FOR EACH ROW EXECUTE FUNCTION enforce_min_one_admin();
