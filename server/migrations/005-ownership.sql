-- When each principal and thing came to its owner: when it was made there, taken on or passed on. The database keeps
-- it as the owner changes, whichever way it changes. A principal without an owner has none.
ALTER TABLE principals ADD COLUMN owned_at timestamptz;
ALTER TABLE resources ADD COLUMN owned_at timestamptz;

-- What came to its owner before this was kept: when it was made, or when the audit last records it passed on. A thing
-- a key protects is passed on by sealing it for its new owner, first recorded there after the other owner's sealing.
UPDATE principals p SET owned_at=greatest(p.created_at,
  (SELECT max(a.created_at) FROM audit_log a WHERE a.action='principal.transfer' AND a.owner_id=p.id))
  WHERE p.owner_id IS NOT NULL;
UPDATE resources x SET owned_at=greatest(x.created_at,
  (SELECT max(a.created_at) FROM audit_log a WHERE a.action='resource.receive' AND a.target_id=x.id),
  (SELECT min(a.created_at) FROM audit_log a WHERE a.action='resource.protect' AND a.target_id=x.id
    AND a.owner_id=x.owner_id AND a.created_at>(SELECT max(b.created_at) FROM audit_log b
      WHERE b.action='resource.protect' AND b.target_id=x.id AND b.owner_id<>x.owner_id)));

ALTER TABLE principals ADD CONSTRAINT principals_owned_at CHECK ((owner_id IS NULL) = (owned_at IS NULL));
ALTER TABLE resources ALTER COLUMN owned_at SET NOT NULL;

CREATE FUNCTION stamp_owned_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' OR NEW.owner_id IS DISTINCT FROM OLD.owner_id THEN
    NEW.owned_at := CASE WHEN NEW.owner_id IS NULL THEN NULL ELSE now() END;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER principals_owned_at BEFORE INSERT OR UPDATE OF owner_id ON principals
  FOR EACH ROW EXECUTE FUNCTION stamp_owned_at();
CREATE TRIGGER resources_owned_at BEFORE INSERT OR UPDATE OF owner_id ON resources
  FOR EACH ROW EXECUTE FUNCTION stamp_owned_at();
