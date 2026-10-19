UPDATE relations SET relation='delegate' WHERE relation='agent';

UPDATE audit_log SET details=jsonb_set(details,'{relation}','"delegate"'::jsonb)
  WHERE action IN ('relation.add','relation.remove') AND details->>'relation'='agent';

UPDATE executions SET proposal=jsonb_set(proposal,'{relation}','"delegate"'::jsonb)
  WHERE proposal->>'kind'='line' AND proposal->>'relation'='agent';
