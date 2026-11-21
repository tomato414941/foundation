-- Foundation takes no payments, so what billing kept goes: payment accounts and Stripe's events, the storage measured
-- each hour to charge for and its marks, the storage limits chosen to bound spending, the operations that set them, and
-- the lines that named who pays and who manages billing.
DROP TABLE payment_webhooks;
DROP TABLE billing_events;
DROP TABLE payment_accounts;
DROP TABLE usage_limits;
DELETE FROM system_settings WHERE name LIKE 'storage-meter:%';
DELETE FROM operations WHERE name LIKE 'billing.%';
DROP INDEX relations_payer;
DELETE FROM relations WHERE relation IN ('payer', 'billing_manager');
-- Only a line naming who pays waited on its other side.
UPDATE requests SET proposal = NULL WHERE proposal->>'kind' = 'line';
