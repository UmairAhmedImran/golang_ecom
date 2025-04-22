-- Add down migration script here
ALTER TABLE users
DROP COLUMN google_id;