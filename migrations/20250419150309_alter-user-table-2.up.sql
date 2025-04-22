-- Add up migration script here
ALTER TABLE users
ADD COLUMN google_id VARCHAR(255);