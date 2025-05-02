ALTER TABLE users
ADD COLUMN first_name varchar not null,
ADD COLUMN last_name varchar not null,
DROP COLUMN full_name;
