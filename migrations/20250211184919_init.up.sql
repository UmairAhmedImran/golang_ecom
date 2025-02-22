CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  "id" uuid PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
  "first_name" varchar NOT NULL,
  "last_name" varchar NOT NULL,
  "email" varchar NOT NULL,
  "password" varchar NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE DEFAUlT NOW(),
  "updated_at" TIMESTAMP WITH TIME ZONE DEFAUlT NOW()
);
