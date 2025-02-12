CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  "id" uuid PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
  "firstName" varchar NOT NULL,
  "lastName" varchar NOT NULL,
  "email" varchar NOT NULL,
  "password" varchar NOT NULL,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAUlT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAUlT NOW()
);
