CREATE TABLE IF NOT EXISTS products (
  "id" uuid PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
  "name" varchar NOT NULL,
  "description" varchar NOT NULL,
  "price" decimal(10, 2) NOT NULL,
  "quantity" int NOT NULL,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAUlT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAUlT NOW()
);
