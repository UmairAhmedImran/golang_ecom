CREATE TYPE status AS ENUM ('pending', 'processing', 'shipped', 'completed', 'cancelled');
CREATE TABLE IF NOT EXISTS orders (
  "id" uuid PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
  "user_Id" uuid NOT NULL REFERENCES users(id),
  "total" decimal(10, 2) NOT NULL,
  "status" status NOT NULL DEFAULT 'pending',
  "address" varchar NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE DEFAUlT NOW()
);
