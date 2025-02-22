CREATE TABLE IF NOT EXISTS refresh_tokens (
    "user_id" uuid REFERENCES users(id) NOT NULL,
    "token" varchar NOT NULL,
    "expires_at" TIMESTAMP NOT NULL
);
