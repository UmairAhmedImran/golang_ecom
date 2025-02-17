CREATE TABLE IF NOT EXISTS refresh_tokens (
    "userId" uuid REFERENCES users(id) NOT NULL,
    "token" varchar NOT NULL,
    "expiresAt" TIMESTAMP NOT NULL
);
