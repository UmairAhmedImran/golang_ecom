ALTER TABLE users
ADD COLUMN otp VARCHAR(6),
ADD COLUMN otp_expiry TIMESTAMP WITH TIME ZONE,
ADD COLUMN verified BOOLEAN DEFAULT FALSE;