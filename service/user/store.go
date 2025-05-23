package user

import (
	"context"
	"fmt"
	"time"

	"github.com/UmairAhmedImran/ecom/types"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	var user types.User
	err := s.db.GetContext(ctx, &user, "SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*types.User, error) {
	var user types.User
	err := s.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) CreateUser(ctx context.Context, user types.User) error {
	query := `
		INSERT INTO users (
			full_name, email, password, 
			otp, otp_expiry, verified, google_id
		) VALUES (
			:full_name, :email, :password, 
			:otp, :otp_expiry, :verified, :google_id
		)
	`

	// For Google users, we need to provide a placeholder password
	if user.Password == "" && user.GoogleID != "" {
		user.Password = "GOOGLE_OAUTH_USER" // Just a placeholder, they'll never login with this
	}

	_, err := s.db.NamedExecContext(ctx, query, &user)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) MarkUserAsVerified(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET verified = TRUE WHERE id = $1`, userID)
	return err
}

func (s *Store) UpdateUserOTP(ctx context.Context, userID string, otp string, otpExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET otp = $1, otp_expiry = $2 WHERE id = $3`, otp, otpExpiry, userID)
	return err
}

func (s *Store) UpdatePassword(ctx context.Context, userID string, hashedPassword string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`, hashedPassword, userID)
	return err
}

func (s *Store) CreateRefreshToken(ctx context.Context, token types.RefreshToken) error {
	_, err := s.db.NamedExecContext(ctx, `INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)`, &token)
	return err
}

func (s *Store) GetRefreshToken(ctx context.Context, token string) (*types.RefreshToken, error) {
	var rt types.RefreshToken
	fmt.Println("token in store", token)
	fmt.Println("rt before query", rt)
	err := s.db.GetContext(ctx, &rt, `SELECT * FROM refresh_tokens WHERE token = $1`, token)
	if err != nil {
		fmt.Println("error in get refresh token", err)
		return nil, err
	}
	fmt.Println("rt after query", rt)
	return &rt, nil
}

func (s *Store) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, token)
	return err
}

func (s *Store) UpdateUserGoogleID(ctx context.Context, userID string, googleID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET google_id = $1 WHERE id = $2`, googleID, userID)
	return err
}
