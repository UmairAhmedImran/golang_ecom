package types

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type UserStore interface {
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	CreateUser(ctx context.Context, user User) error
	MarkUserAsVerified(ctx context.Context, userID string) error
	UpdateUserOTP(ctx context.Context, userID string, otp string, otpExpiry time.Time) error
	UpdatePassword(ctx context.Context, userID string, hashedPassword string) error
	CreateRefreshToken(ctx context.Context, token RefreshToken) error
	DeleteRefreshToken(ctx context.Context, token string) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	UpdateUserGoogleID(ctx context.Context, userID string, googleID string) error
}

type ProductStore interface {
	GetProducts(ctx context.Context) ([]Product, error)
}

type Product struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	Price       float64   `db:"price" json:"price"`
	Quantity    int       `db:"quantity" json:"quantity"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}
type User struct {
	ID                string    `db:"id"         json:"id"`
	FullName          string    `db:"full_name" json:"full_name"`
	Email             string    `db:"email"      json:"email"`
	Password          string    `db:"password"   json:"-"`
	CreatedAt         time.Time `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time `db:"updated_at" json:"updated_at"`
	Otp               string    `db:"otp"        json:"otp"`
	OtpExpiry         time.Time `db:"otp_expiry" json:"otp_expiry"`
	Verified          bool      `db:"verified"   json:"verified"`
	GoogleID          string    `db:"google_id"  json:"google_id"`
	SubscriptionPlan  string    `db:"subscription_plan" json:"subscription_plan"`
	QuotaUsedMinutes  int       `db:"quota_used_minutes" json:"quota_used_minutes"`
	QuotaTotalMinutes int       `db:"quota_total_minutes" json:"quota_total_minutes"`
}

type RegisterUserPayload struct {
	FullName string `json:"full_name" db:"full_name" validate:"required"`
	Email    string `json:"email" db:"email" validate:"required,email"`
	Password string `json:"password" db:"password" validate:"required,min=8,max=130"`
}

type LoginUserPayload struct {
	Email    string `json:"email" db:"email" validate:"required,email"`
	Password string `json:"password" db:"password" validate:"required"`
}

type VerifyOTPPayload struct {
	Email string `json:"email" db:"email" validate:"required,email"`
	OTP   string `json:"otp" db:"otp" validate:"required,len=6"`
}

type ResendOTPPayload struct {
	Email string `json:"email" db:"email" validate:"required,email"`
}

type ForgotPasswordInitPayload struct {
	Email string `json:"email" db:"email" validate:"required,email"`
}

type ForgotPasswordCompletePayload struct {
	Email       string `json:"email" db:"email" validate:"required,email"`
	OTP         string `json:"otp" db:"otp" validate:"required,len=6"`
	NewPassword string `json:"newPassword" db:"new_password" validate:"required,min=8,max=130"`
}

type RefreshToken struct {
	UserID    string    `json:"user_id" db:"user_id" validate:"required"`
	Token     string    `json:"token" db:"token" validate:"required"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at" validate:"required"`
}

// TokenResponse represents the token sent back to client
type TokenResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type GoogleUserInfo struct {
	Sub           string `json:"sub" db:"sub"`
	Name          string `json:"name" db:"name"`
	GivenName     string `json:"given_name" db:"given_name"`
	FamilyName    string `json:"family_name" db:"family_name"`
	Picture       string `json:"picture" db:"picture"`
	Email         string `json:"email" db:"email"`
	EmailVerified bool   `json:"email_verified" db:"email_verified"`
}
