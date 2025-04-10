package types

import (
	"context"
	"time"
)

type UserStore interface {
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id int) (*User, error)
	CreateUser(ctx context.Context, user User) error
	MarkUserAsVerified(ctx context.Context, userID string) error
	UpdateUserOTP(ctx context.Context, userID string, otp string, otpExpiry time.Time) error
	UpdatePassword(ctx context.Context, userID string, hashedPassword string) error
	CreateRefreshToken(ctx context.Context, token RefreshToken) error
	DeleteRefreshToken(ctx context.Context, token string) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
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
	ID        string    `db:"id"         json:"id"`
	FirstName string    `db:"first_name" json:"first_name"`
	LastName  string    `db:"last_name"  json:"last_name"`
	Email     string    `db:"email"      json:"email"`
	Password  string    `db:"password"   json:"-"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
	Otp       string    `db:"otp"        json:"otp"`
	OtpExpiry time.Time `db:"otp_expiry" json:"otp_expiry"`
	Verified  bool      `db:"verified"   json:"verified"`
}

type RegisterUserPayload struct {
	FirstName string `json:"first_name" db:"first_name" validate:"required"`
	LastName  string `json:"last_name" db:"last_name" validate:"required"`
	Email     string `json:"email" db:"email" validate:"required,email"`
	Password  string `json:"password" db:"password" validate:"required,min=8,max=130"`
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
