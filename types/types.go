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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Price     float64   `json:"price"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type User struct {
	ID        string    `json:"id"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Otp       string    `json:"otp"`
	OtpExpiry time.Time `json:"otp_expiry"`
	Verified  bool      `json:"verified"`
}

type RegisterUserPayload struct {
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8,max=130"`
}

type LoginUserPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type VerifyOTPPayload struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

type ResendOTPPayload struct {
	Email string `json:"email" validate:"required,email"`
}

type ForgotPasswordInitPayload struct {
	Email string `json:"email" validate:"required,email"`
}

type ForgotPasswordCompletePayload struct {
	Email       string `json:"email" validate:"required,email"`
	OTP         string `json:"otp" validate:"required,len=6"`
	NewPassword string `json:"newPassword" validate:"required,min=8,max=130"`
}

type RefreshToken struct {
	UserID    string    `json:"userId" validate:"required"`
	Token     string    `json:"token" validate:"required"`
	ExpiresAt time.Time `json:"expiresAt" validate:"required"`
}
