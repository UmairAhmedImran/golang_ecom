package types

import "time"

type UserStore interface {
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id int) (*User, error)
	CreateUser(User) error
	MarkUserAsVerified(userID string) error
	UpdateUserOTP(userID string, otp string, otpExpiry time.Time) error
	UpdatePassword(userID string, hashedPassword string) error
	InvalidateToken(userID string) error
	CreateRefreshToken(token RefreshToken) error
	DeleteRefreshToken(token string) error
	GetRefreshToken(token string) (*RefreshToken, error)
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
	Token     string    `json:"token" validate:"required"`
	UserID    string    `json:"userId" validate:"required"`
	ExpiresAt time.Time `json:"expiresAt" validate:"required"`
}
