package user

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/service/auth"
	"github.com/UmairAhmedImran/ecom/types"
	"github.com/UmairAhmedImran/ecom/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

type Handler struct {
	store types.UserStore
}

func NewHandler(store types.UserStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router chi.Router) {
	router.Post("/login", h.handleLogin)
	router.Post("/register", h.handleRegister)
	router.Post("/handle-verify", h.handleVerify)
	router.Post("/resend-otp", h.handleResendOTP)
	router.Get("/health", h.handleHealth)
	router.Post("/forgot-password/init", h.handleForgotPasswordInit)
	router.Post("/forgot-password/complete", h.handleForgotPasswordComplete)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	log.Println("healthCheck")
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Get JSON payload
	var payload types.LoginUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		return
	}

	// Check if user exists
	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s not found", payload.Email))
		return
	}

	// check if user is verified or not
	if !user.Verified {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("user is not verified"))
		return
	}

	// Compare passwords
	if !auth.ComparePassword(user.Password, []byte(payload.Password)) {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid email or password"))
		return
	}

	// Create JWT token
	secret := []byte(config.GetEnv("JWT_SECRET", ""))
	token, err := auth.CreateJWT(secret, user.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Return the token
	utils.WriteJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Get JSON payload
	var payload types.RegisterUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		return
	}

	// Check if user exists
	existingUser, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to check user existence: %w", err))
		return
	}
	if existingUser != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s already exists", payload.Email))
		return
	}

	// Hash the password
	hashedPassword, err := auth.HashPassword(payload.Password)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate OTP and set expiry time
	otp := auth.GenerateOTP()
	otpExpiry := time.Now().Add(time.Minute * 10) // OTP expires in 10 minutes

	// Create new user
	err = h.store.CreateUser(types.User{
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Email:     payload.Email,
		Password:  hashedPassword,
		Otp:       otp,
		OtpExpiry: otpExpiry,
		Verified:  false,
	})
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	// Send OTP to user's email
	err = auth.SendOTPEmail(payload.Email, otp)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, nil)
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	// Get JSON payload
	var payload types.VerifyOTPPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		return
	}

	// Check if user exists
	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s not found", payload.Email))
		return
	}

	// Verify OTP
	if user.Otp != payload.OTP || time.Now().After(user.OtpExpiry) {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid or expired OTP"))
		return
	}

	// Mark user as verified
	if err := h.store.MarkUserAsVerified(user.ID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Return success response
	utils.WriteJSON(w, http.StatusOK, map[string]string{"message": "User verified successfully"})
}

func (h *Handler) handleResendOTP(w http.ResponseWriter, r *http.Request) {
	// Get JSON payload
	var payload types.ResendOTPPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		return
	}

	// Get user by email
	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s not found", payload.Email))
		return
	}

	// Check if user is already verified
	if user.Verified {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user is already verified"))
		return
	}

	// Check if previous OTP is still valid and not expired
	if !user.OtpExpiry.IsZero() && time.Now().Before(user.OtpExpiry) {
		timeLeft := user.OtpExpiry.Sub(time.Now()).Minutes()
		utils.WriteError(w, http.StatusTooManyRequests,
			fmt.Errorf("please wait %.0f minutes before requesting a new OTP", timeLeft))
		return
	}

	// Generate new OTP and set expiry time
	otp := auth.GenerateOTP()
	otpExpiry := time.Now().Add(time.Minute * 10) // OTP expires in 10 minutes

	// Update user with new OTP
	err = h.store.UpdateUserOTP(user.ID, otp, otpExpiry)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Send OTP to user's email
	err = auth.SendOTPEmail(payload.Email, otp)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Return success response with new JWT
	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "New OTP sent to email",
	})
}

func (h *Handler) handleForgotPasswordInit(w http.ResponseWriter, r *http.Request) {
	// Get JSON payload
	var payload types.ForgotPasswordInitPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		return
	}

	// Get user by email
	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s not found", payload.Email))
		return
	}

	// Check if previous OTP is still valid and not expired
	if !user.OtpExpiry.IsZero() && time.Now().Before(user.OtpExpiry) {
		timeLeft := user.OtpExpiry.Sub(time.Now()).Minutes()
		utils.WriteError(w, http.StatusTooManyRequests,
			fmt.Errorf("please wait %.0f minutes before requesting a new OTP", timeLeft))
		return
	}

	// Generate new OTP and set expiry time
	otp := auth.GenerateOTP()
	otpExpiry := time.Now().Add(time.Minute * 10) // OTP expires in 10 minutes

	// Update user with new OTP
	err = h.store.UpdateUserOTP(user.ID, otp, otpExpiry)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Send password reset OTP to user's email
	err = auth.SendOTPEmail(payload.Email, otp)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset OTP sent to email",
	})
}

func (h *Handler) handleForgotPasswordComplete(w http.ResponseWriter, r *http.Request) {
	// Get JSON payload
	var payload types.ForgotPasswordCompletePayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		return
	}

	// Get user by email
	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s not found", payload.Email))
		return
	}

	// Verify OTP
	if user.Otp != payload.OTP || time.Now().After(user.OtpExpiry) {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid or expired OTP"))
		return
	}

	// Hash the new password
	hashedPassword, err := auth.HashPassword(payload.NewPassword)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Update password
	if err := h.store.UpdatePassword(user.ID, hashedPassword); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Clear the OTP after successful password reset
	err = h.store.UpdateUserOTP(user.ID, "", time.Time{})
	if err != nil {
		// Log the error but don't return it to the user since the password was updated successfully
		log.Printf("Error clearing OTP: %v", err)
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Password updated successfully",
	})
}
