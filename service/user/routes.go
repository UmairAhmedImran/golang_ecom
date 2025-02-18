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
	router.Post("/forgot-password/init", h.handleForgotPasswordInit)
	router.Post("/forgot-password/complete", h.handleForgotPasswordComplete)
	router.Post("/logout", h.handleLogout)
	router.Post("/refresh", h.handleRefresh)
	router.Post("/logout", h.handleLogout)

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
	refreshToken, err := auth.GenerateRandomToken(32)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	// Define a refresh token expiry time, for example, 7 days
	refreshExpiry := time.Now().Add(30 * 24 * time.Hour)

	// Store the refresh token in your database
	rt := types.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: refreshExpiry,
	}
	if err := h.store.CreateRefreshToken(rt); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Set the refresh token as an HTTP-only, secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		Expires:  refreshExpiry,
		HttpOnly: false, // HttpOnly is false because we are not using HTTPS as of now in development
		Secure:   false, // Ensure your application is served over HTTPS
		Path:     "/",   // Set cookie path as needed
		SameSite: http.SameSiteStrictMode,
	})

	// Return both tokens to the client
	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"accessToken":  token,
		"refreshToken": refreshToken,
	})
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
		timeLeft := time.Until(user.OtpExpiry)
		utils.WriteError(w, http.StatusTooManyRequests,
			fmt.Errorf("please wait %d minutes before requesting a new OTP", timeLeft))
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
		timeLeft := time.Until(user.OtpExpiry)
		utils.WriteError(w, http.StatusTooManyRequests,
			fmt.Errorf("please wait %d minutes before requesting a new OTP", timeLeft))
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

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Retrieve the refresh token from the cookie
	cookie, err := r.Cookie("refreshToken")
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("refresh token cookie not found"))
		return
	}
	refreshToken := cookie.Value

	// Delete the refresh token from the database
	if err := h.store.DeleteRefreshToken(refreshToken); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Clear the refresh token cookie by setting a past expiry date
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		Secure:   false,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Get the refresh token from the HTTP-only cookie
	cookie, err := r.Cookie("refreshToken")
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token cookie not found"))
		return
	}
	fmt.Println("refresh token", cookie.Value)
	oldRefreshToken := cookie.Value

	// Validate the old refresh token from the database
	rt, err := h.store.GetRefreshToken(oldRefreshToken)
	if err != nil || rt == nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid refresh token"))
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token expired"))
		return
	}
	fmt.Println("refresh token from database", rt.Token)
	fmt.Println("User ID from database", rt.UserID)
	fmt.Println("Expires at from database", rt.ExpiresAt)

	// At this point, the old refresh token is valid
	// Invalidate/delete the old refresh token (rotation)
	if err := h.store.DeleteRefreshToken(rt.UserID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate a new refresh token
	newRefreshToken, err := auth.GenerateRandomToken(32)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	fmt.Println("new refresh token", newRefreshToken)
	newRefreshExpiry := time.Now().Add(30 * 24 * time.Hour)

	// Store the new refresh token in the database
	newRT := types.RefreshToken{
		Token:     newRefreshToken,
		UserID:    rt.UserID,
		ExpiresAt: newRefreshExpiry,
	}
	if err := h.store.CreateRefreshToken(newRT); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate a new access token
	secret := []byte(config.GetEnv("JWT_SECRET", ""))
	newAccessToken, err := auth.CreateJWT(secret, rt.UserID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	// Set the new refresh token as an HTTP-only, secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    newRefreshToken,
		Expires:  newRefreshExpiry,
		HttpOnly: false,
		Secure:   false,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	// Return the new access token to the client
	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
	})
}
