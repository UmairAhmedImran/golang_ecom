package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/middleware"
	"github.com/UmairAhmedImran/ecom/service/auth"
	"github.com/UmairAhmedImran/ecom/types"
	"github.com/UmairAhmedImran/ecom/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	router.Get("/auth/google", h.googleAuthHandler)
	router.Get("/auth/google/callback", h.googleCallbackHandler)
	router.Get("/cookie", middleware.AuthMiddleware(http.HandlerFunc(h.handleGetProfile)))
}

var googleOauthConfig *oauth2.Config

func init() {
	godotenv.Load()
	googleOauthConfig = &oauth2.Config{
		ClientID:     config.GetEnv("GOOGLE_CLIENT_ID", ""),
		ClientSecret: config.GetEnv("GOOGLE_CLIENT_SECRET", ""),
		RedirectURL:  config.GetEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	user, err := h.store.GetUserByEmail(ctx, payload.Email)
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
	accessExpiry := time.Now().Add(15 * time.Minute)
	refreshExpiry := time.Now().Add(30 * 24 * time.Hour)

	// secure := config.GetEnv("ENV", "development") == "production"
	// Store the refresh token in your database
	rt := types.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: refreshExpiry,
	}
	fmt.Println(rt)
	if err := h.store.CreateRefreshToken(ctx, rt); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Set the refresh token as an HTTP-only, secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		Expires:  refreshExpiry,
		Secure:   false,
		HttpOnly: true, // HttpOnly is false because we are not using HTTPS as of now in development  // Ensure your application is served over HTTPS
		Path:     "/",  // Set cookie path as needed
		// SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Expires:  accessExpiry,
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
	})

	// Return both tokens to the client
	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Get JSON payload
	var payload types.RegisterUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		fmt.Println("Payload working")
		return
	}

	// Validate the payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
		fmt.Println("Validate Payload working")
		return
	}

	// Check if user exists
	existingUser, err := h.store.GetUserByEmail(ctx, payload.Email)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			// User does not exist, proceed to create a new user
		} else {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to check user existence: %w", err))
			return
		}
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
	err = h.store.CreateUser(ctx, types.User{
		FullName:  payload.FullName,
		Email:     payload.Email,
		Password:  hashedPassword,
		Otp:       otp,
		OtpExpiry: otpExpiry,
		Verified:  false,
	})
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		fmt.Println("Creating User working")
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
	ctx := r.Context()
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
	user, err := h.store.GetUserByEmail(ctx, payload.Email)
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
	if err := h.store.MarkUserAsVerified(ctx, user.ID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Return success response
	utils.WriteJSON(w, http.StatusOK, map[string]string{"message": "User verified successfully"})
}

func (h *Handler) handleResendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	user, err := h.store.GetUserByEmail(ctx, payload.Email)
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
	err = h.store.UpdateUserOTP(ctx, user.ID, otp, otpExpiry)
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
	ctx := r.Context()
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
	user, err := h.store.GetUserByEmail(ctx, payload.Email)
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
	err = h.store.UpdateUserOTP(ctx, user.ID, otp, otpExpiry)
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
	ctx := r.Context()
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
	user, err := h.store.GetUserByEmail(ctx, payload.Email)
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
	if err := h.store.UpdatePassword(ctx, user.ID, hashedPassword); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Clear the OTP after successful password reset
	err = h.store.UpdateUserOTP(ctx, user.ID, "", time.Time{})
	if err != nil {
		// Log the error but don't return it to the user since the password was updated successfully
		log.Printf("Error clearing OTP: %v", err)
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Password updated successfully",
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Retrieve the refresh token from the cookie
	cookie, err := r.Cookie("refreshToken")
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("refresh token cookie not found"))
		return
	}
	refreshToken := cookie.Value

	// Delete the refresh token from the database
	if err := h.store.DeleteRefreshToken(ctx, refreshToken); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Clear the refresh token cookie by setting a past expiry date
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		// SameSite: http.SameSiteNoneMode,
		Secure: false,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthstate",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fmt.Println("Cookkieesss", r.Cookies())
	// Get the refresh token from the HTTP-only cookie
	cookie, err := r.Cookie("refreshToken")
	fmt.Println("cookie", cookie)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token cookie not found"))
		return
	}
	oldRefreshToken := cookie.Value
	fmt.Println("oldRefreshToken", oldRefreshToken)

	// Validate the old refresh token from the database
	rt, err := h.store.GetRefreshToken(ctx, oldRefreshToken)
	if err != nil || rt == nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid refresh token"))
		return
	}
	fmt.Println("rt", rt)
	if time.Now().After(rt.ExpiresAt) {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token expired"))
		return
	}
	// At this point, the old refresh token is valid
	// Invalidate/delete the old refresh token (rotation)
	if err := h.store.DeleteRefreshToken(ctx, rt.Token); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate a new refresh token
	newRefreshToken, err := auth.GenerateRandomToken(32)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	accessExpiry := time.Now().Add(15 * time.Minute)
	refreshExpiry := time.Now().Add(30 * 24 * time.Hour) // for refresh

	// Store the new refresh token in the database
	newRT := types.RefreshToken{
		Token:     newRefreshToken,
		UserID:    rt.UserID,
		ExpiresAt: refreshExpiry,
	}
	if err := h.store.CreateRefreshToken(ctx, newRT); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate a new access token
	secret := []byte(config.GetEnv("JWT_SECRET", ""))
	newtoken, err := auth.CreateJWT(secret, rt.UserID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	// Set the new refresh token as an HTTP-only, secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    newRefreshToken,
		Expires:  refreshExpiry,
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
		// SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    newtoken,
		Expires:  accessExpiry,
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
		// SameSite: http.SameSiteNoneMode,
	})

	// Return the new access token to the client
	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"token": newtoken,
	})
}
func (h *Handler) googleAuthHandler(w http.ResponseWriter, r *http.Request) {
	// Generate random state
	state := fmt.Sprintf("%d", time.Now().UnixNano())

	// Store state in cookie for validation during callback
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Expires:  time.Now().Add(15 * time.Minute),
		HttpOnly: true,
		Path:     "/", // Make sure cookie is available for all paths
		// SameSite: http.SameSiteLaxMode, // Less restrictive than Strict
	})

	// Redirect to Google's OAuth server
	url := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
func (h *Handler) googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Validate state
	oauthCookie, err := r.Cookie("oauthstate")
	if err != nil || r.FormValue("state") != oauthCookie.Value {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid OAuth state"))
		return
	}

	// 2. Exchange code for token
	code := r.FormValue("code")
	tok, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// 3. Get user info from Google
	client := googleOauthConfig.Client(ctx, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	defer resp.Body.Close()

	var userInfo types.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// 4. Look up or create user
	user, err := h.store.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		newUser := types.User{
			FullName: userInfo.GivenName + " " + userInfo.FamilyName,
			Email:    userInfo.Email,
			GoogleID: userInfo.Sub,
			Verified: true,
		}
		if err := h.store.CreateUser(ctx, newUser); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		user, _ = h.store.GetUserByEmail(ctx, userInfo.Email)
	} else if user.GoogleID == "" {
		if err := h.store.UpdateUserGoogleID(ctx, user.ID, userInfo.Sub); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}

	// 5. Generate access and refresh tokens
	secret := []byte(config.GetEnv("JWT_SECRET", ""))
	jwtToken, err := auth.CreateJWT(secret, user.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	refreshToken, err := auth.GenerateRandomToken(32)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	accessExpiry := time.Now().Add(15 * time.Minute)
	refreshExpiry := time.Now().Add(30 * 24 * time.Hour)

	// secure := config.GetEnv("ENV", "development") == "production"
	// Store the refresh token in your database
	rt := types.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: refreshExpiry,
	}
	fmt.Println(rt)
	if err := h.store.CreateRefreshToken(ctx, rt); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// 6. Store refresh token (optional: in DB or in-memory)
	// e.g., h.tokenStore.Save(refreshToken)

	// 7. Set refresh token as HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		HttpOnly: true,
		Path:     "/",
		Expires:  refreshExpiry,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    jwtToken,
		Expires:  accessExpiry,
		HttpOnly: true,
		Path:     "/",
	})

	// 8. Redirect to frontend with access token (in URL)
	frontendURL := config.GetEnv("FRONTEND_URL", "http://localhost:3000")
	http.Redirect(w, r,
		fmt.Sprintf("%s/callback?token=%s", frontendURL, jwtToken),
		http.StatusTemporaryRedirect,
	)
}

func (h *Handler) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr, ok := ctx.Value(middleware.UserIDKey).(string)
	fmt.Println("userIDStr", userIDStr)
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("user ID not found in context"))
		return
	}
	user, err := h.store.GetUserByID(ctx, uuid.MustParse(userIDStr))
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, user)
}
