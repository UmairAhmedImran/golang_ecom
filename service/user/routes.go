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
	router.Get("/profile", middleware.AuthMiddleware(http.HandlerFunc(h.handleGetProfile)))
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
	refreshExpiry := time.Now().Add(30 * 24 * time.Hour)

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
		HttpOnly: true, // HttpOnly is false because we are not using HTTPS as of now in development  // Ensure your application is served over HTTPS
		Path:     "/",  // Set cookie path as needed
		SameSite: http.SameSiteStrictMode,
	})

	// Return both tokens to the client
	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
		"user":         user,
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
		SameSite: http.SameSiteStrictMode,
	})

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Get the refresh token from the HTTP-only cookie
	cookie, err := r.Cookie("refreshToken")
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token cookie not found"))
		return
	}
	oldRefreshToken := cookie.Value

	// Validate the old refresh token from the database
	rt, err := h.store.GetRefreshToken(ctx, oldRefreshToken)
	if err != nil || rt == nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid refresh token"))
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token expired"))
		return
	}
	// At this point, the old refresh token is valid
	// Invalidate/delete the old refresh token (rotation)
	if err := h.store.DeleteRefreshToken(ctx, rt.UserID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate a new refresh token
	newRefreshToken, err := auth.GenerateRandomToken(32)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	newRefreshExpiry := time.Now().Add(30 * 24 * time.Hour)

	// Store the new refresh token in the database
	newRT := types.RefreshToken{
		Token:     newRefreshToken,
		UserID:    rt.UserID,
		ExpiresAt: newRefreshExpiry,
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
		Expires:  newRefreshExpiry,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	// Return the new access token to the client
	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"token":        newtoken,
		"refreshToken": newRefreshToken,
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
		Path:     "/",                  // Make sure cookie is available for all paths
		SameSite: http.SameSiteLaxMode, // Less restrictive than Strict
	})

	// Redirect to Google's OAuth server
	url := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
func (h *Handler) googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1) Validate oauth-state from the cookie
	oauthCookie, err := r.Cookie("oauthstate")
	if err != nil {
		log.Printf("Error retrieving oauthstate cookie: %v", err)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid OAuth state: cookie not found"))
		return
	}
	if r.FormValue("state") != oauthCookie.Value {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid OAuth state"))
		return
	}

	// 2) Exchange code for token
	code := r.FormValue("code")
	tok, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// 3) Fetch user info from Google
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

	// 4) Look up or create the user in our DB
	user, err := h.store.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		// Not found → create, then re-fetch
		newUser := types.User{
			FullName: userInfo.FamilyName + " " + userInfo.GivenName,
			Email:    userInfo.Email,
			GoogleID: userInfo.Sub,
			Verified: true,
		}
		if err := h.store.CreateUser(ctx, newUser); err != nil {
			log.Printf("Error creating user: %v", err)
			utils.WriteError(w, http.StatusInternalServerError, err)
			return
		}

		// Re-fetch so we pick up the generated UUID
		user, err = h.store.GetUserByEmail(ctx, userInfo.Email)
		if err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		// Already exists → ensure GoogleID is set
		if user.GoogleID == "" {
			if err := h.store.UpdateUserGoogleID(ctx, user.ID, userInfo.Sub); err != nil {
				utils.WriteError(w, http.StatusInternalServerError, err)
				return
			}
		}
	}

	// 5) Issue JWT with the correct UUID
	secret := []byte(config.GetEnv("JWT_SECRET", ""))
	jwtToken, err := auth.CreateJWT(secret, user.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	// 6) Redirect back to frontend
	frontendURL := config.GetEnv("FRONTEND_URL", "http://localhost:3000")
	http.Redirect(w, r,
		fmt.Sprintf("%s/callback?token=%s", frontendURL, jwtToken),
		http.StatusTemporaryRedirect,
	)
}

func (h *Handler) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := ctx.Value(middleware.UserIDKey).(string)

	user, err := h.store.GetUserByID(ctx, uuid.MustParse(userIDStr))
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, user)
}
