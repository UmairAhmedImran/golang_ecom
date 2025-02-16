package user

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/service/auth"
	"github.com/UmairAhmedImran/ecom/types"
	"github.com/UmairAhmedImran/ecom/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
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
	router.Post("/handle_verify", h.handleVerify)
	router.Get("/health", h.handleHealth)

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
	// Generate JWT with email
    secret := []byte(config.GetEnv("JWT_SECRET", ""))
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "email": payload.Email,
        "exp":   time.Now().Add(time.Minute * 10).Unix(), // Token expires in 10 minutes
    })

    tokenString, err := token.SignedString(secret)
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

	// Return the JWT to the client
    utils.WriteJSON(w, http.StatusCreated, map[string]string{
        "message": "OTP sent to email",
        "token":   tokenString,
    })
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

	// Extract JWT from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("missing authorization header"))
		return
	}

	// Remove "Bearer " prefix
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate JWT
	secret := []byte(config.GetEnv("JWT_SECRET", ""))
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !token.Valid {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid or expired token"))
		return
	}

	// Retrieve email from JWT claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to parse token claims"))
		return
	}
	email := claims["email"].(string)

	// Check if user exists
	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s not found", email))
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