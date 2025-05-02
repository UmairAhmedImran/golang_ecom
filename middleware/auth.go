package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/service/auth"
	"github.com/UmairAhmedImran/ecom/utils"
)

type ctxKey string

// exported so other packages (e.g. your handlers) can read it
const UserIDKey ctxKey = "userID"

func AuthMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		fmt.Printf("Auth header: %s\n", authHeader)

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("missing or invalid auth header"))
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate the token
		secret := []byte(config.GetEnv("JWT_SECRET", "secret"))
		fmt.Printf("Secret: %s\n", secret)

		claims, err := auth.ParseJWT(secret, token)
		if err != nil {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token: %v", err))
			return
		}

		// Check for userID in claims - IMPORTANT: Check both "sub" and "userId"
		var userIDStr string

		// First try "sub" (standard JWT claim)
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			userIDStr = sub
		} else if userId, ok := claims["userId"].(string); ok && userId != "" {
			// Then try "userId" (your custom claim)
			userIDStr = userId
		} else {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("missing user ID in token"))
			return
		}

		// Store the user ID under our custom key
		ctx := context.WithValue(r.Context(), UserIDKey, userIDStr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
