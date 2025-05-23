package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/service/auth"
	"github.com/UmairAhmedImran/ecom/utils"
)

type ctxKey string

// exported so other packages (e.g. your handlers) can read it
const UserIDKey ctxKey = "userID"

func AuthMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ✅ Step 1: Read the token from the cookie
		cookie, err := r.Cookie("token")
		if err != nil {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("missing auth cookie"))
			return
		}
		token := cookie.Value

		// ✅ Step 2: Parse and validate the token
		secret := []byte(config.GetEnv("JWT_SECRET", "secret"))

		claims, err := auth.ParseJWT(secret, token)
		if err != nil {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token: %v", err))
			return
		}

		// ✅ Step 3: Extract user ID
		var userIDStr string
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			userIDStr = sub
		} else if userId, ok := claims["userId"].(string); ok && userId != "" {
			userIDStr = userId
		} else {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("missing user ID in token"))
			return
		}
		fmt.Println("userIDStr", userIDStr)

		// ✅ Step 4: Add userID to context
		ctx := context.WithValue(r.Context(), UserIDKey, userIDStr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
