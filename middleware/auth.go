package middleware

import (
	"net/http"
	"strings"

	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/utils"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware checks if the user is authenticated
func AuthMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the Authorization header
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			utils.WriteError(w, http.StatusUnauthorized, http.ErrNoCookie)
			return
		}

		// Remove "Bearer " prefix
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Parse the token
		secret := []byte(config.GetEnv("JWT_SECRET", ""))
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the algorithm
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNoCookie
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			utils.WriteError(w, http.StatusUnauthorized, err)
			return
		}

		// If valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}
