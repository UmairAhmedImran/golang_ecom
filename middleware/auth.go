// package middleware

// import (
// 	"context"
// 	"fmt"
// 	"net/http"

// 	"github.com/UmairAhmedImran/ecom/config"
// 	"github.com/UmairAhmedImran/ecom/utils"
// 	"github.com/golang-jwt/jwt/v5"
// )

// // Define custom key type
// type contextKey string

// const userIDKey contextKey = "userID"

// // AuthMiddleware checks if the user is authenticated
// // func AuthMiddleware(next http.Handler) http.HandlerFunc {
// // 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 		// Get the token from the Authorization header
// // 		tokenString := r.Header.Get("Authorization")
// // 		fmt.Println(tokenString)
// // 		if tokenString == "" {
// // 			utils.WriteError(w, http.StatusUnauthorized, http.ErrNoCookie)
// // 			return
// // 		}

// // 		// Remove "Bearer " prefix
// // 		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

// // 		// Parse the token
// // 		secret := []byte(config.GetEnv("JWT_SECRET", ""))
// // 		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// // 			// Validate the algorithm
// // 			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// // 				return nil, http.ErrNoCookie
// // 			}
// // 			return secret, nil
// // 		})

// // 		if err != nil || !token.Valid {
// // 			utils.WriteError(w, http.StatusUnauthorized, err)
// // 			return
// // 		}
// // 		fmt.Println("token is valid")

// // 		claims, ok := token.Claims.(jwt.MapClaims)
// // 		if !ok {
// // 			utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token claims"))
// // 			return
// // 		}
// // 		fmt.Println(claims)

// // 		// If valid, proceed to the next handler
// // 		next.ServeHTTP(w, r)
// // 	})
// // }

// func AuthMiddleware(next http.Handler) http.HandlerFunc {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// Get token from Authorization header
// 		authHeader := r.Header.Get("Authorization")
// 		if authHeader == "" {
// 			utils.WriteError(w, http.StatusUnauthorized, http.ErrNoCookie)
// 			return
// 		}

// 		// Check if header starts with "Bearer"
// 		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
// 			utils.WriteError(w, http.StatusUnauthorized, http.ErrNoCookie)
// 			return
// 		}

// 		// Extract token
// 		tokenString := authHeader[7:]

// 		// Parse and validate token
// 		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 			// Validate signing method
// 			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 			}
// 			return []byte(config.GetEnv("JWT_SECRET", "")), nil
// 		})

// 		if err != nil {
// 			utils.WriteError(w, http.StatusUnauthorized, err)
// 			return
// 		}

// 		// Extract claims
// 		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
// 			userIDStr := claims["user_id"].(string) // Get user_id as string
// 			ctx := context.WithValue(r.Context(), userIDKey, userIDStr)
// 			next.ServeHTTP(w, r.WithContext(ctx))
// 		} else {
// 			utils.WriteError(w, http.StatusUnauthorized, http.ErrNoCookie)
// 		}
// 	})
// }

// file: golang_ecom/middleware/auth.go
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

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate the token
		secret := []byte(config.GetEnv("JWT_SECRET", "secret"))
		fmt.Printf("Secret: %s\n", secret)

		claims, err := auth.ParseJWT(secret, tokenString)
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
