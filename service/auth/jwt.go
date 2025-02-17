package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateJWT(secret []byte, userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":    userID,
		"expiredAt": time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString(secret)
}

func ExtractUserIDFromToken(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return "", fmt.Errorf("no token provided")
	}

	claims := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	userID, ok := claims["userId"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}

	return userID, nil
}

func GenerateRandomToken(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
