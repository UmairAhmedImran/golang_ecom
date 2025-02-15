package auth

import (
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
