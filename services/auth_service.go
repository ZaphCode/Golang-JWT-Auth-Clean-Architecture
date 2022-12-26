package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

//* Service
type AuthService interface {
	CreateJWToken(sub any, expiration time.Duration) (string, error)
	DecodeJWToken(jwtoken string) (jwt.MapClaims, error)
}

//* Constructor
func NewAuthService() AuthService {
	return &authServiceImpl{}
}

//* Implementation
type authServiceImpl struct{}

var jwtSecret = []byte("test")

func (s *authServiceImpl) CreateJWToken(sub any, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(expiration).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *authServiceImpl) DecodeJWToken(jwtoken string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(jwtoken, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil

	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); !(ok && token.Valid) {
		return nil, err
	} else {
		return claims, nil
	}
}
