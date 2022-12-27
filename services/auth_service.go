package services

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

//* Service
type AuthService interface {
	CreateJWToken(sub JWTClaims, expiration time.Duration) (string, error)
	DecodeJWToken(jwtoken string) (*JWTClaims, error)
	CreateAccessAndRefreshJWTokens(sub JWTClaims, access_exp, refresh_exp time.Duration) (string, string, error)
}

//* Constructor
func NewAuthService() AuthService {
	return &authServiceImpl{}
}

//* Implementation
type authServiceImpl struct{}

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type JWTClaims struct {
	ID   uuid.UUID
	Role string
}

func (s *authServiceImpl) CreateJWToken(sub JWTClaims, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":       time.Now().Add(expiration).Unix(),
		"user_id":   sub.ID.String(),
		"user_role": sub.Role,
	})

	tokenString, err := token.SignedString(jwtSecret)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *authServiceImpl) CreateAccessAndRefreshJWTokens(sub JWTClaims, access_exp, refresh_exp time.Duration) (string, string, error) {
	accessTokenString, err_1 := s.CreateJWToken(sub, access_exp)

	refreshTokenString, err_2 := s.CreateJWToken(sub, refresh_exp)

	if err_1 != nil || err_2 != nil {
		return "", "", fmt.Errorf("error creating the jwt")
	}

	return accessTokenString, refreshTokenString, nil
}

func (s *authServiceImpl) DecodeJWToken(jwtoken string) (*JWTClaims, error) {
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
		return nil, fmt.Errorf("error getting the claims")
	} else {
		userID := claims["user_id"].(string)
		userRole := claims["user_role"].(string)

		return &JWTClaims{
			ID:   uuid.MustParse(userID),
			Role: userRole,
		}, nil
	}
}
