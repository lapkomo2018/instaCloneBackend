package service

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type (
	JWT struct {
		AccessSecret []byte
		AccessTTL    time.Duration
	}

	// JWTConfig contains the configuration for the JWT service.
	JWTConfig struct {
		AccessSecret []byte
		AccessTTL    time.Duration
	}
)

// NewJWT creates a new JWT service.
func NewJWT(cfg JWTConfig) *JWT {
	return &JWT{
		AccessSecret: cfg.AccessSecret,
		AccessTTL:    cfg.AccessTTL,
	}
}

// GenerateAccessToken generates a new access token for the given data.
func (j *JWT) GenerateAccessToken(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.AccessTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(j.AccessSecret)
}

// ParseAccessToken parses the given access token and returns the user ID.
func (j *JWT) ParseAccessToken(token string) (string, error) {
	return parseToken(token, j.AccessSecret)
}

func parseToken(token string, secret []byte) (string, error) {
	claims := jwt.RegisteredClaims{}

	t, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrInvalidKeyType
		}

		return secret, nil
	})

	if err != nil {
		return "", err
	}

	if !t.Valid {
		return "", jwt.ErrTokenExpired
	}

	return claims.Subject, nil
}
