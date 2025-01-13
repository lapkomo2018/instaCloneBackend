package service

import (
	"context"
	"errors"
	"log"
	"time"

	"instaCloneBackend/internal/model"
	"instaCloneBackend/pkg/hasher"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type (
	Auth struct {
		db     *gorm.DB
		hasher hasher.Hasher
		jwt    *JWT
	}
	AuthOpts struct {
		DB     *gorm.DB
		Hasher hasher.Hasher
		JWT    *JWT
	}
)

// NewAuth creates a new auth service.
func NewAuth(opts AuthOpts) *Auth {
	return &Auth{
		db:     opts.DB,
		hasher: opts.Hasher,
		jwt:    opts.JWT,
	}
}

const (
	EmailTokenTTL    = 24 * time.Hour
	PasswordTokenTTL = 15 * time.Minute
	RefreshTokenTTL  = 7 * 24 * time.Hour
)

// Register registers a new user.
func (a *Auth) Register(ctx context.Context, username, email, password string) (*model.User, error) {
	// Check if the username is already taken.
	if err := a.db.Where("username = ?", username).First(&model.User{}).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	} else {
		return nil, errors.New("username is already taken")
	}

	// Check if the email is already taken.
	if err := a.db.Where("email = ?", email).First(&model.User{}).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	} else {
		return nil, errors.New("email is already taken")
	}

	// Create a new user.
	log.Printf("Registering user with username: %s, email: %s", username, email)
	user := &model.User{
		ID:                 uuid.New().String(),
		Username:           username,
		Email:              email,
		Password:           a.hasher.Hash(password),
		VerificationTokens: make([]*model.VerificationToken, 0),
	}

	// Create a new verification token.
	log.Printf("Creating verification token for user with ID: %s", user.ID)
	token := &model.VerificationToken{
		Token:     uuid.New().String(),
		UserID:    user.ID,
		Purpose:   model.EmailVerification,
		ExpiresAt: time.Now().Add(EmailTokenTTL),
	}

	// Append the token to the user.
	log.Printf("Appending verification token to user with ID: %s", user.ID)
	user.VerificationTokens = append(user.VerificationTokens, token)

	// Save the user to the database.
	log.Printf("Saving user with ID: %s to the database", user.ID)
	if err := a.db.Create(user).Error; err != nil {
		return nil, err
	}

	// Send a verification email.

	// TODO: Implement this.

	return user, nil
}

// Verify verifies a user.
func (a *Auth) Verify(ctx context.Context, token string) error {
	// Get the verification token.
	log.Printf("Getting verification token with token: %s", token)
	verificationToken := &model.VerificationToken{}
	if err := a.db.Where("token = ?", token).First(verificationToken).Error; err != nil {
		return errors.New("token not found")
	}

	// Check if the token is expired.
	log.Printf("Checking if verification token with token: %s is expired", token)
	if verificationToken.ExpiresAt.Before(time.Now()) {
		return errors.New("token is expired")
	}

	// Check if the token is for email verification.
	log.Printf("Checking if verification token with token: %s is for email verification", token)
	if verificationToken.Purpose != model.EmailVerification {
		return errors.New("invalid token")
	}

	// Verify the user.
	log.Printf("Verifying user with ID: %s", verificationToken.UserID)
	user := &model.User{}
	if err := a.db.Where("id = ?", verificationToken.UserID).First(user).Error; err != nil {
		return err
	}

	// Update the user.
	log.Printf("Updating user with ID: %s", user.ID)
	user.Verified = true
	if err := a.db.Save(user).Error; err != nil {
		return err
	}

	// Delete the verification token.
	log.Printf("Deleting verification token with token: %s", token)
	if err := a.db.Delete(verificationToken).Error; err != nil {
		return err
	}

	return nil
}

// Login logs in a user.
func (a *Auth) Login(ctx context.Context, login, password, deviceInfo string) (string, string, error) {
	// Get the user.
	user := &model.User{}
	if err := a.db.Where("username = ? OR email = ?", login, login).First(user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", errors.New("user not found")
		}
		return "", "", err
	}

	// Check if the password is correct.
	if !a.hasher.Compare(user.Password, password) {
		return "", "", errors.New("invalid password")
	}

	// Generate an access token.
	accessToken, err := a.jwt.GenerateAccessToken(user.ID)
	if err != nil {
		return "", "", err
	}

	// Generate a session.
	session := &model.Session{
		RefreshToken: uuid.New().String(),
		UserID:       user.ID,
		DeviceInfo:   deviceInfo,
		ExpiresAt:    time.Now().Add(RefreshTokenTTL),
	}
	if err := a.db.Create(session).Error; err != nil {
		return "", "", err
	}

	return accessToken, session.RefreshToken, nil
}

// Refresh refreshes a session.
func (a *Auth) Refresh(ctx context.Context, refreshToken, deviceInfo string) (string, string, error) {
	// Get the session.
	session := &model.Session{}
	if err := a.db.Where("refresh_token = ?", refreshToken).First(session).Error; err != nil {
		return "", "", errors.New("session not found")
	}

	// Delete the session.
	if err := a.db.Delete(session).Error; err != nil {
		log.Printf("failed to delete session: %v", err)
	}

	// Check if the session is expired.
	if session.ExpiresAt.Before(time.Now()) {
		return "", "", errors.New("session is expired")
	}

	// Generate a new access token.
	accessToken, err := a.jwt.GenerateAccessToken(session.UserID)
	if err != nil {
		return "", "", err
	}

	// Update the session.
	session.RefreshToken = uuid.New().String()
	session.DeviceInfo = deviceInfo
	session.ExpiresAt = time.Now().Add(RefreshTokenTTL)
	if err := a.db.Save(session).Error; err != nil {
		return "", "", err
	}

	return accessToken, session.RefreshToken, nil
}

// Authenticate authenticates a user.
func (a *Auth) Authenticate(ctx context.Context, accessToken string) (*model.User, error) {
	// Parse the access token.
	userID, err := a.jwt.ParseAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	// Get the user.
	user := &model.User{}
	if err := a.db.Where("id = ?", userID).First(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// Logout logs out a user.
func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	// Get the session.
	session := &model.Session{}
	if err := a.db.Where("refresh_token = ?", refreshToken).First(session).Error; err != nil {
		return errors.New("session not found")
	}

	// Delete the session.
	if err := a.db.Delete(session).Error; err != nil {
		return err
	}

	return nil
}

// LogoutAll logs out all sessions of a user.
func (a *Auth) LogoutAll(ctx context.Context, userID string) error {
	// Get the sessions.
	sessions := make([]*model.Session, 0)
	if err := a.db.Where("user_id = ?", userID).Find(&sessions).Error; err != nil {
		return err
	}

	// Delete the sessions.
	if err := a.db.Delete(&sessions).Error; err != nil {
		return err
	}

	return nil
}

// Forgot sends a password reset email.
func (a *Auth) Forgot(ctx context.Context, email string) error {
	// Get the user.
	user := &model.User{}
	if err := a.db.Where("email = ?", email).First(user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		return err
	}

	// Create a password reset token.
	token := &model.VerificationToken{
		Token:     uuid.New().String(),
		UserID:    user.ID,
		Purpose:   model.PasswordReset,
		ExpiresAt: time.Now().Add(PasswordTokenTTL),
	}

	// Save the token to the database.
	if err := a.db.Create(token).Error; err != nil {
		return err
	}

	// Send a password reset email.
	// TODO: Implement this.

	return nil
}

// Reset resets a user's password.
func (a *Auth) Reset(ctx context.Context, token, password string) error {
	// Get the password reset token.
	passwordToken := &model.VerificationToken{}
	if err := a.db.Where("token = ?", token).First(passwordToken).Error; err != nil {
		return errors.New("token not found")
	}

	// Check if the token is expired.
	if passwordToken.ExpiresAt.Before(time.Now()) {
		return errors.New("token is expired")
	}

	// Check if the token is for password reset.
	if passwordToken.Purpose != model.PasswordReset {
		return errors.New("invalid token")
	}

	// Get the user.
	user := &model.User{}
	if err := a.db.Where("id = ?", passwordToken.UserID).First(user).Error; err != nil {
		return err
	}

	// Update the user's password.
	user.Password = a.hasher.Hash(password)
	if err := a.db.Save(user).Error; err != nil {
		return err
	}

	// Delete the password reset token.
	if err := a.db.Delete(passwordToken).Error; err != nil {
		return err
	}

	return nil
}
