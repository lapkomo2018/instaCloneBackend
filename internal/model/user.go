package model

import (
	"database/sql"
	"time"
)

type User struct {
	ID                 string               `gorm:"type:char(36);primaryKey"`
	Email              string               `gorm:"unique;not null"`
	Username           string               `gorm:"unique;not null"`
	Password           string               `gorm:""`
	Verified           bool                 `gorm:"not null;default:false"`
	Sessions           *[]Session           `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Info               *UserInfo            `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Posts              []*Post              `gorm:"foreignKey:UserID"`
	Stories            []*Story             `gorm:"foreignKey:UserID"`
	VerificationTokens []*VerificationToken `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	CreatedAt          time.Time            `gorm:"autoCreateTime"`
	UpdatedAt          time.Time            `gorm:"autoUpdateTime"`
}

const (
	EmailVerification VerificationTokenPurpose = iota
	PasswordReset
)

type (
	VerificationTokenPurpose int
	VerificationToken        struct {
		Token     string                   `gorm:"type:char(36);primaryKey"`
		UserID    string                   `gorm:"type:char(36)"`
		Purpose   VerificationTokenPurpose `gorm:""`
		ExpiresAt time.Time                `gorm:"not null"`
		CreatedAt time.Time                `gorm:"autoCreateTime"`
	}
	Session struct {
		RefreshToken string    `gorm:"type:char(36);primaryKey"`
		UserID       string    `gorm:"type:char(36)"`
		DeviceInfo   string    `gorm:"not null"`
		ExpiresAt    time.Time `gorm:"not null"`
		CreatedAt    time.Time `gorm:"autoCreateTime"`
		UpdatedAt    time.Time `gorm:"autoUpdateTime"`
	}
	UserInfo struct {
		UserID    string       `gorm:"type:char(36);primaryKey"`
		Name      string       `gorm:""`
		Bio       string       `gorm:""`
		Avatar    string       `gorm:""`
		BirthDate sql.NullTime `gorm:""`
		Location  string       `gorm:""`
	}
	Post struct {
		ID     string `gorm:"type:char(36);primaryKey"`
		UserID string `gorm:"type:char(36)"`
	}
	Story struct {
		ID     string `gorm:"type:char(36);primaryKey"`
		UserID string `gorm:"type:char(36)"`
	}
)

// Migrate returns the models that need to be migrated.
func Migrate() []interface{} {
	return []interface{}{
		&User{},
		&VerificationToken{},
		&Session{},
		&UserInfo{},
		&Post{},
		&Story{},
	}
}
