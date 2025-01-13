package service

import "gorm.io/gorm"

type (
	User struct {
		db *gorm.DB
	}
	UserOpts struct {
		DB *gorm.DB
	}
)

// NewUser creates a new user service.
func NewUser(opts UserOpts) *User {
	return &User{
		db: opts.DB,
	}
}
