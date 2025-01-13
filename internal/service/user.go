package service

import (
	"instaCloneBackend/internal/database"
)

type (
	User struct {
		db database.Database
	}
	UserOpts struct {
		DB database.Database
	}
)

// NewUser creates a new user service.
func NewUser(opts UserOpts) *User {
	return &User{
		db: opts.DB,
	}
}
