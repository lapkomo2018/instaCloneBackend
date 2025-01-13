package database

import (
	"fmt"

	"instaCloneBackend/internal/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type (
	Database interface {
		Transaction() *Transaction
	}

	database struct {
		db *gorm.DB
	}

	Config struct {
		// Host is the database host.
		Host string
		// Port is the database port.
		Port string
		// User is the database user.
		User string
		// Password is the database password.
		Password string
		// Name is the database name.
		Name string
		// Schema is the database schema.
		Schema string
	}
)

func New(cfg Config) (Database, error) {
	// Create the database connection.
	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s search_path=%s sslmode=disable", cfg.Host, cfg.Port, cfg.User, cfg.Name, cfg.Password, cfg.Schema)

	db, err := gorm.Open(postgres.Open(dsn))
	if err != nil {
		return nil, err
	}

	// Migrate the database.
	if err := db.AutoMigrate(model.Migrate()...); err != nil {
		return nil, err
	}

	return &database{
		db: db,
	}, nil
}

func (db *database) Transaction() *Transaction {
	return &Transaction{
		DB: db.db.Begin(),
	}
}
