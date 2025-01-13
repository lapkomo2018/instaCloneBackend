package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"instaCloneBackend/internal/database"
	"instaCloneBackend/internal/service"
	"instaCloneBackend/internal/transport"
	v1 "instaCloneBackend/internal/transport/v1"
	"instaCloneBackend/pkg/hasher"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found")
	}

	// Create a new database connection
	db, err := database.New(database.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		Name:     os.Getenv("DB_DATABASE"),
		Schema:   os.Getenv("DB_SCHEMA"),
	})
	if err != nil {
		log.Fatalf("database error: %v", err)
	}

	// Get the port from the environment variables
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	smtpPort, _ := strconv.Atoi(os.Getenv("MAIL_PORT"))

	httpServer := transport.NewServer(transport.Opts{
		Port: port,
		V1: v1.Opts{
			AuthService: service.NewAuth(service.AuthOpts{
				DB:     db,
				Hasher: hasher.NewSHA1Hasher(os.Getenv("PASSWORD_SALT")),
				JWT: service.NewJWT(service.JWTConfig{
					AccessSecret: []byte(os.Getenv("JWT_ACCESS_SECRET")),
					AccessTTL:    15 * time.Minute,
				}),
				Mail: service.NewMail(service.MailOpts{
					Email:    os.Getenv("MAIL_EMAIL"),
					Password: os.Getenv("MAIL_PASSWORD"),
					SMTPHost: os.Getenv("MAIL_HOST"),
					SMTPPort: smtpPort,
				}),
			}),
			UserService: service.NewUser(service.UserOpts{
				DB: db,
			}),
		},
	})

	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool)

	// Register some cleanup tasks
	httpServer.RegisterOnShutdown(func() {
		log.Println("Some cleanup tasks before shutdown")
	})

	// Run graceful shutdown in a separate goroutine
	go gracefulShutdown(httpServer, done)

	log.Printf("Starting server on port %d", port)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}

	// Wait for the graceful shutdown to complete
	<-done
	log.Println("Graceful shutdown complete")
}

func gracefulShutdown(httpServer *http.Server, done chan bool) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()

	log.Println("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown with error: %v", err)
	}

	log.Println("Server exiting")

	done <- true
}
