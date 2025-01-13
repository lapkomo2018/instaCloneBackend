package transport

import (
	"fmt"
	"net/http"
	"time"

	v1 "instaCloneBackend/internal/transport/v1"
)

type (
	Server struct {
		port int
	}
	Opts struct {
		Port int
		V1   v1.Opts
	}
)

func NewServer(opts Opts) *http.Server {
	s := &Server{
		port: opts.Port,
	}

	// Declare Server config
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      s.RegisterRoutes(opts.V1),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
