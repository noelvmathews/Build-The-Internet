// Command server runs acm-dns, the service discovery / DNS microservice.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"acm-dns/internal/config"
	"acm-dns/internal/events"
	"acm-dns/internal/handlers"
	"acm-dns/internal/logging"
	"acm-dns/internal/registry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "acm-dns:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	reg := registry.New(cfg.TTL)
	api := handlers.New(handlers.Options{
		Registry:       reg,
		Logger:         logger,
		Events:         events.NewLog(500),
		AllowedDomains: cfg.AllowedDomains,
		CORSOrigin:     cfg.CORSOrigin,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.TTL > 0 {
		interval := cfg.TTL / 2
		if interval < time.Second {
			interval = time.Second
		}
		go reg.RunSweeper(ctx, interval, api.OnExpire)
	}

	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	logger.Info("SERVER_STARTED",
		"addr", cfg.Addr(),
		"ttl", cfg.TTL.String(),
		"allowlist_enabled", cfg.AllowedDomains != nil,
		"cors_enabled", cfg.CORSOrigin != "")

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	logger.Info("SERVER_SHUTTING_DOWN")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
