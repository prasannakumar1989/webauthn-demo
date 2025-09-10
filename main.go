package main

import (
	"context"
	"log"
	"net/http"
	"webauthn-demo/config"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/graceful"
)


func main() {
	mainCtx := context.Background() 

	// Load config
	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize DB
	dbpool, err := initDB(mainCtx, cfg)
	if err != nil {
		log.Fatalf("initDB: %v", err)
	}
	defer dbpool.Close()

	// router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := dbpool.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"database unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// HTTP Server
	server := graceful.WithDefaults(&http.Server{
		Addr: ":"+cfg.AppPort,
		ReadTimeout: cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout: cfg.IdleTimeout,
		Handler: r,
	})

	log.Println("main: Starting the Server")
	if err := graceful.Graceful(server.ListenAndServe, server.Shutdown); err != nil {
		log.Fatalln("main: Failed to gracefully shutdown")
	}
	log.Println("main: Server was shutdown gracefully")
}

func initDB(ctx context.Context, cfg *config.Configuration) (*pgxpool.Pool, error) {
	poolCfg , err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	poolCfg.MaxConns = cfg.DBMaxConns
	poolCfg.MinConns = cfg.DBMinConns
	poolCfg.MaxConnLifetime = cfg.DBMaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.DBMaxConnIdleTime
	poolCfg.HealthCheckPeriod = cfg.DBHealthCheckPeriod

	dbpool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}

    // availability check
	if err := dbpool.Ping(ctx); err != nil {
		dbpool.Close()
		return nil, err
	}
	return dbpool, nil
}