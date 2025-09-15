package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"webauthn-demo/config"
	"webauthn-demo/generatedmodels"
	"webauthn-demo/handlers"
	"webauthn-demo/models"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/graceful"
)

func main() {
	mainCtx := context.Background()

	// Initialize logger
	logger := log.New(os.Stdout, "[webauthn-demo] ", log.LstdFlags)

	// Load config
	cfg, err := config.LoadConfiguration()
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	// Initialize redis session store
	sessionStore := models.NewSessionStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)

	// Initialize DB
	dbpool, err := initDB(mainCtx, cfg)
	if err != nil {
		logger.Fatalf("initDB: %v", err)
	}
	defer dbpool.Close()

	// router
	r := chi.NewRouter()
	r.Use(cors.Handler(cors.Options{
    	AllowedOrigins:   []string{cfg.RPOrigin}, 
    	AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    	AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
    	ExposedHeaders:   []string{"Link"},
    	AllowCredentials: true,
    	MaxAge:           300,
	}))
	r.Use(middleware.Logger)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := dbpool.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"database unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	
	queries := generatedmodels.New(dbpool)

	// Initialize WebAuthn
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins: []string{cfg.RPOrigin},
	})
	if err != nil {
		logger.Fatalf("Failed to initialize WebAuthn: %v", err)
	}


	regHandler := &handlers.RegistrationHandler{
		Queries:      queries,
		SessionStore: *sessionStore,
		WebAuthn:     wa,
		Logger:       logger,
	}
	r.Post("/register/begin", regHandler.BeginRegistration)
	r.Post("/register/finish", regHandler.FinishRegistration)

	loginHandler := &handlers.LoginHandler{
		Queries:      queries,
		SessionStore: *sessionStore,
		WebAuthn:     wa,
		Logger:       logger,
	}
	r.Post("/login/begin", loginHandler.BeginLogin)
	r.Post("/login/finish", loginHandler.FinishLogin)


	// HTTP Server
	server := graceful.WithDefaults(&http.Server{
		Addr:        ":" + cfg.AppPort,
		ReadTimeout: cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		Handler:      r,
	})

	logger.Println("main: Starting the Server")
	if err := graceful.Graceful(server.ListenAndServe, server.Shutdown); err != nil {
		logger.Fatalln("main: Failed to gracefully shutdown")
	}
	logger.Println("main: Server was shutdown gracefully")
}

func initDB(ctx context.Context, cfg *config.Configuration) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
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