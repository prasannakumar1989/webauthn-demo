package config

import (
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Configuration struct {
	AppPort string `env:"APP_PORT" envDefault:"8080"`
	DatabaseURL string `env:"DATABASE_URL"`
	ReadTimeout time.Duration `env:"READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout time.Duration `env:"WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout time.Duration `env:"IDLE_TIMEOUT" envDefault:"120s"`

	DBMaxConns int32 `env:"DB_MAX_CONNS" envDefault:"20"`
	DBMinConns int32 `env:"DB_MIN_CONNS" envDefault:"2"`
	DBMaxConnLifetime time.Duration `env:"DB_MAX_CONN_LIFETIME" envDefault:"1h"`
	DBMaxConnIdleTime time.Duration `env:"DB_MAX_CONN_IDLE_TIME" envDefault:"30m"`
	DBHealthCheckPeriod time.Duration `env:"DB_HEALTH_CHECK_PERIOD" envDefault:"30s"`

	RedisAddr     string        `env:"REDIS_ADDR" envDefault:"localhost:6379"`
	RedisPassword string        `env:"REDIS_PASSWORD" envDefault:""`
	RedisDB       int           `env:"REDIS_DB" envDefault:"0"`

	RPDisplayName string `env:"RP_DISPLAY_NAME" envDefault:"WebAuthnDemo"`
	RPID string `env:"RP_ID" envDefault:"localhost"`
	RPOrigin string `env:"RP_ORIGIN" envDefault:"http://localhost:8080"`
}

func LoadConfiguration() (*Configuration, error) {
	_ = godotenv.Load() 
	var cfg Configuration
	if err := env.Parse(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

