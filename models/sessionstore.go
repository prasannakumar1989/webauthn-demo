package models

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

type SessionStore struct {
    Client *redis.Client
}

func NewSessionStore(addr, password string, db int) *SessionStore {
    rdb := redis.NewClient(&redis.Options{
        Addr:     addr,
        Password: password,
        DB:       db,
    })
    return &SessionStore{Client: rdb}
}

// Save sessionData in Redis with TTL
func (s *SessionStore) Save(ctx context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error {
    bytes, err := json.Marshal(data)
    if err != nil {
        return err
    }
    return s.Client.Set(ctx, key, bytes, ttl).Err()
}

// Load sessionData from Redis
func (s *SessionStore) Load(ctx context.Context, key string) (*webauthn.SessionData, error) {
    val, err := s.Client.Get(ctx, key).Bytes()
    if err != nil {
        return nil, err
    }
    var data webauthn.SessionData
    if err := json.Unmarshal(val, &data); err != nil {
        return nil, err
    }
    return &data, nil
}

// Delete sessionData from Redis
func (s *SessionStore) Delete(ctx context.Context, key string) error {
    return s.Client.Del(ctx, key).Err()
}
