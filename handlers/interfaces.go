package handlers

//go:generate mockgen -source=interfaces.go -destination=mocks/mock_interfaces.go -package=mocks

import (
	"context"
	"net/http"
	"time"

	"webauthn-demo/generatedmodels"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// DBQuerier abstracts the database operations used by handlers.
type DBQuerier interface {
	GetUserByUsername(ctx context.Context, username string) (generatedmodels.User, error)
	CreateUser(ctx context.Context, arg generatedmodels.CreateUserParams) (generatedmodels.User, error)
	GetCredentialsByUserID(ctx context.Context, userID int64) ([]generatedmodels.GetCredentialsByUserIDRow, error)
	CreateCredential(ctx context.Context, arg generatedmodels.CreateCredentialParams) (generatedmodels.CreateCredentialRow, error)
	UpdateCredentialSignCountAndFlags(ctx context.Context, arg generatedmodels.UpdateCredentialSignCountAndFlagsParams) error
}

// SessionStorer abstracts session storage operations.
type SessionStorer interface {
	Save(ctx context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error
	Load(ctx context.Context, key string) (*webauthn.SessionData, error)
	Delete(ctx context.Context, key string) error
}

// WebAuthnProvider abstracts the WebAuthn ceremony operations.
type WebAuthnProvider interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

