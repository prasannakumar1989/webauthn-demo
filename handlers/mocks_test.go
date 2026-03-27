package handlers

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"webauthn-demo/generatedmodels"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// MockDBQuerier is a test double for DBQuerier.
type MockDBQuerier struct {
	GetUserByUsernameFunc                func(ctx context.Context, username string) (generatedmodels.User, error)
	CreateUserFunc                       func(ctx context.Context, arg generatedmodels.CreateUserParams) (generatedmodels.User, error)
	GetCredentialsByUserIDFunc           func(ctx context.Context, userID int64) ([]generatedmodels.GetCredentialsByUserIDRow, error)
	CreateCredentialFunc                 func(ctx context.Context, arg generatedmodels.CreateCredentialParams) (generatedmodels.CreateCredentialRow, error)
	UpdateCredentialSignCountAndFlagsFunc func(ctx context.Context, arg generatedmodels.UpdateCredentialSignCountAndFlagsParams) error
}

func (m *MockDBQuerier) GetUserByUsername(ctx context.Context, username string) (generatedmodels.User, error) {
	return m.GetUserByUsernameFunc(ctx, username)
}

func (m *MockDBQuerier) CreateUser(ctx context.Context, arg generatedmodels.CreateUserParams) (generatedmodels.User, error) {
	return m.CreateUserFunc(ctx, arg)
}

func (m *MockDBQuerier) GetCredentialsByUserID(ctx context.Context, userID int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
	return m.GetCredentialsByUserIDFunc(ctx, userID)
}

func (m *MockDBQuerier) CreateCredential(ctx context.Context, arg generatedmodels.CreateCredentialParams) (generatedmodels.CreateCredentialRow, error) {
	return m.CreateCredentialFunc(ctx, arg)
}

func (m *MockDBQuerier) UpdateCredentialSignCountAndFlags(ctx context.Context, arg generatedmodels.UpdateCredentialSignCountAndFlagsParams) error {
	return m.UpdateCredentialSignCountAndFlagsFunc(ctx, arg)
}

// MockSessionStorer is a test double for SessionStorer.
type MockSessionStorer struct {
	SaveFunc   func(ctx context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error
	LoadFunc   func(ctx context.Context, key string) (*webauthn.SessionData, error)
	DeleteFunc func(ctx context.Context, key string) error
}

func (m *MockSessionStorer) Save(ctx context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error {
	return m.SaveFunc(ctx, key, data, ttl)
}

func (m *MockSessionStorer) Load(ctx context.Context, key string) (*webauthn.SessionData, error) {
	return m.LoadFunc(ctx, key)
}

func (m *MockSessionStorer) Delete(ctx context.Context, key string) error {
	return m.DeleteFunc(ctx, key)
}

// MockWebAuthnProvider is a test double for WebAuthnProvider.
type MockWebAuthnProvider struct {
	BeginRegistrationFunc  func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistrationFunc func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	BeginLoginFunc         func(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishLoginFunc        func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

func (m *MockWebAuthnProvider) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return m.BeginRegistrationFunc(user, opts...)
}

func (m *MockWebAuthnProvider) FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	return m.FinishRegistrationFunc(user, session, response)
}

func (m *MockWebAuthnProvider) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return m.BeginLoginFunc(user, opts...)
}

func (m *MockWebAuthnProvider) FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	return m.FinishLoginFunc(user, session, response)
}

// discardLogger returns a logger that discards all output, suitable for tests.
func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

