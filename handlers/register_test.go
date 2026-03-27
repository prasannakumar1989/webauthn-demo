package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"webauthn-demo/generatedmodels"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func newRegistrationHandler(q DBQuerier, s SessionStorer, wa WebAuthnProvider) *RegistrationHandler {
	return &RegistrationHandler{
		Queries:      q,
		SessionStore: s,
		WebAuthn:     wa,
		Logger:       discardLogger(),
	}
}

func postJSON(t *testing.T, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// --- BeginRegistration tests ---

func TestBeginRegistration_InvalidBody(t *testing.T) {
	h := newRegistrationHandler(&MockDBQuerier{}, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginRegistration, `not-json`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginRegistration_EmptyUsername(t *testing.T) {
	h := newRegistrationHandler(&MockDBQuerier{}, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginRegistration, `{"username":""}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginRegistration_UserDiscoveryFails(t *testing.T) {
	dbErr := errors.New("db error")
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{}, dbErr
		},
		CreateUserFunc: func(_ context.Context, _ generatedmodels.CreateUserParams) (generatedmodels.User, error) {
			return generatedmodels.User{}, dbErr
		},
	}
	h := newRegistrationHandler(q, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginRegistration_WebAuthnBeginFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		BeginRegistrationFunc: func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			return nil, nil, errors.New("webauthn error")
		},
	}
	h := newRegistrationHandler(q, &MockSessionStorer{}, wa)
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginRegistration_SessionSaveFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		BeginRegistrationFunc: func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			return &protocol.CredentialCreation{}, &webauthn.SessionData{}, nil
		},
	}
	ss := &MockSessionStorer{
		SaveFunc: func(_ context.Context, _ string, _ *webauthn.SessionData, _ time.Duration) error {
			return errors.New("redis error")
		},
	}
	h := newRegistrationHandler(q, ss, wa)
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginRegistration_Success(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		BeginRegistrationFunc: func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			return &protocol.CredentialCreation{}, &webauthn.SessionData{}, nil
		},
	}
	ss := &MockSessionStorer{
		SaveFunc: func(_ context.Context, _ string, _ *webauthn.SessionData, _ time.Duration) error {
			return nil
		},
	}
	h := newRegistrationHandler(q, ss, wa)
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
}

// --- FinishRegistration tests ---

func finishRegRequest(t *testing.T, username string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/?username="+username, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestFinishRegistration_MissingUsername(t *testing.T) {
	h := newRegistrationHandler(&MockDBQuerier{}, &MockSessionStorer{}, &MockWebAuthnProvider{})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishRegistration_UserDiscoveryFails(t *testing.T) {
	dbErr := errors.New("db error")
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{}, dbErr
		},
		CreateUserFunc: func(_ context.Context, _ generatedmodels.CreateUserParams) (generatedmodels.User, error) {
			return generatedmodels.User{}, dbErr
		},
	}
	h := newRegistrationHandler(q, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishRegistration_SessionLoadFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
	}
	ss := &MockSessionStorer{
		LoadFunc: func(_ context.Context, _ string) (*webauthn.SessionData, error) {
			return nil, errors.New("session expired")
		},
	}
	h := newRegistrationHandler(q, ss, &MockWebAuthnProvider{})
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishRegistration_WebAuthnFinishFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
	}
	ss := &MockSessionStorer{
		LoadFunc: func(_ context.Context, _ string) (*webauthn.SessionData, error) {
			return &webauthn.SessionData{}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		FinishRegistrationFunc: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return nil, errors.New("invalid attestation")
		},
	}
	h := newRegistrationHandler(q, ss, wa)
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishRegistration_CreateCredentialFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		CreateCredentialFunc: func(_ context.Context, _ generatedmodels.CreateCredentialParams) (generatedmodels.CreateCredentialRow, error) {
			return generatedmodels.CreateCredentialRow{}, errors.New("db error")
		},
	}
	ss := &MockSessionStorer{
		LoadFunc: func(_ context.Context, _ string) (*webauthn.SessionData, error) {
			return &webauthn.SessionData{}, nil
		},
		DeleteFunc: func(_ context.Context, _ string) error { return nil },
	}
	wa := &MockWebAuthnProvider{
		FinishRegistrationFunc: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return &webauthn.Credential{ID: []byte("cred-id"), PublicKey: []byte("pub-key")}, nil
		},
	}
	h := newRegistrationHandler(q, ss, wa)
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishRegistration_Success(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		CreateCredentialFunc: func(_ context.Context, _ generatedmodels.CreateCredentialParams) (generatedmodels.CreateCredentialRow, error) {
			return generatedmodels.CreateCredentialRow{}, nil
		},
	}
	ss := &MockSessionStorer{
		LoadFunc:   func(_ context.Context, _ string) (*webauthn.SessionData, error) { return &webauthn.SessionData{}, nil },
		DeleteFunc: func(_ context.Context, _ string) error { return nil },
	}
	wa := &MockWebAuthnProvider{
		FinishRegistrationFunc: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return &webauthn.Credential{ID: []byte("cred-id"), PublicKey: []byte("pub-key")}, nil
		},
	}
	h := newRegistrationHandler(q, ss, wa)
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}
	if resp["status"] != "registration successful" {
		t.Errorf("unexpected status: %q", resp["status"])
	}
}

