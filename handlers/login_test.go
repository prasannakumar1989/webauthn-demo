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

func newLoginHandler(q DBQuerier, s SessionStorer, wa WebAuthnProvider) *LoginHandler {
	return &LoginHandler{
		Queries:      q,
		SessionStore: s,
		WebAuthn:     wa,
		Logger:       discardLogger(),
	}
}

func finishLoginRequest(t *testing.T, username string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/?username="+username, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// --- BeginLogin tests ---

func TestBeginLogin_InvalidBody(t *testing.T) {
	h := newLoginHandler(&MockDBQuerier{}, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginLogin, `not-json`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginLogin_EmptyUsername(t *testing.T) {
	h := newLoginHandler(&MockDBQuerier{}, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginLogin, `{"username":""}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginLogin_UserNotFound(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{}, errors.New("not found")
		},
	}
	h := newLoginHandler(q, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestBeginLogin_GetCredentialsFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		GetCredentialsByUserIDFunc: func(_ context.Context, _ int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
			return nil, errors.New("db error")
		},
	}
	h := newLoginHandler(q, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginLogin_WebAuthnBeginFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		GetCredentialsByUserIDFunc: func(_ context.Context, _ int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
			return []generatedmodels.GetCredentialsByUserIDRow{}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		BeginLoginFunc: func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
			return nil, nil, errors.New("webauthn error")
		},
	}
	h := newLoginHandler(q, &MockSessionStorer{}, wa)
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginLogin_SessionSaveFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		GetCredentialsByUserIDFunc: func(_ context.Context, _ int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
			return []generatedmodels.GetCredentialsByUserIDRow{}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		BeginLoginFunc: func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
			return &protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil
		},
	}
	ss := &MockSessionStorer{
		SaveFunc: func(_ context.Context, _ string, _ *webauthn.SessionData, _ time.Duration) error {
			return errors.New("redis error")
		},
	}
	h := newLoginHandler(q, ss, wa)
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginLogin_Success(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		GetCredentialsByUserIDFunc: func(_ context.Context, _ int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
			return []generatedmodels.GetCredentialsByUserIDRow{}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		BeginLoginFunc: func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
			return &protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil
		},
	}
	ss := &MockSessionStorer{
		SaveFunc: func(_ context.Context, _ string, _ *webauthn.SessionData, _ time.Duration) error { return nil },
	}
	h := newLoginHandler(q, ss, wa)
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
}

// --- FinishLogin tests ---

func baseLoginQuerier() *MockDBQuerier {
	return &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		GetCredentialsByUserIDFunc: func(_ context.Context, _ int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
			return []generatedmodels.GetCredentialsByUserIDRow{
				{CredentialID: []byte("cred-id"), PublicKey: []byte("pub-key"), SignCount: 1},
			}, nil
		},
	}
}

func TestFinishLogin_MissingUsername(t *testing.T) {
	h := newLoginHandler(&MockDBQuerier{}, &MockSessionStorer{}, &MockWebAuthnProvider{})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishLogin_UserNotFound(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{}, errors.New("not found")
		},
	}
	h := newLoginHandler(q, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestFinishLogin_GetCredentialsFails(t *testing.T) {
	q := &MockDBQuerier{
		GetUserByUsernameFunc: func(_ context.Context, _ string) (generatedmodels.User, error) {
			return generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil
		},
		GetCredentialsByUserIDFunc: func(_ context.Context, _ int64) ([]generatedmodels.GetCredentialsByUserIDRow, error) {
			return nil, errors.New("db error")
		},
	}
	h := newLoginHandler(q, &MockSessionStorer{}, &MockWebAuthnProvider{})
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishLogin_SessionLoadFails(t *testing.T) {
	ss := &MockSessionStorer{
		LoadFunc: func(_ context.Context, _ string) (*webauthn.SessionData, error) {
			return nil, errors.New("session expired")
		},
	}
	h := newLoginHandler(baseLoginQuerier(), ss, &MockWebAuthnProvider{})
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishLogin_WebAuthnFinishFails(t *testing.T) {
	ss := &MockSessionStorer{
		LoadFunc: func(_ context.Context, _ string) (*webauthn.SessionData, error) {
			return &webauthn.SessionData{}, nil
		},
	}
	wa := &MockWebAuthnProvider{
		FinishLoginFunc: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return nil, errors.New("invalid assertion")
		},
	}
	h := newLoginHandler(baseLoginQuerier(), ss, wa)
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestFinishLogin_UpdateSignCountFails(t *testing.T) {
	q := baseLoginQuerier()
	q.UpdateCredentialSignCountAndFlagsFunc = func(_ context.Context, _ generatedmodels.UpdateCredentialSignCountAndFlagsParams) error {
		return errors.New("db error")
	}
	ss := &MockSessionStorer{
		LoadFunc:   func(_ context.Context, _ string) (*webauthn.SessionData, error) { return &webauthn.SessionData{}, nil },
		DeleteFunc: func(_ context.Context, _ string) error { return nil },
	}
	wa := &MockWebAuthnProvider{
		FinishLoginFunc: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return &webauthn.Credential{ID: []byte("cred-id")}, nil
		},
	}
	h := newLoginHandler(q, ss, wa)
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishLogin_Success(t *testing.T) {
	q := baseLoginQuerier()
	q.UpdateCredentialSignCountAndFlagsFunc = func(_ context.Context, _ generatedmodels.UpdateCredentialSignCountAndFlagsParams) error {
		return nil
	}
	ss := &MockSessionStorer{
		LoadFunc:   func(_ context.Context, _ string) (*webauthn.SessionData, error) { return &webauthn.SessionData{}, nil },
		DeleteFunc: func(_ context.Context, _ string) error { return nil },
	}
	wa := &MockWebAuthnProvider{
		FinishLoginFunc: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return &webauthn.Credential{ID: []byte("cred-id")}, nil
		},
	}
	h := newLoginHandler(q, ss, wa)
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}
	if resp["status"] != "login successful" {
		t.Errorf("unexpected status: %q", resp["status"])
	}
}

