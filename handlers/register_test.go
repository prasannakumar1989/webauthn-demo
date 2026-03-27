package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"webauthn-demo/generatedmodels"
	"webauthn-demo/handlers/mocks"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.uber.org/mock/gomock"
)

// discardLogger returns a logger that discards all output, suitable for tests.
func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

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
	ctrl := gomock.NewController(t)
	h := newRegistrationHandler(
		mocks.NewMockDBQuerier(ctrl),
		mocks.NewMockSessionStorer(ctrl),
		mocks.NewMockWebAuthnProvider(ctrl),
	)
	rr := postJSON(t, h.BeginRegistration, `not-json`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginRegistration_EmptyUsername(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newRegistrationHandler(
		mocks.NewMockDBQuerier(ctrl),
		mocks.NewMockSessionStorer(ctrl),
		mocks.NewMockWebAuthnProvider(ctrl),
	)
	rr := postJSON(t, h.BeginRegistration, `{"username":""}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginRegistration_UserDiscoveryFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	dbErr := errors.New("db error")
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{}, dbErr)
	mockDB.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(generatedmodels.User{}, dbErr)

	h := newRegistrationHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mocks.NewMockWebAuthnProvider(ctrl))
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginRegistration_WebAuthnBeginFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().BeginRegistration(gomock.Any()).Return(nil, nil, errors.New("webauthn error"))

	h := newRegistrationHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mockWA)
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginRegistration_SessionSaveFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().BeginRegistration(gomock.Any()).Return(&protocol.CredentialCreation{}, &webauthn.SessionData{}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("redis error"))

	h := newRegistrationHandler(mockDB, mockSS, mockWA)
	rr := postJSON(t, h.BeginRegistration, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginRegistration_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().BeginRegistration(gomock.Any()).Return(&protocol.CredentialCreation{}, &webauthn.SessionData{}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	h := newRegistrationHandler(mockDB, mockSS, mockWA)
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
	ctrl := gomock.NewController(t)
	h := newRegistrationHandler(
		mocks.NewMockDBQuerier(ctrl),
		mocks.NewMockSessionStorer(ctrl),
		mocks.NewMockWebAuthnProvider(ctrl),
	)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishRegistration_UserDiscoveryFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	dbErr := errors.New("db error")
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{}, dbErr)
	mockDB.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(generatedmodels.User{}, dbErr)

	h := newRegistrationHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mocks.NewMockWebAuthnProvider(ctrl))
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishRegistration_SessionLoadFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, errors.New("session expired"))

	h := newRegistrationHandler(mockDB, mockSS, mocks.NewMockWebAuthnProvider(ctrl))
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishRegistration_WebAuthnFinishFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(&webauthn.SessionData{}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().FinishRegistration(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid attestation"))

	h := newRegistrationHandler(mockDB, mockSS, mockWA)
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishRegistration_CreateCredentialFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().CreateCredential(gomock.Any(), gomock.Any()).Return(generatedmodels.CreateCredentialRow{}, errors.New("db error"))

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(&webauthn.SessionData{}, nil)
	mockSS.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().FinishRegistration(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		&webauthn.Credential{ID: []byte("cred-id"), PublicKey: []byte("pub-key")}, nil,
	)

	h := newRegistrationHandler(mockDB, mockSS, mockWA)
	rr := httptest.NewRecorder()
	h.FinishRegistration(rr, finishRegRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishRegistration_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().CreateCredential(gomock.Any(), gomock.Any()).Return(generatedmodels.CreateCredentialRow{}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(&webauthn.SessionData{}, nil)
	mockSS.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().FinishRegistration(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		&webauthn.Credential{ID: []byte("cred-id"), PublicKey: []byte("pub-key")}, nil,
	)

	h := newRegistrationHandler(mockDB, mockSS, mockWA)
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

