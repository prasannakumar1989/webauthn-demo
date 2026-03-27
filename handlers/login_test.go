package handlers

import (
	"encoding/json"
	"errors"
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
	ctrl := gomock.NewController(t)
	h := newLoginHandler(
		mocks.NewMockDBQuerier(ctrl),
		mocks.NewMockSessionStorer(ctrl),
		mocks.NewMockWebAuthnProvider(ctrl),
	)
	rr := postJSON(t, h.BeginLogin, `not-json`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginLogin_EmptyUsername(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newLoginHandler(
		mocks.NewMockDBQuerier(ctrl),
		mocks.NewMockSessionStorer(ctrl),
		mocks.NewMockWebAuthnProvider(ctrl),
	)
	rr := postJSON(t, h.BeginLogin, `{"username":""}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestBeginLogin_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{}, errors.New("not found"))

	h := newLoginHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mocks.NewMockWebAuthnProvider(ctrl))
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestBeginLogin_GetCredentialsFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().GetCredentialsByUserID(gomock.Any(), int64(1)).Return(nil, errors.New("db error"))

	h := newLoginHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mocks.NewMockWebAuthnProvider(ctrl))
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginLogin_WebAuthnBeginFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().GetCredentialsByUserID(gomock.Any(), int64(1)).Return([]generatedmodels.GetCredentialsByUserIDRow{}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().BeginLogin(gomock.Any()).Return(nil, nil, errors.New("webauthn error"))

	h := newLoginHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mockWA)
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginLogin_SessionSaveFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().GetCredentialsByUserID(gomock.Any(), int64(1)).Return([]generatedmodels.GetCredentialsByUserIDRow{}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().BeginLogin(gomock.Any()).Return(&protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("redis error"))

	h := newLoginHandler(mockDB, mockSS, mockWA)
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestBeginLogin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().GetCredentialsByUserID(gomock.Any(), int64(1)).Return([]generatedmodels.GetCredentialsByUserIDRow{}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().BeginLogin(gomock.Any()).Return(&protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	h := newLoginHandler(mockDB, mockSS, mockWA)
	rr := postJSON(t, h.BeginLogin, `{"username":"alice"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, rr.Code)
	}
}

// --- FinishLogin tests ---

// setupFinishLoginQuerier sets up a mock DB with the two calls needed for most FinishLogin tests.
func setupFinishLoginQuerier(ctrl *gomock.Controller) *mocks.MockDBQuerier {
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().GetCredentialsByUserID(gomock.Any(), int64(1)).Return([]generatedmodels.GetCredentialsByUserIDRow{
		{CredentialID: []byte("cred-id"), PublicKey: []byte("pub-key"), SignCount: 1},
	}, nil)
	return mockDB
}

func TestFinishLogin_MissingUsername(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newLoginHandler(
		mocks.NewMockDBQuerier(ctrl),
		mocks.NewMockSessionStorer(ctrl),
		mocks.NewMockWebAuthnProvider(ctrl),
	)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishLogin_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{}, errors.New("not found"))

	h := newLoginHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mocks.NewMockWebAuthnProvider(ctrl))
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestFinishLogin_GetCredentialsFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := mocks.NewMockDBQuerier(ctrl)
	mockDB.EXPECT().GetUserByUsername(gomock.Any(), "alice").Return(generatedmodels.User{ID: 1, Username: "alice", DisplayName: "alice"}, nil)
	mockDB.EXPECT().GetCredentialsByUserID(gomock.Any(), int64(1)).Return(nil, errors.New("db error"))

	h := newLoginHandler(mockDB, mocks.NewMockSessionStorer(ctrl), mocks.NewMockWebAuthnProvider(ctrl))
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishLogin_SessionLoadFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, errors.New("session expired"))

	h := newLoginHandler(setupFinishLoginQuerier(ctrl), mockSS, mocks.NewMockWebAuthnProvider(ctrl))
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestFinishLogin_WebAuthnFinishFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(&webauthn.SessionData{}, nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().FinishLogin(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid assertion"))

	h := newLoginHandler(setupFinishLoginQuerier(ctrl), mockSS, mockWA)
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestFinishLogin_UpdateSignCountFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := setupFinishLoginQuerier(ctrl)
	mockDB.EXPECT().UpdateCredentialSignCountAndFlags(gomock.Any(), gomock.Any()).Return(errors.New("db error"))

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(&webauthn.SessionData{}, nil)
	mockSS.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().FinishLogin(gomock.Any(), gomock.Any(), gomock.Any()).Return(&webauthn.Credential{ID: []byte("cred-id")}, nil)

	h := newLoginHandler(mockDB, mockSS, mockWA)
	rr := httptest.NewRecorder()
	h.FinishLogin(rr, finishLoginRequest(t, "alice"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestFinishLogin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDB := setupFinishLoginQuerier(ctrl)
	mockDB.EXPECT().UpdateCredentialSignCountAndFlags(gomock.Any(), gomock.Any()).Return(nil)

	mockSS := mocks.NewMockSessionStorer(ctrl)
	mockSS.EXPECT().Load(gomock.Any(), gomock.Any()).Return(&webauthn.SessionData{}, nil)
	mockSS.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil)

	mockWA := mocks.NewMockWebAuthnProvider(ctrl)
	mockWA.EXPECT().FinishLogin(gomock.Any(), gomock.Any(), gomock.Any()).Return(&webauthn.Credential{ID: []byte("cred-id")}, nil)

	h := newLoginHandler(mockDB, mockSS, mockWA)
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

