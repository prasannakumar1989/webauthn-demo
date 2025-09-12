package handlers

import (
	"context"
	"net/http"

	"webauthn-demo/generatedmodels"
	"webauthn-demo/models"

	"github.com/go-webauthn/webauthn/webauthn"
)

type LoginHandler struct {
    Queries      *generatedmodels.Queries
    SessionStore models.SessionStore
    WebAuthn     *webauthn.WebAuthn
}

func (h *LoginHandler) findUser(ctx context.Context, username string) (*models.WAUser, error) {
    u, err := h.Queries.GetUserByUsername(ctx, username)
    if err == nil {
        return &models.WAUser{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}, nil
    }
    if err != nil {
        return nil, err
    }
    return &models.WAUser{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}, nil
}

func (h *LoginHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	
}
