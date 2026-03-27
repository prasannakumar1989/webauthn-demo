package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"webauthn-demo/generatedmodels"
	"webauthn-demo/models"
)

type RegistrationHandler struct {
	Queries      DBQuerier
	SessionStore SessionStorer
	WebAuthn     WebAuthnProvider
	Logger       *log.Logger
}

func (h *RegistrationHandler) discoverUser(ctx context.Context, username string) (*models.WAUser, error) {
	u, err := h.Queries.GetUserByUsername(ctx, username)
	if err == nil {
		return &models.WAUser{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}, nil
	}

	u, err = h.Queries.CreateUser(ctx, generatedmodels.CreateUserParams{
		Username:    username,
		DisplayName: username,
	})
	if err != nil {
		return nil, err
	}
	return &models.WAUser{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}, nil
}

func (h *RegistrationHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	h.Logger.Println("BeginRegistration called")
	var req struct{ Username string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		h.Logger.Printf("Invalid request: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// find or create user
	waUser, err := h.discoverUser(r.Context(), req.Username)
	if err != nil {
		h.Logger.Printf("Failed to find or create user: %v", err)
		http.Error(w, "failed to find or create user", http.StatusInternalServerError)
		return
	}

	// get webauthn credential operations for the user
	options, sessionData, err := h.WebAuthn.BeginRegistration(waUser)
	if err != nil {
		h.Logger.Printf("Failed to begin registration: %v", err)
		http.Error(w, "failed to begin registration", http.StatusInternalServerError)
		return
	}

	// store session Data in redis for associating completion request
	key := "webauthn:register:" + req.Username
	if err := h.SessionStore.Save(r.Context(), key, sessionData, 5*time.Minute); err != nil {
		h.Logger.Printf("Failed to save session: %v", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	h.Logger.Printf("Registration options sent for user: %s", req.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (h *RegistrationHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	h.Logger.Println("FinishRegistration called")
	username := r.URL.Query().Get("username")
	if username == "" {
		h.Logger.Println("Username required")
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	waUser, err := h.discoverUser(r.Context(), username)
	if err != nil {
		h.Logger.Printf("Failed to fetch user: %v", err)
		http.Error(w, "failed to fetch user", http.StatusInternalServerError)
		return
	}

	key := "webauthn:register:" + username
	sessionData, err := h.SessionStore.Load(r.Context(), key)
	if err != nil {
		h.Logger.Printf("Session expired or missing: %v", err)
		http.Error(w, "session expired or missing", http.StatusBadRequest)
		return
	}

	cred, err := h.WebAuthn.FinishRegistration(waUser, *sessionData, r)
	if err != nil {
		h.Logger.Printf("Failed to finish registration: %v", err)
		http.Error(w, "failed to finish registration", http.StatusBadRequest)
		return
	}

	_ = h.SessionStore.Delete(r.Context(), key)

	_, err = h.Queries.CreateCredential(r.Context(), generatedmodels.CreateCredentialParams{
		UserID:         waUser.ID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      int32(cred.Authenticator.SignCount),
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	})
	if err != nil {
		h.Logger.Printf("Failed to save credential: %v", err)
		http.Error(w, "failed to save credential", http.StatusInternalServerError)
		return
	}

	h.Logger.Printf("Registration successful for user: %s", username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "registration successful"})
}
