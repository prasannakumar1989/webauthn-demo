package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"webauthn-demo/generatedmodels"
	"webauthn-demo/models"

	"github.com/go-webauthn/webauthn/webauthn"
)

type LoginHandler struct {
	Queries      *generatedmodels.Queries
	SessionStore models.SessionStore
	WebAuthn     *webauthn.WebAuthn
	Logger       *log.Logger
}

// BeginLogin starts the WebAuthn login/authentication flow
func (h *LoginHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.Println("BeginLogin called")
	var req struct{ Username string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		h.Logger.Printf("Invalid request: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Fetch user
	u, err := h.Queries.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		h.Logger.Printf("User not found: %v", err)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Fetch credentials for this user
	creds, err := h.Queries.GetCredentialsByUserID(r.Context(), u.ID)
	if err != nil {
		h.Logger.Printf("Failed to fetch credentials: %v", err)
		http.Error(w, "failed to fetch credentials", http.StatusInternalServerError)
		return
	}

	// Convert db creds to webauthn creds
	var waCreds []webauthn.Credential
	for _, c := range creds {
		waCreds = append(waCreds, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(c.SignCount),
			},
		})
	}

	waUser := &models.WAUser{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Credentials: waCreds,
	}

	// Begin login
	options, sessionData, err := h.WebAuthn.BeginLogin(waUser)
	if err != nil {
		h.Logger.Printf("Failed to begin login: %v", err)
		http.Error(w, "failed to begin login", http.StatusInternalServerError)
		return
	}

	// Save session in Redis
	key := "webauthn:login:" + req.Username
	if err := h.SessionStore.Save(r.Context(), key, sessionData, 5*time.Minute); err != nil {
		h.Logger.Printf("Failed to save session: %v", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	h.Logger.Printf("Login options sent for user: %s", req.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// FinishLogin completes WebAuthn authentication
func (h *LoginHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.Println("FinishLogin called")
	username := r.URL.Query().Get("username")
	if username == "" {
		h.Logger.Println("Username required")
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	u, err := h.Queries.GetUserByUsername(r.Context(), username)
	if err != nil {
		h.Logger.Printf("User not found: %v", err)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Fetch credentials
	creds, err := h.Queries.GetCredentialsByUserID(r.Context(), u.ID)
	if err != nil {
		h.Logger.Printf("Failed to fetch credentials: %v", err)
		http.Error(w, "failed to fetch credentials", http.StatusInternalServerError)
		return
	}
	var waCreds []webauthn.Credential
	for _, c := range creds {
		waCreds = append(waCreds, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(c.SignCount),
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible, 
				BackupState:    c.BackupState, 
			},
		})
	}
	waUser := &models.WAUser{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Credentials: waCreds,
	}

	// Load session from Redis
	key := "webauthn:login:" + username
	sessionData, err := h.SessionStore.Load(r.Context(), key)
	if err != nil {
		h.Logger.Printf("Session expired or missing: %v", err)
		http.Error(w, "session expired or missing", http.StatusBadRequest)
		return
	}

	// Finish login
	cred, err := h.WebAuthn.FinishLogin(waUser, *sessionData, r)
	if err != nil {
		h.Logger.Printf("Failed to finish login: %v", err)
		http.Error(w, "failed to finish login", http.StatusUnauthorized)
		return
	}

	// Delete session
	_ = h.SessionStore.Delete(r.Context(), key)

	// Update sign count and flags in DB using flags from 'cred'
	err = h.Queries.UpdateCredentialSignCountAndFlags(r.Context(), generatedmodels.UpdateCredentialSignCountAndFlagsParams{
		UserID:         u.ID,
		CredentialID:   cred.ID,
		SignCount:      int32(cred.Authenticator.SignCount),
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	})
	if err != nil {
		h.Logger.Printf("Failed to update credential sign count/flags: %v", err)
		http.Error(w, "failed to update credential sign count/flags", http.StatusInternalServerError)
		return
	}
	
	h.Logger.Printf("Login successful for user: %s", username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "login successful"})
}
