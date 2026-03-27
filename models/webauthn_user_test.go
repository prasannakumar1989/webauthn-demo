package models

import (
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWAUser_WebAuthnID(t *testing.T) {
    user := WAUser{
        ID:          1,
        Username:    "testuser",
        DisplayName: "Test User",
        Credentials: []webauthn.Credential{},
    }

    expected := []byte("testuser")
    actual := user.WebAuthnID()

    if !reflect.DeepEqual(actual, expected) {
        t.Errorf("WebAuthnID() = %v, want %v", actual, expected)
    }
}

func TestWAUser_WebAuthnName(t *testing.T) {
    user := WAUser{
        ID:          1,
        Username:    "testuser",
        DisplayName: "Test User",
        Credentials: []webauthn.Credential{},
    }

    expected := "testuser"
    actual := user.WebAuthnName()

    if actual != expected {
        t.Errorf("WebAuthnName() = %v, want %v", actual, expected)
    }
}

func TestWAUser_WebAuthnDisplayName(t *testing.T) {
    user := WAUser{
        ID:          1,
        Username:    "testuser",
        DisplayName: "Test User",
        Credentials: []webauthn.Credential{},
    }

    expected := "Test User"
    actual := user.WebAuthnDisplayName()

    if actual != expected {
        t.Errorf("WebAuthnDisplayName() = %v, want %v", actual, expected)
    }
}

func TestWAUser_WebAuthnCredentials(t *testing.T) {
    cred := webauthn.Credential{ID: []byte("cred1")}
    user := WAUser{
        ID:          1,
        Username:    "testuser",
        DisplayName: "Test User",
        Credentials: []webauthn.Credential{cred},
    }

    expected := []webauthn.Credential{cred}
    actual := user.WebAuthnCredentials()

    if !reflect.DeepEqual(actual, expected) {
        t.Errorf("WebAuthnCredentials() = %v, want %v", actual, expected)
    }
}

func TestWAUser_EmptyValues(t *testing.T) {
    user := WAUser{
        ID:          0,
        Username:    "",
        DisplayName: "",
        Credentials: nil,
    }

    if len(user.WebAuthnID()) != 0 {
        t.Errorf("WebAuthnID() should be empty for empty username")
    }

    if user.WebAuthnName() != "" {
        t.Errorf("WebAuthnName() should be empty")
    }

    if user.WebAuthnDisplayName() != "" {
        t.Errorf("WebAuthnDisplayName() should be empty")
    }

    if user.WebAuthnCredentials() != nil {
        t.Errorf("WebAuthnCredentials() should be nil")
    }
}