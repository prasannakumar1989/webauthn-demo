package models

import "github.com/go-webauthn/webauthn/webauthn"

type WAUser struct {
    ID          int64
    Username    string
    DisplayName string
    Credentials []webauthn.Credential
}

func (u *WAUser) WebAuthnID() []byte {
    return []byte(u.Username)
}
func (u *WAUser) WebAuthnName() string {
    return u.Username
}
func (u *WAUser) WebAuthnDisplayName() string {
    return u.DisplayName
}
func (u *WAUser) WebAuthnCredentials() []webauthn.Credential {
    return u.Credentials
}
