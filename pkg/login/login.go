package login

import (
	"github.com/sikalabs/sikalabs-kubernetes-oidc-login/internal/login"
)

func Login(issuerURL, clientID string) error {
	return login.Login(issuerURL, clientID)
}
