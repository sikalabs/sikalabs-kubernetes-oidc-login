package login

import (
	"github.com/sikalabs/sikalabs-kubernetes-oidc-login/internal/login"
)

func Login(issuerURL, clientID, clientSecret string) error {
	return login.Login(issuerURL, clientID, clientSecret)
}
