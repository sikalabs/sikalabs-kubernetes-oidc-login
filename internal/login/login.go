package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sikalabs/dogsay/pkg/dogsay"
)

type oidcConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type tokenResponse struct {
	IDToken   string `json:"id_token"`
	ExpiresIn int    `json:"expires_in"`
}

type execCredential struct {
	Kind       string               `json:"kind"`
	APIVersion string               `json:"apiVersion"`
	Spec       execCredentialSpec   `json:"spec"`
	Status     execCredentialStatus `json:"status"`
}

type execCredentialSpec struct {
	Interactive bool `json:"interactive"`
}

type execCredentialStatus struct {
	ExpirationTimestamp string `json:"expirationTimestamp"`
	Token               string `json:"token"`
}

func randomBase64URL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func discoverOIDC(issuerURL string) (*oidcConfig, error) {
	resp, err := http.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cfg oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	_ = cmd.Start()
}

func exchangeCode(tokenEndpoint, code, redirectURI, clientID, clientSecret, codeVerifier string) (*tokenResponse, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	if clientSecret != "" {
		params.Set("client_secret", clientSecret)
	}
	resp, err := http.PostForm(tokenEndpoint, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("no id_token in response: %s", body)
	}
	return &tr, nil
}

func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".kube", ".sikalabs-kubernetes-oidc-login"), nil
}

func cacheKey(issuerURL, clientID, clientSecret string) string {
	h := sha256.Sum256([]byte(issuerURL + "|" + clientID + "|" + clientSecret))
	return base64.RawURLEncoding.EncodeToString(h[:])[:16]
}

func loadCachedCredential(issuerURL, clientID, clientSecret string) (*execCredential, error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, cacheKey(issuerURL, clientID, clientSecret)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cred execCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}
	expiry, err := time.Parse(time.RFC3339, cred.Status.ExpirationTimestamp)
	if err != nil {
		return nil, err
	}
	if time.Now().Add(10 * time.Second).After(expiry) {
		return nil, fmt.Errorf("token expired")
	}
	return &cred, nil
}

func saveCredential(issuerURL, clientID, clientSecret string, cred *execCredential) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, cacheKey(issuerURL, clientID, clientSecret)+".json")
	return os.WriteFile(path, data, 0600)
}

func Login(issuerURL, clientID, clientSecret string) error {
	if cached, err := loadCachedCredential(issuerURL, clientID, clientSecret); err == nil {
		return json.NewEncoder(os.Stdout).Encode(cached)
	}

	cfg, err := discoverOIDC(strings.TrimRight(issuerURL, "/"))
	if err != nil {
		return fmt.Errorf("OIDC discovery: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:9999")
	if err != nil {
		return err
	}
	redirectURI := "http://127.0.0.1:9999/callback"

	codeVerifier := randomBase64URL(64)
	state := randomBase64URL(16)
	nonce := randomBase64URL(16)

	authURL := cfg.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"code_challenge":        {pkceChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"nonce":                 {nonce},
	}.Encode()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch")
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code in callback: %s", r.URL.RawQuery)
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, dogsay.DogSay("Login successful. You can close this window."))
		codeCh <- code
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer srv.Shutdown(context.Background())

	fmt.Fprintf(os.Stderr, "Opening browser for login...\n%s\n\nIf running on a server without a browser, open the URL above on your local machine,\ncomplete login, then paste the callback URL here and press Enter:\n", authURL)
	openBrowser(authURL)

	go func() {
		var line string
		fmt.Fscan(os.Stdin, &line)
		if line == "" {
			return
		}
		u, err := url.Parse(line)
		if err != nil {
			errCh <- fmt.Errorf("invalid callback URL: %w", err)
			return
		}
		if u.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch")
			return
		}
		code := u.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code in pasted URL: %s", line)
			return
		}
		codeCh <- code
	}()

	var code string
	select {
	case code = <-codeCh:
	case err = <-errCh:
		return err
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timeout waiting for login")
	}

	tr, err := exchangeCode(cfg.TokenEndpoint, code, redirectURI, clientID, clientSecret, codeVerifier)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}

	expiry := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()

	cred := execCredential{
		Kind:       "ExecCredential",
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Spec:       execCredentialSpec{Interactive: false},
		Status: execCredentialStatus{
			ExpirationTimestamp: expiry.Format(time.RFC3339),
			Token:               tr.IDToken,
		},
	}

	_ = saveCredential(issuerURL, clientID, clientSecret, &cred)
	return json.NewEncoder(os.Stdout).Encode(cred)
}
