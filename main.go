package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/copilot-extensions/rag-extension/agent"
	"github.com/copilot-extensions/rag-extension/config"
	"github.com/copilot-extensions/rag-extension/oauth"

	"github.com/patrickmn/go-cache"
)

var memCache *cache.Cache

func main() {

	initCache()

	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initCache() {
	// Create a cache with a default expiration time of 5 minutes, and which
	// purges expired items every 10 minutes
	memCache = cache.New(5*time.Minute, 10*time.Minute)
}

func run() error {
	pubKey, err := fetchPublicKey()
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}

	config, err := config.New()
	if err != nil {
		return fmt.Errorf("error fetching config: %w", err)
	}

	callbackFromGitHub, err := url.Parse(config.FQDN)
	if err != nil {
		return fmt.Errorf("unable to parse HOST environment variable: %w", err)
	}

	callbackFromGitHub.Path = "auth/callback/github"

	callbackFromEntra, err := url.Parse(config.FQDN)
	if err != nil {
		return fmt.Errorf("unable to parse HOST environment variable: %w", err)
	}

	callbackFromEntra.Path = "auth/callback/entra"

	oauthService := oauth.NewService(config.GitHubClientID, config.GitHubClientSecret, config.EntraIdClientID, config.EntraIdClientSecret, config.EntraIdTenantId, callbackFromGitHub.String(), callbackFromEntra.String(), memCache)
	http.HandleFunc("/auth/authorization", oauthService.PreAuthGitHub)
	http.HandleFunc("/auth/callback/github", oauthService.PostAuthGitHub)
	http.HandleFunc("/auth/callback/entra", oauthService.PostAuthEntra)

	agentService := agent.NewService(pubKey, memCache)

	http.HandleFunc("/agent", agentService.ChatCompletion)
	http.HandleFunc("/", agentService.HelloWorld)

	fmt.Println("Listening on port", config.Port)
	return http.ListenAndServe(":"+config.Port, nil)
}

// fetchPublicKey fetches the keys used to sign messages from copilot.  Checking
// the signature with one of these keys verifies that the request to the
// completions API comes from GitHub and not elsewhere on the internet.
func fetchPublicKey() (*ecdsa.PublicKey, error) {
	resp, err := http.Get("https://api.github.com/meta/public_keys/copilot_api")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch public key: %s", resp.Status)
	}

	var respBody struct {
		PublicKeys []struct {
			Key       string `json:"key"`
			IsCurrent bool   `json:"is_current"`
		} `json:"public_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	var rawKey string
	for _, pk := range respBody.PublicKeys {
		if pk.IsCurrent {
			rawKey = pk.Key
			break
		}
	}
	if rawKey == "" {
		return nil, fmt.Errorf("could not find current public key")
	}

	pubPemStr := strings.ReplaceAll(rawKey, "\\n", "\n")
	// Decode the Public Key
	block, _ := pem.Decode([]byte(pubPemStr))
	if block == nil {
		return nil, fmt.Errorf("error parsing PEM block with GitHub public key")
	}

	// Create our ECDSA Public Key
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Because of documentation, we know it's a *ecdsa.PublicKey
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("GitHub key is not ECDSA")
	}

	return ecdsaKey, nil
}
