package config

import (
	"fmt"
	"os"
)

type Info struct {
	// Port is the local port on which the application will run
	Port string

	// FQDN (for Fully-Qualified Domain Name) is the internet facing host address
	// where application will live (e.g. https://example.com)
	FQDN string

	// ClientID comes from your configured GitHub app
	GitHubClientID string

	// ClientSecret comes from your configured GitHub app
	GitHubClientSecret string

	// ClientID comes from your configured EntraId app
	EntraIdClientID string

	// ClientSecret comes from your configured EntraId app
	EntraIdClientSecret string

	// TenantId comes from your configured EntraId app
	EntraIdTenantId string
}

const (
	portEnv                = "PORT"
	entraIdClientIdEnv     = "ENTRA_CLIENT_ID"
	entraIdTenantEnv       = "ENTRA_TENANT_ID"
	entraIdClientSecretEnv = "ENTRA_CLIENT_SECRET"
	fqdnEnv                = "FQDN"
	gitHubClientIdEnv      = "GITHUB_CLIENT_ID"
	gitHubClientSecretEnv  = "GITHUB_SECRET"
)

func New() (*Info, error) {
	port := os.Getenv(portEnv)
	if port == "" {
		return nil, fmt.Errorf("%s environment variable required", portEnv)
	}

	fqdn := os.Getenv(fqdnEnv)
	if fqdn == "" {
		return nil, fmt.Errorf("%s environment variable required", fqdnEnv)
	}

	entraIdClientID := os.Getenv(entraIdClientIdEnv)
	if entraIdClientID == "" {
		return nil, fmt.Errorf("%s environment variable required", entraIdClientIdEnv)
	}

	entraIdClientSecret := os.Getenv(entraIdClientSecretEnv)
	if entraIdClientSecret == "" {
		return nil, fmt.Errorf("%s environment variable required", entraIdClientSecretEnv)
	}

	entraIdTenantId := os.Getenv(entraIdTenantEnv)
	if entraIdTenantId == "" {
		return nil, fmt.Errorf("%s environment variable required", entraIdTenantEnv)
	}

	gitHubClientID := os.Getenv(gitHubClientIdEnv)
	if gitHubClientID == "" {
		return nil, fmt.Errorf("%s environment variable required", gitHubClientIdEnv)
	}

	gitHubClientSecret := os.Getenv(gitHubClientSecretEnv)
	if gitHubClientSecret == "" {
		return nil, fmt.Errorf("%s environment variable required", gitHubClientSecretEnv)
	}

	return &Info{
		Port:                port,
		FQDN:                fqdn,
		GitHubClientID:      gitHubClientID,
		GitHubClientSecret:  gitHubClientSecret,
		EntraIdClientID:     entraIdClientID,
		EntraIdClientSecret: entraIdClientSecret,
		EntraIdTenantId:     entraIdTenantId,
	}, nil
}
