package oauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v50/github"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
)

// Service provides endpoints to allow this agent to be authorized.
type Service struct {
	confGitHub *oauth2.Config
	confEntra  *oauth2.Config
	cache      *cache.Cache
}

// resolveGitHubHandleViaToken retrieves the GitHub handle using the access token.
func (s *Service) resolveGitHubHandleViaToken(accessToken string) string {
	client := github.NewClient(oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	)))

	user, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		fmt.Printf("error retrieving GitHub user: %v", err)
		return ""
	}

	return user.GetLogin()
}

func NewService(gitHubClientID, gitHubClientSecret, entraClientId, entraClientSecret, entraTenantId, callbackGitHub, callbackEntra string, cache *cache.Cache) *Service {
	return &Service{
		confGitHub: &oauth2.Config{
			ClientID:     gitHubClientID,
			ClientSecret: gitHubClientSecret,
			RedirectURL:  callbackGitHub,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
		},
		confEntra: &oauth2.Config{
			ClientID:     entraClientId,
			ClientSecret: entraClientSecret,
			RedirectURL:  callbackEntra,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", entraTenantId),
				TokenURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", entraTenantId),
			},
		},
		cache: cache,
	}
}

const (
	STATE_COOKIE_GITHUB = "oauth_state_github"
	STATE_COOKIE_ENTRA  = "oauth_state_entra"
	GITHUB_ID_COOKIE    = "github_handle"
)

// PreAuth is the landing page that the user arrives at when they first attempt
// to use the agent while unauthorized.  You can do anything you want here,
// including making sure the user has an account on your side.  At some point,
// you'll probably want to make a call to the authorize endpoint to authorize
// the app.
func (s *Service) PreAuthGitHub(w http.ResponseWriter, r *http.Request) {
	// In our example, we're not doing anything except going through the
	// authorization flow.  This is standard Oauth2.

	verifier := oauth2.GenerateVerifier()
	state := uuid.New()

	url := s.confGitHub.AuthCodeURL(state.String(), oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
	stateCookie := &http.Cookie{
		Name:     STATE_COOKIE_GITHUB,
		Value:    state.String(),
		MaxAge:   10 * 60, // 10 minutes in seconds
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, stateCookie)
	w.Header().Set("location", url)
	w.WriteHeader(http.StatusFound)
}

// PostAuth is the landing page where the user lads after authorizing.  As
// above, you can do anything you want here.  A common thing you might do is
// get the user information and then perform some sort of account linking in
// your database.
func (s *Service) PostAuthGitHub(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	stateCookie, err := r.Cookie(STATE_COOKIE_GITHUB)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("state cookie not found"))
		return
	}

	// Important:  Compare the state!  This prevents CSRF attacks
	if state != stateCookie.Value {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid state"))
		return
	}

	githubToken, err := s.confGitHub.Exchange(r.Context(), code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("error exchange code for token: %v", err)))
		return
	}

	// Response contains an GitHub access token
	// TODO retrieve user id/information (via go-github)
	github_handle := s.resolveGitHubHandleViaToken(githubToken.AccessToken) //"github_handle"

	// Now do the same thing for Entra Authentication
	s.PreAuthEntra(github_handle, w, r) // <- chain github id/information

	// w.WriteHeader(http.StatusOK)
	// w.Write([]byte("All done!  Please return to the app"))
}

func (s *Service) PreAuthEntra(github_handle string, w http.ResponseWriter, r *http.Request) {
	// In our example, we're not doing anything except going through the
	// authorization flow.  This is standard Oauth2.

	// verifier := oauth2.GenerateVerifier()
	state := uuid.New()

	url := s.confEntra.AuthCodeURL(state.String(), oauth2.AccessTypeOnline)
	stateCookie := &http.Cookie{
		Name:     STATE_COOKIE_ENTRA,
		Value:    state.String(),
		MaxAge:   10 * 60, // 10 minutes in seconds
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// to chain github id/information back to the callback function
	githubIdCookie := &http.Cookie{
		Name:     GITHUB_ID_COOKIE,
		Value:    github_handle,
		MaxAge:   10 * 60, // 10 minutes in seconds
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, stateCookie)
	http.SetCookie(w, githubIdCookie)
	w.Header().Set("location", url)
	w.WriteHeader(http.StatusFound)
}

func (s *Service) PostAuthEntra(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	stateCookie, err := r.Cookie(STATE_COOKIE_ENTRA)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("state cookie not found"))
		return
	}

	githubIdCookie, err := r.Cookie(GITHUB_ID_COOKIE)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("github id cookie not found"))
		return
	}

	// Important:  Compare the state!  This prevents CSRF attacks
	if state != stateCookie.Value {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid state"))
		return
	}

	entraToken, err := s.confEntra.Exchange(r.Context(), code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("error exchange code for token: %v", err)))
		return
	}
	// map and store token in cache
	s.cache.Set(githubIdCookie.Value, entraToken.AccessToken, cache.DefaultExpiration)

	s.TestCache(githubIdCookie.Value)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("All done!  Please return to the app"))
}

func (s *Service) TestCache(item string) {
	// Debug out the values of the entraToken
	result, found := s.cache.Get(item)
	if found {
		fmt.Printf("Cache hit for %s: %s\n", item, result)
	} else {
		fmt.Printf("Cache miss for %s\n", item)
	}
}
