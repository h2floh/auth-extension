package oauth

import (
	"fmt"
	"net/http"

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

	_, err = s.confGitHub.Exchange(r.Context(), code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("error exchange code for token: %v", err)))
		return
	}

	// Response contains an GitHub access token
	// TODO retrieve user id/information (via oktokit sdk?!)
	github_handle := "github_handle"

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

	s.TestCache()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("All done!  Please return to the app"))
}

func (s *Service) TestCache() {
	// Debug out the values of the entraToken
	result, found := s.cache.Get("github_handle")
	if found {
		fmt.Printf("Cache hit: %s\n", result)
	} else {
		fmt.Println("Cache miss")
	}
}
