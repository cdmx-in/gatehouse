package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	sessionTTL    = 12 * time.Hour
	sessionCookie = "gatehouse_session"
	stateCookie   = "gatehouse_oauth_state"
)

type session struct {
	user string
	exp  time.Time
}

type userKey struct{}

type googleConfig struct {
	ClientID, ClientSecret string
	Allowed                []string // lower-case emails ("a@b.c") and domains ("b.c") that may sign in
	PublicURL              string   // external base URL; taken from the request when empty

	authURL, tokenURL, userURL string // Google's endpoints; tests point these at a fake
}

func (g *googleConfig) enabled() bool { return g.ClientID != "" }

func (g *googleConfig) allows(email string) bool {
	email = strings.ToLower(email)
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return false
	}
	for _, a := range g.Allowed {
		if a == email || a == domain {
			return true
		}
	}
	return false
}

// validate refuses configurations nobody could sign in to, or that anyone could.
func (c *config) validate() error {
	g := &c.Google
	switch {
	case c.PasswordLogin && c.AdminPass == "":
		return errors.New("GATEHOUSE_ADMIN_PASSWORD is required (or set GATEHOUSE_PASSWORD_LOGIN=false and configure Google sign-in)")
	case g.enabled() && g.ClientSecret == "":
		return errors.New("GATEHOUSE_GOOGLE_CLIENT_SECRET is required with GATEHOUSE_GOOGLE_CLIENT_ID")
	case g.enabled() && len(g.Allowed) == 0:
		return errors.New("GATEHOUSE_GOOGLE_ALLOWED must list the emails or domains allowed to sign in")
	case !c.PasswordLogin && !g.enabled():
		return errors.New("no sign-in method is enabled: turn password login back on or configure Google sign-in")
	}
	return nil
}

func isJSON(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

func secure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *server) startSession(w http.ResponseWriter, r *http.Request, user string) {
	id, now := randID()+randID(), time.Now()
	s.mu.Lock()
	for k, v := range s.sessions {
		if now.After(v.exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = session{user, now.Add(sessionTTL)}
	s.mu.Unlock()
	// SameSite=Strict keeps other sites from riding the session.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: secure(r), MaxAge: int(sessionTTL.Seconds())})
}

// authMethods tells the sign-in page which options to show.
func (s *server) authMethods(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"password": s.cfg.PasswordLogin, "google": s.cfg.Google.enabled()})
}

// ponytail: one password account from the environment, and one global failure
// counter (ten bad sign-ins lock the form for everyone for a minute). Use
// Google sign-in for per-person access; add per-IP limits if the form stays on.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.PasswordLogin {
		http.Error(w, "Password sign-in is disabled.", http.StatusForbidden)
		return
	}
	if !isJSON(r) {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var in struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	now := time.Now()

	s.mu.Lock()
	recent := s.fails[:0]
	for _, t := range s.fails {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	s.fails = recent
	locked := len(s.fails) >= 10
	s.mu.Unlock()
	if locked {
		http.Error(w, "Too many failed sign-ins. Try again in a minute.", http.StatusTooManyRequests)
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.User), []byte(s.cfg.AdminUser))&subtle.ConstantTimeCompare([]byte(in.Password), []byte(s.cfg.AdminPass)) != 1 {
		s.mu.Lock()
		s.fails = append(s.fails, now)
		s.mu.Unlock()
		http.Error(w, "Wrong username or password.", http.StatusUnauthorized)
		return
	}
	s.startSession(w, r, s.cfg.AdminUser)
	writeJSON(w, map[string]string{"user": s.cfg.AdminUser})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			s.mu.Lock()
			sess, ok := s.sessions[c.Value]
			s.mu.Unlock()
			if ok && time.Now().Before(sess.exp) {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, sess.user)))
				return
			}
		}
		http.Error(w, "sign in required", http.StatusUnauthorized)
	})
}

func (s *server) redirectURI(r *http.Request) string {
	base := s.cfg.Google.PublicURL
	if base == "" {
		// A forged Host gets nowhere: Google only redirects to URIs registered for the client.
		base = "http://" + r.Host
		if secure(r) {
			base = "https://" + r.Host
		}
	}
	return base + "/auth/google/callback"
}

func (s *server) googleStart(w http.ResponseWriter, r *http.Request) {
	state := randID()
	// Lax, not Strict: the browser must send it back on the redirect that arrives from Google.
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/auth/google", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: secure(r), MaxAge: 600})
	q := url.Values{"client_id": {s.cfg.Google.ClientID}, "redirect_uri": {s.redirectURI(r)}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {state}, "prompt": {"select_account"}}
	http.Redirect(w, r, s.cfg.Google.authURL+"?"+q.Encode(), http.StatusFound)
}

func (s *server) googleCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(code string, err error) {
		log.Printf("google sign-in %s: %v", code, err)
		http.Redirect(w, r, "/?error="+code, http.StatusFound)
	}
	c, err := r.Cookie(stateCookie)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Path: "/auth/google", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.FormValue("state"))) != 1 {
		fail("failed", errors.New("state mismatch"))
		return
	}
	email, err := s.googleEmail(r.Context(), r.FormValue("code"), s.redirectURI(r))
	if err != nil {
		fail("failed", err)
		return
	}
	if !s.cfg.Google.allows(email) {
		fail("denied", fmt.Errorf("%s is not in GATEHOUSE_GOOGLE_ALLOWED", email))
		return
	}
	s.startSession(w, r, email)
	http.Redirect(w, r, "/", http.StatusFound)
}

// googleEmail trades the authorization code for the signed-in account's verified email.
// It asks Google's userinfo endpoint over TLS rather than parsing the ID token, so there is no JWT code to get wrong.
func (s *server) googleEmail(ctx context.Context, code, redirectURI string) (string, error) {
	g := &s.cfg.Google
	client := &http.Client{Timeout: 10 * time.Second}
	getJSON := func(req *http.Request, v any) error {
		resp, err := client.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", req.URL.Host, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}

	form := url.Values{"code": {code}, "client_id": {g.ClientID}, "client_secret": {g.ClientSecret},
		"redirect_uri": {redirectURI}, "grant_type": {"authorization_code"}}
	req, _ := http.NewRequest("POST", g.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := getJSON(req, &tok); err != nil {
		return "", err
	}

	req, _ = http.NewRequest("GET", g.userURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	var info struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := getJSON(req, &info); err != nil {
		return "", err
	}
	if info.Email == "" || !info.Verified {
		return "", errors.New("google account has no verified email")
	}
	return info.Email, nil
}
