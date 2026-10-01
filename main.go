// gatehouse is a pass-through proxy for Claude Code: it forwards each user's own
// Claude login to Anthropic, enforces policy on what is sent, and keeps the audit trail.
package main

import (
	"cmp"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed all:web/dist
var webFS embed.FS

const schema = `
CREATE TABLE IF NOT EXISTS events(
  id TEXT PRIMARY KEY, ts INTEGER NOT NULL, user TEXT NOT NULL, session TEXT NOT NULL,
  kind TEXT NOT NULL, tool TEXT NOT NULL, decision TEXT NOT NULL, rule TEXT NOT NULL,
  detail TEXT NOT NULL, model TEXT NOT NULL, tokens_in INTEGER NOT NULL, tokens_out INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS members(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0);`

type Event struct {
	ID        string `json:"id"`
	TS        int64  `json:"ts"`
	User      string `json:"user"`
	Session   string `json:"session"`
	Kind      string `json:"kind"` // request | tool | prompt
	Tool      string `json:"tool"`
	Decision  string `json:"decision"` // allow | block
	Rule      string `json:"rule"`
	Detail    string `json:"detail"`
	Model     string `json:"model"`
	TokensIn  int64  `json:"tokens_in"`
	TokensOut int64  `json:"tokens_out"`
}

type config struct {
	DB, Upstream         string
	AdminUser, AdminPass string
	PasswordLogin        bool
	Google               googleConfig
}

type server struct {
	db     *sql.DB
	policy *Policy
	cfg    config
	rp     *httputil.ReverseProxy

	mu       sync.Mutex
	sessions map[string]session // dashboard session id -> who and until when
	fails    []time.Time        // recent failed password sign-ins
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newServer(policy *Policy, cfg config) (*server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	g := &cfg.Google
	g.authURL = cmp.Or(g.authURL, "https://accounts.google.com/o/oauth2/v2/auth")
	g.tokenURL = cmp.Or(g.tokenURL, "https://oauth2.googleapis.com/token")
	g.userURL = cmp.Or(g.userURL, "https://openidconnect.googleapis.com/v1/userinfo")
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+cfg.DB+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	s := &server{db: db, policy: policy, cfg: cfg, sessions: map[string]session{}}
	s.rp = newProxy(u, s.responded)
	return s, nil
}

func (s *server) routes() http.Handler {
	admin := http.NewServeMux()
	admin.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"user": r.Context().Value(userKey{})})
	})
	admin.HandleFunc("GET /api/stats", s.stats)
	admin.HandleFunc("GET /api/events", s.events)
	admin.HandleFunc("GET /api/members", s.listMembers)
	admin.HandleFunc("POST /api/members", s.addMember)
	admin.HandleFunc("DELETE /api/members/{id}", s.delMember)
	admin.HandleFunc("GET /api/policy", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.policy) })

	mux := http.NewServeMux()
	mux.HandleFunc("/m/{token}/{rest...}", s.proxy)
	mux.HandleFunc("GET /api/auth", s.authMethods)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	if s.cfg.Google.enabled() {
		mux.HandleFunc("GET /auth/google", s.googleStart)
		mux.HandleFunc("GET /auth/google/callback", s.googleCallback)
	}
	mux.Handle("/api/", s.requireAdmin(admin))
	// The UI itself holds no data, so it is served without a session and shows the sign-in form.
	dist, _ := fs.Sub(webFS, "web/dist")
	mux.Handle("/", http.FileServerFS(dist))
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func cut(s string, n int) string {
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

func (s *server) insert(e Event) {
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.TS, e.User, e.Session, e.Kind, cut(e.Tool, 200), e.Decision, e.Rule, cut(e.Detail, 1000), cut(e.Model, 200), e.TokensIn, e.TokensOut)
	if err != nil {
		log.Printf("audit insert failed: %v", err)
	}
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *server) memberByToken(token string) (name string, ok bool) {
	h := tokenHash(token)
	if s.db.QueryRow(`SELECT name FROM members WHERE token_hash=?`, h).Scan(&name) != nil {
		return "", false
	}
	s.db.Exec(`UPDATE members SET last_seen=? WHERE token_hash=?`, time.Now().Unix(), h)
	return name, true
}

type member struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	LastSeen int64  `json:"last_seen"`
	Token    string `json:"token,omitempty"` // only in the response that creates the member
}

func (s *server) listMembers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT id, name, created, last_seen FROM members ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	ms := []member{}
	for rows.Next() {
		var m member
		rows.Scan(&m.ID, &m.Name, &m.Created, &m.LastSeen)
		ms = append(ms, m)
	}
	writeJSON(w, ms)
}

func (s *server) addMember(w http.ResponseWriter, r *http.Request) {
	if !isJSON(r) {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var m member
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&m)
	m.Name = strings.TrimSpace(m.Name)
	if m.Name == "" || len(m.Name) > 100 {
		http.Error(w, "name is required (max 100 chars)", http.StatusBadRequest)
		return
	}
	m.Token, m.Created = "gt_"+randID()+randID(), time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO members(name, token_hash, created) VALUES(?,?,?)`, m.Name, tokenHash(m.Token), m.Created)
	if err != nil {
		http.Error(w, "a member with that name already exists", http.StatusConflict)
		return
	}
	m.ID, _ = res.LastInsertId()
	writeJSON(w, m)
}

func (s *server) delMember(w http.ResponseWriter, r *http.Request) {
	s.db.Exec(`DELETE FROM members WHERE id=?`, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// since turns ?hours= into a start timestamp, clamped to 1 hour..1 year.
func since(r *http.Request) (start, hours int64) {
	hours, _ = strconv.ParseInt(r.URL.Query().Get("hours"), 10, 64)
	if hours < 1 {
		hours = 24
	}
	hours = min(hours, 24*365)
	return time.Now().Unix() - hours*3600, hours
}

type rank struct {
	Name    string `json:"name"`
	Allowed int64  `json:"allowed"`
	Blocked int64  `json:"blocked"`
	Tokens  int64  `json:"tokens"`
}

// top ranks one column. col, where and order are fixed strings from this file, never user input.
func (s *server) top(start int64, col, where, order string) []rank {
	out := []rank{}
	rows, err := s.db.Query(`SELECT `+col+`, COALESCE(SUM(decision='allow'),0), COALESCE(SUM(decision='block'),0),
		COALESCE(SUM(tokens_in+tokens_out),0) FROM events WHERE ts>=? AND `+where+` GROUP BY 1 ORDER BY `+order+` DESC LIMIT 8`, start)
	if err != nil {
		log.Printf("stats: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k rank
		rows.Scan(&k.Name, &k.Allowed, &k.Blocked, &k.Tokens)
		out = append(out, k)
	}
	return out
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	start, hours := since(r)
	var t struct {
		Requests int64 `json:"requests"`
		Tools    int64 `json:"tools"`
		Blocked  int64 `json:"blocked"`
		Users    int64 `json:"users"`
		Sessions int64 `json:"sessions"`
		Tokens   int64 `json:"tokens"`
	}
	s.db.QueryRow(`SELECT COALESCE(SUM(kind='request' AND decision='allow'),0), COALESCE(SUM(kind='tool'),0),
		COALESCE(SUM(decision='block'),0), COUNT(DISTINCT user), COUNT(DISTINCT NULLIF(session,'')),
		COALESCE(SUM(tokens_in+tokens_out),0) FROM events WHERE ts>=?`, start).
		Scan(&t.Requests, &t.Tools, &t.Blocked, &t.Users, &t.Sessions, &t.Tokens)

	// ponytail: daily buckets are UTC days; pass a tz offset if local-midnight buckets matter.
	bucket := int64(3600)
	if hours > 7*24 {
		bucket = 86400
	}
	type point struct {
		T        int64 `json:"t"`
		Requests int64 `json:"requests"`
		Blocked  int64 `json:"blocked"`
	}
	byT := map[int64]point{}
	rows, err := s.db.Query(`SELECT ts/?*?, COALESCE(SUM(kind='request' AND decision='allow'),0), COALESCE(SUM(decision='block'),0)
		FROM events WHERE ts>=? GROUP BY 1`, bucket, bucket, start)
	if err == nil {
		for rows.Next() {
			var p point
			rows.Scan(&p.T, &p.Requests, &p.Blocked)
			byT[p.T] = p
		}
		rows.Close()
	}
	series := []point{}
	for ts := start / bucket * bucket; ts <= time.Now().Unix(); ts += bucket {
		p := byT[ts]
		p.T = ts
		series = append(series, p)
	}
	writeJSON(w, map[string]any{
		"totals": t, "series": series,
		"users":  s.top(start, "user", "kind='request'", "COUNT(*)"),
		"tools":  s.top(start, "tool", "tool!=''", "COUNT(*)"),
		"rules":  s.top(start, "rule", "decision='block'", "COUNT(*)"),
		"models": s.top(start, "model", "kind='request' AND model!=''", "4"),
	})
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	start, _ := since(r)
	q := r.URL.Query()
	where, args := "ts>=?", []any{start}
	switch show := q.Get("show"); show {
	case "blocked":
		where += " AND decision='block'"
	case "tool", "prompt", "request":
		where += " AND kind=?"
		args = append(args, show)
	}
	if text := q.Get("q"); text != "" {
		where += " AND (user LIKE ? OR tool LIKE ? OR rule LIKE ? OR detail LIKE ? OR session LIKE ?)"
		like := "%" + text + "%"
		args = append(args, like, like, like, like, like)
	}
	rows, err := s.db.Query(`SELECT id, ts, user, session, kind, tool, decision, rule, detail, model, tokens_in, tokens_out
		FROM events WHERE `+where+` ORDER BY ts DESC, rowid DESC LIMIT 200`, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		rows.Scan(&e.ID, &e.TS, &e.User, &e.Session, &e.Kind, &e.Tool, &e.Decision, &e.Rule, &e.Detail, &e.Model, &e.TokensIn, &e.TokensOut)
		out = append(out, e)
	}
	writeJSON(w, out)
}

func (s *server) pruneOnce(days int) {
	s.db.Exec(`DELETE FROM events WHERE ts<?`, time.Now().Unix()-int64(days)*86400)
}

func (s *server) prune(days int) {
	for ; ; time.Sleep(24 * time.Hour) {
		s.pruneOnce(days)
	}
}

func main() {
	passwordLogin, err := strconv.ParseBool(env("GATEHOUSE_PASSWORD_LOGIN", "true"))
	if err != nil {
		log.Fatal("GATEHOUSE_PASSWORD_LOGIN must be true or false")
	}
	cfg := config{
		DB:            env("GATEHOUSE_DB", "gatehouse.db"),
		Upstream:      env("GATEHOUSE_UPSTREAM", "https://api.anthropic.com"),
		AdminUser:     env("GATEHOUSE_ADMIN_USER", "admin"),
		AdminPass:     os.Getenv("GATEHOUSE_ADMIN_PASSWORD"),
		PasswordLogin: passwordLogin,
		Google: googleConfig{
			ClientID:     os.Getenv("GATEHOUSE_GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GATEHOUSE_GOOGLE_CLIENT_SECRET"),
			PublicURL:    strings.TrimRight(os.Getenv("GATEHOUSE_PUBLIC_URL"), "/"),
		},
	}
	for _, a := range strings.Split(os.Getenv("GATEHOUSE_GOOGLE_ALLOWED"), ",") {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			cfg.Google.Allowed = append(cfg.Google.Allowed, a)
		}
	}
	policy, err := loadPolicy(env("GATEHOUSE_POLICY", "policy.json"))
	if err != nil {
		log.Fatal(err)
	}
	s, err := newServer(policy, cfg)
	if err != nil {
		log.Fatal(err)
	}
	days, err := strconv.Atoi(env("GATEHOUSE_RETENTION_DAYS", "365"))
	if err != nil || days < 1 {
		log.Fatal("GATEHOUSE_RETENTION_DAYS must be a positive number")
	}
	go s.prune(days)

	addr := env("GATEHOUSE_ADDR", "127.0.0.1:8787")
	log.Printf("gatehouse listening on http://%s", addr)
	// No write timeout: model responses stream for minutes.
	srv := &http.Server{Addr: addr, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
