package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func parse(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("bad JSON %q: %v", body, err)
	}
}

// rig is a Gatehouse in front of a fake upstream whose reply each test can swap.
type rig struct {
	t       *testing.T
	s       *server
	srv     *httptest.Server
	session *http.Cookie

	mu      sync.Mutex
	hits    int
	last    *http.Request // the latest upstream request, body already read
	respond http.HandlerFunc
}

func sse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":90,\"output_tokens\":1}}}\n\n")
	io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":25}}\n\n")
}

func newRig(t *testing.T, policyJSON string) *rig {
	t.Helper()
	e := &rig{t: t, respond: sse}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		e.mu.Lock()
		e.hits++
		e.last = r
		fn := e.respond
		e.mu.Unlock()
		fn(w, r)
	}))
	t.Cleanup(upstream.Close)
	path := "policy.json"
	if policyJSON != "" {
		path = writePolicy(t, policyJSON)
	}
	policy, err := loadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	e.s, err = newServer(policy, config{DB: filepath.Join(t.TempDir(), "gatehouse.db"), Upstream: upstream.URL, AdminUser: "admin", AdminPass: "pw", PasswordLogin: true})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(e.s.routes())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *rig) upstreamHits() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hits
}

// do sends one request with the dashboard session (if signed in) and a fake Claude login.
func (e *rig) do(method, path, body string, headers ...string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer users-own-claude-login")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if e.session != nil && strings.HasPrefix(path, "/api/") {
		req.AddCookie(e.session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if path == "/api/login" && resp.StatusCode == 200 {
		e.session = resp.Cookies()[0]
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *rig) login() {
	e.t.Helper()
	if code, body := e.do("POST", "/api/login", `{"user":"admin","password":"pw"}`); code != 200 {
		e.t.Fatalf("login = %d %s", code, body)
	}
}

func (e *rig) addMember(name string) member {
	e.t.Helper()
	code, body := e.do("POST", "/api/members", fmt.Sprintf(`{"name":%q}`, name))
	if code != 200 {
		e.t.Fatalf("add member %s = %d %s", name, code, body)
	}
	var m member
	parse(e.t, body, &m)
	return m
}

func (e *rig) events(query string) []Event {
	e.t.Helper()
	code, body := e.do("GET", "/api/events?"+query, "")
	if code != 200 {
		e.t.Fatalf("events = %d %s", code, body)
	}
	var out []Event
	parse(e.t, body, &out)
	return out
}

func (e *rig) messages(token, body string, headers ...string) (int, string) {
	return e.do("POST", "/m/"+token+"/v1/messages", body, headers...)
}

func TestAdminAPI(t *testing.T) {
	e := newRig(t, "")

	if code, body := e.do("GET", "/api/auth", ""); code != 200 || strings.TrimSpace(body) != `{"google":false,"password":true}` {
		t.Errorf("auth methods = %d %s", code, body)
	}
	if code, _ := e.do("GET", "/auth/google", ""); code != 404 {
		t.Errorf("google route with google off = %d, want 404", code)
	}
	if code, body := e.do("GET", "/", ""); code != 200 || !strings.Contains(body, "<title>Gatehouse</title>") {
		t.Errorf("dashboard = %d, body %.80q", code, body)
	}
	if code, _ := e.do("POST", "/api/login", `{"user":"admin","password":"pw"}`, "Content-Type", "text/plain"); code != 415 {
		t.Errorf("non-JSON login = %d, want 415", code)
	}
	e.login()
	if _, body := e.do("GET", "/api/session", ""); !strings.Contains(body, `"admin"`) {
		t.Errorf("session = %s", body)
	}

	// Members: validation, uniqueness, listing without tokens.
	if code, _ := e.do("POST", "/api/members", `{"name":"x"}`, "Content-Type", "text/plain"); code != 415 {
		t.Errorf("non-JSON member = %d, want 415", code)
	}
	for _, bad := range []string{`{"name":"   "}`, `{}`, `{"name":"` + strings.Repeat("n", 101) + `"}`, `not json`} {
		if code, _ := e.do("POST", "/api/members", bad); code != 400 {
			t.Errorf("member %.30s = %d, want 400", bad, code)
		}
	}
	asha := e.addMember("asha@example.com")
	if code, _ := e.do("POST", "/api/members", `{"name":"asha@example.com"}`); code != 409 {
		t.Errorf("duplicate member = %d, want 409", code)
	}
	ben := e.addMember("  ben@example.com ")
	if ben.Name != "ben@example.com" || asha.Token == ben.Token {
		t.Errorf("members %+v %+v", asha, ben)
	}
	_, body := e.do("GET", "/api/members", "")
	var list []member
	parse(t, body, &list)
	if len(list) != 2 || list[0].Name != "asha@example.com" || list[1].Name != "ben@example.com" || strings.Contains(body, "token") || list[0].LastSeen != 0 {
		t.Errorf("members list = %s", body)
	}

	// A member's first request stamps last_seen; removing the member revokes the URL at once.
	if code, _ := e.messages(asha.Token, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`); code != 200 || e.upstreamHits() != 1 {
		t.Fatalf("member request = %d, hits %d", code, e.upstreamHits())
	}
	_, body = e.do("GET", "/api/members", "")
	parse(t, body, &list)
	if list[0].LastSeen == 0 || list[1].LastSeen != 0 {
		t.Errorf("last_seen after one request: %s", body)
	}
	if code, _ := e.do("DELETE", fmt.Sprintf("/api/members/%d", asha.ID), ""); code != 204 {
		t.Errorf("delete = %d, want 204", code)
	}
	if code, body := e.messages(asha.Token, `{}`); code != 401 || !strings.Contains(body, "revoked") || e.upstreamHits() != 1 {
		t.Errorf("revoked token = %d %s (hits %d)", code, body, e.upstreamHits())
	}
	if _, body = e.do("GET", "/api/members", ""); strings.Contains(body, "asha") {
		t.Errorf("deleted member still listed: %s", body)
	}
	// The audit trail outlives the member.
	if evs := e.events("q=asha"); len(evs) == 0 {
		t.Error("deleting a member dropped their events")
	}

	// Sign out, then an expired session.
	if code, _ := e.do("POST", "/api/logout", ""); code != 204 {
		t.Errorf("logout = %d", code)
	}
	if code, _ := e.do("GET", "/api/stats", ""); code != 401 {
		t.Errorf("after logout = %d, want 401", code)
	}
	e.session = nil
	if code, _ := e.do("POST", "/api/logout", ""); code != 204 {
		t.Errorf("logout without a session = %d, want 204", code)
	}
	e.login()
	e.s.mu.Lock()
	e.s.sessions[e.session.Value] = session{"admin", time.Now().Add(-time.Second)}
	e.s.mu.Unlock()
	if code, _ := e.do("GET", "/api/stats", ""); code != 401 {
		t.Errorf("expired session = %d, want 401", code)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newRig(t, "")
	for i := 0; i < 10; i++ {
		if code, _ := e.do("POST", "/api/login", `{"user":"admin","password":"nope"}`); code != 401 {
			t.Fatalf("attempt %d = %d, want 401", i, code)
		}
	}
	if code, _ := e.do("POST", "/api/login", `{"user":"admin","password":"pw"}`); code != 429 || e.session != nil {
		t.Fatalf("after ten failures = %d, want 429 even with the right password", code)
	}
}

func TestProxyPassthrough(t *testing.T) {
	e := newRig(t, "")
	e.login()
	m := e.addMember("asha")
	base := "/m/" + m.Token

	// Any other endpoint goes straight through, query string and headers intact, and leaves no audit rows.
	e.respond = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"data":[]}`) }
	code, body := e.do("GET", base+"/v1/models?limit=5", "", "anthropic-version", "2023-06-01", "Accept-Encoding", "br")
	if code != 200 || body != `{"data":[]}` {
		t.Fatalf("models = %d %s", code, body)
	}
	up := e.last
	if up.URL.Path != "/v1/models" || up.URL.RawQuery != "limit=5" || up.Header.Get("anthropic-version") != "2023-06-01" ||
		up.Header.Get("Authorization") != "Bearer users-own-claude-login" || up.Header.Get("Accept-Encoding") != "gzip" || up.Header.Get("X-Forwarded-For") != "" {
		t.Errorf("upstream saw %s %s?%s %v", up.Method, up.URL.Path, up.URL.RawQuery, up.Header)
	}
	if evs := e.events(""); len(evs) != 0 {
		t.Errorf("non-message request left %d audit rows", len(evs))
	}

	// Oversized bodies are refused before anything is parsed or forwarded.
	defer func(n int) { maxBody = n }(maxBody)
	maxBody = 1024
	if code, _ := e.messages(m.Token, `{"model":"m","messages":[{"role":"user","content":"`+strings.Repeat("x", 2000)+`"}]}`); code != 413 || e.upstreamHits() != 1 {
		t.Errorf("oversized = %d (hits %d), want 413 and no forward", code, e.upstreamHits())
	}
	maxBody = 64 << 20

	// Upstream errors pass through and are recorded as such; non-streaming replies still yield token counts.
	e.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		io.WriteString(w, `{"type":"error"}`)
	}
	if code, body := e.messages(m.Token, `{"model":"claude-x","messages":[{"role":"user","content":"hi"}]}`); code != 429 || body != `{"type":"error"}` {
		t.Errorf("upstream 429 = %d %s", code, body)
	}
	e.respond = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"usage":{"input_tokens":5,"output_tokens":7}}`)
	}
	e.messages(m.Token, `{"model":"claude-y","messages":[{"role":"user","content":"hi again"}]}`)
	reqs := e.events("show=request")
	if len(reqs) != 2 || reqs[1].Detail != "upstream 429" || reqs[1].TokensIn+reqs[1].TokensOut != 0 ||
		reqs[0].Model != "claude-y" || reqs[0].TokensIn != 5 || reqs[0].TokensOut != 7 || reqs[0].Detail != "" {
		t.Errorf("request rows = %+v", reqs)
	}

	// Session id: the Claude Code header wins, then the uuid in metadata, else none.
	uuid := "11111111-2222-3333-4444-555555555555"
	withMeta := `{"model":"m","metadata":{"user_id":"user_abc_session_` + uuid + `"},"messages":[{"role":"user","content":"a"}]}`
	e.messages(m.Token, withMeta, "X-Claude-Code-Session-Id", "from-header")
	e.messages(m.Token, withMeta)
	e.messages(m.Token, `{"model":"m","messages":[{"role":"user","content":"a"}]}`)
	got := []string{}
	for _, ev := range e.events("show=request") {
		got = append(got, ev.Session)
	}
	if want := []string{"", uuid, "from-header"}; strings.Join(got[:3], ",") != strings.Join(want, ",") {
		t.Errorf("sessions = %q, want %q first", got, want)
	}

	// A body Gatehouse cannot parse is still forwarded: upstream decides what is valid.
	hits := e.upstreamHits()
	if code, _ := e.messages(m.Token, `{"model": oops`); code != 200 || e.upstreamHits() != hits+1 {
		t.Errorf("unparseable body = %d, forwarded %v", code, e.upstreamHits() == hits+1)
	}

	// Policy covers sibling endpoints that carry the conversation too.
	hits = e.upstreamHits()
	code, body = e.do("POST", base+"/v1/messages/count_tokens", turn("assistant", "Read", `{"file_path":"/srv/.env"}`))
	if code != 400 || !strings.Contains(body, "path:env-file") || e.upstreamHits() != hits {
		t.Errorf("count_tokens with a denied path = %d %s (forwarded %v)", code, body, e.upstreamHits() != hits)
	}
}

func TestAuditTrail(t *testing.T) {
	e := newRig(t, "")
	e.login()
	asha, ben := e.addMember("asha"), e.addMember("ben")
	sid := "11111111-2222-3333-4444-555555555555"
	convo := func(messages string) string {
		return `{"model":"claude-x","metadata":{"user_id":"user_abc_session_` + sid + `"},"messages":[` + messages + `]}`
	}
	count := func(query string) int { return len(e.events(query)) }

	// A prompt is recorded once, as its length, and a retry does not duplicate it.
	for i := 0; i < 2; i++ {
		if code, _ := e.messages(asha.Token, convo(`{"role":"user","content":"hello"}`)); code != 200 {
			t.Fatalf("prompt = %d", code)
		}
	}
	prompts := e.events("show=prompt")
	if len(prompts) != 1 || prompts[0].Detail != "prompt (5 chars)" || prompts[0].Session != sid || prompts[0].User != "asha" || prompts[0].Model != "claude-x" {
		t.Errorf("prompt rows = %+v", prompts)
	}
	if n := count("show=request"); n != 2 {
		t.Errorf("request rows = %d, want one per call", n)
	}

	// System reminders are not the user's words; a message that is only reminders is not a prompt at all.
	e.messages(asha.Token, convo(`{"role":"user","content":[{"type":"text","text":" <system-reminder>ctx</system-reminder>"},{"type":"text","text":"do it"}]}`))
	e.messages(asha.Token, convo(`{"role":"user","content":[{"type":"text","text":"<system-reminder>only</system-reminder>"}]}`))
	if prompts = e.events("show=prompt"); len(prompts) != 2 || prompts[0].Detail != "prompt (5 chars)" {
		t.Errorf("prompt rows after reminders = %+v", prompts)
	}

	// Tool calls are recorded when their results go up, once per tool_use id.
	toolTurn := convo(`{"role":"user","content":"hello"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"go test ./..."}},{"type":"tool_use","id":"toolu_2","name":"WebFetch","input":{"url":"https://x.test"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"ok"},{"type":"tool_result","tool_use_id":"toolu_2","content":"ok"}]}`)
	e.messages(asha.Token, toolTurn)
	e.messages(asha.Token, toolTurn)
	tools := e.events("show=tool")
	if len(tools) != 2 || tools[0].Tool != "WebFetch" || tools[0].Detail != "https://x.test" || tools[1].Tool != "Bash" || tools[1].Detail != "go test ./..." {
		t.Errorf("tool rows = %+v", tools)
	}
	// A prefilled assistant turn at the end is not a prompt and holds no new tool results.
	e.messages(asha.Token, convo(`{"role":"user","content":"hello"},{"role":"assistant","content":"Sure,"}`))
	if count("show=prompt") != 2 || count("show=tool") != 2 {
		t.Error("assistant-last request added prompt or tool rows")
	}

	// A block is one row per user and session, however often it is retried.
	denied := convo(`{"role":"user","content":"x"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_9","name":"Read","input":{"file_path":"/srv/.env"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_9","content":"SECRET=1"}]}`)
	e.messages(asha.Token, denied)
	e.messages(asha.Token, denied)
	noSession := strings.Replace(denied, "user_abc_session_"+sid, "", 1)
	e.messages(asha.Token, noSession)
	e.messages(ben.Token, noSession)
	blocked := e.events("show=blocked")
	if len(blocked) != 3 {
		t.Errorf("blocked rows = %d, want 3 (asha with session, asha without, ben without): %+v", len(blocked), blocked)
	}
	for _, b := range blocked {
		if b.Rule != "path:env-file" || b.Tool != "Read" || b.Detail != "/srv/.env" || b.Decision != "block" {
			t.Errorf("blocked row = %+v", b)
		}
	}

	// Event filters and search.
	for query, want := range map[string]int{"show=blocked&q=ben": 1, "q=go+test": 1, "q=nomatch": 0, "show=tool&q=ben": 0, "show=request&q=ben": 1} {
		if n := count(query); n != want {
			t.Errorf("events?%s = %d rows, want %d", query, n, want)
		}
	}
	if evs := e.events("show=request&q=ben"); evs[0].Decision != "block" {
		t.Errorf("ben's only request row = %+v, want the block", evs[0])
	}
	if n := count("q=" + url.QueryEscape(sid)); n == 0 || n == count("") {
		t.Errorf("session search = %d of %d", n, count(""))
	}

	// Stats: totals, rankings, and hourly vs daily series.
	_, body := e.do("GET", "/api/stats?hours=24", "")
	var st struct {
		Totals                      struct{ Requests, Tools, Blocked, Users, Sessions, Tokens int64 }
		Series                      []struct{ T, Requests, Blocked int64 }
		Users, Tools, Rules, Models []rank
	}
	parse(t, body, &st)
	if st.Totals.Blocked != 3 || st.Totals.Tools != 2 || st.Totals.Users != 2 || st.Totals.Sessions != 1 || st.Totals.Tokens == 0 {
		t.Errorf("totals = %+v", st.Totals)
	}
	if len(st.Series) != 25 {
		t.Errorf("24h series has %d points, want 25 hourly", len(st.Series))
	}
	if len(st.Users) != 2 || st.Users[0].Name != "asha" || st.Users[0].Blocked != 2 || st.Users[1].Name != "ben" || st.Users[1].Blocked != 1 ||
		len(st.Rules) != 1 || st.Rules[0].Name != "path:env-file" || st.Rules[0].Blocked != 3 ||
		len(st.Models) != 1 || st.Models[0].Name != "claude-x" || st.Models[0].Tokens != st.Totals.Tokens {
		t.Errorf("ranks: users %+v rules %+v models %+v", st.Users, st.Rules, st.Models)
	}
	toolNames := []string{}
	for _, r := range st.Tools {
		toolNames = append(toolNames, r.Name)
	}
	if strings.Join(toolNames, ",") != "Read,Bash,WebFetch" && strings.Join(toolNames, ",") != "Read,WebFetch,Bash" {
		t.Errorf("top tools = %v", toolNames)
	}
	_, body = e.do("GET", "/api/stats?hours=720", "")
	parse(t, body, &st)
	if len(st.Series) != 31 {
		t.Errorf("30d series has %d points, want 31 daily", len(st.Series))
	}

	// With log_content the prompt itself is stored.
	e2 := newRig(t, `{"log_content": true}`)
	e2.login()
	m := e2.addMember("asha")
	e2.messages(m.Token, `{"model":"m","messages":[{"role":"user","content":"the actual words"}]}`)
	if p := e2.events("show=prompt"); len(p) != 1 || p[0].Detail != "the actual words" {
		t.Errorf("log_content prompt = %+v", p)
	}
}

func TestPrune(t *testing.T) {
	e := newRig(t, "")
	now := time.Now().Unix()
	e.s.insert(Event{ID: "old", TS: now - 400*86400, User: "u", Kind: "request", Decision: "allow"})
	e.s.insert(Event{ID: "new", TS: now - 10, User: "u", Kind: "request", Decision: "allow"})
	e.s.pruneOnce(365)
	var ids []string
	rows, _ := e.s.db.Query(`SELECT id FROM events`)
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 1 || ids[0] != "new" {
		t.Errorf("after prune: %v, want only new", ids)
	}
}

func TestGoogleEdgeCases(t *testing.T) {
	verified := true
	var gotRedirect string
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			gotRedirect = r.FormValue("redirect_uri")
			io.WriteString(w, `{"access_token":"at"}`)
		case "/userinfo":
			fmt.Fprintf(w, `{"email":"asha@example.com","email_verified":%v}`, verified)
		}
	}))
	defer google.Close()

	policy, _ := loadPolicy("policy.json")
	newSrv := func(publicURL string) *httptest.Server {
		s, err := newServer(policy, config{DB: filepath.Join(t.TempDir(), "g.db"), Upstream: "http://unused.invalid",
			Google: googleConfig{ClientID: "id", ClientSecret: "secret", Allowed: []string{"example.com"}, PublicURL: publicURL,
				authURL: google.URL + "/auth", tokenURL: google.URL + "/token", userURL: google.URL + "/userinfo"}})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(s.routes())
		t.Cleanup(srv.Close)
		return srv
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(srv *httptest.Server, path string, headers []string, cookies ...*http.Cookie) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	cookie := func(resp *http.Response, name string) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == name && c.Value != "" {
				return c
			}
		}
		return nil
	}
	signIn := func(srv *httptest.Server, headers ...string) (*http.Response, *http.Cookie) {
		start := get(srv, "/auth/google", headers)
		state := cookie(start, stateCookie)
		if state == nil {
			t.Fatal("no state cookie")
		}
		loc, _ := url.Parse(start.Header.Get("Location"))
		cb := get(srv, "/auth/google/callback?code=c&state="+state.Value, headers, state)
		if want := loc.Query().Get("redirect_uri"); gotRedirect != want {
			t.Errorf("redirect_uri sent to Google: start %q, token exchange %q", want, gotRedirect)
		}
		return cb, cookie(cb, sessionCookie)
	}

	// Unverified Google accounts are refused.
	srv := newSrv("")
	verified = false
	if cb, sess := signIn(srv); cb.Header.Get("Location") != "/?error=failed" || sess != nil {
		t.Errorf("unverified email: %q, session %v", cb.Header.Get("Location"), sess)
	}
	verified = true

	// Without GATEHOUSE_PUBLIC_URL the redirect follows the request's host and scheme, and cookies go Secure behind TLS.
	cb, sess := signIn(srv)
	if !strings.HasPrefix(gotRedirect, "http://127.0.0.1:") || sess == nil || sess.Secure {
		t.Errorf("plain http: redirect %q, session %v", gotRedirect, sess)
	}
	cb, sess = signIn(srv, "X-Forwarded-Proto", "https")
	if !strings.HasPrefix(gotRedirect, "https://127.0.0.1:") || sess == nil || !sess.Secure || cb.Header.Get("Location") != "/" {
		t.Errorf("behind TLS: redirect %q, session %v", gotRedirect, sess)
	}

	// With GATEHOUSE_PUBLIC_URL the redirect ignores the Host header.
	srv = newSrv("https://gatehouse.example.test")
	signIn(srv, "Host", "evil.test")
	if gotRedirect != "https://gatehouse.example.test/auth/google/callback" {
		t.Errorf("public URL redirect = %q", gotRedirect)
	}
}
