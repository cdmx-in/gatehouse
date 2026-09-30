package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxBody    = 64 << 20 // requests carry the whole conversation, images included
	maxCapture = 8 << 20  // ponytail: responses past this lose token counts, not content
)

type reqInfo struct{ user, session, model string }

type infoKey struct{}

var uuidRe = regexp.MustCompile(`[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}`)

func hashID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func apiError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": msg}})
}

func newProxy(upstream *url.URL, done func(reqInfo, int, []byte)) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			// Let the transport negotiate gzip itself so the captured response is plain text.
			r.Out.Header.Del("Accept-Encoding")
		},
		FlushInterval: -1, // streaming responses must not be buffered
		ModifyResponse: func(resp *http.Response) error {
			if info, ok := resp.Request.Context().Value(infoKey{}).(reqInfo); ok {
				resp.Body = &capture{ReadCloser: resp.Body, done: func(b []byte) { done(info, resp.StatusCode, b) }}
			}
			return nil
		},
	}
}

// capture copies the response as it streams to the client and hands it over at the end.
type capture struct {
	io.ReadCloser
	buf  bytes.Buffer
	once sync.Once
	done func([]byte)
}

func (c *capture) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if c.buf.Len() < maxCapture {
		c.buf.Write(p[:n])
	}
	if err != nil {
		c.once.Do(func() { c.done(c.buf.Bytes()) })
	}
	return n, err
}

func (c *capture) Close() error {
	c.once.Do(func() { c.done(c.buf.Bytes()) })
	return c.ReadCloser.Close()
}

// usage sums token counts from a JSON or SSE response body.
func usage(body []byte) (in, out int64) {
	type u struct {
		Input       int64 `json:"input_tokens"`
		CacheCreate int64 `json:"cache_creation_input_tokens"`
		CacheRead   int64 `json:"cache_read_input_tokens"`
		Output      int64 `json:"output_tokens"`
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(nil, maxCapture)
	for sc.Scan() {
		var ev struct {
			Usage   u `json:"usage"`
			Message struct {
				Usage u `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal(bytes.TrimPrefix(sc.Bytes(), []byte("data: ")), &ev) != nil {
			continue
		}
		// message_start carries the input side, message_delta the running output total.
		for _, x := range []u{ev.Usage, ev.Message.Usage} {
			in = max(in, x.Input+x.CacheCreate+x.CacheRead)
			out = max(out, x.Output)
		}
	}
	return in, out
}

// proxy forwards /m/{token}/... to Anthropic unchanged. The caller's own
// Authorization header (their Claude login) passes through and is never stored or logged.
func (s *server) proxy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.memberByToken(r.PathValue("token"))
	if !ok {
		apiError(w, http.StatusUnauthorized, "authentication_error", "gate: unknown or revoked member token in ANTHROPIC_BASE_URL")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		apiError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "gate: request body too large")
		return
	}
	r.URL.Path, r.URL.RawPath = "/"+r.PathValue("rest"), ""
	r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))

	info := reqInfo{user: user}
	var req msgReq
	isMessages := strings.HasSuffix(r.URL.Path, "/v1/messages") && json.Unmarshal(body, &req) == nil
	if isMessages {
		info.model = req.Model
		info.session = first(r.Header.Get("X-Claude-Code-Session-Id"), lastMatch(uuidRe, req.Metadata.UserID))
	}
	if rule, tool, detail := s.policy.violation(body, &req); rule != "" {
		// One row per violation per session, however often the client retries.
		s.insert(Event{ID: hashID(info.session, rule, tool, detail), User: user, Session: info.session, Kind: "request",
			Tool: tool, Decision: "block", Rule: rule, Detail: detail, Model: info.model})
		msg := fmt.Sprintf("Blocked by company AI policy (rule %s). This conversation holds content that may not be sent to the model: use /rewind to go back before it, or /clear. %s", rule, s.policy.Contact)
		if rule == "mcp:not-allowed" {
			msg = fmt.Sprintf("Blocked by company AI policy: MCP tool %s is not on the approved list. Remove that server with /mcp and retry. %s", tool, s.policy.Contact)
		}
		apiError(w, http.StatusBadRequest, "invalid_request_error", msg)
		return
	}
	if isMessages {
		s.audit(info, &req)
		r = r.WithContext(context.WithValue(r.Context(), infoKey{}, info))
	}
	s.rp.ServeHTTP(w, r)
}

func lastMatch(re *regexp.Regexp, s string) string {
	if m := re.FindAllString(s, -1); len(m) > 0 {
		return m[len(m)-1]
	}
	return ""
}

// audit records what is new in this request: the user's prompt, or the tool
// calls whose results are being sent up. Earlier turns were recorded when they were new.
func (s *server) audit(info reqInfo, req *msgReq) {
	n := len(req.Messages)
	if n == 0 || req.Messages[n-1].Role != "user" {
		return
	}
	var prompt strings.Builder
	results := false
	for _, b := range blocks(req.Messages[n-1].Content) {
		switch {
		case b.Type == "tool_result":
			results = true
		case b.Type == "text" && !strings.HasPrefix(strings.TrimSpace(b.Text), "<system-reminder>"):
			prompt.WriteString(b.Text)
		}
	}
	if !results {
		if p := prompt.String(); p != "" {
			detail := fmt.Sprintf("prompt (%d chars)", len(p))
			if s.policy.LogContent {
				detail = p
			}
			s.insert(Event{ID: hashID(info.session, "prompt", fmt.Sprint(n), p), User: info.user, Session: info.session,
				Kind: "prompt", Decision: "allow", Detail: detail, Model: info.model})
		}
		return
	}
	if n < 2 {
		return
	}
	for _, b := range blocks(req.Messages[n-2].Content) {
		if b.Type == "tool_use" {
			s.insert(Event{ID: hashID(info.session, b.ID), User: info.user, Session: info.session,
				Kind: "tool", Tool: b.Name, Decision: "allow", Detail: b.summary(), Model: info.model})
		}
	}
}

// responded records one model call with its token usage once the response has finished.
func (s *server) responded(info reqInfo, status int, body []byte) {
	in, out := usage(body)
	ev := Event{ID: randID(), User: info.user, Session: info.session, Kind: "request", Decision: "allow",
		Model: info.model, TokensIn: in, TokensOut: out, TS: time.Now().Unix()}
	if status != http.StatusOK {
		ev.Detail = fmt.Sprintf("upstream %d", status)
	}
	s.insert(ev)
}
