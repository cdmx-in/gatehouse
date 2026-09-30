package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	re      *regexp.Regexp
}

type Policy struct {
	DenyPaths    []*Rule `json:"deny_paths"`
	DenyCommands []*Rule `json:"deny_commands"`
	Secrets      []*Rule `json:"secrets"`
	AllowMCP     []*Rule `json:"allow_mcp"`   // absent = MCP unrestricted, [] = no MCP at all
	LogContent   bool    `json:"log_content"` // store prompt text, not just its length
	Contact      string  `json:"contact"`
}

func loadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, rules := range [][]*Rule{p.DenyPaths, p.DenyCommands, p.Secrets, p.AllowMCP} {
		for _, r := range rules {
			if r.re, err = regexp.Compile(r.Pattern); err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.Name, err)
			}
		}
	}
	return &p, nil
}

func match(rules []*Rule, s string) string {
	if s == "" {
		return ""
	}
	for _, r := range rules {
		if r.re.MatchString(s) {
			return r.Name
		}
	}
	return ""
}

// The subset of an Anthropic /v1/messages request that policy and audit need.
type msgReq struct {
	Model    string `json:"model"`
	Metadata struct {
		UserID string `json:"user_id"`
	} `json:"metadata"`
	Tools []struct {
		Name string `json:"name"`
	} `json:"tools"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

type block struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Input struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Path         string `json:"path"`
		Glob         string `json:"glob"`
		URL          string `json:"url"`
		Pattern      string `json:"pattern"`
		Query        string `json:"query"`
	} `json:"input"`
}

// blocks decodes a message's content, which is either a string or a block list.
func blocks(content json.RawMessage) []block {
	var bs []block
	if json.Unmarshal(content, &bs) != nil {
		var s string
		if json.Unmarshal(content, &s) == nil {
			bs = []block{{Type: "text", Text: s}}
		}
	}
	return bs
}

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (b block) path() string { return first(b.Input.FilePath, b.Input.NotebookPath, b.Input.Path) }

// summary is the one line of a tool call worth keeping in the audit trail.
func (b block) summary() string {
	return first(b.Input.Command, b.path(), b.Input.URL, b.Input.Pattern, b.Input.Query)
}

// violation returns the first rule the request breaks ("" = allowed), plus the
// offending tool and an audit detail. It checks the whole conversation, not just
// the newest turn: a denied file's contents stay in the history, so the request
// must keep failing until the user rewinds or clears.
func (p *Policy) violation(body []byte, req *msgReq) (rule, tool, detail string) {
	if p.AllowMCP != nil {
		for _, t := range req.Tools {
			if strings.HasPrefix(t.Name, "mcp__") && match(p.AllowMCP, t.Name) == "" {
				return "mcp:not-allowed", t.Name, ""
			}
		}
	}
	for _, m := range req.Messages {
		if m.Role != "assistant" {
			continue
		}
		for _, b := range blocks(m.Content) {
			if b.Type != "tool_use" {
				continue
			}
			if n := match(p.DenyCommands, b.Input.Command); n != "" {
				return "command:" + n, b.Name, b.summary()
			}
			if n := first(match(p.DenyPaths, b.path()), match(p.DenyPaths, b.Input.Command), match(p.DenyPaths, b.Input.Glob)); n != "" {
				return "path:" + n, b.Name, b.summary()
			}
		}
	}
	// ponytail: regex over the raw JSON body, so a secret split by JSON escapes
	// is missed. Swap in a real scanner (gitleaks) if that gap matters.
	if n := match(p.Secrets, string(body)); n != "" {
		return "secret:" + n, "", "[redacted]"
	}
	return "", "", ""
}
