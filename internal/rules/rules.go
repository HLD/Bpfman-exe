// Package rules implements warden's YAML detection rule language.
//
//	- id: WD-001
//	  title: Reverse shell
//	  severity: critical        # info|low|medium|high|critical
//	  mitre: T1059.004
//	  event: exec               # one type or a list
//	  action: alert             # alert|kill
//	  match:
//	    all:
//	      - {field: exec.stdin_socket, eq: true}
//	      - {field: proc.name, in: [bash, sh]}
//	      - not: {field: parent.name, in: [sshd]}
//
// Operators: eq, in, prefix, suffix, contains, glob, regex, cidr, gt, lt,
// exists. String operators take a string or a list (any match). When the
// field is a list (e.g. ancestors.name) the condition matches if any element does.
package rules

import (
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exedev/warden/internal/event"
)

// StrList accepts a scalar or a sequence in YAML.
type StrList []string

func (s *StrList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = []string{n.Value}
		return nil
	}
	var l []string
	if err := n.Decode(&l); err != nil {
		return err
	}
	*s = l
	return nil
}

type Node struct {
	All []Node `yaml:"all"`
	Any []Node `yaml:"any"`
	Not *Node  `yaml:"not"`

	Field    string   `yaml:"field"`
	Eq       any      `yaml:"eq"`
	In       []any    `yaml:"in"`
	Prefix   StrList  `yaml:"prefix"`
	Suffix   StrList  `yaml:"suffix"`
	Contains StrList  `yaml:"contains"`
	Glob     StrList  `yaml:"glob"`
	Regex    string   `yaml:"regex"`
	CIDR     StrList  `yaml:"cidr"`
	Gt       *float64 `yaml:"gt"`
	Lt       *float64 `yaml:"lt"`
	Exists   *bool    `yaml:"exists"`

	re    *regexp.Regexp
	cidrs []netip.Prefix
}

type Rule struct {
	ID          string  `yaml:"id" json:"id"`
	Title       string  `yaml:"title" json:"title"`
	Description string  `yaml:"description" json:"description,omitempty"`
	Severity    string  `yaml:"severity" json:"severity"`
	MITRE       string  `yaml:"mitre" json:"mitre,omitempty"`
	Events      StrList `yaml:"event" json:"-"`
	Action      string  `yaml:"action" json:"-"`
	Disabled    bool    `yaml:"disabled" json:"-"`
	Match       Node    `yaml:"match" json:"-"`
}

func (n *Node) compile() error {
	for i := range n.All {
		if err := n.All[i].compile(); err != nil {
			return err
		}
	}
	for i := range n.Any {
		if err := n.Any[i].compile(); err != nil {
			return err
		}
	}
	if n.Not != nil {
		if err := n.Not.compile(); err != nil {
			return err
		}
	}
	if n.Regex != "" {
		re, err := regexp.Compile(n.Regex)
		if err != nil {
			return fmt.Errorf("regex %q: %w", n.Regex, err)
		}
		n.re = re
	}
	for _, c := range n.CIDR {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("cidr %q: %w", c, err)
		}
		n.cidrs = append(n.cidrs, p)
	}
	if n.Field == "" && n.All == nil && n.Any == nil && n.Not == nil {
		return fmt.Errorf("empty condition")
	}
	return nil
}

func (n *Node) Eval(e *event.Event) bool {
	if n.All != nil {
		for i := range n.All {
			if !n.All[i].Eval(e) {
				return false
			}
		}
	}
	if n.Any != nil {
		ok := false
		for i := range n.Any {
			if n.Any[i].Eval(e) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if n.Not != nil && n.Not.Eval(e) {
		return false
	}
	if n.Field == "" {
		return true
	}

	v, ok := e.Get(n.Field)
	if n.Exists != nil {
		present := ok && v != nil && v != ""
		if present != *n.Exists {
			return false
		}
	}
	if !ok {
		return n.Exists != nil && !*n.Exists
	}
	if l, isList := v.([]string); isList {
		for _, s := range l {
			if n.leaf(s) {
				return true
			}
		}
		return false
	}
	return n.leaf(v)
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}

func eq(a, b any) bool {
	if ab, ok := a.(bool); ok {
		bb, ok := b.(bool)
		return ok && ab == bb
	}
	if an, ok := num(a); ok {
		if bn, ok := num(b); ok {
			return an == bn
		}
	}
	return str(a) == str(b)
}

func (n *Node) leaf(v any) bool {
	s := str(v)
	if n.Eq != nil && !eq(v, n.Eq) {
		return false
	}
	if n.In != nil {
		ok := false
		for _, x := range n.In {
			if eq(v, x) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if n.Prefix != nil && !anyOf(n.Prefix, func(p string) bool { return strings.HasPrefix(s, p) }) {
		return false
	}
	if n.Suffix != nil && !anyOf(n.Suffix, func(p string) bool { return strings.HasSuffix(s, p) }) {
		return false
	}
	if n.Contains != nil && !anyOf(n.Contains, func(p string) bool { return strings.Contains(s, p) }) {
		return false
	}
	if n.Glob != nil && !anyOf(n.Glob, func(p string) bool { ok, _ := path.Match(p, s); return ok }) {
		return false
	}
	if n.re != nil && !n.re.MatchString(s) {
		return false
	}
	if n.cidrs != nil {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return false
		}
		ok := false
		for _, p := range n.cidrs {
			if p.Contains(ip.Unmap()) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if n.Gt != nil {
		f, ok := num(v)
		if !ok || f <= *n.Gt {
			return false
		}
	}
	if n.Lt != nil {
		f, ok := num(v)
		if !ok || f >= *n.Lt {
			return false
		}
	}
	return true
}

func anyOf(l []string, f func(string) bool) bool {
	for _, s := range l {
		if f(s) {
			return true
		}
	}
	return false
}

// Engine indexes rules by event type.
type Engine struct {
	Rules  []*Rule
	byType map[string][]*Rule
}

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

func Parse(data []byte) ([]*Rule, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.ID == "" || len(r.Events) == 0 {
			return nil, fmt.Errorf("rule %q: id and event are required", r.Title)
		}
		if !severities[r.Severity] {
			return nil, fmt.Errorf("rule %s: bad severity %q", r.ID, r.Severity)
		}
		if r.Action == "" {
			r.Action = "alert"
		}
		if r.Action != "alert" && r.Action != "kill" {
			return nil, fmt.Errorf("rule %s: bad action %q", r.ID, r.Action)
		}
		if err := r.Match.compile(); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	return rs, nil
}

func ParseFile(p string) ([]*Rule, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	rs, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return rs, nil
}

// NewEngine builds an engine; later rules with the same ID override earlier ones.
func NewEngine(sets [][]*Rule, disabled map[string]bool) *Engine {
	byID := map[string]*Rule{}
	var order []string
	for _, set := range sets {
		for _, r := range set {
			if _, seen := byID[r.ID]; !seen {
				order = append(order, r.ID)
			}
			byID[r.ID] = r
		}
	}
	en := &Engine{byType: map[string][]*Rule{}}
	for _, id := range order {
		r := byID[id]
		if r.Disabled || disabled[id] {
			continue
		}
		en.Rules = append(en.Rules, r)
		for _, t := range r.Events {
			en.byType[t] = append(en.byType[t], r)
		}
	}
	return en
}

func (en *Engine) Match(e *event.Event) []*Rule {
	var out []*Rule
	for _, r := range en.byType[e.Type] {
		if r.Match.Eval(e) {
			out = append(out, r)
		}
	}
	return out
}
