package redaction

import (
	"regexp"

	"github.com/Busness-app/kypost-server/backend/internal/config"
)

type compiledPattern struct {
	regex       *regexp.Regexp
	replacement string
}

type Engine struct {
	patterns []compiledPattern
}

func New(patterns []config.Pattern) (*Engine, error) {
	compiled := make([]compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledPattern{regex: r, replacement: p.Replacement})
	}
	return &Engine{patterns: compiled}, nil
}

func (e *Engine) Apply(input string) string {
	result := input
	for _, p := range e.patterns {
		result = p.regex.ReplaceAllString(result, p.replacement)
	}
	return result
}
