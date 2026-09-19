package fetcher

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/expr-lang/expr"
)

const exprPrefix = "expr:"
const exprDatePrefix = "exprdate:"

// Env is the variable environment exposed to expr expressions.
// Fields are exported so that expr-lang can reflect on them.
type Env struct {
	Date dateVars `expr:"date"`
}

// dateVars exposes individual date components as zero-padded strings.
type dateVars struct {
	Year  string `expr:"year"`
	Month string `expr:"month"`
	Day   string `expr:"day"`
}

func newEnv(t time.Time) Env {
	return Env{
		Date: dateVars{
			Year:  fmt.Sprintf("%04d", t.Year()),
			Month: fmt.Sprintf("%02d", int(t.Month())),
			Day:   fmt.Sprintf("%02d", t.Day()),
		},
	}
}

// evalExprDate expands an "exprdate:" template URL by substituting date placeholders
// with the current UTC date:
//
//	{y} → 4-digit year  (e.g. 2026)
//	{m} → 2-digit month (e.g. 04)
//	{d} → 2-digit day   (e.g. 07)
//
// Example:
//
//	"exprdate: https://example.com/{y}{m}{d}.yaml" → "https://example.com/20260407.yaml"
func evalExprDate(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, exprDatePrefix) {
		return content, nil
	}
	src := strings.TrimSpace(trimmed[len(exprDatePrefix):])
	if src == "" {
		return "", fmt.Errorf("exprdate: template is empty")
	}
	now := time.Now().UTC()
	src = strings.ReplaceAll(src, "{y}", fmt.Sprintf("%04d", now.Year()))
	src = strings.ReplaceAll(src, "{m}", fmt.Sprintf("%02d", int(now.Month())))
	src = strings.ReplaceAll(src, "{d}", fmt.Sprintf("%02d", now.Day()))
	return src, nil
}

// the remainder as an expr-lang expression returning a string URL.
// If content does not start with the prefix it is returned unchanged.
// The expression is evaluated with the current UTC time as the date context.
func evalContent(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, exprPrefix) {
		return content, nil
	}

	src := strings.TrimSpace(trimmed[len(exprPrefix):])
	env := newEnv(time.Now().UTC())

	program, err := expr.Compile(src,
		expr.Env(env),
		expr.AsKind(reflect.String),
	)
	if err != nil {
		return "", fmt.Errorf("expr compile %q: %w", src, err)
	}

	out, err := expr.Run(program, env)
	if err != nil {
		return "", fmt.Errorf("expr run %q: %w", src, err)
	}

	result, ok := out.(string)
	if !ok {
		return "", fmt.Errorf("expr %q: expected string result, got %T", src, out)
	}
	return result, nil
}
