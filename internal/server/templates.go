package server

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"time"

	"upturtle/internal/monitor"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

func loadTemplates() (*template.Template, error) {
	tmpl := template.New("layout.gohtml")
	funcMap := template.FuncMap{
		"statusClass":    statusClass,
		"formatTime":     formatTime,
		"formatRelative": formatRelative,
		"formatDuration": formatDuration,
		"currentYear":    currentYear,
		"idSafe":         idSafe,
		// safeURL marks a string as a trusted URL for attribute contexts. Use sparingly.
		"safeURL":        func(s string) template.URL { return template.URL(s) },
	}

	funcMap["render"] = func(name string, data any) (template.HTML, error) {
		if name == "" {
			return "", nil
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return template.HTML(buf.String()), nil
	}

	tmpl = tmpl.Funcs(funcMap)
	parsed, err := tmpl.ParseFS(templateFS, "templates/*.gohtml")
	if err != nil {
		return nil, err
	}
	tmpl = parsed
	return tmpl, nil
}

func statusClass(status monitor.Status) string {
	switch status {
	case monitor.StatusUp:
		return "status-up"
	case monitor.StatusDown:
		return "status-down"
	default:
		return "status-unknown"
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func formatRelative(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	diff := time.Since(t)
	if diff < time.Second {
		diff = time.Second
	}
	if diff < time.Minute {
		return diff.Round(time.Second).String() + " ago"
	}
	if diff < time.Hour {
		return diff.Round(time.Minute).String() + " ago"
	}
	if diff < 24*time.Hour {
		return diff.Round(time.Hour).String() + " ago"
	}
	days := int(diff / (24 * time.Hour))
	return fmt.Sprintf("%dd ago", days)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Millisecond {
		return d.String()
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func currentYear() int {
	return time.Now().Year()
}

// idSafe creates a safe HTML id fragment from a name: lowercased and replacing
// non-alphanumeric characters with dashes.
func idSafe(s string) string {
	if s == "" {
		return "unnamed"
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			// keep alphanumerics (lowercased)
			if r >= 'A' && r <= 'Z' {
				r = r - 'A' + 'a'
			}
			out = append(out, r)
		} else {
			// replace others with dash, avoid duplicate dashes
			if len(out) == 0 || out[len(out)-1] != '-' {
				out = append(out, '-')
			}
		}
	}
	// trim trailing dash
	if len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "unnamed"
	}
	return string(out)
}
