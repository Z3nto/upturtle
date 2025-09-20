package notifier

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"upturtle/internal/monitor"

	"github.com/containrrr/shoutrrr"
	"github.com/sirupsen/logrus"
)

// ShoutrrrNotifier sends notifications using containrrr/shoutrrr.
// It uses the per-notification NotifyURL; if empty, no message is sent.
type ShoutrrrNotifier struct{}

// NewShoutrrrNotifier creates a notifier instance.
func NewShoutrrrNotifier() *ShoutrrrNotifier { return &ShoutrrrNotifier{} }

// Notify implements the monitor.Notifier interface.
func (n *ShoutrrrNotifier) Notify(notif monitor.Notification) error {
	target := strings.TrimSpace(notif.NotifyURL)
	if target == "" {
		// No destination configured for this notification
		return nil
	}

	statusEmoji := "✅"
	statusText := "is UP"
	if notif.Status == monitor.StatusDown {
		statusEmoji = "🚨"
		statusText = "went DOWN"
	}
	latencyText := ""
	if notif.Latency > 0 {
		latencyText = fmt.Sprintf(" (latency %s)", notif.Latency.Round(time.Millisecond))
	}
	typeLabel := strings.ToUpper(string(notif.Type))
	message := fmt.Sprintf("%s `%s` [%s] %s%s", statusEmoji, notif.MonitorName, typeLabel, statusText, latencyText)
	if notif.Message != "" {
		message += "\n" + notif.Message
	}

	// Discord
	if strings.HasPrefix(strings.ToLower(target), "discord://") {
		if u, err := url.Parse(target); err == nil {
			q := u.Query()
			q.Set("splitlines", "no")
			q.Set("username", "Upturtle")

			if notif.Status == monitor.StatusDown {
				q.Set("color", "#FF0000")
			} else {
				q.Set("color", "#00FF00")
			}
			q.Set("title", fmt.Sprintf("%s %s %s %s", statusEmoji, notif.MonitorName, statusText, statusEmoji))

			u.RawQuery = q.Encode()
			target = u.String()
		}
	}

	if notif.Target != "" {
		message += "\nTarget: " + notif.Target
	}

	return shoutrrr.Send(target, message)
}

var _ monitor.Notifier = (*ShoutrrrNotifier)(nil)

// ConfigureDebugLogging sets up the Shoutrrr library logging.
// When enabled is true, the global logrus level is set to Debug and wired into Shoutrrr.
// Otherwise, Info level is used. This centralizes Shoutrrr-related logging config here.
func ConfigureDebugLogging(enabled bool) {
	if enabled {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	// Route Shoutrrr logs through logrus
	shoutrrr.SetLogger(logrus.StandardLogger())
}
