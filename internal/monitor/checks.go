package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"os/exec"
	"regexp"
)

func checkHTTP(cfg MonitorConfig) CheckResult {
	result := CheckResult{Timestamp: time.Now()}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Target, nil)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "upturtle/1.0")

	client := &http.Client{
		Timeout: timeout,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Timestamp = time.Now()
		result.Success = false
		result.Message = err.Error()
		return result
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	latency := time.Since(start)
	result.Timestamp = time.Now()
	result.Latency = latency

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.Success = true
		result.Message = resp.Status
	} else {
		result.Success = false
		result.Message = resp.Status
	}

	return result
}

func checkICMP(cfg MonitorConfig) CheckResult {
    timeout := cfg.Timeout
    if timeout <= 0 {
        timeout = 5 * time.Second
    }

    latency, err := pingHost(cfg.Target, timeout)
    if err != nil {
        return CheckResult{Success: false, Message: err.Error(), Timestamp: time.Now()}
    }
    return CheckResult{Success: true, Latency: latency, Message: "icmp reply", Timestamp: time.Now()}
}

// pingHost executes /bin/ping once and parses RTT
func pingHost(target string, timeout time.Duration) (time.Duration, error) {
    target = strings.TrimSpace(target)
    if target == "" {
        return 0, errors.New("empty target")
    }

    // Use system ping binary. We prefer iputils-ping at /bin/ping.
    // Build command: ping -n -c 1 -W <timeoutSec> <target>
    toSec := int(timeout.Truncate(time.Second) / time.Second)
    if toSec <= 0 {
        toSec = 1
    }
    args := []string{"-n", "-c", "1", "-W", fmt.Sprintf("%d", toSec), target}
    pingPath, lerr := exec.LookPath("ping")
    if lerr != nil {
        return 0, fmt.Errorf("could not find 'ping' in PATH: %w", lerr)
    }

    ctx, cancel := context.WithTimeout(context.Background(), timeout+1*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, pingPath, args...)
    output, err := cmd.CombinedOutput()
    outStr := string(output)
    if ctx.Err() == context.DeadlineExceeded {
        return 0, fmt.Errorf("ping timed out after %v", timeout)
    }
    if err != nil {
        return 0, fmt.Errorf("ping failed: %w; output: %s", err, strings.TrimSpace(outStr))
    }

    // Try to parse time=XX ms from reply line.
    msRe := regexp.MustCompile(`time=([0-9]+(?:\.[0-9]+)?)\s*ms`)
    if m := msRe.FindStringSubmatch(outStr); len(m) == 2 {
        ms, perr := time.ParseDuration(m[1] + "ms")
        if perr == nil {
            return ms, nil
        }
    }

    // Fallback: parse rtt min/avg/max/mdev = a/b/c/d ms line and take avg (second number)
    rttRe := regexp.MustCompile(`(?m)rtt [^=]*=\s*([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?) ms`)
    if m := rttRe.FindStringSubmatch(outStr); len(m) == 5 {
        avg := m[2]
        ms, perr := time.ParseDuration(avg + "ms")
        if perr == nil {
            return ms, nil
        }
    }

    return 0, errors.New("failed to parse ping latency from output")
}
