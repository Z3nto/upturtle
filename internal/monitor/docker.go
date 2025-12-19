package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/client"
)

// checkDockerContainer inspects a Docker container and returns a CheckResult
func checkDockerContainer(containerID string, timeout time.Duration) CheckResult {
	result := CheckResult{Timestamp: time.Now()}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to create Docker client: %v", err)
		return result
	}
	defer cli.Close()

	start := time.Now()

	// Inspect the container
	containerJSON, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Container not found or error: %v", err)
		return result
	}

	result.Latency = time.Since(start)

	// Check if container is running
	if containerJSON.State == nil {
		result.Success = false
		result.Message = "Container state is unknown"
		return result
	}

	if containerJSON.State.Running {
		result.Success = true
		
		// Build status message with useful info
		statusMsg := "Running"
		if containerJSON.State.Health != nil {
			healthStatus := containerJSON.State.Health.Status
			statusMsg = fmt.Sprintf("Running (Health: %s)", healthStatus)
			
			// Consider unhealthy containers as down
			if healthStatus == "unhealthy" {
				result.Success = false
				statusMsg = "Unhealthy (Health check failed)"
			}
		}
		
		result.Message = statusMsg
	} else {
		result.Success = false
		
		// Provide detailed status
		status := containerJSON.State.Status
		if containerJSON.State.ExitCode != 0 {
			result.Message = fmt.Sprintf("Stopped (Status: %s, Exit code: %d)", status, containerJSON.State.ExitCode)
		} else {
			result.Message = fmt.Sprintf("Stopped (Status: %s)", status)
		}
	}

	return result
}
