package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	birdSocket    = "/var/run/bird.ctl" // Default BIRD control socket
	configFile    = "/etc/bird/exported-prefixes.conf"
	socketTimeout = 5 * time.Second // Connection timeout
)

// BirdClient manages connection to BIRD control socket
type BirdClient struct {
	socketPath string
}

// NewBirdClient creates a new BIRD client instance
func NewBirdClient(socketPath string) *BirdClient {
	if socketPath == "" {
		socketPath = birdSocket
	}
	return &BirdClient{socketPath: socketPath}
}

// SendCommand sends a command to BIRD and returns the response
func (bc *BirdClient) SendCommand(command string) (string, error) {
	// Connect to UNIX socket with timeout
	conn, err := net.DialTimeout("unix", bc.socketPath, socketTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to BIRD socket: %w", err)
	}
	defer conn.Close()

	// Set write/read deadlines
	deadline := time.Now().Add(socketTimeout)
	conn.SetDeadline(deadline)

	// Send command with newline terminator
	cmd := command + "\n"
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	// Read response (BIRD terminates with "0000\n")
	var response strings.Builder
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("failed to read response: %w", err)
		}

		response.WriteString(line)

		// Check for BIRD's termination sequence
		if strings.HasSuffix(line, "0000\n") {
			break
		}
	}

	return response.String(), nil
}

// UpdateStaticRoutes updates the config file and triggers BIRD reload
func UpdateStaticRoutes(client *BirdClient, routes []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// 1. Write new routes to temporary file (atomic operation)
	tmpFile, err := os.CreateTemp(filepath.Dir(configFile), "bird-prefixes-*.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Clean up on failure

	// Write all routes
	writer := bufio.NewWriter(tmpFile)
	for _, route := range routes {
		if _, err := writer.WriteString(route + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write route: %w", err)
		}
	}
	writer.Flush()
	tmpFile.Sync()
	tmpFile.Close()

	// 2. Atomically replace the config file
	if err := os.Rename(tmpPath, configFile); err != nil {
		return nil, fmt.Errorf("failed to replace config file: %w", err)
	}

	// 3. Trigger soft reconfiguration
	reloadResp, err := client.SendCommand("configure soft")
	if err != nil {
		return nil, fmt.Errorf("BIRD reload failed: %w", err)
	}

	result["reload_response"] = reloadResp

	// 4. Verify the reload succeeded
	if strings.Contains(reloadResp, "Reconfigured") ||
		strings.Contains(reloadResp, "Reconfiguration in progress") {
		result["success"] = true

		// Optional: Verify routes are active
		if verifyResp, err := client.SendCommand("show route export_table all"); err == nil {
			result["current_routes"] = verifyResp
		}
	} else {
		result["success"] = false
		result["error"] = "BIRD did not confirm reconfiguration"
	}

	return result, nil
}

// BatchOperation allows grouping multiple route changes
type RouteOperation struct {
	Action  string // "add", "remove", "replace"
	Routes  []string
	Comment string
}

// BatchUpdateRoutes processes multiple operations efficiently
func BatchUpdateRoutes(client *BirdClient, operations []RouteOperation) (map[string]interface{}, error) {
	// Read existing routes
	existingRoutes, err := readExistingRoutes()
	if err != nil {
		return nil, fmt.Errorf("failed to read existing routes: %w", err)
	}

	// Apply operations
	for _, op := range operations {
		switch strings.ToLower(op.Action) {
		case "add":
			existingRoutes = append(existingRoutes, op.Routes...)
		case "remove":
			existingRoutes = removeRoutes(existingRoutes, op.Routes)
		case "replace":
			existingRoutes = op.Routes
		}
	}

	// Update all routes at once
	return UpdateStaticRoutes(client, existingRoutes)
}

func readExistingRoutes() ([]string, error) {
	file, err := os.Open(configFile)
	if err != nil {
		// File might not exist yet
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var routes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			routes = append(routes, line)
		}
	}
	return routes, scanner.Err()
}

func removeRoutes(existing, toRemove []string) []string {
	removeSet := make(map[string]bool)
	for _, r := range toRemove {
		removeSet[strings.TrimSpace(r)] = true
	}

	var result []string
	for _, route := range existing {
		cleanRoute := strings.TrimSpace(route)
		if !removeSet[cleanRoute] {
			result = append(result, route)
		}
	}
	return result
}

// Example usage
func main() {
	// Initialize BIRD client
	client := NewBirdClient("/var/run/bird.ctl") // Can also use default

	// Example 1: Simple route update
	fmt.Println("=== Example 1: Simple Update ===")
	routes := []string{
		"route 203.0.113.0/24 blackhole;",
		"route 198.51.100.0/24 blackhole;",
		"# Added via Go API",
	}

	result, err := UpdateStaticRoutes(client, routes)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Success: %v\n", result["success"])
		if routes, ok := result["current_routes"]; ok {
			fmt.Printf("Current routes snippet: %.100s...\n", routes)
		}
	}

	// Example 2: Batch operations
	fmt.Println("\n=== Example 2: Batch Operations ===")
	operations := []RouteOperation{
		{
			Action:  "add",
			Routes:  []string{"route 192.0.2.0/24 blackhole;"},
			Comment: "Add test network",
		},
		{
			Action:  "remove",
			Routes:  []string{"route 198.51.100.0/24 blackhole;"},
			Comment: "Remove old test",
		},
	}

	batchResult, err := BatchUpdateRoutes(client, operations)
	if err != nil {
		fmt.Printf("Batch error: %v\n", err)
	} else {
		fmt.Printf("Batch success: %v\n", batchResult["success"])
	}

	// Example 3: Health check
	fmt.Println("\n=== Example 3: Health Check ===")
	if status, err := client.SendCommand("show status"); err != nil {
		fmt.Printf("BIRD health check failed: %v\n", err)
	} else {
		fmt.Printf("BIRD status:\n%s\n", status)
	}
}
