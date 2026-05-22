package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type RouteInfo struct {
	Destination string `json:"destination"`
	Via         string `json:"via,omitempty"`
	Interface   string `json:"interface"`
	Source      string `json:"source,omitempty"`
	Error       string `json:"error,omitempty"`
}

type NetworkInfo struct {
	IP           string `json:"ip"`
	ASN          string `json:"asn,omitempty"`
	ASName       string `json:"as_name,omitempty"`
	Network      string `json:"network,omitempty"`
	CIDR         string `json:"cidr,omitempty"`
	Country      string `json:"country,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Error        string `json:"error,omitempty"`
	ResolvedFrom string `json:"resolved_from,omitempty"`
}

type RouteResponse struct {
	Input        string        `json:"input"`
	ResolvedIP   []string      `json:"resolved_ip,omitempty"`
	IsDomain     bool          `json:"is_domain"`
	Routes       []RouteInfo   `json:"routes,omitempty"`
	NetworkInfo  []NetworkInfo `json:"network_info,omitempty"`
	Error        string        `json:"error,omitempty"`
	ResponseTime string        `json:"response_time"`
}

// whoisCache is a simple in-memory cache for whois data
type whoisCache struct {
	mu    sync.RWMutex
	items map[string]NetworkInfo
}

var cache = &whoisCache{
	items: make(map[string]NetworkInfo),
}

var (
	paramPort   = flag.Int("p", 8800, "listen port")
	paramDaemon = flag.Bool("d", false, "daemon mode")
	paramHelp   = flag.Bool("h", false, "print help")
)

// getFromCache retrieves network info from cache
func (c *whoisCache) getFromCache(ip string) (NetworkInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, found := c.items[ip]
	return info, found
}

// saveToCache saves network info to cache
func (c *whoisCache) saveToCache(ip string, info NetworkInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[ip] = info
}

// getNetworkInfo retrieves AS and network information for an IP
func getNetworkInfo(ip string) NetworkInfo {
	info := NetworkInfo{IP: ip}

	// Try to get from cache first
	if cachedInfo, found := cache.getFromCache(ip); found {
		return cachedInfo
	}

	// Method 1: Try using whois command (local, fast)
	info = getNetworkInfoFromWhois(ip)
	if info.Error == "" {
		cache.saveToCache(ip, info)
		return info
	}

	// Method 2: Try using external API (ipinfo.io)
	info = getNetworkInfoFromAPI(ip)
	if info.Error == "" {
		cache.saveToCache(ip, info)
		return info
	}

	return info
}

// getNetworkInfoFromWhois uses local whois command
func getNetworkInfoFromWhois(ip string) NetworkInfo {
	info := NetworkInfo{IP: ip}

	// Execute whois command
	cmd := exec.Command("whois", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// whois might not be installed or other error
		info.Error = "whois command failed"
		return info
	}

	result := string(output)
	lines := strings.Split(result, "\n")

	// Parse whois output for common fields
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract AS number (various formats)
		if strings.HasPrefix(line, "origin:") || strings.HasPrefix(line, "Origin:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info.ASN = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "aut-num:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info.ASN = strings.TrimSpace(parts[1])
			}
		}

		// Extract AS name
		if strings.HasPrefix(line, "descr:") || strings.HasPrefix(line, "Descr:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if info.ASName == "" {
					info.ASName = strings.TrimSpace(parts[1])
				}
			}
		}

		// Extract network/CIDR
		if strings.HasPrefix(line, "route:") || strings.HasPrefix(line, "Route:") ||
			strings.HasPrefix(line, "inetnum:") || strings.HasPrefix(line, "Inetnum:") ||
			strings.HasPrefix(line, "CIDR:") || strings.HasPrefix(line, "cidr:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cidr := strings.TrimSpace(parts[1])
				info.Network = cidr
				// Try to extract CIDR mask
				if !strings.Contains(cidr, "/") {
					// For simple IP ranges, try to calculate CIDR
					if strings.Contains(cidr, " - ") {
						rangeParts := strings.Split(cidr, " - ")
						if len(rangeParts) == 2 {
							startIP := net.ParseIP(strings.TrimSpace(rangeParts[0]))
							endIP := net.ParseIP(strings.TrimSpace(rangeParts[1]))
							if startIP != nil && endIP != nil {
								// Simple approximation - use first IP with /24
								info.CIDR = fmt.Sprintf("%s/24", startIP.String())
							}
						}
					}
				} else {
					info.CIDR = cidr
				}
			}
		}

		// Extract country
		if strings.HasPrefix(line, "country:") || strings.HasPrefix(line, "Country:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info.Country = strings.TrimSpace(parts[1])
			}
		}

		// Extract ISP/Organization
		if strings.HasPrefix(line, "netname:") || strings.HasPrefix(line, "NetName:") ||
			strings.HasPrefix(line, "org-name:") || strings.HasPrefix(line, "OrgName:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if info.ISP == "" {
					info.ISP = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// If we got at least some info, clear error
	if info.ASN != "" || info.Network != "" || info.Country != "" {
		info.Error = ""
	}

	return info
}

// getNetworkInfoFromAPI uses external API (ipinfo.io)
func getNetworkInfoFromAPI(ip string) NetworkInfo {
	info := NetworkInfo{IP: ip}

	// Note: ipinfo.io requires token for ASN info in free tier
	// You can get a free token at https://ipinfo.io/
	// For production use, consider using your own token
	ipinfoToken := os.Getenv("IPINFO_TOKEN")
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	if ipinfoToken != "" {
		url = fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, ipinfoToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		info.Error = fmt.Sprintf("API request failed: %v", err)
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("API returned status: %d", resp.StatusCode)
		return info
	}

	var apiResponse struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname,omitempty"`
		City     string `json:"city,omitempty"`
		Region   string `json:"region,omitempty"`
		Country  string `json:"country,omitempty"`
		Loc      string `json:"loc,omitempty"`
		Org      string `json:"org,omitempty"`
		Postal   string `json:"postal,omitempty"`
		Timezone string `json:"timezone,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		info.Error = fmt.Sprintf("Failed to parse API response: %v", err)
		return info
	}

	// Parse AS information from org field (format: "AS##### Organization Name")
	if apiResponse.Org != "" {
		parts := strings.Fields(apiResponse.Org)
		if len(parts) >= 1 && strings.HasPrefix(parts[0], "AS") {
			info.ASN = parts[0]
			if len(parts) > 1 {
				info.ASName = strings.Join(parts[1:], " ")
			}
		}
		info.ISP = apiResponse.Org
	}

	info.Country = apiResponse.Country

	// Try to get network/CIDR information
	// For this, we can make another request or use local calculation
	// Here's a simple local calculation of the /24 network
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		if ipv4 := parsedIP.To4(); ipv4 != nil {
			// Create a /24 network (common for many ISPs)
			network := net.IPNet{
				IP:   net.IPv4(ipv4[0], ipv4[1], ipv4[2], 0),
				Mask: net.CIDRMask(24, 32),
			}
			info.CIDR = network.String()
			info.Network = network.IP.String()
		}
	}

	return info
}

// resolveDomain resolves a domain name to IP addresses
func resolveDomain(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain: %v", err)
	}

	var ipv4Addrs []string
	for _, ip := range ips {
		// Only include IPv4 addresses
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4Addrs = append(ipv4Addrs, ipv4.String())
		}
	}

	if len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for domain")
	}

	return ipv4Addrs, nil
}

// getRouteInfo retrieves route information for a given IP address
func getRouteInfo(ip string) (*RouteInfo, error) {
	// Validate the input as a valid IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Execute "ip r get" command
	cmd := exec.Command("ip", "r", "get", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error executing ip command: %v", err)
	}

	// Parse command output
	result := string(output)
	result = strings.TrimSpace(result)

	routeInfo := &RouteInfo{
		Destination: ip,
	}

	// Parse output string
	// Example: "1.2.3.4 via 100.115.0.1 dev eth3 src 100.115.237.118"
	parts := strings.Fields(result)

	// Basic output format validation
	if len(parts) < 2 {
		routeInfo.Error = "unexpected ip command output format"
		return routeInfo, nil
	}

	// Look for keywords in the output
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "via":
			if i+1 < len(parts) {
				routeInfo.Via = parts[i+1]
			}
		case "dev":
			if i+1 < len(parts) {
				routeInfo.Interface = parts[i+1]
			}
		case "src":
			if i+1 < len(parts) {
				routeInfo.Source = parts[i+1]
			}
		}
	}

	// If interface not found, it might be a local route
	if routeInfo.Interface == "" {
		// Check if address is local
		if parsedIP.IsLoopback() {
			routeInfo.Interface = "lo"
			routeInfo.Via = "local"
		} else if strings.Contains(result, "local") {
			routeInfo.Interface = "lo"
			routeInfo.Via = "local"
		} else if strings.Contains(result, "linkdown") {
			routeInfo.Interface = "unknown"
			routeInfo.Error = "interface unavailable (linkdown)"
		} else {
			routeInfo.Interface = "unknown"
			routeInfo.Error = "failed to determine interface"
		}
	}

	return routeInfo, nil
}

// processInput handles both IP addresses and domain names
func processInput(input string, asQuery bool) (*RouteResponse, error) {
	startTime := time.Now()
	response := &RouteResponse{
		Input: input,
	}

	// Try to parse as IP first
	parsedIP := net.ParseIP(input)
	if parsedIP != nil {
		// It's an IP address
		response.IsDomain = false
		response.ResolvedIP = append([]string{}, input)

		// Get route info
		routeInfo, err := getRouteInfo(input)
		if err != nil {
			return nil, err
		}
		response.Routes = []RouteInfo{*routeInfo}

		if asQuery {
			// Get network/AS info
			networkInfo := getNetworkInfo(input)
			networkInfo.ResolvedFrom = "direct_ip"
			response.NetworkInfo = []NetworkInfo{networkInfo}
		}
	} else {
		// It might be a domain name
		response.IsDomain = true

		// Resolve domain name
		ips, err := resolveDomain(input)
		if err != nil {
			return nil, err
		}

		// Get route info and network info for each resolved IP
		var routes []RouteInfo
		var networkInfos []NetworkInfo
		for _, ip := range ips {
			// Get route info
			routeInfo, err := getRouteInfo(ip)
			if err != nil {
				// Create error entry for this IP
				errorRoute := RouteInfo{
					Destination: ip,
					Error:       err.Error(),
				}
				routes = append(routes, errorRoute)
			} else {
				routes = append(routes, *routeInfo)
			}

			if asQuery {
				// Get network info
				networkInfo := getNetworkInfo(ip)
				networkInfo.ResolvedFrom = input
				networkInfos = append(networkInfos, networkInfo)
			}
		}

		response.Routes = routes
		response.NetworkInfo = networkInfos
		if len(ips) > 0 {
			response.ResolvedIP = ips
		}
	}

	response.ResponseTime = time.Since(startTime).String()

	return response, nil
}

func routeHandler(w http.ResponseWriter, r *http.Request) {
	// Allow CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get input from request parameters
	input := r.URL.Query().Get("ip")
	if input == "" {
		// Try to get from POST request
		if r.Method == "POST" {
			r.ParseForm()
			input = r.Form.Get("ip")
		}

		// If still empty
		if input == "" {
			http.Error(w, `{"error": "Parameter 'ip' is required"}`, http.StatusBadRequest)
			return
		}
	}

	asQuery := r.URL.Query().Get("as") == "1"
	// Process input (IP or domain)
	response, err := processInput(input, asQuery)
	if err != nil {
		errorResponse := RouteResponse{
			Input: input,
			Error: err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Check for port parameter
	flag.Parse()

	if *paramHelp {
		fmt.Printf("Usage: %s [-p <port>][-d]\n", os.Args[0])
		fmt.Println("Parameters:")
		fmt.Println("  -p <port> - listen port (default: 8800)")
		fmt.Println("  -d        - daemon mode")
		fmt.Println("Optional environment variables:")
		fmt.Println("  IPINFO_TOKEN - Token for ipinfo.io API (for better AS information)")
		os.Exit(1)
	}

	// Check if whois is installed
	_, err := exec.LookPath("whois")
	if err != nil {
		log.Printf("Warning: 'whois' command not found. Install it for better network information:")
		log.Printf("  Ubuntu/Debian: sudo apt install whois")
		log.Printf("  CentOS/RHEL: sudo yum install whois")
	}

	// Configure HTTP server
	http.HandleFunc("/route", routeHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		// Simple HTML page for testing
		html := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Router Interface Checker</title>
			<meta charset="utf-8">
			<style>
				body { font-family: Arial, sans-serif; margin: 40px; }
				.container { max-width: 900px; margin: 0 auto; }
				input[type="text"] { padding: 10px; width: 300px; }
				button { padding: 10px 20px; }
				.result { margin-top: 20px; padding: 15px; background: #f5f5f5; }
				pre { background: #eee; padding: 10px; overflow-x: auto; }
				.info { background: #e8f4fd; padding: 10px; border-left: 4px solid #2196F3; margin-bottom: 20px; }
				.network-info { background: #f0f8ff; padding: 10px; margin: 10px 0; border-left: 4px solid #4CAF50; }
				.route-info { background: #fff8e1; padding: 10px; margin: 10px 0; border-left: 4px solid #FF9800; }
				.api-token { background: #fff3e0; padding: 10px; margin: 10px 0; border-left: 4px solid #FF5722; }
			</style>
		</head>
		<body>
			<div class="container">
				<h1>Route Interface Checker</h1>
				<div class="info">
					<h3>Features:</h3>
					<ul>
						<li>Check routing information for any IP address or domain</li>
						<li>Get AS (Autonomous System) information</li>
						<li>View network/CIDR information</li>
						<li>For domains: resolves all A records and shows info for each IP</li>
					</ul>
				</div>
				<form id="ipForm">
					<input type="text" id="ip" placeholder="Enter IP address or domain" value="8.8.8.8">
					<div><input id="as" type="checkbox" value="1"/> AS Lookup</div>
					<button type="submit">Check</button>
				</form>
				<div id="result" class="result" style="display:none;"></div>
				<div id="examples" style="margin-top: 20px;">
					<h3>Try these examples:</h3>
					<button class="example" onclick="setExample('8.8.8.8')">Google DNS</button>
					<button class="example" onclick="setExample('google.com')">Google (Domain)</button>
					<button class="example" onclick="setExample('1.1.1.1')">Cloudflare DNS</button>
					<button class="example" onclick="setExample('github.com')">GitHub (Domain)</button>
				</div>
			</div>
			<script>
				function setExample(value) {
					document.getElementById('ip').value = value;
				}
				
				document.getElementById('ipForm').onsubmit = function(e) {
					e.preventDefault();
					var ip = document.getElementById('ip').value;
					var as = document.getElementById('as').checked ? '1' : '0';
					fetch('/route?ip=' + encodeURIComponent(ip)+'&as=' + as)
						.then(response => response.json())
						.then(data => {
							var result = document.getElementById('result');
							result.style.display = 'block';
							result.innerHTML = '<h3>Result:</h3><pre>' + 
								JSON.stringify(data, null, 2) + '</pre>';
						})
						.catch(error => {
							var result = document.getElementById('result');
							result.style.display = 'block';
							result.innerHTML = '<h3>Error:</h3><pre>' + error + '</pre>';
						});
				};
			</script>
		</body>
		</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	// Start server
	addr := fmt.Sprintf(":%d", *paramPort)
	log.Printf("Server started on port %v", *paramPort)
	log.Printf("Example requests:")
	log.Printf("  curl http://localhost:%v/route?ip=8.8.8.8", *paramPort)
	log.Printf("  curl http://localhost:%v/route?ip=google.com", *paramPort)
	log.Printf("  curl http://localhost:%v/route?ip=as13335", *paramPort)
	log.Printf("\nNote: For better AS information, set IPINFO_TOKEN environment variable")

	log.Fatal(http.ListenAndServe(addr, nil))
}
