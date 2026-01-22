package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// Duration after which we log the same IP again
	logRateLimitDuration = 1 * time.Minute
)

type Config struct {
	ContainerName     string
	TCPPorts          []uint16
	UDPPorts          []uint16
	InactivityTimeout time.Duration
	AllowedSubnets    []*net.IPNet
	NetworkInterface  string
	GeoIPEnabled      bool
	AllowedCountries  []string
}

type ServerController struct {
	config       Config
	dockerClient *client.Client
	httpClient   *http.Client

	lastActivity  time.Time
	serverStatus  bool
	statusMutex   sync.RWMutex
	activityMutex sync.RWMutex

	ipWhitelist map[string]bool
	ipBlacklist map[string]bool
	ipListMutex sync.RWMutex

	// Track last log time per IP to avoid log flooding
	lastLogTime      map[string]time.Time
	lastLogTimeMutex sync.RWMutex
}

type GeoIPResponse struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	City        string `json:"city"`
}

func NewServerController(config Config) (*ServerController, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &ServerController{
		config:       config,
		dockerClient: dockerClient,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		lastActivity: time.Now(),
		ipWhitelist:  make(map[string]bool),
		ipBlacklist:  make(map[string]bool),
		lastLogTime:  make(map[string]time.Time),
	}, nil
}

func (sc *ServerController) Close() {
	if sc.dockerClient != nil {
		sc.dockerClient.Close()
	}
}

// shouldLogIP checks if we should log activity for this IP based on rate limiting.
// Returns true if enough time has passed since the last log for this IP.
// The key parameter allows differentiating between allowed/blocked logs for the same IP.
func (sc *ServerController) shouldLogIP(ip string, logType string) bool {
	key := logType + ":" + ip

	sc.lastLogTimeMutex.RLock()
	lastTime, exists := sc.lastLogTime[key]
	sc.lastLogTimeMutex.RUnlock()

	if !exists || time.Since(lastTime) > logRateLimitDuration {
		sc.lastLogTimeMutex.Lock()
		sc.lastLogTime[key] = time.Now()
		sc.lastLogTimeMutex.Unlock()
		return true
	}

	return false
}

// updateIPLogTime updates the last log time for an IP without checking.
// Used to keep the rate limit active while traffic continues.
func (sc *ServerController) updateIPLogTime(ip string, logType string) {
	key := logType + ":" + ip

	sc.lastLogTimeMutex.Lock()
	sc.lastLogTime[key] = time.Now()
	sc.lastLogTimeMutex.Unlock()
}

func (sc *ServerController) GetServerStatus(ctx context.Context) (bool, error) {
	containerJSON, err := sc.dockerClient.ContainerInspect(ctx, sc.config.ContainerName)
	if err != nil {
		return false, fmt.Errorf("failed to inspect container: %w", err)
	}

	return containerJSON.State.Running, nil
}

func (sc *ServerController) UpdateServerStatus(ctx context.Context) {
	status, err := sc.GetServerStatus(ctx)
	if err != nil {
		log.Printf("Error getting server status: %v", err)
		return
	}

	sc.statusMutex.Lock()
	previousStatus := sc.serverStatus
	sc.serverStatus = status
	sc.statusMutex.Unlock()

	// Only log if status changed
	if status != previousStatus {
		if status {
			log.Printf("Container '%s' is now running", sc.config.ContainerName)
		} else {
			log.Printf("Container '%s' is now stopped", sc.config.ContainerName)
		}
	}
}

func (sc *ServerController) StartServer(ctx context.Context) error {
	log.Println("Starting container...")

	if err := sc.dockerClient.ContainerStart(ctx, sc.config.ContainerName, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	sc.statusMutex.Lock()
	sc.serverStatus = true
	sc.statusMutex.Unlock()

	log.Printf("Container '%s' started successfully", sc.config.ContainerName)
	return nil
}

func (sc *ServerController) StopServer(ctx context.Context) error {
	log.Println("Stopping container due to inactivity...")

	timeout := 30 // seconds
	if err := sc.dockerClient.ContainerStop(ctx, sc.config.ContainerName, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	sc.statusMutex.Lock()
	sc.serverStatus = false
	sc.statusMutex.Unlock()

	log.Printf("Container '%s' stopped successfully", sc.config.ContainerName)
	return nil
}

func (sc *ServerController) IsServerRunning() bool {
	sc.statusMutex.RLock()
	defer sc.statusMutex.RUnlock()
	return sc.serverStatus
}

func (sc *ServerController) UpdateLastActivity() {
	sc.activityMutex.Lock()
	sc.lastActivity = time.Now()
	sc.activityMutex.Unlock()
}

func (sc *ServerController) GetLastActivity() time.Time {
	sc.activityMutex.RLock()
	defer sc.activityMutex.RUnlock()
	return sc.lastActivity
}

func (sc *ServerController) CheckGeoIP(ip string) (bool, error) {
	if !sc.config.GeoIPEnabled {
		return true, nil // If GeoIP is disabled, allow all
	}

	url := fmt.Sprintf("https://geolocation-db.com/jsonp/%s", ip)
	resp, err := sc.httpClient.Get(url)
	if err != nil {
		return false, fmt.Errorf("geoip request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response and parse JSONP
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	content := string(buf[:n])

	// Extract JSON from JSONP callback
	start := strings.Index(content, "(")
	end := strings.LastIndex(content, ")")
	if start == -1 || end == -1 || start >= end {
		return false, fmt.Errorf("invalid geoip response format")
	}

	jsonStr := content[start+1 : end]
	var geoResp GeoIPResponse
	if err := json.Unmarshal([]byte(jsonStr), &geoResp); err != nil {
		return false, fmt.Errorf("failed to parse geoip response: %w", err)
	}

	for _, country := range sc.config.AllowedCountries {
		if strings.EqualFold(geoResp.CountryCode, country) {
			return true, nil
		}
	}

	return false, nil
}

func (sc *ServerController) IsIPAllowed(ip string) bool {
	sc.ipListMutex.RLock()
	if sc.ipBlacklist[ip] {
		sc.ipListMutex.RUnlock()
		return false
	}
	if sc.ipWhitelist[ip] {
		sc.ipListMutex.RUnlock()
		return true
	}
	sc.ipListMutex.RUnlock()

	// Check allowed subnets
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, subnet := range sc.config.AllowedSubnets {
		if subnet.Contains(parsedIP) {
			sc.addToWhitelist(ip)
			return true
		}
	}

	// Check GeoIP if enabled
	if sc.config.GeoIPEnabled {
		allowed, err := sc.CheckGeoIP(ip)
		if err != nil {
			log.Printf("GeoIP check failed for %s: %v", ip, err)
			// On error, we don't blacklist - could be temporary
			return false
		}
		if allowed {
			sc.addToWhitelist(ip)
			return true
		}
	} else {
		// If GeoIP is disabled, allow IPs not in blacklist
		sc.addToWhitelist(ip)
		return true
	}

	sc.addToBlacklist(ip)
	return false
}

func (sc *ServerController) addToWhitelist(ip string) {
	sc.ipListMutex.Lock()
	sc.ipWhitelist[ip] = true
	sc.ipListMutex.Unlock()
}

func (sc *ServerController) addToBlacklist(ip string) {
	sc.ipListMutex.Lock()
	sc.ipBlacklist[ip] = true
	sc.ipListMutex.Unlock()
}

func (sc *ServerController) BuildBPFFilter() string {
	var filters []string

	for _, port := range sc.config.TCPPorts {
		filters = append(filters, fmt.Sprintf("tcp port %d", port))
	}
	for _, port := range sc.config.UDPPorts {
		filters = append(filters, fmt.Sprintf("udp port %d", port))
	}

	return strings.Join(filters, " or ")
}

func (sc *ServerController) StartPacketCapture(ctx context.Context) error {
	iface := sc.config.NetworkInterface
	if iface == "" {
		iface = "eth0"
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", iface, err)
	}
	defer handle.Close()

	filter := sc.BuildBPFFilter()
	log.Printf("Setting BPF filter: %s", filter)

	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	log.Println("Packet capture started")

	for {
		select {
		case <-ctx.Done():
			log.Println("Packet capture stopped")
			return nil
		case packet := <-packets:
			sc.handlePacket(ctx, packet)
		}
	}
}

func (sc *ServerController) handlePacket(ctx context.Context, packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP string

	switch v := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = v.SrcIP.String()
	case *layers.IPv6:
		srcIP = v.SrcIP.String()
	default:
		return
	}

	if !sc.IsIPAllowed(srcIP) {
		// Rate-limited logging for blocked traffic
		if sc.shouldLogIP(srcIP, "blocked") {
			log.Printf("Blocked traffic from: %s", srcIP)
		}
		return
	}

	// Rate-limited logging for allowed traffic
	if sc.shouldLogIP(srcIP, "allowed") {
		log.Printf("Detected network activity from: %s", srcIP)
	} else {
		// Keep the timer fresh while traffic continues
		sc.updateIPLogTime(srcIP, "allowed")
	}

	sc.UpdateLastActivity()

	if !sc.IsServerRunning() {
		if err := sc.StartServer(ctx); err != nil {
			log.Printf("Failed to start container: %v", err)
		}
	}
}

func (sc *ServerController) StartInactivityMonitor(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.UpdateServerStatus(ctx)

			if sc.IsServerRunning() {
				lastActivity := sc.GetLastActivity()
				if time.Since(lastActivity) > sc.config.InactivityTimeout {
					log.Printf("Inactivity timeout reached (last activity: %v ago)", time.Since(lastActivity).Round(time.Second))
					if err := sc.StopServer(ctx); err != nil {
						log.Printf("Failed to stop container: %v", err)
					}
				}
			}
		}
	}
}

func parseConfig() (Config, error) {
	config := Config{
		ContainerName:    os.Getenv("CONTAINER_NAME"),
		NetworkInterface: os.Getenv("NETWORK_INTERFACE"),
		GeoIPEnabled:     os.Getenv("GEOIP_ENABLED") == "true",
	}

	config.AllowedCountries = []string{}
	if countries := os.Getenv("ALLOWED_COUNTRIES"); countries != "" {
		config.AllowedCountries = strings.Split(countries, ",")
	}

	if config.ContainerName == "" {
		return config, fmt.Errorf("CONTAINER_NAME environment variable is required")
	}

	// Parse TCP ports
	if tcpPorts := os.Getenv("TCP_PORTS"); tcpPorts != "" {
		for _, portStr := range strings.Split(tcpPorts, ",") {
			port, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
			if err != nil {
				return config, fmt.Errorf("invalid TCP port: %s", portStr)
			}
			config.TCPPorts = append(config.TCPPorts, uint16(port))
		}
	}

	// Parse UDP ports
	if udpPorts := os.Getenv("UDP_PORTS"); udpPorts != "" {
		for _, portStr := range strings.Split(udpPorts, ",") {
			port, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
			if err != nil {
				return config, fmt.Errorf("invalid UDP port: %s", portStr)
			}
			config.UDPPorts = append(config.UDPPorts, uint16(port))
		}
	}

	if len(config.TCPPorts) == 0 && len(config.UDPPorts) == 0 {
		return config, fmt.Errorf("at least one TCP_PORTS or UDP_PORTS must be specified")
	}

	// Parse inactivity timeout (default 30 minutes)
	timeoutStr := os.Getenv("INACTIVITY_TIMEOUT")
	if timeoutStr == "" {
		config.InactivityTimeout = 30 * time.Minute
	} else {
		timeout, err := strconv.Atoi(timeoutStr)
		if err != nil {
			return config, fmt.Errorf("invalid INACTIVITY_TIMEOUT: %s", timeoutStr)
		}
		config.InactivityTimeout = time.Duration(timeout) * time.Minute
	}

	// Parse allowed subnets
	if subnets := os.Getenv("ALLOWED_SUBNETS"); subnets != "" {
		for _, subnet := range strings.Split(subnets, ",") {
			subnet = strings.TrimSpace(subnet)
			if subnet == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(subnet)
			if err != nil {
				return config, fmt.Errorf("invalid subnet: %s", subnet)
			}
			config.AllowedSubnets = append(config.AllowedSubnets, ipNet)
		}
	}

	return config, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	config, err := parseConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	log.Println("Starting server control...")
	log.Printf("Container name: %s", config.ContainerName)
	log.Printf("TCP ports: %v", config.TCPPorts)
	log.Printf("UDP ports: %v", config.UDPPorts)
	log.Printf("Inactivity timeout: %v", config.InactivityTimeout)
	log.Printf("Allowed subnets: %v", config.AllowedSubnets)
	log.Printf("GeoIP enabled: %v", config.GeoIPEnabled)
	if config.GeoIPEnabled {
		log.Printf("Allowed countries: %v", config.AllowedCountries)
	}
	if config.NetworkInterface != "" {
		log.Printf("Network interface: %s", config.NetworkInterface)
	}

	controller, err := NewServerController(config)
	if err != nil {
		log.Fatalf("Failed to create server controller: %v", err)
	}
	defer controller.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		cancel()
	}()

	// Get initial server status
	controller.UpdateServerStatus(ctx)

	// Start inactivity monitor in background
	go controller.StartInactivityMonitor(ctx)

	// Start packet capture (blocks until context is cancelled)
	if err := controller.StartPacketCapture(ctx); err != nil {
		log.Fatalf("Packet capture failed: %v", err)
	}

	log.Println("Server control stopped")
}
