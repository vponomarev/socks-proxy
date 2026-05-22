// cmd/route-manager/main.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	//	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	BirdSocket        string `json:"bird_socket"`
	DynamicConfigFile string `json:"dynamic_config_file"`
	APIAddr           string `json:"api_addr"`
	MetricsAddr       string `json:"metrics_addr"`
}

var (
	cfg = Config{
		BirdSocket:        "/var/run/bird.ctl",
		DynamicConfigFile: "/etc/bird/dynamic-prefixes.conf",
		APIAddr:           ":8080",
		MetricsAddr:       ":9090",
	}

	// Prometheus метрики
	metricsRouteOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bird_route_operations_total",
		Help: "Total number of route operations",
	}, []string{"operation", "type"})

	metricsRouteCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bird_routes_total",
		Help: "Total number of dynamic routes",
	}, []string{"nexthop_type"})

	metricsLastOperation = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "bird_last_operation_timestamp",
		Help: "Timestamp of last route operation",
	})

	mu sync.RWMutex
)

type AddRouteRequest struct {
	Prefix      string `json:"prefix"`
	Nexthop     string `json:"nexthop"`
	Description string `json:"description"`
}

type BirdRouteManager struct {
	dynamicConfigPath string
	routes            map[string]RouteInfo
}

type RouteInfo struct {
	Prefix      string    `json:"prefix"`
	Nexthop     string    `json:"nexthop"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

func NewBirdRouteManager() *BirdRouteManager {
	mgr := &BirdRouteManager{
		dynamicConfigPath: cfg.DynamicConfigFile,
		routes:            make(map[string]RouteInfo),
	}
	mgr.loadRoutesFromFile()
	return mgr
}

func validateCIDR(prefix string) bool {
	_, _, err := net.ParseCIDR(prefix)
	return err == nil
}

func (b *BirdRouteManager) birdExec(command string) (string, error) {
	cmd := exec.Command("birdc", "-s", cfg.BirdSocket, command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("birdc error: %v, output: %s", err, output)
	}
	return string(output), nil
}

func (b *BirdRouteManager) AddRoute(prefix, nexthop, description string) error {
	mu.Lock()
	defer mu.Unlock()

	if !validateCIDR(prefix) {
		return fmt.Errorf("invalid CIDR: %s", prefix)
	}

	// Проверяем, существует ли уже маршрут
	if _, exists := b.routes[prefix]; exists {
		return fmt.Errorf("route already exists: %s", prefix)
	}

	// 1. Добавляем через birdc
	var birdCmd string
	if nexthop == "blackhole" {
		birdCmd = fmt.Sprintf("route add %s blackhole", prefix)
	} else {
		birdCmd = fmt.Sprintf("route add %s via %s", prefix, nexthop)
	}

	if _, err := b.birdExec(birdCmd); err != nil {
		return fmt.Errorf("failed to add route via birdc: %v", err)
	}

	// 2. Добавляем в файл конфигурации
	if err := b.appendToConfigFile(prefix, nexthop, description); err != nil {
		// Откатываем изменение в Bird если не удалось записать в файл
		b.birdExec(fmt.Sprintf("route del %s", prefix))
		return fmt.Errorf("failed to write config file: %v", err)
	}

	// 3. Сохраняем в памяти
	b.routes[prefix] = RouteInfo{
		Prefix:      prefix,
		Nexthop:     nexthop,
		Description: description,
		CreatedAt:   time.Now(),
	}

	// Обновляем метрики
	metricsRouteOperations.WithLabelValues("add", getRouteType(nexthop)).Inc()
	metricsRouteCount.WithLabelValues(getRouteType(nexthop)).Inc()
	metricsLastOperation.Set(float64(time.Now().Unix()))

	return nil
}

func (b *BirdRouteManager) appendToConfigFile(prefix, nexthop, description string) error {
	file, err := os.OpenFile(b.dynamicConfigPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	if description != "" {
		if _, err := writer.WriteString(fmt.Sprintf("# %s\n", description)); err != nil {
			return err
		}
	}

	var line string
	if nexthop == "blackhole" {
		line = fmt.Sprintf("route %s blackhole;\n", prefix)
	} else {
		line = fmt.Sprintf("route %s via %s;\n", prefix, nexthop)
	}

	if _, err := writer.WriteString(line); err != nil {
		return err
	}

	return writer.Flush()
}

func (b *BirdRouteManager) DeleteRoute(prefix string) error {
	mu.Lock()
	defer mu.Unlock()

	// Проверяем существование маршрута
	if _, exists := b.routes[prefix]; !exists {
		return fmt.Errorf("route not found: %s", prefix)
	}

	// 1. Удаляем из Bird
	if _, err := b.birdExec(fmt.Sprintf("route del %s", prefix)); err != nil {
		log.Printf("Warning: route not found in Bird: %s", prefix)
	}

	// 2. Удаляем из файла конфигурации
	if err := b.removeFromConfigFile(prefix); err != nil {
		return fmt.Errorf("failed to remove from config file: %v", err)
	}

	// 3. Удаляем из памяти
	delete(b.routes, prefix)

	// Обновляем метрики
	metricsRouteOperations.WithLabelValues("delete", "unknown").Inc()
	metricsLastOperation.Set(float64(time.Now().Unix()))

	return nil
}

func (b *BirdRouteManager) removeFromConfigFile(prefix string) error {
	// Создаем временный файл
	tempFile := b.dynamicConfigPath + ".tmp"

	input, err := os.ReadFile(b.dynamicConfigPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(input), "\n")
	var output []string
	skipNext := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if skipNext && strings.HasPrefix(trimmed, "#") {
			// Пропускаем комментарий связанный с удаляемым маршрутом
			continue
		}
		skipNext = false

		if strings.HasPrefix(trimmed, fmt.Sprintf("route %s", prefix)) {
			// Нашли маршрут для удаления
			skipNext = true
			continue
		}

		output = append(output, line)
	}

	// Записываем во временный файл
	if err := os.WriteFile(tempFile, []byte(strings.Join(output, "\n")), 0644); err != nil {
		return err
	}

	// Атомарно заменяем оригинальный файл
	return os.Rename(tempFile, b.dynamicConfigPath)
}

func (b *BirdRouteManager) ListRoutes() map[string]RouteInfo {
	mu.RLock()
	defer mu.RUnlock()

	// Создаем копию для безопасности
	routesCopy := make(map[string]RouteInfo)
	for k, v := range b.routes {
		routesCopy[k] = v
	}

	return routesCopy
}

func (b *BirdRouteManager) GetRoutesFromBird() (string, error) {
	return b.birdExec("show route protocol static_dyn")
}

func (b *BirdRouteManager) loadRoutesFromFile() error {
	mu.Lock()
	defer mu.Unlock()

	content, err := os.ReadFile(b.dynamicConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Файл не существует, это нормально
		}
		return err
	}

	lines := strings.Split(string(content), "\n")
	var currentDesc string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "#") {
			currentDesc = strings.TrimPrefix(trimmed, "# ")
			continue
		}

		if strings.HasPrefix(trimmed, "route ") && strings.HasSuffix(trimmed, ";") {
			// Парсим строку маршрута: "route 1.2.3.4/32 blackhole;" или "route 1.2.3.4/32 via 10.0.0.1;"
			parts := strings.Fields(trimmed)
			if len(parts) < 3 {
				continue
			}

			prefix := parts[1]
			nexthop := parts[2]

			b.routes[prefix] = RouteInfo{
				Prefix:      prefix,
				Nexthop:     nexthop,
				Description: currentDesc,
				CreatedAt:   time.Now(),
			}

			currentDesc = ""
		}
	}

	log.Printf("Loaded %d routes from config file", len(b.routes))
	return nil
}

func getRouteType(nexthop string) string {
	if nexthop == "blackhole" {
		return "blackhole"
	} else if strings.HasPrefix(nexthop, "10.8.") || strings.HasPrefix(nexthop, "192.168.") {
		return "vpn"
	}
	return "other"
}

// HTTP Handlers
func addRouteHandler(w http.ResponseWriter, r *http.Request) {
	var req AddRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Prefix == "" {
		http.Error(w, "prefix is required", http.StatusBadRequest)
		return
	}

	if req.Nexthop == "" {
		req.Nexthop = "blackhole"
	}

	manager := NewBirdRouteManager()
	if err := manager.AddRoute(req.Prefix, req.Nexthop, req.Description); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "added",
		"prefix": req.Prefix,
	})
}

func deleteRouteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	prefix := vars["prefix"]

	if prefix == "" {
		http.Error(w, "prefix is required", http.StatusBadRequest)
		return
	}

	manager := NewBirdRouteManager()
	if err := manager.DeleteRoute(prefix); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "deleted",
		"prefix": prefix,
	})
}

func listRoutesHandler(w http.ResponseWriter, r *http.Request) {
	manager := NewBirdRouteManager()

	routes := manager.ListRoutes()
	birdRoutes, err := manager.GetRoutesFromBird()
	if err != nil {
		birdRoutes = fmt.Sprintf("Error getting routes from Bird: %v", err)
	}

	response := map[string]interface{}{
		"dynamic_routes": routes,
		"bird_routes":    birdRoutes,
		"total_routes":   len(routes),
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	manager := NewBirdRouteManager()

	// Проверяем доступность Bird
	if _, err := manager.birdExec("show status"); err != nil {
		http.Error(w, "Bird not available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func updateRouteMetrics() {
	manager := NewBirdRouteManager()
	routes := manager.ListRoutes()

	counts := map[string]int{
		"blackhole": 0,
		"vpn":       0,
		"other":     0,
	}

	for _, route := range routes {
		counts[getRouteType(route.Nexthop)]++
	}

	for typ, count := range counts {
		metricsRouteCount.WithLabelValues(typ).Set(float64(count))
	}
}

func main() {
	// Инициализируем менеджер маршрутов
	//manager := NewBirdRouteManager()

	// Настраиваем HTTP роутер
	router := mux.NewRouter()

	// API endpoints
	router.HandleFunc("/api/v1/route", addRouteHandler).Methods("POST")
	router.HandleFunc("/api/v1/route/{prefix}", deleteRouteHandler).Methods("DELETE")
	router.HandleFunc("/api/v1/routes", listRoutesHandler).Methods("GET")
	router.HandleFunc("/health", healthHandler).Methods("GET")

	// Prometheus метрики
	router.Path("/metrics").Handler(promhttp.Handler())

	// Статический файл для простого web-интерфейса
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	// Запускаем обновление метрик в фоне
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			updateRouteMetrics()
		}
	}()

	// Запускаем HTTP сервер
	log.Printf("Starting Bird Route Manager API on %s", cfg.APIAddr)
	log.Printf("Metrics available on %s/metrics", cfg.MetricsAddr)

	srv := &http.Server{
		Addr:         cfg.APIAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
