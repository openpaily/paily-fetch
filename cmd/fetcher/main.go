// Command fetcher is the paily proxy subscription fetcher daemon.
//
// Configuration is entirely via environment variables:
//
//	PAILY_CORE_URL          paily-core base URL (default: http://localhost:8080)
//	PAILY_SERVICE_SECRET    Bearer token for paily-core (required)
//	FETCH_INTERVAL          Seconds between fetch rounds (default: 600)
//	FETCH_CONCURRENCY       Parallel HTTP download workers (default: 10)
//	FETCH_PARSE_CONCURRENCY Parallel parse workers (default: NumCPU)
//	DOWNLOAD_TIMEOUT        Per-request download timeout in seconds (default: 30)
//	FETCH_UA                User-Agent for subscription downloads (default: clash-verge/v1.0.0)
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/openpaily/paily-fetch/fetcher"
)

func main() {
	cfg := fetcher.Config{
		CoreURL:          envStr("PAILY_CORE_URL", "http://localhost:8080"),
		ServiceSecret:    requireEnv("PAILY_SERVICE_SECRET"),
		FetchInterval:    envDuration("FETCH_INTERVAL", 600),
		HTTPConcurrency:  envInt("FETCH_CONCURRENCY", 10),
		ParseConcurrency: envInt("FETCH_PARSE_CONCURRENCY", runtime.NumCPU()),
		DownloadTimeout:  envDuration("DOWNLOAD_TIMEOUT", 30),
		FetchUA:          envStr("FETCH_UA", "clash-verge/v1.0.0"),
	}

	f := fetcher.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	f.Run(ctx)
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return n
		}
		log.Printf("invalid %s=%q — using default %d", key, v, fallback)
	}
	return fallback
}

func envDuration(key string, fallbackSec int) time.Duration {
	return time.Duration(envInt(key, fallbackSec)) * time.Second
}
