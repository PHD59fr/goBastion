package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"goBastion/internal/utils/logger"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := logger.RunAuditCollector(ctx); err != nil {
		// Never print records or client-provided error text to the console.
		fmt.Fprintln(os.Stderr, "audit_collector_failed")
		os.Exit(1)
	}
}
