package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/akshatagarwl/pgtracer/internal/tracer"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting pgtracer")

	t, err := tracer.New()
	if err != nil {
		slog.Error("failed to create tracer", "error", err)
		os.Exit(1)
	}
	defer t.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		slog.Info("received signal, shutting down")
		t.Close()
		os.Exit(0)
	}()

	if err := t.Run(); err != nil {
		slog.Error("failed to run tracer", "error", err)
		os.Exit(1)
	}
}
