package main

import (
	"fmt"
	"github.com/Busness-app/kypost-server/backend/internal/app"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"log/slog"
	"os"
)

func main() {
	logger, err := logging.New("")
	if err != nil {
		fmt.Fprintln(os.Stderr, `{"app":"kypost","level":"ERROR","message":"invalid KY_LOG_LEVEL; use debug, info, warn or error"}`)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(logger.Handler()))
	if err := app.Run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err.Error())
		os.Exit(1)
	}
}
