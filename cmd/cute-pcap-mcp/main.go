package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"cute-pcap-mcp/internal/buildinfo"
	"cute-pcap-mcp/internal/config"
	"cute-pcap-mcp/internal/pcap"
)

func main() {
	args, err := parseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	if args.version {
		fmt.Fprintln(os.Stdout, buildinfo.Get().String())
		return
	}
	if args.configPath == "" {
		fmt.Fprintln(os.Stderr, "-c/--config is required")
		os.Exit(2)
	}
	cfg, err := config.Load(args.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: args.level.slogLevel()}))
	info := buildinfo.Get()
	logger.Info("server.start",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("build_time", info.BuildTime),
		slog.String("go", info.GoVersion),
		slog.Int("allowed_artifact_dir_count", len(cfg.AllowedArtifactDirs)),
		slog.String("log_level", string(args.level)),
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := pcap.Run(ctx, cfg, pcap.ServerOptions{Logger: logger}); err != nil {
		logger.Error("server.exit", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("server.exit", slog.String("outcome", "graceful_shutdown"))
}

type cliArgs struct {
	configPath string
	version    bool
	level      logLevel
}

type logLevel string

const (
	logLevelDebug logLevel = "debug"
	logLevelInfo  logLevel = "info"
	logLevelWarn  logLevel = "warn"
	logLevelError logLevel = "error"
)

func (l logLevel) slogLevel() slog.Level {
	switch l {
	case logLevelDebug:
		return slog.LevelDebug
	case logLevelWarn:
		return slog.LevelWarn
	case logLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func parseCLI(argv []string) (cliArgs, error) {
	fs := flag.NewFlagSet("cute-pcap-mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var configLong, configShort, levelRaw string
	var versionLong, versionShort bool
	fs.StringVar(&configLong, "config", "", "path to YAML config file")
	fs.StringVar(&configShort, "c", "", "shorthand for --config")
	fs.StringVar(&levelRaw, "log-level", "info", "log verbosity: debug, info, warn, error")
	fs.BoolVar(&versionLong, "version", false, "print build metadata and exit")
	fs.BoolVar(&versionShort, "v", false, "shorthand for --version")
	if err := fs.Parse(argv); err != nil {
		return cliArgs{}, fmt.Errorf("invalid CLI arguments: %w", err)
	}
	configPath := configLong
	if configPath == "" {
		configPath = configShort
	}
	if configLong != "" && configShort != "" && configLong != configShort {
		return cliArgs{}, fmt.Errorf("conflicting --config %q and -c %q", configLong, configShort)
	}
	level := logLevel(levelRaw)
	switch level {
	case logLevelDebug, logLevelInfo, logLevelWarn, logLevelError:
	default:
		return cliArgs{}, fmt.Errorf("--log-level must be one of debug, info, warn, error")
	}
	return cliArgs{configPath: configPath, version: versionLong || versionShort, level: level}, nil
}
