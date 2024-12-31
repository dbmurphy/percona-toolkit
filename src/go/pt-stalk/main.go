package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sevlyar/go-daemon"
)

type Config struct {
	Function        string
	Variable        string
	Match           string
	Threshold       float64
	Cycles          int
	Interval        int
	RunTime         int
	Sleep           int
	SleepCollect    int
	Dest            string
	Prefix          string
	CollectGDB      bool
	CollectOProfile bool
	CollectStrace   bool
	CollectTcpdump  bool
	Socket          string
	Host            string
	Port            int
	User            string
	Password        string
	DefaultsFile    string
	Log             string
	Pid             string
	Plugin          string
	Daemonize       bool
	SystemOnly      bool
	MySQLOnly       bool
	RetentionTime   int
	RetentionCount  int
	RetentionSize   int
	DiskBytesFree   int64
	DiskPctFree     int
	NotifyByEmail   string
	Verbose         int
}

type Stalker struct {
	config *Config
	ctx    context.Context
	cancel context.CancelFunc
	logger *Logger
	plugin *Plugin
}

func main() {
	cfg := &Config{}

	// Parse command line flags
	flag.StringVar(&cfg.Function, "function", "status", "Trigger function (status|processlist)")
	flag.StringVar(&cfg.Variable, "variable", "Threads_running", "Variable to monitor")
	flag.StringVar(&cfg.Match, "match", "", "Pattern to match (for processlist)")
	flag.Float64Var(&cfg.Threshold, "threshold", 25, "Threshold value")
	flag.IntVar(&cfg.Cycles, "cycles", 5, "Number of cycles before collecting")
	flag.IntVar(&cfg.Interval, "interval", 1, "Check interval in seconds")
	flag.IntVar(&cfg.RunTime, "run-time", 30, "How long to collect data in seconds")
	flag.IntVar(&cfg.Sleep, "sleep", 300, "How long to sleep after collection")
	flag.IntVar(&cfg.SleepCollect, "sleep-collect", 1, "How long to sleep between collection cycles")
	flag.StringVar(&cfg.Dest, "dest", "/var/lib/pt-stalk", "Output destination directory")
	flag.StringVar(&cfg.Prefix, "prefix", "", "Filename prefix for samples")
	flag.BoolVar(&cfg.CollectGDB, "collect-gdb", false, "Collect GDB stacktraces")
	flag.BoolVar(&cfg.CollectOProfile, "collect-oprofile", false, "Collect OProfile data")
	flag.BoolVar(&cfg.CollectStrace, "collect-strace", false, "Collect strace data")
	flag.BoolVar(&cfg.CollectTcpdump, "collect-tcpdump", false, "Collect tcpdump data")
	flag.StringVar(&cfg.Socket, "socket", "", "MySQL socket file")
	flag.StringVar(&cfg.Host, "host", "", "MySQL host")
	flag.IntVar(&cfg.Port, "port", 3306, "MySQL port")
	flag.StringVar(&cfg.User, "user", "", "MySQL user")
	flag.StringVar(&cfg.Password, "password", "", "MySQL password")
	flag.StringVar(&cfg.DefaultsFile, "defaults-file", "", "MySQL defaults file")
	flag.StringVar(&cfg.Log, "log", "/var/log/pt-stalk.log", "Log file when daemonized")
	flag.StringVar(&cfg.Pid, "pid", "/var/run/pt-stalk.pid", "PID file")
	flag.BoolVar(&cfg.Daemonize, "daemonize", false, "Run as daemon")
	flag.BoolVar(&cfg.SystemOnly, "system-only", false, "Collect only system metrics")
	flag.BoolVar(&cfg.MySQLOnly, "mysql-only", false, "Collect only MySQL metrics")
	flag.IntVar(&cfg.RetentionTime, "retention-time", 30, "Days to retain samples")
	flag.IntVar(&cfg.RetentionCount, "retention-count", 0, "Number of samples to retain")
	flag.IntVar(&cfg.RetentionSize, "retention-size", 0, "Maximum size in MB to retain")
	flag.Int64Var(&cfg.DiskBytesFree, "disk-bytes-free", 100*1024*1024, "Minimum bytes free")
	flag.IntVar(&cfg.DiskPctFree, "disk-pct-free", 5, "Minimum percent free")
	flag.StringVar(&cfg.NotifyByEmail, "notify-by-email", "", "Email address for notifications")
	flag.IntVar(&cfg.Verbose, "verbose", 2, "Verbosity level (0-3)")
	flag.Parse()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize logger
	logger, err := NewLogger(cfg.Log, cfg.Verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	stalker := &Stalker{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		logger: logger,
	}

	// Initialize plugin if specified
	if err := stalker.initPlugin(); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing plugin: %v\n", err)
		os.Exit(1)
	}

	// Create PID file if daemonizing
	if cfg.Daemonize {
		if err := createPIDFile(cfg.Pid); err != nil {
			stalker.logger.Error("Failed to create PID file: %v", err)
			os.Exit(1)
		}
		defer os.Remove(cfg.Pid)
	}

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(cfg.Dest, 0755); err != nil {
		stalker.logger.Error("Failed to create destination directory: %v", err)
		os.Exit(1)
	}

	// Start stalking in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- stalker.Stalk()
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		stalker.logger.Info("Received signal: %v", sig)
		cancel()
	case err := <-errChan:
		if err != nil {
			stalker.logger.Error("Stalking error: %v", err)
			os.Exit(1)
		}
	}

	// Wait for cleanup
	cleanup := make(chan struct{})
	go func() {
		stalker.cleanup()
		close(cleanup)
	}()

	select {
	case <-cleanup:
	case <-time.After(time.Duration(cfg.RunTime*3) * time.Second):
		stalker.logger.Warn("Cleanup timed out")
	}
}

func createPIDFile(pidFile string) error {
	if _, err := os.Stat(pidFile); err == nil {
		// PID file exists, check if process is running
		pidBytes, err := os.ReadFile(pidFile)
		if err != nil {
			return fmt.Errorf("failed to read PID file: %v", err)
		}

		pid := string(pidBytes)
		if _, err := os.Stat(filepath.Join("/proc", pid)); err == nil {
			return fmt.Errorf("process %s is already running", pid)
		}
	}

	return os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
}

func (s *Stalker) daemonize() error {
	if !s.config.Daemonize {
		return nil
	}

	cntxt := &daemon.Context{
		PidFileName: s.config.Pid,
		PidFilePerm: 0644,
		LogFileName: s.config.Log,
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
	}

	d, err := cntxt.Reborn()
	if err != nil {
		return fmt.Errorf("failed to daemonize: %v", err)
	}
	if d != nil {
		os.Exit(0)
	}

	return nil
}
