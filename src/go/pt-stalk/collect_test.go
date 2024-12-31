package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectionFunctionality(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-collect-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Dest:           tmpDir,
		RunTime:        2,
		CollectGDB:     true,
		CollectStrace:  true,
		CollectTcpdump: true,
		MySQLOnly:      false,
		SystemOnly:     false,
	}

	logger, _ := NewLogger("", 3)
	stalker := &Stalker{
		config: cfg,
		logger: logger,
	}

	db, err := setupTestDB(t)
	if err != nil {
		t.Skip("MySQL not available:", err)
	}
	defer db.Close()

	prefix := time.Now().Format("2006_01_02_15_04_05")
	ctx := context.Background()
	if err := stalker.collect(ctx, db, prefix); err != nil {
		t.Fatal(err)
	}

	// Verify collection files
	expectedFiles := []string{
		"mysql-variables.txt",
		"mysql-status.txt",
		"mysql-processlist.txt",
		"vmstat.txt",
		"iostat.txt",
		"mpstat.txt",
		"tcpdump.cap",
	}

	outDir := filepath.Join(tmpDir, prefix)
	for _, file := range expectedFiles {
		path := filepath.Join(outDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected file not found: %s", file)
		}
	}
}

func TestMySQLOnlyCollection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-mysql-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Dest:      tmpDir,
		RunTime:   2,
		MySQLOnly: true,
	}

	logger, _ := NewLogger("", 3)
	stalker := &Stalker{
		config: cfg,
		logger: logger,
	}

	db, err := setupTestDB(t)
	if err != nil {
		t.Skip("MySQL not available:", err)
	}
	defer db.Close()

	prefix := time.Now().Format("2006_01_02_15_04_05")
	ctx := context.Background()
	if err := stalker.collect(ctx, db, prefix); err != nil {
		t.Fatal(err)
	}

	// Verify only MySQL files exist
	files, err := os.ReadDir(filepath.Join(tmpDir, prefix))
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "mysql-") {
			t.Errorf("Found non-MySQL file: %s", file.Name())
		}
	}
}

func TestSystemOnlyCollection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-system-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Dest:       tmpDir,
		RunTime:    2,
		SystemOnly: true,
	}

	logger, _ := NewLogger("", 3)
	stalker := &Stalker{
		config: cfg,
		logger: logger,
	}

	prefix := time.Now().Format("2006_01_02_15_04_05")
	ctx := context.Background()
	if err := stalker.collect(ctx, nil, prefix); err != nil {
		t.Fatal(err)
	}

	// Verify only system files exist
	files, err := os.ReadDir(filepath.Join(tmpDir, prefix))
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "mysql-") {
			t.Errorf("Found MySQL file in system-only mode: %s", file.Name())
		}
	}
}

func TestDaemonization(t *testing.T) {
	if os.Getenv("TEST_DAEMONIZATION") != "1" {
		t.Skip("Skipping daemonization test")
	}

	tmpDir, err := os.MkdirTemp("", "pt-stalk-daemon-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pidFile := filepath.Join(tmpDir, "pt-stalk.pid")
	logFile := filepath.Join(tmpDir, "pt-stalk.log")

	cfg := &Config{
		Dest:      tmpDir,
		Pid:       pidFile,
		Log:       logFile,
		Daemonize: true,
	}

	logger, _ := NewLogger(logFile, 3)
	stalker := &Stalker{
		config: cfg,
		logger: logger,
	}

	if err := stalker.daemonize(); err != nil {
		t.Fatal(err)
	}

	// Verify PID file
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		t.Error("PID file not created")
	}

	// Verify log file
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file not created")
	}
}

func TestCollectionErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		setupDB     bool
		expectError bool
	}{
		{
			name: "invalid_dest",
			config: &Config{
				Dest: "/nonexistent/directory",
			},
			setupDB:     true,
			expectError: true,
		},
		{
			name: "no_db_mysql_only",
			config: &Config{
				MySQLOnly: true,
			},
			setupDB:     false,
			expectError: true,
		},
		{
			name: "invalid_command",
			config: &Config{
				CollectGDB: true,
			},
			setupDB:     true,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var db *sql.DB
			if tc.setupDB {
				var err error
				db, err = setupTestDB(t)
				if err != nil {
					t.Skip("MySQL not available:", err)
				}
				defer db.Close()
			}

			logger, _ := NewLogger("", 3)
			stalker := &Stalker{
				config: tc.config,
				logger: logger,
			}

			ctx := context.Background()
			err := stalker.collect(ctx, db, "test")
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			} else if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCollectionTimeout(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-timeout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Dest:    tmpDir,
		RunTime: 1,
	}

	logger, _ := NewLogger("", 3)
	stalker := &Stalker{
		config: cfg,
		logger: logger,
	}

	db, err := setupTestDB(t)
	if err != nil {
		t.Skip("MySQL not available:", err)
	}
	defer db.Close()

	// Create a long-running collection
	done := make(chan error)
	go func() {
		done <- stalker.collect(context.Background(), db, "test")
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Expected timeout error")
		}
	case <-time.After(time.Duration(cfg.RunTime+1) * time.Second):
		t.Error("Collection did not timeout as expected")
	}
}
