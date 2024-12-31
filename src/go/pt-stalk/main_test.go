package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func TestStalker(t *testing.T) {
	// Create temporary directory for test outputs
	tmpDir, err := os.MkdirTemp("", "pt-stalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test configuration
	cfg := &Config{
		Function:      "status",
		Variable:      "Threads_running",
		Threshold:     5,
		Cycles:        2,
		Interval:      1,
		RunTime:       5,
		Sleep:         2,
		Dest:          tmpDir,
		Host:          "localhost",
		Port:          3306,
		User:          os.Getenv("MYSQL_TEST_USER"),
		Password:      os.Getenv("MYSQL_TEST_PASS"),
		Verbose:       3,
		DiskBytesFree: 1024 * 1024, // 1MB
		DiskPctFree:   1,
	}

	// Initialize logger
	logger, err := NewLogger("", cfg.Verbose)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Initialize stalker
	stalker := &Stalker{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		logger: logger,
	}

	// Test MySQL connection
	db, err := sql.Open("mysql", stalker.buildDSN())
	if err != nil {
		t.Skipf("Skipping test, could not connect to MySQL: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Skipf("Skipping test, MySQL not responding: %v", err)
	}

	// Run stalker in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- stalker.Stalk()
	}()

	// Create some test load
	go func() {
		for i := 0; i < 10; i++ {
			db.Exec("SELECT SLEEP(1)")
			time.Sleep(time.Second)
		}
	}()

	// Wait for stalker to finish or timeout
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Stalker failed: %v", err)
		}
	case <-ctx.Done():
		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("Unexpected context error: %v", ctx.Err())
		}
	}

	// Verify outputs
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read output directory: %v", err)
	}

	if len(files) == 0 {
		t.Error("No output files were created")
	}

	// Check specific files
	expectedFiles := []string{
		"mysql-variables.txt",
		"mysql-status.txt",
		"mysql-processlist.txt",
		"uptime.txt",
		"vmstat.txt",
		"iostat.txt",
	}

	for _, dir := range files {
		if !dir.IsDir() {
			continue
		}

		for _, expected := range expectedFiles {
			path := filepath.Join(tmpDir, dir.Name(), expected)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Errorf("Expected file %s not found", path)
			}
		}
	}
}

func TestPluginExecution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-plugin-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test plugin
	pluginContent := `#!/bin/bash
before_stalk() {
    echo "before_stalk called"
    return 0
}
before_collect() {
    echo "before_collect called with $1"
    return 0
}
after_collect() {
    echo "after_collect called with $1"
    return 0
}`

	pluginPath := filepath.Join(tmpDir, "test-plugin.sh")
	if err := os.WriteFile(pluginPath, []byte(pluginContent), 0755); err != nil {
		t.Fatalf("Failed to write test plugin: %v", err)
	}

	logger, err := NewLogger("", 3)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	plugin, err := NewPlugin(pluginPath, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	// Test each hook
	hooks := []struct {
		hook PluginHook
		args []string
	}{
		{BeforeStalk, nil},
		{BeforeCollect, []string{"test_prefix"}},
		{AfterCollect, []string{"test_prefix"}},
	}

	for _, tc := range hooks {
		err := plugin.Execute(tc.hook, tc.args...)
		if err != nil {
			t.Errorf("Plugin execution failed for %s: %v", tc.hook, err)
		}
	}
}

func TestSizeParser(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasError bool
	}{
		{"1K", 1024, false},
		{"1M", 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"1T", 1024 * 1024 * 1024 * 1024, false},
		{"1.5G", 1610612736, false},
		{"1024", 1024, false},
		{"invalid", 0, true},
	}

	for _, tc := range tests {
		result, err := ParseSize(tc.input)
		if tc.hasError && err == nil {
			t.Errorf("Expected error for input %s, got none", tc.input)
		}
		if !tc.hasError && err != nil {
			t.Errorf("Unexpected error for input %s: %v", tc.input, err)
		}
		if !tc.hasError && result != tc.expected {
			t.Errorf("For input %s, expected %d, got %d", tc.input, tc.expected, result)
		}
	}
}
