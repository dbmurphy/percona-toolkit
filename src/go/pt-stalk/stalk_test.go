package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTriggerFunctions(t *testing.T) {
	tests := []struct {
		name      string
		function  string
		variable  string
		match     string
		threshold float64
		expected  bool
	}{
		{"status_threads_running", "status", "Threads_running", "", 5, false},
		{"processlist_sleep", "processlist", "", "Sleep", 10, false},
		{"invalid_function", "invalid", "", "", 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Function:  tc.function,
				Variable:  tc.variable,
				Match:     tc.match,
				Threshold: tc.threshold,
			}
			stalker := &Stalker{config: cfg}

			// Setup test database connection
			db, err := setupTestDB(t)
			if err != nil {
				t.Skip("MySQL not available:", err)
			}
			defer db.Close()

			triggered, err := stalker.checkTrigger(db)
			if tc.function == "invalid" {
				if err == nil {
					t.Error("Expected error for invalid function")
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			} else if triggered != tc.expected {
				t.Errorf("Expected triggered=%v, got %v", tc.expected, triggered)
			}
		})
	}
}

func TestRetention(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-retention-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files with different dates
	dates := []struct {
		dir  string
		time time.Time
	}{
		{"old", time.Now().AddDate(0, 0, -31)},
		{"new", time.Now()},
	}

	for _, d := range dates {
		dir := filepath.Join(tmpDir, d.dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, d.time, d.time); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &Config{
		Dest:          tmpDir,
		RetentionTime: 30,
	}
	stalker := &Stalker{config: cfg}

	if err := stalker.cleanup(); err != nil {
		t.Fatal(err)
	}

	// Check that old directory was removed and new remains
	if _, err := os.Stat(filepath.Join(tmpDir, "old")); !os.IsNotExist(err) {
		t.Error("Old directory should have been removed")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "new")); os.IsNotExist(err) {
		t.Error("New directory should still exist")
	}
}

func TestDiskSpace(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-disk-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name        string
		bytesFree   int64
		pctFree     int
		shouldError bool
	}{
		{"sufficient_space", 1024 * 1024 * 1024, 10, false},
		{"insufficient_bytes", 1024, 10, true},
		{"insufficient_percent", 1024 * 1024 * 1024, 99, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Dest:          tmpDir,
				DiskBytesFree: tc.bytesFree,
				DiskPctFree:   tc.pctFree,
			}
			stalker := &Stalker{config: cfg}

			err := stalker.checkDiskSpace("test")
			if tc.shouldError && err == nil {
				t.Error("Expected disk space error")
			} else if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestPluginHooks(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pt-stalk-plugin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test plugin
	pluginContent := `#!/bin/bash
before_stalk() { echo "before_stalk"; }
before_collect() { echo "before_collect $1"; }
after_collect() { echo "after_collect $1"; }
after_collect_sleep() { echo "after_collect_sleep"; }
after_interval_sleep() { echo "after_interval_sleep"; }
after_stalk() { echo "after_stalk"; }
`
	pluginPath := filepath.Join(tmpDir, "test.sh")
	if err := os.WriteFile(pluginPath, []byte(pluginContent), 0755); err != nil {
		t.Fatal(err)
	}

	logger, _ := NewLogger("", 3)
	cfg := &Config{
		Plugin: pluginPath,
	}
	stalker := &Stalker{
		config: cfg,
		logger: logger,
	}

	if err := stalker.initPlugin(); err != nil {
		t.Fatal(err)
	}

	hooks := []struct {
		hook PluginHook
		args []string
	}{
		{BeforeStalk, nil},
		{BeforeCollect, []string{"test"}},
		{AfterCollect, []string{"test"}},
		{AfterCollectSleep, nil},
		{AfterIntervalSleep, nil},
		{AfterStalk, nil},
	}

	for _, h := range hooks {
		if err := stalker.executePluginHook(h.hook, h.args...); err != nil {
			t.Errorf("Hook %s failed: %v", h.hook, err)
		}
	}
}

func setupTestDB(t *testing.T) (*sql.DB, error) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		dsn = "root@tcp(localhost:3306)/test"
	}
	return sql.Open("mysql", dsn)
}
