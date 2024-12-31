package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const (
	defaultInterval    = 1
	defaultCycles      = 1
	defaultRetention   = 30
	defaultDiskPctFree = 5
	timeFormat         = "2006_01_02_15_04_05"
)

type MetricCollector interface {
	Collect(ctx context.Context, prefix string) error
}

type MetricChecker interface {
	Check(ctx context.Context) (bool, error)
}

type StalkConfig interface {
	Validate() error
}

type LogEntry struct {
	Level   string
	Message string
	Time    time.Time
	Fields  map[string]interface{}
}

func (s *Stalker) buildDSN() string {
	dsn := ""
	if s.config.DefaultsFile != "" {
		dsn += fmt.Sprintf("defaults-file=%s", s.config.DefaultsFile)
	}
	if s.config.User != "" {
		if dsn != "" {
			dsn += "&"
		}
		dsn += fmt.Sprintf("user=%s", s.config.User)
	}
	if s.config.Password != "" {
		if dsn != "" {
			dsn += "&"
		}
		dsn += fmt.Sprintf("password=%s", s.config.Password)
	}
	if s.config.Socket != "" {
		if dsn != "" {
			dsn += "&"
		}
		dsn += fmt.Sprintf("socket=%s", s.config.Socket)
	} else {
		if s.config.Host != "" {
			if dsn != "" {
				dsn += "&"
			}
			dsn += fmt.Sprintf("host=%s", s.config.Host)
		}
		if s.config.Port != 0 {
			if dsn != "" {
				dsn += "&"
			}
			dsn += fmt.Sprintf("port=%d", s.config.Port)
		}
	}
	return dsn
}

func (s *Stalker) Stalk() error {
	s.logger.Info("Starting stalker with config: %+v", s.config)

	// Don't connect to MySQL if we're only collecting system metrics
	var db *sql.DB
	var err error
	if !s.config.SystemOnly {
		db, err = sql.Open("mysql", s.buildDSN())
		if err != nil {
			return fmt.Errorf("failed to connect to MySQL: %v", err)
		}
		defer db.Close()

		// Test the connection
		if err := db.Ping(); err != nil {
			return fmt.Errorf("failed to ping MySQL: %v", err)
		}
	}

	triggerCount := 0
	iteration := 0

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("Stalker received shutdown signal")
			return nil
		default:
			if s.config.SystemOnly {
				// For system-only mode, we treat it as always triggered
				triggerCount++
			} else {
				triggered, err := s.checkTrigger(db)
				if err != nil {
					return fmt.Errorf("failed to check trigger: %v", err)
				}

				if triggered {
					triggerCount++
					s.logger.Info("Trigger condition met (%d/%d)", triggerCount, s.config.Cycles)
				} else {
					if triggerCount > 0 {
						s.logger.Debug("Trigger condition reset (was %d/%d)", triggerCount, s.config.Cycles)
					}
					triggerCount = 0
				}
			}

			if triggerCount >= s.config.Cycles {
				s.logger.Info("Trigger threshold reached, starting collection")

				// Generate collection prefix
				prefix := s.config.Prefix
				if prefix == "" {
					prefix = time.Now().Format("2006_01_02_15_04_05")
				}

				// Check disk space
				if err := s.checkDiskSpace(prefix); err != nil {
					s.logger.Error("Disk space check failed: %v", err)
					return err
				}

				// Start collection
				if err := s.collectWithTimeout(db, prefix); err != nil {
					s.logger.Error("Collection failed: %v", err)
					return err
				}

				// Reset trigger count
				triggerCount = 0
				iteration++

				// Sleep after collection
				s.logger.Info("Sleeping for %d seconds after collection", s.config.Sleep)
				time.Sleep(time.Duration(s.config.Sleep) * time.Second)

				// Check if we've reached max iterations
				if s.config.RetentionCount > 0 && iteration >= s.config.RetentionCount {
					s.logger.Info("Reached maximum iterations (%d), shutting down", s.config.RetentionCount)
					return nil
				}
			}

			// Sleep before next check
			time.Sleep(time.Duration(s.config.Interval) * time.Second)
		}
	}
}

func (s *Stalker) checkTrigger(db *sql.DB) (bool, error) {
	switch s.config.Function {
	case "status":
		return s.checkStatusTrigger(db)
	case "processlist":
		return s.checkProcesslistTrigger(db)
	default:
		return false, fmt.Errorf("unknown function: %s", s.config.Function)
	}
}

func (s *Stalker) checkStatusTrigger(db *sql.DB) (bool, error) {
	query := "SHOW GLOBAL STATUS WHERE Variable_name = ?"
	var name, value string
	err := db.QueryRow(query, s.config.Variable).Scan(&name, &value)
	if err != nil {
		return false, fmt.Errorf("failed to query status: %v", err)
	}

	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false, fmt.Errorf("failed to parse value %s: %v", value, err)
	}

	s.logger.Debug("Status check: %s = %v (threshold: %v)", s.config.Variable, val, s.config.Threshold)
	return val > s.config.Threshold, nil
}

func (s *Stalker) checkProcesslistTrigger(db *sql.DB) (bool, error) {
	query := `SELECT COUNT(*) FROM INFORMATION_SCHEMA.PROCESSLIST WHERE State = ?`
	var count int
	err := db.QueryRow(query, s.config.Match).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to query processlist: %v", err)
	}

	s.logger.Debug("Processlist check: count = %d (threshold: %v)", count, s.config.Threshold)
	return float64(count) > s.config.Threshold, nil
}

func (s *Stalker) checkDiskSpace(prefix string) error {
	// Get disk usage information
	var stat syscall.Statfs_t
	err := syscall.Statfs(s.config.Dest, &stat)
	if err != nil {
		return fmt.Errorf("failed to get disk stats: %v", err)
	}

	// Calculate free space
	blockSize := uint64(stat.Bsize)
	totalBlocks := stat.Blocks
	freeBlocks := stat.Bfree

	totalBytes := totalBlocks * blockSize
	freeBytes := freeBlocks * blockSize
	freePercent := float64(freeBytes) / float64(totalBytes) * 100

	// Check if we have enough free space
	if freeBytes < uint64(s.config.DiskBytesFree) {
		return fmt.Errorf("insufficient free disk space: %d bytes (need %d)", freeBytes, s.config.DiskBytesFree)
	}

	if freePercent < float64(s.config.DiskPctFree) {
		return fmt.Errorf("insufficient free disk space: %.2f%% (need %d%%)", freePercent, s.config.DiskPctFree)
	}

	s.logger.Debug("Disk space check passed: %.2f%% (%.2f GB) free", freePercent, float64(freeBytes)/(1024*1024*1024))
	return nil
}

func (s *Stalker) cleanup() error {
	s.logger.Info("Starting cleanup")

	// Clean up based on retention time
	if s.config.RetentionTime > 0 {
		cutoff := time.Now().AddDate(0, 0, -s.config.RetentionTime)
		err := filepath.Walk(s.config.Dest, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && info.ModTime().Before(cutoff) {
				if err := os.RemoveAll(path); err != nil {
					s.logger.Error("Failed to remove old directory %s: %v", path, err)
					return err
				}
				s.logger.Info("Removed old directory %s", path)
			}
			return nil
		})
		if err != nil {
			s.logger.Error("Error during retention cleanup: %v", err)
			return err
		}
	}
	return nil
}

func (s *Stalker) collectWithTimeout(db *sql.DB, prefix string) error {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(s.config.RunTime)*time.Second)
	defer cancel()

	return s.collect(ctx, db, prefix)
}

type Metrics struct {
	TriggersTotal    int64
	CollectionsTotal int64
	ErrorsTotal      int64
	// ... etc
}

type CollectionError struct {
	Prefix string
	Err    error
}

func (e *CollectionError) Error() string {
	return fmt.Sprintf("collection failed for %s: %v", e.Prefix, e.Err)
}
