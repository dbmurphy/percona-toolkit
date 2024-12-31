package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Collector struct {
	stalker *Stalker
	db      *sql.DB
	outDir  string
	prefix  string
	wg      sync.WaitGroup
}

func (s *Stalker) collect(ctx context.Context, db *sql.DB, prefix string) error {
	outDir := filepath.Join(s.config.Dest, prefix)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	collector := &Collector{
		stalker: s,
		db:      db,
		outDir:  outDir,
		prefix:  prefix,
	}

	// Start collection goroutines
	collector.wg.Add(1)
	go func() {
		defer collector.wg.Done()
		if err := collector.collectSystemMetrics(); err != nil {
			s.logger.Error("System metrics collection failed: %v", err)
		}
	}()

	if !s.config.SystemOnly {
		collector.wg.Add(1)
		go func() {
			defer collector.wg.Done()
			if err := collector.collectMySQLMetrics(); err != nil {
				s.logger.Error("MySQL metrics collection failed: %v", err)
			}
		}()
	}

	// Wait for collections with timeout
	done := make(chan struct{})
	go func() {
		collector.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("Collection completed successfully")
	case <-time.After(time.Duration(s.config.RunTime) * time.Second):
		s.logger.Warn("Collection timed out after %d seconds", s.config.RunTime)
	}

	return nil
}

func (c *Collector) collectSystemMetrics() error {
	if c.stalker.config.MySQLOnly {
		return nil
	}

	metrics := []struct {
		name    string
		command string
		args    []string
	}{
		{"uptime", "uptime", nil},
		{"uname", "uname", []string{"-a"}},
		{"vmstat", "vmstat", []string{"1"}},
		{"iostat", "iostat", []string{"-dx", "1"}},
		{"mpstat", "mpstat", []string{"1"}},
		{"free", "free", []string{"-m"}},
		{"df", "df", []string{"-h"}},
		{"dmesg", "dmesg", nil},
		{"netstat", "netstat", []string{"-antp"}},
		{"top", "top", []string{"-b", "-n", "1"}},
	}

	for _, metric := range metrics {
		c.wg.Add(1)
		go func(m struct {
			name    string
			command string
			args    []string
		}) {
			defer c.wg.Done()
			outFile := filepath.Join(c.outDir, fmt.Sprintf("%s-%s.txt", c.prefix, m.name))
			if err := c.runCommand(m.command, m.args, outFile); err != nil {
				c.stalker.logger.Error("Failed to collect %s: %v", m.name, err)
			}
		}(metric)
	}

	// Collect special metrics that need custom handling
	if c.stalker.config.CollectTcpdump {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if err := c.collectTcpdump(); err != nil {
				c.stalker.logger.Error("Failed to collect tcpdump: %v", err)
			}
		}()
	}

	return nil
}

func (c *Collector) collectMySQLMetrics() error {
	queries := []struct {
		name  string
		query string
	}{
		{"variables", "SHOW GLOBAL VARIABLES"},
		{"status", "SHOW GLOBAL STATUS"},
		{"processlist", "SHOW FULL PROCESSLIST"},
		{"slave_status", "SHOW SLAVE STATUS"},
		{"innodb_status", "SHOW ENGINE INNODB STATUS"},
		{"mutex_status", "SHOW ENGINE INNODB MUTEX"},
	}

	for _, q := range queries {
		c.wg.Add(1)
		go func(query struct {
			name  string
			query string
		}) {
			defer c.wg.Done()
			outFile := filepath.Join(c.outDir, fmt.Sprintf("%s-mysql-%s.txt", c.prefix, query.name))
			if err := c.collectMySQLQuery(query.query, outFile); err != nil {
				c.stalker.logger.Error("Failed to collect MySQL %s: %v", query.name, err)
			}
		}(q)
	}

	// Collect special MySQL metrics that need custom handling
	if c.stalker.config.CollectGDB {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if err := c.collectGDBStacktrace(); err != nil {
				c.stalker.logger.Error("Failed to collect GDB stacktrace: %v", err)
			}
		}()
	}

	return nil
}

func (c *Collector) runCommand(command string, args []string, outFile string) error {
	cmd := exec.Command(command, args...)

	out, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer out.Close()

	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("command failed: %v", err)
		}
	case <-time.After(time.Duration(c.stalker.config.RunTime) * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			c.stalker.logger.Error("Failed to kill process: %v", err)
		}
		return fmt.Errorf("command timed out")
	}

	return nil
}

func (c *Collector) collectMySQLQuery(query string, outFile string) error {
	rows, err := c.db.Query(query)
	if err != nil {
		return fmt.Errorf("query failed: %v", err)
	}
	defer rows.Close()

	out, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)

	// Get column names
	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("failed to get columns: %v", err)
	}

	// Write header
	fmt.Fprintf(w, "# %s\n", strings.Join(cols, "\t"))

	// Prepare values holders
	vals := make([]interface{}, len(cols))
	for i := range vals {
		vals[i] = new(sql.RawBytes)
	}

	// Write data
	for rows.Next() {
		if err := rows.Scan(vals...); err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}

		for i, val := range vals {
			if i > 0 {
				w.WriteString("\t")
			}
			if rb, ok := val.(*sql.RawBytes); ok {
				w.Write(*rb)
			}
		}
		w.WriteString("\n")
	}

	return w.Flush()
}

func (c *Collector) collectGDBStacktrace() error {
	// Find MySQL process ID
	var pid int
	err := c.db.QueryRow("SELECT @@pid").Scan(&pid)
	if err != nil {
		return fmt.Errorf("failed to get MySQL PID: %v", err)
	}

	outFile := filepath.Join(c.outDir, fmt.Sprintf("%s-gdb.txt", c.prefix))

	gdbCommands := fmt.Sprintf("attach %d\nthread apply all bt\ndetach\nquit", pid)
	cmd := exec.Command("gdb", "-batch", "-nx", "-ex", gdbCommands)

	out, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer out.Close()

	cmd.Stdout = out
	cmd.Stderr = out

	return cmd.Run()
}

func (c *Collector) collectTcpdump() error {
	// Get MySQL port
	var port int
	err := c.db.QueryRow("SELECT @@port").Scan(&port)
	if err != nil {
		return fmt.Errorf("failed to get MySQL port: %v", err)
	}

	outFile := filepath.Join(c.outDir, fmt.Sprintf("%s-tcpdump.cap", c.prefix))

	cmd := exec.Command("tcpdump", "-i", "any", fmt.Sprintf("port %d", port), "-w", outFile)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tcpdump: %v", err)
	}

	time.Sleep(time.Duration(c.stalker.config.RunTime) * time.Second)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop tcpdump: %v", err)
	}

	return cmd.Wait()
}
