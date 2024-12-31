package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Plugin struct {
	path   string
	env    map[string]string
	logger *Logger
}

type PluginHook string

const (
	BeforeStalk        PluginHook = "before_stalk"
	BeforeCollect      PluginHook = "before_collect"
	AfterCollect       PluginHook = "after_collect"
	AfterCollectSleep  PluginHook = "after_collect_sleep"
	AfterIntervalSleep PluginHook = "after_interval_sleep"
	AfterStalk         PluginHook = "after_stalk"
)

func NewPlugin(path string, logger *Logger) (*Plugin, error) {
	if path == "" {
		return nil, nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve plugin path: %v", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("plugin file not found: %v", err)
	}

	return &Plugin{
		path:   absPath,
		env:    make(map[string]string),
		logger: logger,
	}, nil
}

func (p *Plugin) SetEnv(key, value string) {
	if p != nil {
		p.env[key] = value
	}
}

func (p *Plugin) Execute(hook PluginHook, args ...string) error {
	if p == nil {
		return nil
	}

	p.logger.Debug("Executing plugin hook: %s", hook)

	// Prepare environment variables
	env := os.Environ()
	for k, v := range p.env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Add hook name to environment
	env = append(env, fmt.Sprintf("PT_HOOK=%s", hook))

	// Create temporary script to execute the plugin
	tmpScript, err := os.CreateTemp("", "pt-stalk-plugin-*.sh")
	if err != nil {
		return fmt.Errorf("failed to create temporary script: %v", err)
	}
	defer os.Remove(tmpScript.Name())

	// Write plugin execution script
	script := fmt.Sprintf(`#!/bin/bash
source "%s"
if type %s >/dev/null 2>&1; then
    %s "$@"
    exit $?
else
    exit 0
fi
`, p.path, hook, hook)

	if _, err := tmpScript.WriteString(script); err != nil {
		return fmt.Errorf("failed to write plugin script: %v", err)
	}

	if err := tmpScript.Close(); err != nil {
		return fmt.Errorf("failed to close plugin script: %v", err)
	}

	if err := os.Chmod(tmpScript.Name(), 0755); err != nil {
		return fmt.Errorf("failed to make plugin script executable: %v", err)
	}

	// Execute the plugin
	cmd := exec.Command(tmpScript.Name(), args...)
	cmd.Env = env
	cmd.Dir = filepath.Dir(p.path)

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("plugin hook %s failed: %v\nOutput: %s", hook, err, output)
	}

	if len(output) > 0 {
		p.logger.Debug("Plugin output (%s):\n%s", hook, strings.TrimSpace(string(output)))
	}

	return nil
}

// Helper methods for the Stalker struct to handle plugins
func (s *Stalker) initPlugin() error {
	if s.config.Plugin != "" {
		plugin, err := NewPlugin(s.config.Plugin, s.logger)
		if err != nil {
			return fmt.Errorf("failed to initialize plugin: %v", err)
		}
		s.plugin = plugin

		// Set up environment variables for the plugin
		s.plugin.SetEnv("PT_DEST", s.config.Dest)
		s.plugin.SetEnv("PT_MYSQL_USER", s.config.User)
		s.plugin.SetEnv("PT_MYSQL_HOST", s.config.Host)
		s.plugin.SetEnv("PT_MYSQL_PORT", fmt.Sprintf("%d", s.config.Port))
		s.plugin.SetEnv("PT_INTERVAL", fmt.Sprintf("%d", s.config.Interval))
		s.plugin.SetEnv("PT_SLEEP", fmt.Sprintf("%d", s.config.Sleep))
		s.plugin.SetEnv("PT_FUNCTION", s.config.Function)
		s.plugin.SetEnv("PT_VARIABLE", s.config.Variable)
		s.plugin.SetEnv("PT_THRESHOLD", fmt.Sprintf("%f", s.config.Threshold))
	}
	return nil
}

func (s *Stalker) executePluginHook(hook PluginHook, args ...string) error {
	if s.plugin != nil {
		return s.plugin.Execute(hook, args...)
	}
	return nil
}

// Example plugin usage in the Stalker.Stalk() method:
/*
   // Before starting to stalk
   if err := s.executePluginHook(BeforeStalk); err != nil {
       return fmt.Errorf("plugin before_stalk hook failed: %v", err)
   }

   // Before collecting metrics
   if err := s.executePluginHook(BeforeCollect, prefix); err != nil {
       return fmt.Errorf("plugin before_collect hook failed: %v", err)
   }

   // After collecting metrics
   if err := s.executePluginHook(AfterCollect, prefix); err != nil {
       s.logger.Warn("Plugin after_collect hook failed: %v", err)
   }
*/
