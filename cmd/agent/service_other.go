//go:build !windows

package main

import "context"

func isWindowsService() bool { return false }

func runService(func(ctx context.Context) int) int { return exitError }
