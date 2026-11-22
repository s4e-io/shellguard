//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// detachedProcAttr puts the background sender in its own session so it
// outlives the hook process and is not killed with the AI tool's process group.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func platformSystemConfigDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/ShellGuard"
	}
	return "/etc/shellguard"
}

// lockFile takes an advisory flock on path. The kernel drops it if the process
// dies, so a crashed holder can never leave a stale lock behind.
// The parent directory is created first so `--send` works before any hook
// has run for this user.
func lockFile(path string, exclusive, nonblock bool) (func(), error) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if nonblock {
		how |= syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), how)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLocked
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}
