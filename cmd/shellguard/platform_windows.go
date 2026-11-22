//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

const detachedProcess = 0x00000008 // DETACHED_PROCESS

// detachedProcAttr runs the background sender without a console, in its own
// process group, so it outlives the hook process.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

// platformSystemConfigDir resolves ProgramData through the shell API rather
// than %ProgramData%, which a user can override in their own environment.
func platformSystemConfigDir() string {
	if pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && pd != "" {
		return pd + `\ShellGuard`
	}
	return `C:\ProgramData\ShellGuard`
}

// lockFile takes a LockFileEx lock on path; Windows releases it when the
// process exits, so a crashed holder can never leave a stale lock behind.
// The parent directory is created first: `--send` (e.g. the heartbeat task)
// can run for a user who has never triggered a hook, before anything else
// has created %APPDATA%\ShellGuard.
func lockFile(path string, exclusive, nonblock bool) (func(), error) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var flags uint32
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	if nonblock {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	ol := new(windows.Overlapped)
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, flags, 0, 1, 0, ol); err != nil {
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, errLocked
		}
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, nil
}

func isConnReset(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET)
}
