package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Automatic rollback of a self-update that does not start.
//
// After an update the previous binary is kept as <exe>.rollback and <exe>.update.json records
// the switch. The new version must then run for UpdateHealthyAfter before the update counts as
// good (ConfirmUpdate removes both files). Until then:
//   - under a supervisor (Windows System Service, systemd), every start of the new version is
//     counted, and after maxUpdateAttempts starts the previous binary is put back;
//   - in user mode nothing would restart a crashed process, so the first start runs as a small
//     guard that launches the real process, restarts it if it fails, and rolls back if it keeps
//     failing.
//
// This matters most for remote machines: an update that does not start would otherwise leave the
// machine offline with nobody there to fix it.

const (
	// UpdateHealthyAfter is how long a new version must keep running to confirm the update.
	UpdateHealthyAfter = 90 * time.Second
	maxUpdateAttempts  = 4
	guardEnv           = "APN_UPDATE_GUARD"
)

type updateMarker struct {
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Backup      string    `json:"backup"`
	Attempts    int       `json:"attempts"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func markerPath(exe string) string { return exe + ".update.json" }
func backupPath(exe string) string { return exe + ".rollback" }

func readMarker(exe string) (*updateMarker, error) {
	data, err := os.ReadFile(markerPath(exe))
	if err != nil {
		return nil, err
	}
	var mk updateMarker
	if err := json.Unmarshal(data, &mk); err != nil {
		return nil, err
	}
	return &mk, nil
}

func writeMarker(exe string, mk *updateMarker) error {
	data, err := json.MarshalIndent(mk, "", "  ")
	if err != nil {
		return err
	}
	tmp := markerPath(exe) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, markerPath(exe))
}

// recordUpdate keeps a copy of the previous binary and writes the marker. oldBinary is where the
// previous version now lives (it may still be running, which still allows reading it).
func recordUpdate(exe, oldBinary, fromVersion, toVersion string) error {
	if err := copyFile(oldBinary, backupPath(exe)); err != nil {
		return fmt.Errorf("keep previous version: %w", err)
	}
	return writeMarker(exe, &updateMarker{
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Backup:      backupPath(exe),
		UpdatedAt:   time.Now().UTC(),
	})
}

// pendingFor returns the marker when exe was just updated to curVersion and not yet confirmed.
func pendingFor(exe, curVersion string) *updateMarker {
	mk, err := readMarker(exe)
	if err != nil || mk == nil || strings.TrimPrefix(mk.ToVersion, "v") != strings.TrimPrefix(curVersion, "v") {
		return nil
	}
	return mk
}

// ConfirmUpdate marks the running version as good: the marker and the kept previous binary are
// removed. Safe to call when there is nothing to confirm.
func ConfirmUpdate(curVersion string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	confirmUpdate(exe, curVersion)
}

func confirmUpdate(exe, curVersion string) {
	if pendingFor(exe, curVersion) == nil {
		return
	}
	_ = os.Remove(markerPath(exe))
	_ = os.Remove(backupPath(exe))
}

// rollBack puts the previous binary back at exe. The failed binary is renamed aside (a running
// file can be renamed on Windows) and removed later by CleanupOldBinary.
func rollBack(exe string, mk *updateMarker) error {
	backup := mk.Backup
	if backup == "" {
		backup = backupPath(exe)
	}
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("previous version not found: %w", err)
	}
	failed := fmt.Sprintf("%s.old-failed-%d", exe, time.Now().UnixNano())
	if err := os.Rename(exe, failed); err != nil {
		return fmt.Errorf("move failed version aside: %w", err)
	}
	if err := os.Rename(backup, exe); err != nil {
		_ = os.Rename(failed, exe)
		return fmt.Errorf("restore previous version: %w", err)
	}
	_ = os.Chmod(exe, 0o755)
	_ = os.Remove(markerPath(exe))
	return nil
}

// CountSupervisedStart is called at the start of a process that a supervisor restarts (System
// Service worker, systemd). It counts starts of a just-updated version and rolls back after
// maxUpdateAttempts unconfirmed starts. rolledBack=true means the caller should exit so the
// supervisor starts the restored binary.
func CountSupervisedStart(curVersion string) (rolledBack bool, err error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	return countStart(exe, curVersion)
}

func countStart(exe, curVersion string) (bool, error) {
	mk := pendingFor(exe, curVersion)
	if mk == nil {
		return false, nil
	}
	mk.Attempts++
	if mk.Attempts <= maxUpdateAttempts {
		return false, writeMarker(exe, mk)
	}
	if err := rollBack(exe, mk); err != nil {
		return false, err
	}
	return true, nil
}

// guardLauncher starts one run of the real process and returns its exit error (nil = exit 0).
// healthy is closed if the process is still running after the healthy period.
type guardLauncher func(healthy chan<- struct{}) error

// RunUpdateGuard is the user-mode guard. It returns handled=false when no guard is needed (no
// pending update for this version, or this process is the guarded child); the caller then runs
// normally. Otherwise it supervises the new version and returns handled=true: the caller must exit
// (the real process keeps running on its own, or the previous version was started instead).
func RunUpdateGuard(curVersion string, args []string) (handled bool, err error) {
	if os.Getenv(guardEnv) == "child" {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, nil
	}
	if pendingFor(exe, curVersion) == nil {
		return false, nil
	}
	launch := func(healthy chan<- struct{}) error {
		cmd := exec.Command(exe, args...)
		cmd.Env = append(os.Environ(), guardEnv+"=child")
		detachRestartedCmd(cmd)
		if err := cmd.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			return err
		case <-time.After(UpdateHealthyAfter):
			close(healthy)
			return nil // still running: leave it running on its own
		}
	}
	restorePrevious := func() error {
		cmd := exec.Command(exe, args...)
		detachRestartedCmd(cmd)
		return cmd.Start()
	}
	return true, guardLoop(exe, curVersion, launch, restorePrevious, 2*time.Second)
}

func guardLoop(exe, curVersion string, launch guardLauncher, startPrevious func() error, retryDelay time.Duration) error {
	for {
		mk := pendingFor(exe, curVersion)
		if mk == nil {
			return nil
		}
		healthy := make(chan struct{})
		runErr := launch(healthy)
		select {
		case <-healthy:
			confirmUpdate(exe, curVersion)
			return nil
		default:
		}
		var exitErr *exec.ExitError
		if runErr == nil || (errors.As(runErr, &exitErr) && exitErr.ExitCode() == 0) {
			// A clean exit (the user quit, or another instance already runs) is not a failure.
			return nil
		}
		mk.Attempts++
		if mk.Attempts < maxUpdateAttempts {
			if err := writeMarker(exe, mk); err != nil {
				return err
			}
			time.Sleep(retryDelay)
			continue
		}
		if err := rollBack(exe, mk); err != nil {
			return err
		}
		return startPrevious()
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
