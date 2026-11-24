package updater

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func setupUpdated(t *testing.T) (exe string) {
	t.Helper()
	dir := t.TempDir()
	exe = filepath.Join(dir, "APN.exe")
	old := filepath.Join(dir, "APN.exe.old")
	if err := os.WriteFile(exe, []byte("new version"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("old version"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := recordUpdate(exe, old, "1.3.21", "1.3.22"); err != nil {
		t.Fatal(err)
	}
	return exe
}

func content(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSupervisedStartsRollBackAfterRepeatedFailures(t *testing.T) {
	exe := setupUpdated(t)
	for i := 1; i <= maxUpdateAttempts; i++ {
		rolled, err := countStart(exe, "1.3.22")
		if err != nil || rolled {
			t.Fatalf("start %d: rolled=%v err=%v", i, rolled, err)
		}
	}
	rolled, err := countStart(exe, "1.3.22")
	if err != nil || !rolled {
		t.Fatalf("expected a rollback, rolled=%v err=%v", rolled, err)
	}
	if got := content(t, exe); got != "old version" {
		t.Fatalf("exe = %q, want the previous version", got)
	}
	if _, err := os.Stat(markerPath(exe)); !os.IsNotExist(err) {
		t.Fatal("marker should be gone after rollback")
	}
	// The restored (older) version starting again must not count or roll anything back.
	if rolled, _ := countStart(exe, "1.3.21"); rolled {
		t.Fatal("previous version rolled back again")
	}
}

func TestConfirmedUpdateKeepsNewVersion(t *testing.T) {
	exe := setupUpdated(t)
	if rolled, _ := countStart(exe, "1.3.22"); rolled {
		t.Fatal("unexpected rollback")
	}
	confirmUpdate(exe, "1.3.22")
	if _, err := os.Stat(markerPath(exe)); !os.IsNotExist(err) {
		t.Fatal("marker not removed")
	}
	if _, err := os.Stat(backupPath(exe)); !os.IsNotExist(err) {
		t.Fatal("backup not removed")
	}
	for i := 0; i < maxUpdateAttempts+2; i++ {
		if rolled, _ := countStart(exe, "1.3.22"); rolled {
			t.Fatal("a confirmed update must never roll back")
		}
	}
	if got := content(t, exe); got != "new version" {
		t.Fatalf("exe = %q", got)
	}
}

func TestOtherVersionIgnoresMarker(t *testing.T) {
	exe := setupUpdated(t)
	confirmUpdate(exe, "1.3.21") // an older binary must not confirm the newer update
	if _, err := os.Stat(markerPath(exe)); err != nil {
		t.Fatal("marker removed by a different version")
	}
}

func exitErr(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperExit$")
	cmd.Env = append(os.Environ(), "APN_TEST_EXIT_CODE="+string(rune('0'+code)))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("helper did not fail: %v", err)
	}
	return err
}

func TestHelperExit(t *testing.T) {
	if c := os.Getenv("APN_TEST_EXIT_CODE"); c != "" {
		os.Exit(int(c[0] - '0'))
	}
}

func TestGuardRollsBackCrashingVersion(t *testing.T) {
	exe := setupUpdated(t)
	crash := exitErr(t, 2)
	runs, restarted := 0, false
	launch := func(healthy chan<- struct{}) error { runs++; return crash }
	err := guardLoopNoSleep(exe, "1.3.22", launch, func() error { restarted = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if runs != maxUpdateAttempts || !restarted {
		t.Fatalf("runs=%d restarted=%v", runs, restarted)
	}
	if got := content(t, exe); got != "old version" {
		t.Fatalf("exe = %q, want the previous version", got)
	}
}

func TestGuardConfirmsHealthyVersion(t *testing.T) {
	exe := setupUpdated(t)
	crash := exitErr(t, 3)
	runs := 0
	launch := func(healthy chan<- struct{}) error {
		runs++
		if runs == 1 {
			return crash // one crash, then it runs fine
		}
		close(healthy)
		return nil
	}
	if err := guardLoopNoSleep(exe, "1.3.22", launch, func() error { t.Fatal("must not roll back"); return nil }); err != nil {
		t.Fatal(err)
	}
	if runs != 2 || content(t, exe) != "new version" {
		t.Fatalf("runs=%d exe=%q", runs, content(t, exe))
	}
	if _, err := os.Stat(markerPath(exe)); !os.IsNotExist(err) {
		t.Fatal("healthy run did not confirm the update")
	}
}

func TestGuardCleanExitIsNotAFailure(t *testing.T) {
	exe := setupUpdated(t)
	launch := func(healthy chan<- struct{}) error { return nil } // e.g. another instance already runs
	if err := guardLoopNoSleep(exe, "1.3.22", launch, func() error { t.Fatal("must not roll back"); return nil }); err != nil {
		t.Fatal(err)
	}
	if content(t, exe) != "new version" {
		t.Fatal("clean exit rolled back")
	}
}

func guardLoopNoSleep(exe, v string, launch guardLauncher, prev func() error) error {
	return guardLoop(exe, v, launch, prev, 0)
}
