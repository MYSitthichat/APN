//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"relayvpn/internal/version"
)

const (
	WinServiceName        = "APNService"
	WinServiceDisplayName = "APN Remote Desktop & VPN Service"
	WinServiceDesc        = "APN 60 FPS P2P Remote Desktop & Built-in L3 VPN (runs at boot before Windows login with Lock Screen & UAC support)"

	serviceWin32OwnProcess      = 0x00000010
	serviceStopped              = 0x00000001
	serviceStartPending         = 0x00000002
	serviceStopPending          = 0x00000003
	serviceRunning              = 0x00000004
	serviceAcceptStop           = 0x00000001
	serviceAcceptShutdown       = 0x00000004
	serviceAcceptSessionChange  = 0x00000080
	serviceControlStop          = 0x00000001
	serviceControlInterrogate   = 0x00000004
	serviceControlShutdown      = 0x00000005
	serviceControlSessionChange = 0x0000000E

	tokenDuplicate        = 0x0002
	tokenQuery            = 0x0008
	tokenAssignPrimary    = 0x0001
	tokenAdjustDefault    = 0x0080
	tokenAdjustSessionID  = 0x0100
	tokenAllAccess        = 0x000F01FF
	tokenElevationClass   = 20
	tokenSessionIDClass   = 12
	securityImpersonation = 2
	tokenPrimary          = 1
	maximumAllowed        = 0x02000000
	createNoWindow        = 0x08000000
	createUnicodeEnv      = 0x00000400
	normalPriorityClass   = 0x00000020
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procStartServiceCtrlDispatcherW  = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerEx = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus             = advapi32.NewProc("SetServiceStatus")
	procOpenProcessToken             = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation          = advapi32.NewProc("GetTokenInformation")
	procDuplicateTokenEx             = advapi32.NewProc("DuplicateTokenEx")
	procSetTokenInformation          = advapi32.NewProc("SetTokenInformation")
	procCreateProcessAsUserW         = advapi32.NewProc("CreateProcessAsUserW")

	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procGetCurrentProcess            = kernel32.NewProc("GetCurrentProcess")
	procWaitForSingleObject          = kernel32.NewProc("WaitForSingleObject")
	procTerminateProcess             = kernel32.NewProc("TerminateProcess")
	procCloseHandle                  = kernel32.NewProc("CloseHandle")

	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// SystemBinaryPath returns C:\Program Files\APN\APN.exe.
func SystemBinaryPath() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "APN", "APN.exe")
}

// SystemDataDir returns C:\ProgramData\APN.
func SystemDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "APN")
}

// SystemConfigPath returns C:\ProgramData\APN\peer.json.
func SystemConfigPath() string {
	return filepath.Join(SystemDataDir(), "peer.json")
}

// SystemBinDir returns C:\ProgramData\APN\bin (persistent ffmpeg.exe, cloudflared.exe, wintun.dll for LocalSystem).
func SystemBinDir() string {
	return filepath.Join(SystemDataDir(), "bin")
}

// IsElevated reports whether the current process has Administrator / LocalSystem privileges.
func IsElevated() bool {
	var hToken syscall.Handle
	cur, _, _ := procGetCurrentProcess.Call()
	r, _, _ := procOpenProcessToken.Call(cur, tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if r == 0 || hToken == 0 {
		return false
	}
	defer procCloseHandle.Call(uintptr(hToken))
	var elev uint32
	var retLen uint32
	r2, _, _ := procGetTokenInformation.Call(
		uintptr(hToken),
		tokenElevationClass,
		uintptr(unsafe.Pointer(&elev)),
		unsafe.Sizeof(elev),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r2 != 0 && elev != 0
}

// GetInfo inspects live Windows SCM status of APNService (works even as non-admin user).
func GetInfo() Info {
	info := Info{
		Supported:        true,
		RunningAsService: os.Getenv("APN_SERVICE_WORKER") == "1",
		ServiceName:      WinServiceName,
		BinaryPath:       SystemBinaryPath(),
		ConfigPath:       SystemConfigPath(),
	}
	cmd := exec.Command("sc.exe", "query", WinServiceName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err == nil {
		txt := strings.ToUpper(string(out))
		info.Installed = true
		info.Running = strings.Contains(txt, "RUNNING") || strings.Contains(txt, "START_PENDING")
	}
	return info
}

// InstallSystemService installs & starts APNService as a boot-time LocalSystem Windows Service.
// If called from a non-elevated user process, it triggers one native Windows UAC prompt cleanly.
func InstallSystemService(migrateCfg, migrateBin string) (Info, error) {
	if !IsElevated() {
		exe, err := os.Executable()
		if err != nil {
			return GetInfo(), err
		}
		var args []string
		args = append(args, "service", "install")
		if migrateCfg != "" {
			args = append(args, "-migrate-cfg", migrateCfg)
		}
		if migrateBin != "" {
			args = append(args, "-migrate-bin", migrateBin)
		}
		if err := elevateSelf(exe, args); err != nil {
			return GetInfo(), err
		}
		// Poll up to 8s for elevated installer to register and start APNService
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			st := GetInfo()
			if st.Installed && st.Running {
				return st, nil
			}
			time.Sleep(350 * time.Millisecond)
		}
		return GetInfo(), nil
	}

	curExe, err := os.Executable()
	if err != nil {
		return GetInfo(), err
	}
	dstExe := SystemBinaryPath()
	dstDir := filepath.Dir(dstExe)

	// Stop existing service if already running so we can cleanly replace binary
	runHiddenWin("sc.exe", "stop", WinServiceName)
	time.Sleep(600 * time.Millisecond)

	if !strings.EqualFold(filepath.Clean(curExe), filepath.Clean(dstExe)) {
		if err := copyFileAtomic(curExe, dstExe, 0o755); err != nil {
			return GetInfo(), fmt.Errorf("คัดลอก APN.exe ไปยัง %s ไม่สำเร็จ: %w", dstExe, err)
		}
	}
	// Copy wintun.dll next to Program Files\APN if present
	curDir := filepath.Dir(curExe)
	for _, dll := range []string{"wintun.dll", "wintun-arm64.dll"} {
		srcDLL := filepath.Join(curDir, dll)
		if _, serr := os.Stat(srcDLL); serr == nil {
			_ = copyFileAtomic(srcDLL, filepath.Join(dstDir, dll), 0o644)
			_ = copyFileAtomic(srcDLL, filepath.Join(SystemBinDir(), dll), 0o644)
		}
	}

	// Preserve existing Device ID, Permanent Password, Saved Peers & FFmpeg/Cloudflared helpers!
	migrateConfigDir(migrateCfg, SystemDataDir())
	migrateBinDir(migrateBin, SystemBinDir())

	// Enable Windows SoftwareSASGeneration=3 so APNService can send Ctrl+Alt+Del (SendSAS) on the Lock Screen!
	runHiddenWin("reg.exe", "add", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"/v", "SoftwareSASGeneration", "/t", "REG_DWORD", "/d", "3", "/f")

	// Register or update Windows Service (Automatic at boot, LocalSystem, auto-restart on failure in 2s!)
	binPathArg := fmt.Sprintf(`"%s" service run`, dstExe)
	if GetInfo().Installed {
		runHiddenWin("sc.exe", "config", WinServiceName, "binPath=", binPathArg, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", WinServiceDisplayName)
	} else {
		if out, err := runHiddenWinOut("sc.exe", "create", WinServiceName, "binPath=", binPathArg, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", WinServiceDisplayName); err != nil {
			return GetInfo(), fmt.Errorf("สร้าง Windows Service ไม่สำเร็จ: %s (%w)", strings.TrimSpace(out), err)
		}
	}
	runHiddenWin("sc.exe", "description", WinServiceName, WinServiceDesc)
	runHiddenWin("sc.exe", "failure", WinServiceName, "reset=", "86400", "actions=", "restart/2000/restart/2000/restart/5000")

	// Update All-Users Desktop & Start Menu shortcuts to launch C:\Program Files\APN\APN.exe
	escExe := strings.ReplaceAll(dstExe, `'`, `''`)
	escDir := strings.ReplaceAll(dstDir, `'`, `''`)
	ps := fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$exe = '%s'; $dir = '%s'
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'APN' -Force
$ws = New-Object -ComObject WScript.Shell
foreach ($lnk in @(
  (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'APN.lnk'),
  (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'APN.lnk')
)) {
  $s = $ws.CreateShortcut($lnk)
  $s.TargetPath = $exe
  $s.WorkingDirectory = $dir
  $s.IconLocation = "$exe,0"
  $s.Description = 'APN Remote Desktop & Built-in L3 VPN (System Service)'
  $s.Save()
}
`, escExe, escDir)
	runHiddenWin("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)

	// Start the service now!
	if out, err := runHiddenWinOut("sc.exe", "start", WinServiceName); err != nil && !strings.Contains(strings.ToUpper(out), "ALREADY RUNNING") {
		return GetInfo(), fmt.Errorf("เริ่มทำงาน APNService ไม่สำเร็จ: %s (%w)", strings.TrimSpace(out), err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := GetInfo()
		if st.Running {
			return st, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return GetInfo(), nil
}

// UninstallSystemService stops and deletes APNService (elevating via UAC if needed).
func UninstallSystemService() error {
	if !IsElevated() {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := elevateSelf(exe, []string{"service", "uninstall"}); err != nil {
			return err
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if !GetInfo().Installed {
				return nil
			}
			time.Sleep(350 * time.Millisecond)
		}
		return nil
	}
	runHiddenWin("sc.exe", "stop", WinServiceName)
	time.Sleep(700 * time.Millisecond)
	runHiddenWin("sc.exe", "delete", WinServiceName)
	return nil
}

// RunSystemService enters the Windows Service Control Manager (SCM) dispatcher loop.
// Once running as LocalSystem in Session 0, it supervises a SYSTEM worker inside the active
// Windows console session (Lock Screen / Winlogon / User Desktop) so APN is online before login
// and can capture/control both the Windows Lock Screen and UAC Admin prompts!
func RunSystemService() error {
	namePtr, _ := syscall.UTF16PtrFromString(WinServiceName)
	table := [2]serviceTableEntry{
		{Name: namePtr, Proc: syscall.NewCallback(winServiceMain)},
		{Name: nil, Proc: 0},
	}
	r, _, err := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		return fmt.Errorf("StartServiceCtrlDispatcherW failed (must be started by Windows SCM): %w", err)
	}
	return nil
}

var (
	svcMu            sync.Mutex
	svcStatusHandle  uintptr
	svcStopCh        chan struct{}
	svcSessionPokeCh chan struct{}
)

func setWinServiceState(state, controls, waitHint uint32) {
	svcMu.Lock()
	h := svcStatusHandle
	svcMu.Unlock()
	if h == 0 {
		return
	}
	st := serviceStatus{
		ServiceType:      serviceWin32OwnProcess,
		CurrentState:     state,
		ControlsAccepted: controls,
		WaitHint:         waitHint,
	}
	_, _, _ = procSetServiceStatus.Call(h, uintptr(unsafe.Pointer(&st)))
}

func winServiceCtrlHandler(control, eventType uint32, eventData, context uintptr) uintptr {
	switch control {
	case serviceControlStop, serviceControlShutdown:
		setWinServiceState(serviceStopPending, 0, 4000)
		svcMu.Lock()
		ch := svcStopCh
		svcStopCh = nil
		svcMu.Unlock()
		if ch != nil {
			close(ch)
		}
		return 0
	case serviceControlSessionChange:
		svcMu.Lock()
		poke := svcSessionPokeCh
		svcMu.Unlock()
		if poke != nil {
			select {
			case poke <- struct{}{}:
			default:
			}
		}
		return 0
	case serviceControlInterrogate:
		return 0
	default:
		return 0
	}
}

func winServiceMain(argc uint32, argv **uint16) uintptr {
	svcMu.Lock()
	stopCh := make(chan struct{})
	pokeCh := make(chan struct{}, 1)
	svcStopCh = stopCh
	svcSessionPokeCh = pokeCh
	svcMu.Unlock()

	namePtr, _ := syscall.UTF16PtrFromString(WinServiceName)
	h, _, _ := procRegisterServiceCtrlHandlerEx.Call(
		uintptr(unsafe.Pointer(namePtr)),
		syscall.NewCallback(winServiceCtrlHandler),
		0,
	)
	if h == 0 {
		return 0
	}
	svcMu.Lock()
	svcStatusHandle = h
	svcMu.Unlock()

	setWinServiceState(serviceStartPending, 0, 3000)
	setWinServiceState(serviceRunning, serviceAcceptStop|serviceAcceptShutdown|serviceAcceptSessionChange, 0)

	superviseActiveConsoleWorker(stopCh, pokeCh)

	setWinServiceState(serviceStopped, 0, 0)
	return 0
}

func activeConsoleSessionID() uint32 {
	r, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r)
}

func superviseActiveConsoleWorker(stopCh <-chan struct{}, pokeCh <-chan struct{}) {
	var (
		curSession uint32 = 0xFFFFFFFF
		workerProc syscall.Handle
		workerExit chan struct{}
	)

	killWorker := func() {
		if workerProc != 0 {
			_, _, _ = procTerminateProcess.Call(uintptr(workerProc), 0)
			_, _, _ = procWaitForSingleObject.Call(uintptr(workerProc), 2500)
			_, _, _ = procCloseHandle.Call(uintptr(workerProc))
			workerProc = 0
			workerExit = nil
			curSession = 0xFFFFFFFF
		}
	}
	defer killWorker()

	launchForSession := func(sid uint32) {
		if sid == 0xFFFFFFFF {
			return
		}
		exe := SystemBinaryPath()
		if _, err := os.Stat(exe); err != nil {
			if cur, cerr := os.Executable(); cerr == nil {
				exe = cur
			}
		}
		cmdLine := fmt.Sprintf(`"%s" peer -config "%s" -service-worker -tray`, exe, SystemConfigPath())
		hProc, err := launchSystemProcessInSession(sid, exe, cmdLine)
		if err != nil {
			return
		}
		workerProc = hProc
		curSession = sid
		done := make(chan struct{})
		workerExit = done
		go func(hp syscall.Handle) {
			_, _, _ = procWaitForSingleObject.Call(uintptr(hp), 0xFFFFFFFF)
			close(done)
		}(hProc)
	}

	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	// Launch immediately on boot (captures Lock Screen / Winlogon Session 1 before login!)
	launchForSession(activeConsoleSessionID())

	for {
		select {
		case <-stopCh:
			return
		case <-workerExit:
			// Worker exited (e.g. after auto-update or unexpected crash) -> clean up & respawn!
			if workerProc != 0 {
				_, _, _ = procCloseHandle.Call(uintptr(workerProc))
				workerProc = 0
				workerExit = nil
				curSession = 0xFFFFFFFF
			}
			select {
			case <-stopCh:
				return
			case <-time.After(800 * time.Millisecond):
			}
			launchForSession(activeConsoleSessionID())
		case <-pokeCh:
			sid := activeConsoleSessionID()
			if sid != 0xFFFFFFFF && sid != curSession {
				killWorker()
				launchForSession(sid)
			}
		case <-ticker.C:
			sid := activeConsoleSessionID()
			if sid == 0xFFFFFFFF {
				continue
			}
			if workerProc == 0 {
				launchForSession(sid)
			} else if sid != curSession {
				killWorker()
				launchForSession(sid)
			}
		}
	}
}

// launchSystemProcessInSession duplicates LocalSystem's own token, assigns TokenSessionId = sid,
// and starts APN peer worker directly inside the active console session (including Lock Screen!).
func launchSystemProcessInSession(sessionID uint32, exePath, cmdLine string) (syscall.Handle, error) {
	var curToken syscall.Handle
	curProc, _, _ := procGetCurrentProcess.Call()
	r, _, err := procOpenProcessToken.Call(curProc, tokenAllAccess, uintptr(unsafe.Pointer(&curToken)))
	if r == 0 || curToken == 0 {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer procCloseHandle.Call(uintptr(curToken))

	var dupToken syscall.Handle
	r, _, err = procDuplicateTokenEx.Call(
		uintptr(curToken),
		maximumAllowed,
		0,
		securityImpersonation,
		tokenPrimary,
		uintptr(unsafe.Pointer(&dupToken)),
	)
	if r == 0 || dupToken == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer procCloseHandle.Call(uintptr(dupToken))

	r, _, err = procSetTokenInformation.Call(
		uintptr(dupToken),
		tokenSessionIDClass,
		uintptr(unsafe.Pointer(&sessionID)),
		unsafe.Sizeof(sessionID),
	)
	if r == 0 {
		return 0, fmt.Errorf("SetTokenInformation(TokenSessionId): %w", err)
	}

	desktopPtr, _ := syscall.UTF16PtrFromString(`winsta0\default`)
	exePtr, _ := syscall.UTF16PtrFromString(exePath)
	cmdPtr, _ := syscall.UTF16PtrFromString(cmdLine)
	workDirPtr, _ := syscall.UTF16PtrFromString(filepath.Dir(exePath))
	envBlock := buildWorkerEnvBlock()

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = desktopPtr

	var pi syscall.ProcessInformation
	r, _, err = procCreateProcessAsUserW.Call(
		uintptr(dupToken),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(cmdPtr)),
		0,
		0,
		0,
		createNoWindow|createUnicodeEnv|normalPriorityClass,
		uintptr(unsafe.Pointer(&envBlock[0])),
		uintptr(unsafe.Pointer(workDirPtr)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return 0, fmt.Errorf("CreateProcessAsUserW: %w", err)
	}
	if pi.Thread != 0 {
		_, _, _ = procCloseHandle.Call(uintptr(pi.Thread))
	}
	return pi.Process, nil
}

func buildWorkerEnvBlock() []uint16 {
	env := os.Environ()
	env = append(env,
		"APN_SERVICE_WORKER=1",
		"APN_BIN_DIR="+SystemBinDir(),
	)
	var out []uint16
	for _, kv := range env {
		u := syscall.StringToUTF16(kv) // includes trailing 0
		out = append(out, u...)
	}
	out = append(out, 0) // double-NUL terminator
	return out
}

func elevateSelf(exePath string, args []string) error {
	var quoted []string
	for _, a := range args {
		if strings.ContainsAny(a, " \t\"") {
			quoted = append(quoted, `"`+strings.ReplaceAll(a, `"`, `\"`)+`"`)
		} else {
			quoted = append(quoted, a)
		}
	}
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exePath)
	paramsPtr, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	dirPtr, _ := syscall.UTF16PtrFromString(filepath.Dir(exePath))
	r, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(filePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		uintptr(unsafe.Pointer(dirPtr)),
		0, // SW_HIDE
	)
	if r <= 32 {
		return errors.New("ผู้ใช้ยกเลิกคำขอสิทธิ์ Administrator (UAC) หรือไม่สามารถยกระดับสิทธิ์ได้")
	}
	return nil
}

func runHiddenWin(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

func runHiddenWinOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// Keep version import used for Windows installer metadata parity.
var _ = version.Version
