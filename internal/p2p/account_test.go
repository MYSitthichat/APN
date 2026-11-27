package p2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relayvpn/internal/config"
	"relayvpn/internal/rendezvous"
)

func TestDeriveAccountKeys(t *testing.T) {
	a1, e1, err := deriveAccountKeys("somchai", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	a2, e2, _ := deriveAccountKeys("somchai", "correct horse battery")
	if !bytes.Equal(a1, a2) || !bytes.Equal(e1, e2) {
		t.Fatal("the same username and password must give the same keys on every machine")
	}
	if len(a1) != 32 || len(e1) != 32 || bytes.Equal(a1, e1) {
		t.Fatal("auth key and vault key must be 32 bytes and differ from each other")
	}
	a3, e3, _ := deriveAccountKeys("somchai", "correct horse battery!")
	a4, e4, _ := deriveAccountKeys("malee", "correct horse battery")
	if bytes.Equal(a1, a3) || bytes.Equal(e1, e3) || bytes.Equal(a1, a4) || bytes.Equal(e1, e4) {
		t.Fatal("another password or another username must give other keys")
	}
}

func TestVaultSealOpen(t *testing.T) {
	_, key, _ := deriveAccountKeys("somchai", "correct horse battery")
	_, other, _ := deriveAccountKeys("somchai", "another password")
	peers := []config.SyncedPeer{
		{DeviceID: "123456789", Name: "ห้องประชุม", CustomName: true, Group: "ออฟฟิศ", SavedPassword: "s3cret-pass", Fingerprint: "sha256:aa"},
		{DeviceID: "987654321", Deleted: true, UpdatedAt: 5},
	}
	blob, err := sealVault(key, "somchai", peers)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("s3cret-pass")) || bytes.Contains(blob, []byte("123456789")) {
		t.Fatal("the sealed vault shows a password or a device ID in clear")
	}
	got, err := openVault(key, "somchai", blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != peers[0] || got[1] != peers[1] {
		t.Fatalf("round trip changed the list: %+v", got)
	}
	if _, err := openVault(other, "somchai", blob); !errors.Is(err, errVaultKey) {
		t.Fatalf("wrong key: err = %v, want errVaultKey", err)
	}
	if _, err := openVault(key, "malee", blob); !errors.Is(err, errVaultKey) {
		t.Fatalf("another username: err = %v, want errVaultKey", err)
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 1
	if _, err := openVault(key, "somchai", tampered); !errors.Is(err, errVaultKey) {
		t.Fatalf("tampered vault: err = %v, want errVaultKey", err)
	}
	if got, err := openVault(key, "somchai", nil); err != nil || got != nil {
		t.Fatalf("empty vault: %v %v", got, err)
	}
}

func TestAccountServerOK(t *testing.T) {
	for _, ok := range []string{"https://rdv.example.com", "http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787"} {
		if err := accountServerOK(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://rdv.example.com", "http://192.168.1.10:8787", ""} {
		if err := accountServerOK(bad); err == nil {
			t.Errorf("%s: accepted, want refused", bad)
		}
	}
}

// ---- merge ----

func ts(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }

func baseOf(peers ...config.SyncedPeer) map[string]config.SyncedPeer {
	m := map[string]config.SyncedPeer{}
	for _, p := range peers {
		m[p.DeviceID] = p
	}
	return m
}

func find(peers []config.SyncedPeer, id string) (config.SyncedPeer, bool) {
	for _, p := range peers {
		if p.DeviceID == id {
			return p, true
		}
	}
	return config.SyncedPeer{}, false
}

func TestMergeFirstUploadAndFirstDownload(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	local := []config.KnownPeer{
		{DeviceID: "111 111 111", Name: "PC-A", SavedPassword: "pw-a", Fingerprint: "sha256:aa", QUICAddr: "1.2.3.4:4433", LastConnected: ts(900_000)},
		{DeviceID: "222222222", Name: "Server", CustomName: true, Group: "งาน"},
	}
	up := mergeAddressBook("", local, nil, nil, now)
	if !up.push || len(up.vault) != 2 || len(up.upserts) != 0 || len(up.deletes) != 0 || len(up.base) != 2 {
		t.Fatalf("first upload: %+v", up)
	}
	a, _ := find(up.vault, "111111111")
	if a.SavedPassword != "pw-a" || a.Fingerprint != "sha256:aa" || a.UpdatedAt != now.UnixMilli() {
		t.Fatalf("uploaded record: %+v", a)
	}

	// A machine with nothing remembered signs in: everything comes down, nothing goes up.
	down := mergeAddressBook("", nil, nil, up.vault, now)
	if down.push || len(down.upserts) != 2 || len(down.deletes) != 0 || len(down.base) != 2 {
		t.Fatalf("first download: %+v", down)
	}

	// Nothing changed anywhere: a second sync is a no-op.
	again := mergeAddressBook("", local, up.base, up.vault, now.Add(time.Hour))
	if again.push || len(again.upserts) != 0 || len(again.deletes) != 0 {
		t.Fatalf("idle sync: %+v", again)
	}
	if localDiffersFromBase("", local, up.base) {
		t.Fatal("localDiffersFromBase is true right after a sync")
	}
}

func TestMergeFieldChangesFromBothSides(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	synced := config.SyncedPeer{DeviceID: "111111111", Name: "PC-A", OS: "windows/amd64", Fingerprint: "sha256:aa", UpdatedAt: 1}
	base := baseOf(synced)

	// This machine filed it in a group; another machine saved the password meanwhile.
	local := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A", OS: "windows/amd64", Fingerprint: "sha256:aa", Group: "ออฟฟิศ"}}
	remote := synced
	remote.SavedPassword = "pw-from-b"
	remote.UpdatedAt = 50
	res := mergeAddressBook("", local, base, []config.SyncedPeer{remote}, now)
	out, _ := find(res.vault, "111111111")
	if out.Group != "ออฟฟิศ" || out.SavedPassword != "pw-from-b" {
		t.Fatalf("both changes must survive: %+v", out)
	}
	if !res.push || len(res.upserts) != 1 || res.upserts[0].SavedPassword != "pw-from-b" {
		t.Fatalf("expected an upload and a local update: %+v", res)
	}

	// Only the other machine changed it: applied here, nothing to upload.
	plain := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A", OS: "windows/amd64", Fingerprint: "sha256:aa"}}
	renamed := synced
	renamed.Name, renamed.CustomName = "เครื่องบัญชี", true
	res = mergeAddressBook("", plain, base, []config.SyncedPeer{renamed}, now)
	if res.push || len(res.upserts) != 1 || res.upserts[0].Name != "เครื่องบัญชี" || !res.upserts[0].CustomName {
		t.Fatalf("remote rename: %+v", res)
	}

	// The saved password was cleared here: the clear is uploaded, not undone.
	withPw := synced
	withPw.SavedPassword = "pw"
	res = mergeAddressBook("", plain, baseOf(withPw), []config.SyncedPeer{withPw}, now)
	out, _ = find(res.vault, "111111111")
	if !res.push || out.SavedPassword != "" || len(res.upserts) != 0 {
		t.Fatalf("cleared password: %+v", res)
	}
}

func TestMergeNamesOnFirstSync(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	// Same device known on both sides before this machine ever synced.
	local := []config.KnownPeer{{DeviceID: "111111111", Name: "DESKTOP-X1", SavedPassword: "local-pw"}}
	remote := []config.SyncedPeer{{DeviceID: "111111111", Name: "เครื่องหน้าร้าน", CustomName: true, Group: "ร้าน"}}
	res := mergeAddressBook("", local, nil, remote, now)
	out, _ := find(res.vault, "111111111")
	if out.Name != "เครื่องหน้าร้าน" || !out.CustomName || out.Group != "ร้าน" || out.SavedPassword != "local-pw" {
		t.Fatalf("a typed name must win over a hostname, and each side's extra fields must be kept: %+v", out)
	}
}

func TestMergeRemovals(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	a := config.SyncedPeer{DeviceID: "111111111", Name: "PC-A", LastConnected: ts(2_000_000)}
	b := config.SyncedPeer{DeviceID: "222222222", Name: "PC-B"}
	base := baseOf(a, b)

	// Removed here: the account gets a tombstone.
	res := mergeAddressBook("", []config.KnownPeer{{DeviceID: "222222222", Name: "PC-B"}}, base, []config.SyncedPeer{a, b}, now)
	tomb, ok := find(res.vault, "111111111")
	if !res.push || !ok || !tomb.Deleted || tomb.UpdatedAt != now.UnixMilli() || len(res.base) != 1 {
		t.Fatalf("local removal: %+v", res)
	}

	// Another machine that still has it, unchanged: it is removed there too.
	other := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A", LastConnected: ts(2_000_000)}, {DeviceID: "222222222", Name: "PC-B"}}
	res2 := mergeAddressBook("", other, base, res.vault, now.Add(time.Minute))
	if res2.push || len(res2.deletes) != 1 || res2.deletes[0] != "111111111" {
		t.Fatalf("removal must reach the other machine: %+v", res2)
	}
	if _, ok := res2.base["111111111"]; ok {
		t.Fatal("a removed device must leave the base")
	}

	// A machine that connected to it after the removal keeps it and uploads it again.
	used := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A", LastConnected: ts(3_000_100)}, {DeviceID: "222222222", Name: "PC-B"}}
	res3 := mergeAddressBook("", used, base, res.vault, now.Add(time.Hour))
	back, _ := find(res3.vault, "111111111")
	if !res3.push || back.Deleted || len(res3.deletes) != 0 {
		t.Fatalf("a device used after its removal must come back: %+v", res3)
	}

	// Removed here, but changed on another machine meanwhile: the change wins.
	changed := a
	changed.Group = "สำคัญ"
	res4 := mergeAddressBook("", []config.KnownPeer{{DeviceID: "222222222", Name: "PC-B"}}, base, []config.SyncedPeer{changed, b}, now)
	if res4.push || len(res4.upserts) != 1 || res4.upserts[0].Group != "สำคัญ" {
		t.Fatalf("remote change against local removal: %+v", res4)
	}

	// Old tombstones are dropped from the next upload.
	old := config.SyncedPeer{DeviceID: "333333333", Deleted: true, UpdatedAt: now.Add(-tombstoneTTL - time.Hour).UnixMilli()}
	res5 := mergeAddressBook("", nil, nil, []config.SyncedPeer{old}, now)
	if len(res5.vault) != 0 || res5.push {
		t.Fatalf("expired tombstone: %+v", res5)
	}
}

func TestMergeLastConnectedAlone(t *testing.T) {
	now := time.Unix(4_000_000, 0)
	synced := config.SyncedPeer{DeviceID: "111111111", Name: "PC-A", LastConnected: ts(3_000_000)}
	base := baseOf(synced)
	soon := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A", LastConnected: ts(3_000_000 + 3600)}}
	if res := mergeAddressBook("", soon, base, []config.SyncedPeer{synced}, now); res.push {
		t.Fatal("a reconnect an hour later must not rewrite the account's copy")
	}
	if localDiffersFromBase("", soon, base) {
		t.Fatal("localDiffersFromBase must ignore a small last-connected change")
	}
	later := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A", LastConnected: ts(3_000_000 + 2*86400)}}
	res := mergeAddressBook("", later, base, []config.SyncedPeer{synced}, now)
	out, _ := find(res.vault, "111111111")
	if !res.push || out.LastConnected != ts(3_000_000+2*86400) || !localDiffersFromBase("", later, base) {
		t.Fatalf("a last-connected time two days newer must be uploaded: %+v", res)
	}
}

func TestMergeLeavesOwnDeviceAlone(t *testing.T) {
	now := time.Unix(5_000_000, 0)
	// Another machine remembers this one (999999999). It must not show up in this machine's own
	// list, and its absence here must not turn into a removal for everyone else.
	me := config.SyncedPeer{DeviceID: "999999999", Name: "THIS-PC", SavedPassword: "pw-to-this-pc", UpdatedAt: 7}
	other := config.SyncedPeer{DeviceID: "111111111", Name: "PC-A"}
	res := mergeAddressBook("999 999 999", nil, nil, []config.SyncedPeer{me, other}, now)
	if res.push || len(res.upserts) != 1 || res.upserts[0].DeviceID != "111111111" {
		t.Fatalf("first sync: %+v", res)
	}
	if kept, ok := find(res.vault, "999999999"); !ok || kept != me {
		t.Fatalf("own device must stay in the account untouched: %+v", res.vault)
	}
	if _, ok := res.base["999999999"]; ok {
		t.Fatal("own device must not enter the base")
	}
	local := []config.KnownPeer{{DeviceID: "111111111", Name: "PC-A"}}
	again := mergeAddressBook("999999999", local, res.base, res.vault, now.Add(time.Hour))
	if again.push || len(again.deletes) != 0 || len(again.vault) != 2 {
		t.Fatalf("second sync: %+v", again)
	}
	if localDiffersFromBase("999999999", local, res.base) {
		t.Fatal("localDiffersFromBase is true although nothing changed")
	}
}

// ---- end to end against the real account server ----

func newAccountTestNode(t *testing.T, server string, peers ...config.KnownPeer) *Node {
	t.Helper()
	return &Node{
		cfg:           &config.PeerConfig{Name: "test", KnownPeers: peers},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		rendezvousURL: server,
		rdvClient:     &http.Client{Timeout: 10 * time.Second},
		presence:      make(map[string]peerPresence),
		accountKick:   make(chan struct{}, 1),
	}
}

func knownByID(n *Node, id string) (config.KnownPeer, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, kp := range n.cfg.KnownPeers {
		if NormalizeDeviceID(kp.DeviceID) == id {
			return kp, true
		}
	}
	return config.KnownPeer{}, false
}

func TestAccountSyncBetweenTwoMachines(t *testing.T) {
	dir := t.TempDir()
	srv := rendezvous.NewServer(rendezvous.Options{AccountsDir: dir, AccountSignup: true, RatePerMin: -1})
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	ctx := context.Background()
	const pw, pw2 = "correct horse battery", "an even longer new one"

	// Machine A has used APN for a while, then creates an account.
	a := newAccountTestNode(t, hs.URL,
		config.KnownPeer{DeviceID: "111111111", Name: "ห้องเซิร์ฟเวอร์", CustomName: true, Group: "งาน", OS: "linux/amd64",
			Fingerprint: "sha256:aa11", SavedPassword: "host-pass-1", QUICAddr: "10.0.0.5:4433", LastConnected: ts(1_700_000_000)},
		config.KnownPeer{DeviceID: "222222222", Name: "DESKTOP-B", Fingerprint: "sha256:bb22", SavedPassword: "host-pass-2"},
	)
	if err := a.AccountRegister(ctx, "short", "tooshort", "somchai@example.com"); err == nil {
		t.Fatal("a 8-character password was accepted for a new account")
	}
	if err := a.AccountRegister(ctx, "Somchai", pw, "Somchai@Example.com"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if st := a.Snapshot0(); !st.SignedIn || st.Username != "somchai" || st.Devices != 2 || st.Error != "" {
		t.Fatalf("status on A after register: %+v", st)
	}

	// What the server keeps must not show the list.
	vault, err := os.ReadFile(filepath.Join(dir, "u-somchai.vault"))
	if err != nil {
		t.Fatalf("vault file: %v", err)
	}
	meta, _ := os.ReadFile(filepath.Join(dir, "u-somchai.json"))
	for _, secret := range []string{"host-pass-1", "host-pass-2", "111111111", "sha256:aa11", pw} {
		if bytes.Contains(vault, []byte(secret)) || bytes.Contains(meta, []byte(secret)) {
			t.Fatalf("server files contain %q in clear", secret)
		}
	}

	// Machine B is new: wrong password first, then the right one.
	b := newAccountTestNode(t, hs.URL)
	if err := b.AccountLogin(ctx, "somchai", "wrong password!!"); err == nil || !strings.Contains(err.Error(), "ไม่ถูกต้อง") {
		t.Fatalf("wrong password: err = %v", err)
	}
	if err := b.AccountLogin(ctx, "somchai", pw); err != nil {
		t.Fatalf("login on B: %v", err)
	}
	got, ok := knownByID(b, "111111111")
	if !ok || got.Name != "ห้องเซิร์ฟเวอร์" || !got.CustomName || got.Group != "งาน" || got.SavedPassword != "host-pass-1" ||
		got.Fingerprint != "sha256:aa11" || got.LastConnected != ts(1_700_000_000) {
		t.Fatalf("device 1 on B: %+v (found %v)", got, ok)
	}
	if got.QUICAddr != "" {
		t.Fatalf("network addresses must stay on the machine that learned them, got %q", got.QUICAddr)
	}
	if kp, ok := knownByID(b, "222222222"); !ok || kp.SavedPassword != "host-pass-2" {
		t.Fatalf("device 2 on B: %+v (found %v)", kp, ok)
	}

	// B renames one device and removes the other; A picks both changes up.
	if err := b.RenameSavedPeer("222222222", "เครื่องบัญชี"); err != nil {
		t.Fatal(err)
	}
	if err := b.RemoveSavedPeer("111111111"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.accountKick:
	default:
		t.Fatal("a local change did not ask for a sync")
	}
	if err := b.SyncAccount(ctx); err != nil {
		t.Fatalf("sync on B: %v", err)
	}
	if err := a.SyncAccount(ctx); err != nil {
		t.Fatalf("sync on A: %v", err)
	}
	if _, ok := knownByID(a, "111111111"); ok {
		t.Fatal("the device removed on B is still on A")
	}
	if kp, _ := knownByID(a, "222222222"); kp.Name != "เครื่องบัญชี" || !kp.CustomName || kp.SavedPassword != "host-pass-2" {
		t.Fatalf("rename did not reach A: %+v", kp)
	}

	// Both machines add a device at the same moment: neither is lost.
	a.mu.Lock()
	a.cfg.KnownPeers = append(a.cfg.KnownPeers, config.KnownPeer{DeviceID: "333333333", Name: "from-a"})
	a.mu.Unlock()
	b.mu.Lock()
	b.cfg.KnownPeers = append(b.cfg.KnownPeers, config.KnownPeer{DeviceID: "444444444", Name: "from-b"})
	b.mu.Unlock()
	for _, n := range []*Node{a, b, a} {
		if err := n.SyncAccount(ctx); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}
	for _, n := range []*Node{a, b} {
		for _, id := range []string{"222222222", "333333333", "444444444"} {
			if _, ok := knownByID(n, id); !ok {
				t.Fatalf("device %s missing after both machines added one", id)
			}
		}
	}

	// A changes the account password: B is signed out, keeps its devices, and can sign in again.
	if err := a.AccountChangePassword(ctx, "not the password", pw2); err == nil {
		t.Fatal("password change with a wrong current password was accepted")
	}
	if err := a.AccountChangePassword(ctx, pw, pw2); err != nil {
		t.Fatalf("password change: %v", err)
	}
	if err := a.SyncAccount(ctx); err != nil {
		t.Fatalf("sync on A after password change: %v", err)
	}
	if err := b.SyncAccount(ctx); err == nil {
		t.Fatal("B still synced after the password was changed on A")
	}
	if st := b.Snapshot0(); st.SignedIn || st.Username != "somchai" || st.Error == "" {
		t.Fatalf("status on B after the password change: %+v", st)
	}
	if _, ok := knownByID(b, "222222222"); !ok {
		t.Fatal("B lost its devices when its session ended")
	}
	if err := b.AccountLogin(ctx, "somchai", pw); err == nil {
		t.Fatal("the old password still signs in")
	}
	if err := b.AccountLogin(ctx, "somchai", pw2); err != nil {
		t.Fatalf("login on B with the new password: %v", err)
	}
	if st := b.Snapshot0(); !st.SignedIn || st.Error != "" || st.Devices != 3 {
		t.Fatalf("status on B after signing in again: %+v", st)
	}

	// Signing out with "wipe" clears this machine but not the account.
	if err := b.AccountLogout(ctx, true); err != nil {
		t.Fatal(err)
	}
	b.mu.RLock()
	left, acct := len(b.cfg.KnownPeers), b.cfg.Account
	b.mu.RUnlock()
	if left != 0 || acct != nil {
		t.Fatalf("after wipe sign-out: %d devices, account %+v", left, acct)
	}
	if err := a.SyncAccount(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := knownByID(a, "444444444"); !ok {
		t.Fatal("wiping B removed devices from the account")
	}
}

// Snapshot0 returns only the account status (the full Snapshot needs a started node).
func (n *Node) Snapshot0() AccountStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.accountStatusLocked()
}
