package p2p

import (
	"sort"
	"strings"
	"time"

	"relayvpn/internal/config"
)

// Address book sync: a three-way merge between this machine's remembered devices (local), the
// account's copy (remote) and what both looked like after the last sync (base). Each field is
// taken from the side that changed it; when both changed it, this machine wins.
//
// A device removed while signed in becomes a tombstone in the account, so the other machines
// remove it too instead of uploading it again.

const (
	// tombstoneTTL is how long a removal is remembered. A machine that stays offline longer
	// than this uploads the removed device again on its next sync.
	tombstoneTTL = 180 * 24 * time.Hour

	// lastConnectedSlack: a newer "last connected" time alone is uploaded only when it moved
	// this far, so ordinary reconnects do not rewrite the account's copy every time.
	lastConnectedSlack = 24 * time.Hour
)

func syncedFromKnown(kp config.KnownPeer) config.SyncedPeer {
	return config.SyncedPeer{
		DeviceID:      NormalizeDeviceID(kp.DeviceID),
		Name:          kp.Name,
		CustomName:    kp.CustomName,
		Group:         kp.Group,
		OS:            kp.OS,
		Fingerprint:   kp.Fingerprint,
		SavedPassword: kp.SavedPassword,
		LastConnected: kp.LastConnected,
	}
}

// sameSynced compares the fields whose change is worth a sync (not the timestamps).
func sameSynced(a, b config.SyncedPeer) bool {
	return a.Name == b.Name && a.CustomName == b.CustomName && a.Group == b.Group && a.OS == b.OS &&
		strings.EqualFold(a.Fingerprint, b.Fingerprint) && a.SavedPassword == b.SavedPassword
}

func parseRFC3339(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func laterRFC3339(a, b string) string {
	if parseRFC3339(b).After(parseRFC3339(a)) {
		return b
	}
	return a
}

// lastConnectedMoved reports whether a is newer than b by more than lastConnectedSlack.
func lastConnectedMoved(a, b string) bool {
	ta, tb := parseRFC3339(a), parseRFC3339(b)
	return !ta.IsZero() && ta.Sub(tb) > lastConnectedSlack
}

// mergeFields merges one device that exists on both sides. base is the last synced state;
// hasBase is false on a first sync, where a field set only on one side is kept.
func mergeFields(local, base, remote config.SyncedPeer, hasBase bool) config.SyncedPeer {
	out := remote
	pick := func(l, b, r string) string {
		if l != b {
			return l
		}
		return r
	}
	if !hasBase {
		base = config.SyncedPeer{}
	}
	localName := local.Name != base.Name || local.CustomName != base.CustomName
	remoteName := remote.Name != base.Name || remote.CustomName != base.CustomName
	switch {
	case localName && !remoteName:
		out.Name, out.CustomName = local.Name, local.CustomName
	case localName && remoteName:
		// A name the user typed wins over a hostname picked up on reconnect; otherwise this machine wins.
		if local.CustomName || !remote.CustomName {
			if local.Name != "" {
				out.Name, out.CustomName = local.Name, local.CustomName
			}
		}
	}
	out.Group = pick(local.Group, base.Group, remote.Group)
	out.OS = pick(local.OS, base.OS, remote.OS)
	out.Fingerprint = pick(local.Fingerprint, base.Fingerprint, remote.Fingerprint)
	out.SavedPassword = pick(local.SavedPassword, base.SavedPassword, remote.SavedPassword)
	out.LastConnected = laterRFC3339(local.LastConnected, remote.LastConnected)
	out.Deleted = false
	return out
}

type addressBookMerge struct {
	vault   []config.SyncedPeer          // the account's new copy, tombstones included
	push    bool                         // vault differs from remote and has to be uploaded
	upserts []config.SyncedPeer          // devices to add or update on this machine
	deletes []string                     // device IDs to remove from this machine
	base    map[string]config.SyncedPeer // live devices after the merge: the next sync's base
}

// selfID is this machine's own device ID. The account's list can contain it (another machine
// remembers this one); it is passed through untouched and never becomes a local entry, and
// its absence here must not be read as "removed on this machine".
func mergeAddressBook(selfID string, local []config.KnownPeer, base map[string]config.SyncedPeer, remote []config.SyncedPeer, now time.Time) addressBookMerge {
	nowMs := now.UnixMilli()
	selfID = NormalizeDeviceID(selfID)
	res := addressBookMerge{base: make(map[string]config.SyncedPeer)}

	localByID := make(map[string]config.SyncedPeer, len(local))
	for _, kp := range local {
		if sp := syncedFromKnown(kp); sp.DeviceID != "" {
			localByID[sp.DeviceID] = sp
		}
	}
	remoteByID := make(map[string]config.SyncedPeer, len(remote))
	for _, rp := range remote {
		rp.DeviceID = NormalizeDeviceID(rp.DeviceID)
		if rp.DeviceID != "" {
			remoteByID[rp.DeviceID] = rp
		}
	}
	ids := make(map[string]struct{}, len(localByID)+len(remoteByID))
	for id := range localByID {
		ids[id] = struct{}{}
	}
	for id := range remoteByID {
		ids[id] = struct{}{}
	}
	order := make([]string, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Strings(order)

	keep := func(sp config.SyncedPeer) {
		res.vault = append(res.vault, sp)
		res.base[sp.DeviceID] = sp
	}
	for _, id := range order {
		l, hasL := localByID[id]
		r, hasR := remoteByID[id]
		b, hasB := base[id]
		if selfID != "" && id == selfID {
			if hasR {
				res.vault = append(res.vault, r)
			}
			continue
		}
		switch {
		case hasL && hasR && !r.Deleted:
			out := mergeFields(l, b, r, hasB)
			if !sameSynced(out, r) {
				out.UpdatedAt = nowMs
				res.push = true
			} else if lastConnectedMoved(out.LastConnected, r.LastConnected) {
				res.push = true
			}
			if !sameSynced(out, l) || out.LastConnected != l.LastConnected {
				res.upserts = append(res.upserts, out)
			}
			keep(out)

		case hasL && hasR && r.Deleted:
			// Removed on another machine. It comes back only if this machine changed it or
			// connected to it after the removal.
			changedHere := hasB && !sameSynced(l, b)
			usedAfter := parseRFC3339(l.LastConnected).UnixMilli() > r.UpdatedAt
			if changedHere || usedAfter {
				l.UpdatedAt = nowMs
				res.push = true
				keep(l)
			} else {
				res.deletes = append(res.deletes, id)
				res.vault = append(res.vault, r)
			}

		case hasL && !hasR:
			// New on this machine (or the account lost it): upload.
			l.UpdatedAt = nowMs
			res.push = true
			keep(l)

		case !hasL && hasR && !r.Deleted:
			if hasB && sameSynced(r, b) {
				// Removed on this machine since the last sync: tell the others.
				res.vault = append(res.vault, config.SyncedPeer{DeviceID: id, Deleted: true, UpdatedAt: nowMs})
				res.push = true
			} else {
				// New on another machine, or changed there after it was removed here.
				res.upserts = append(res.upserts, r)
				keep(r)
			}

		case !hasL && hasR && r.Deleted:
			if nowMs-r.UpdatedAt < tombstoneTTL.Milliseconds() {
				res.vault = append(res.vault, r)
			}
		}
	}
	return res
}

// localDiffersFromBase reports whether this machine has changes the account has not seen:
// the quick check that lets a sync stop after learning the account's copy is unchanged too.
func localDiffersFromBase(selfID string, local []config.KnownPeer, base map[string]config.SyncedPeer) bool {
	selfID = NormalizeDeviceID(selfID)
	seen := 0
	for _, kp := range local {
		sp := syncedFromKnown(kp)
		if sp.DeviceID == "" || sp.DeviceID == selfID {
			continue
		}
		b, ok := base[sp.DeviceID]
		if !ok || !sameSynced(sp, b) || lastConnectedMoved(sp.LastConnected, b.LastConnected) {
			return true
		}
		seen++
	}
	return seen != len(base)
}
