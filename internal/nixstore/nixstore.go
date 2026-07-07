// Package nixstore wraps the stock `nix-store` CLI operations machokeeper
// needs, so repair uses only documented plumbing — no daemon patch, no
// direct database access.
package nixstore

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StorePathOf returns the top-level store path containing file `p`
// (…/<hash>-<name>), and true, or ("", false) if `p` is not under a
// store directory. The store dir is taken from NIX_STORE_DIR (tests) or
// defaults to /nix/store.
func StorePathOf(p string) (string, bool) {
	storeDir := os.Getenv("NIX_STORE_DIR")
	if storeDir == "" {
		storeDir = "/nix/store"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(storeDir, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	first := rel
	if i := strings.IndexByte(rel, filepath.Separator); i >= 0 {
		first = rel[:i]
	}
	if first == "" || first == "." {
		return "", false
	}
	return filepath.Join(storeDir, first), true
}

// Roots returns the GC roots holding `storePath` alive. A non-empty
// result means the path is live (in use); repairing it needs the
// operator's explicit `--fix-live` consent.
func Roots(storePath string) ([]string, error) {
	out, err := exec.Command("nix-store", "--query", "--roots", storePath).Output()
	if err != nil {
		return nil, fmt.Errorf("querying roots of %s: %w", storePath, err)
	}
	var roots []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			roots = append(roots, line)
		}
	}
	return roots, nil
}

// Referrers returns store paths that reference `storePath`. Like a GC
// root, a referrer blocks deletion.
func Referrers(storePath string) ([]string, error) {
	out, err := exec.Command("nix-store", "--query", "--referrers", storePath).Output()
	if err != nil {
		return nil, fmt.Errorf("querying referrers of %s: %w", storePath, err)
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" && line != storePath {
			refs = append(refs, line)
		}
	}
	return refs, nil
}

// DumpNAR streams the NAR serialisation of `path` to `w` (nix-store
// --dump). Used to recompute a path's NAR hash after an in-place
// repair, without deleting it.
func DumpNAR(path string) ([]byte, error) {
	out, err := exec.Command("nix-store", "--dump", path).Output()
	if err != nil {
		return nil, fmt.Errorf("dumping %s: %w", path, err)
	}
	return out, nil
}

// RegisterValidity re-registers `storePath` with a corrected NAR hash
// and size, preserving its references and deriver, via
// `nix-store --register-validity --reregister`. This updates the
// database row in place — the path is not deleted — so it works on
// live (even GC-rooted) paths. It is the ONLY route that works after
// an in-place repair: `nix-store --export` verifies the recorded hash
// before streaming, so export/delete/import can never round-trip a
// just-repaired path. `references` and `deriver` come from a prior
// query; `narHash` is the sha256 of the repaired NAR in
// `sha256:<base32>` form.
func RegisterValidity(storePath, deriver, narHash string, narSize int64, references []string) error {
	cmd := exec.Command("nix-store", "--register-validity", "--reregister", "--hash-given")
	cmd.Stdin = strings.NewReader(registrationLines(storePath, deriver, narHash, narSize, references))
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("re-registering validity of %s: %w", storePath, err)
	}
	return nil
}

// registrationLines builds the stdin format `nix-store
// --register-validity --hash-given` reads, per line group — the same
// field order `nix-store --dump-db` emits:
//
//	<store path>
//	<narHash>            (with --hash-given: hash then size, before deriver)
//	<narSize>
//	<deriver or empty>
//	<#references>
//	<reference>...       (one per line)
func registrationLines(storePath, deriver, narHash string, narSize int64, references []string) string {
	var b strings.Builder
	fmt.Fprintln(&b, storePath)
	fmt.Fprintln(&b, narHash)
	fmt.Fprintln(&b, narSize)
	fmt.Fprintln(&b, deriver)
	fmt.Fprintln(&b, len(references))
	for _, r := range references {
		fmt.Fprintln(&b, r)
	}
	return b.String()
}

// IsContentAddressed reports whether `storePath` is content-addressed
// (its name derives from its bytes, so a repair would break the
// address). Reads the `ca` field of `nix path-info --json`, handling
// both the pre-2.19 array form and the newer path-keyed object form.
// Errors are returned, not swallowed: callers must fail closed.
func IsContentAddressed(storePath string) (bool, error) {
	out, err := exec.Command("nix", "--extra-experimental-features", "nix-command",
		"path-info", "--json", storePath).Output()
	if err != nil {
		return false, fmt.Errorf("querying path info of %s: %w", storePath, err)
	}
	return parsePathInfoCA(out, storePath)
}

// parsePathInfoCA reads the `ca` field for storePath out of a
// `nix path-info --json` response, in either the pre-2.19 array form or
// the newer path-keyed object form. Any shape it cannot positively
// resolve is an error, never a false.
func parsePathInfoCA(out []byte, storePath string) (bool, error) {
	type info struct {
		Path string `json:"path"`
		CA   string `json:"ca"`
	}
	var arr []info
	if err := json.Unmarshal(out, &arr); err == nil {
		for _, i := range arr {
			if i.Path == storePath || len(arr) == 1 {
				return i.CA != "", nil
			}
		}
		return false, fmt.Errorf("path info response does not name %s", storePath)
	}
	var obj map[string]info
	if err := json.Unmarshal(out, &obj); err != nil {
		return false, fmt.Errorf("parsing path info of %s: %w", storePath, err)
	}
	if i, ok := obj[storePath]; ok {
		return i.CA != "", nil
	}
	// Single-entry response keyed by a differently-normalised name.
	if len(obj) == 1 {
		for _, i := range obj {
			return i.CA != "", nil
		}
	}
	return false, fmt.Errorf("path info response does not name %s", storePath)
}

// PathInfo returns the deriver and references of `storePath`, needed to
// re-register it with a new hash.
func PathInfo(storePath string) (deriver string, references []string, err error) {
	d, err := exec.Command("nix-store", "--query", "--deriver", storePath).Output()
	if err != nil {
		return "", nil, fmt.Errorf("querying deriver of %s: %w", storePath, err)
	}
	deriver = strings.TrimSpace(string(d))
	if deriver == "unknown-deriver" {
		deriver = ""
	}
	r, err := exec.Command("nix-store", "--query", "--references", storePath).Output()
	if err != nil {
		return "", nil, fmt.Errorf("querying references of %s: %w", storePath, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(r)), "\n") {
		if line != "" {
			references = append(references, line)
		}
	}
	return deriver, references, nil
}
