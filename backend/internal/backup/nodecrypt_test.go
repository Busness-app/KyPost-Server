package backup

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

// TestNothingInTheServerDecrypts pins that no server code opens a capsule
// sealed to the suite key, combines shares, or calls Restore, except the
// restore verb.
func TestNothingInTheServerDecrypts(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..")) // backend/
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		"internal/app/backup.go": {"runRestore"},
	})
}
