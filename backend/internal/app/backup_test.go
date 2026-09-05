package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kypost-server/backend/internal/backup"
)

func TestRestoreCLIUsesCustodianSharesAndRefusesOverwrite(t *testing.T) {
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(key, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw, manifest, err := recoveryclient.Seal(recoveryclient.Payload{ServiceName: backup.AppName, AppVersion: "test", Files: []recoveryclient.File{{Path: "config/test.json", Data: []byte(`{"synthetic":true}`), Mode: 0600}}}, recoveryclient.RecoveryKey{Public: key.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.kycap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restore")
	input := shares[0].String() + "\n" + shares[2].String() + "\n"
	var out bytes.Buffer
	if err := runBackupCommand("restore", []string{path, target}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(target, "config/test.json"))
	if err != nil || string(got) != `{"synthetic":true}` {
		t.Fatalf("restored payload: %s %v", got, err)
	}
	if !strings.Contains(out.String(), manifest.CapsuleID) || strings.Contains(out.String(), shares[0].String()) {
		t.Fatal("restore output missing identity or leaked shares")
	}
	if err := runBackupCommand("restore", []string{path, target}, strings.NewReader(input), &out); err == nil {
		t.Fatal("restore overwrote occupied destination")
	}
	if err := runBackupCommand("restore", []string{path, filepath.Join(t.TempDir(), "short")}, strings.NewReader(shares[0].String()), &out); err == nil {
		t.Fatal("one custodian restored a two-share capsule")
	}
}
