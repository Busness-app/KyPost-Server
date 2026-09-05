package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kypost-server/backend/internal/cryptutil"
)

func (s *Service) Drill(ctx context.Context) (*recoveryclient.DrillResult, error) {
	release, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer release()
	p, err := s.collect(ctx)
	if err != nil {
		return nil, err
	}
	return recoveryclient.Drill(ctx, filepath.Join(s.dirs.State, scratchDirName), p, drillChecks)
}

func drillChecks(dir string, opened capsule.Manifest) []recoveryclient.Check {
	checks := []recoveryclient.Check{}
	check := func(name string, ok bool) { checks = append(checks, recoveryclient.Check{Name: name, Passed: ok}) }
	recipe, validRecipe := opened.VerificationRecipe.(map[string]any)
	if !validRecipe {
		return []recoveryclient.Check{{Name: "recipe object", Passed: false}}
	}
	check("recipe version", recipe["version"] == float64(1))

	check("recipe:sqlite", recipe["sqlite"] == "all-state-databases")
	check("recipe:imap", recipe["imap"] == "all-stored-credentials")
	rawRequired, ok := recipe["required"].([]any)
	check("recipe:required", ok && len(rawRequired) > 0)
	requiredSet := map[string]bool{}
	for _, value := range rawRequired {
		path, ok := value.(string)
		valid := ok && fs.ValidPath(path) && path != "."
		check("recipe path", valid)
		if valid {
			requiredSet[path] = true
		}
	}
	for _, name := range required {
		check("recipe requires:"+name, requiredSet[name])
		_, err := os.Stat(filepath.Join(dir, name))
		check("present:"+name, err == nil)
	}
	for _, file := range opened.Files {
		if !fs.ValidPath(file.Path) {
			check("file path", false)
			continue
		}
		if filepath.Base(file.Path) == "state.db" {
			check("sqlite:"+file.Path, integrityOK(filepath.Join(dir, file.Path)))
		}
	}
	var doc struct {
		Users []struct {
			Role   string `json:"role"`
			Active bool   `json:"active"`
		} `json:"users"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config/users.json"))
	admin := false
	if err == nil && json.Unmarshal(raw, &doc) == nil {
		for _, u := range doc.Users {
			admin = admin || (u.Role == "admin" && u.Active)
		}
	}
	check("accounts:active-admin", admin)
	_, err = cryptutil.LoadKey(filepath.Join(dir, "private/totp-secret.key"))
	check("TOTP master key", err == nil)

	for _, f := range opened.Files {
		if !fs.ValidPath(f.Path) {
			continue
		}
		if filepath.Base(f.Path) == "imap-config.json" {
			raw, err := os.ReadFile(filepath.Join(dir, f.Path))
			if err == nil {
				_, err = cryptutil.OpenBytes(raw, filepath.Join(dir, "private/imap-config.key"))
			}
			check("decrypt:"+f.Path, err == nil)
		}
	}
	return checks
}
func integrityOK(path string) bool {
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String()+"?mode=ro")
	if err != nil {
		return false
	}
	defer db.Close()
	var v string
	return db.QueryRow("PRAGMA integrity_check").Scan(&v) == nil && v == "ok"
}
