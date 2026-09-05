package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kypost-server/backend/internal/backup"
)

// depositBudget bounds one run: the library's upload budget is 15 minutes,
// plus snapshotting. Runs on context.WithoutCancel so a closed browser tab
// does not abandon a half-uploaded capsule.
const depositBudget = 16 * time.Minute

type backupCredential struct {
	Password   string `json:"password"`
	AuthSecret string `json:"authSecret"`
}

// backupGate is the product's step-up for the routes that change backup
// state: admin session (withAdmin) plus the account credential in the body.
// Returns the acting admin's user ID on success; the response is already
// written on failure.
func (s *Server) backupGate(w http.ResponseWriter, r *http.Request, into any) (actor string, ok bool) {
	ac, found := authFromContext(r)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return "", false
	}
	if s.backup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "backup unavailable: state store did not open"})
		return "", false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return "", false
	}
	var cred backupCredential
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cred); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return "", false
		}
		if into != nil {
			if err := json.Unmarshal(raw, into); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return "", false
			}
		}
	}
	if !s.confirmAccountCredential(w, r, ac.UserID, cred.Password, cred.AuthSecret) {
		return "", false
	}
	if !s.backupAudit(w, "admin.backup_intent", ac.UserID, r.URL.Path, "started", nil) {
		return "", false
	}
	return ac.UserID, true
}

func backupError(w http.ResponseWriter, err error) {
	msg := recoveryclient.AuditSafe(err.Error())
	switch {
	case errors.Is(err, recoveryclient.ErrNotPaired):
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": "no recovery key: pair with KyRecovery or pin the suite public key first"})
	case errors.Is(err, recoveryclient.ErrNoDestination):
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": "a key is pinned but there is nowhere to send a capsule: pair with KyRecovery or set KYPOST_BACKUP_DIR"})
	case errors.Is(err, backup.ErrKeyAlreadyPinned):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "a different recovery key is already pinned; unpairing does not remove it"})
	case errors.Is(err, recoveryclient.ErrInProgress):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "a backup is already running"})
	case errors.Is(err, recoveryclient.ErrKeyPinMissing), errors.Is(err, recoveryclient.ErrKeyMismatch):
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": msg})
	case errors.Is(err, recoveryclient.ErrRemote):
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": msg})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
	}
}

// backupAudit records durable intent before action and its outcome afterwards.
func (s *Server) backupAudit(w http.ResponseWriter, action, actor, target, outcome string, details map[string]any) bool {
	if err := s.backup.Audit(action, actor, target, outcome, details); err != nil {
		s.logger.Error("backup audit write failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "audit log unavailable; an action already started may have completed; check backup status before retrying"})
		return false
	}
	return true
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "backup unavailable: state store did not open"})
		return
	}
	st, err := s.backup.Status()
	if err != nil {
		backupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupGate(w, r, nil)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), depositBudget)
	defer cancel()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(depositBudget))
	res, err := s.backup.Run(ctx)
	action, outcome, details := recoveryclient.Outcome(res, err)
	if !s.backupAudit(w, action, actor, res.Manifest.CapsuleID, outcome, details) {
		return
	}
	if err != nil && !errors.Is(err, recoveryclient.ErrReceiptUnrecorded) {
		if res.LocalPath != "" {
			writeJSON(w, http.StatusOK, map[string]any{"result": res, "warning": "Local capsule saved, but KyRecovery deposit failed: " + recoveryclient.AuditSafe(err.Error())})
			return
		}
		backupError(w, err)
		return
	}
	out := map[string]any{"result": res}
	if err != nil {
		out["warning"] = "KyRecovery holds the capsule but the receipt was not recorded here: " + recoveryclient.AuditSafe(err.Error())
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleBackupDrill(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupGate(w, r, nil)
	if !ok {
		return
	}
	res, err := s.backup.Drill(r.Context())
	outcome := "success"
	details := map[string]any{}
	if err != nil {
		outcome, details["error"] = "failure", recoveryclient.AuditSafe(err.Error())
	} else {
		details["checks"] = res.Checks
		if !res.Passed {
			outcome = "failure"
		}
	}
	if !s.backupAudit(w, "admin.backup_drill", actor, "", outcome, details) {
		return
	}
	if err != nil {
		backupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupGate(w, r, nil)
	if !ok {
		return
	}
	raw, manifest, err := s.backup.Export(r.Context())
	if err != nil {
		if !s.backupAudit(w, "admin.backup_export", actor, "", "failure", map[string]any{"error": recoveryclient.AuditSafe(err.Error())}) {
			return
		}
		backupError(w, err)
		return
	}
	if !s.backupAudit(w, "admin.backup_export", actor, manifest.CapsuleID, "success", map[string]any{"size_bytes": len(raw)}) {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.kycap"`, recoveryclient.FilenameSafe(backup.AppName+"."+manifest.CapsuleID)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleBackupPair(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL  string `json:"url"`
		Code string `json:"code"`
	}
	actor, ok := s.backupGate(w, r, &req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	key, err := s.backup.Pair(ctx, req.URL, req.Code)
	details := map[string]any{"allow_private": s.backup.AllowPrivate()}
	if err != nil {
		details["error"] = recoveryclient.AuditSafe(err.Error())
		if !s.backupAudit(w, "admin.backup_pair", actor, "", "failure", details) {
			return
		}
		backupError(w, err)
		return
	}
	id := key.Public.ID()
	details["key_id"] = id
	if !s.backupAudit(w, "admin.backup_pair", actor, id, "success", details) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keyId": id, "threshold": key.Threshold, "totalShares": key.TotalShares})
}

func (s *Server) handleBackupUnpair(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupGate(w, r, nil)
	if !ok {
		return
	}
	err := s.backup.Unpair()
	outcome, details := "success", map[string]any{}
	if err != nil {
		outcome, details["error"] = "failure", recoveryclient.AuditSafe(err.Error())
	}
	if !s.backupAudit(w, "admin.backup_unpair", actor, "", outcome, details) {
		return
	}
	if err != nil {
		backupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "KyRecovery URL and token rows removed. The key pin, receipts and local copies stay. The credential is dead only once a KyRecovery admin revokes it.",
	})
}

func (s *Server) handleBackupPinKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey   string `json:"publicKey"`
		Threshold   int    `json:"threshold"`
		TotalShares int    `json:"totalShares"`
	}
	actor, ok := s.backupGate(w, r, &req)
	if !ok {
		return
	}
	err := s.backup.PinKey(req.PublicKey, req.Threshold, req.TotalShares)
	outcome, details := "success", map[string]any{"threshold": req.Threshold, "total_shares": req.TotalShares}
	if err != nil {
		outcome, details["error"] = "failure", recoveryclient.AuditSafe(err.Error())
	}
	id := ""
	if err == nil {
		id, err = s.backup.PinnedKeyID()
		if err != nil {
			outcome = "failure"
		}
	}
	if !s.backupAudit(w, "admin.backup_pin_key", actor, id, outcome, details) {
		return
	}
	if err != nil {
		backupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keyId": id})
}

func (s *Server) handleBackupSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IntervalSec int64 `json:"intervalSec"`
	}
	actor, ok := s.backupGate(w, r, &req)
	if !ok {
		return
	}
	if err := s.backup.SetIntervalSeconds(req.IntervalSec); err != nil {
		if !s.backupAudit(w, "admin.backup_schedule", actor, "", "failure", map[string]any{"error": recoveryclient.AuditSafe(err.Error())}) {
			return
		}
		backupError(w, err)
		return
	}
	interval, err := s.backup.IntervalSeconds()
	if err != nil {
		backupError(w, err)
		return
	}
	if !s.backupAudit(w, "admin.backup_schedule", actor, "", "success", map[string]any{"interval_sec": interval}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"intervalSec": interval})
}
