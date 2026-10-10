package api

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kypost-server/backend/internal/config"
	"github.com/Busnes-app/kypost-server/backend/internal/fsutil"
	"github.com/Busnes-app/kypost-server/backend/internal/mailbox"
	"github.com/Busnes-app/kypost-server/backend/internal/mailmsg"
	"github.com/Busnes-app/kypost-server/backend/internal/sso"
	"github.com/Busnes-app/kypost-server/backend/internal/users"
)

func (s *Server) nativeOutbound() sso.NativeOutbound {
	return sso.NativeOutbound{ConfigDir: s.configDir, StateRoot: s.stateDir, SecretDir: config.SecretDir(), Accounts: s.users, Domains: s.nativeDomains, Settings: s.ssoStore, Logger: s.logger}
}

// The existing OK response still means confirmed primary SMTP acceptance. A
// durable queue entry alone cannot tell older clients that mail was sent.
func (s *Server) finishNativeSend(w http.ResponseWriter, r *http.Request, ac AuthContext, u users.User, from string, deliveries []mailbox.OutboundDelivery, sent []byte, enrollment bool, generation *uint64, expiresAt int64, warning string) {
	if len(deliveries) == 0 {
		http.Error(w, "no native deliveries supplied", http.StatusBadRequest)
		return
	}
	for i := range deliveries {
		raw, err := mailmsg.NormalizeSMTPMessage(deliveries[i].Raw)
		if err != nil {
			http.Error(w, "native message cannot be submitted; correct the MIME size or line formatting", http.StatusBadRequest)
			return
		}
		deliveries[i].Raw = raw
	}
	job := mailbox.OutboundJob{From: from, Deliveries: deliveries, Sent: sent, DeviceID: ac.DeviceID, DeviceWitness: ac.DeviceWitness, NativeSendEpoch: ac.NativeSendEpoch, PGPRevision: u.PGPRevision, RequiresEnrollment: enrollment, ExpiresAt: expiresAt}
	if generation != nil {
		job.MaterialGeneration = *generation
	} else if u.PGPKeyring != nil && !enrollment {
		job.MaterialGeneration = u.PGPKeyring.MaterialGeneration
	}
	id, err := fsutil.NewUUIDv4()
	if err != nil {
		http.Error(w, "cannot create native delivery intent; retry later", http.StatusServiceUnavailable)
		return
	}
	sender := s.nativeOutbound()
	// The selected mailbox sends and files Sent; a primary's ID is its user's.
	mailboxID := cmp.Or(ac.Mailbox, ac.UserID)
	first, sendErr := sender.Send(r.Context(), mailboxID, id, job)
	if !first.Accepted {
		if s.refuseNativeAdministrator(w, r, ac.UserID, sendErr) {
			return
		}
		message := "native submission was not confirmed; inspect this outbox job before resubmitting to avoid duplicates"
		if errors.Is(sendErr, sso.ErrNativeOutboundStale) || errors.Is(sendErr, sso.ErrNativeProvisioning) {
			message = "native sender authority changed; reload account and domain setup before sending"
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": message, "outboxId": id, "ok": false})
		return
	}
	if sendErr != nil {
		warning = joinWarnings(warning, "relay accepted the primary message but completion failed; do not resubmit it")
	}
	unconfirmed := 0
	for sequence := 1; sequence < len(deliveries); sequence++ {
		result, err := sender.Submit(r.Context(), mailboxID, id, sequence)
		if !result.Accepted || err != nil {
			unconfirmed++
		}
	}
	if unconfirmed > 0 {
		warning = joinWarnings(warning, "some follow-on deliveries are pending or unconfirmed; inspect the outbox before resubmitting")
	}
	if !first.SentSaved && len(sent) > 0 {
		finish, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		first.SentSaved = sender.FileSent(finish, mailboxID, id) == nil
		cancel()
	}
	if !first.SentSaved && len(sent) > 0 {
		warning = joinWarnings(warning, "email accepted but Sent filing remains pending; sending it again will not repair Sent")
	}
	writeJSON(w, http.StatusOK, withCalendarReplyAck(r, map[string]any{"ok": true, "sentSaved": first.SentSaved, "warning": warning, "outboxId": id}))
}

// nativeFrom resolves the requested From to an active ledger address of the
// sending mailbox a (empty means that mailbox's primary address). Outbound rechecks it, with its
// generation, under the authority fence.
func (s *Server) nativeFrom(a sso.NativeAssignment, requested string) (string, bool, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if requested == "" || requested == a.Address {
		return a.Address, true, nil
	}
	addresses, err := s.ssoLifecycle.NativeAddresses()
	x := addresses[requested]
	return requested, err == nil && x.Mailbox == a.Owner.Mailbox && x.State == "active", err
}

// refuseNativeFrom answers an unusable From; it reports whether it wrote.
func (s *Server) refuseNativeFrom(w http.ResponseWriter, a sso.NativeAssignment, requested string) (string, bool) {
	from, allowed, err := s.nativeFrom(a, requested)
	if err != nil {
		http.Error(w, "native mailbox unavailable; preserve mail and repair account authority", http.StatusServiceUnavailable)
		return "", true
	}
	if !allowed {
		http.Error(w, "From must be an active address of your mailbox", http.StatusForbidden)
		return "", true
	}
	return from, false
}

// The diagnostics response contains state only, never decrypted intent or device credentials.
func (s *Server) handleNativeOutboxStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if !s.nativeMail {
		http.Error(w, "native outbox requires native mail mode", http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	if len(id) != 36 || !fsutil.SafePathComponent(id) {
		http.Error(w, "invalid outbox id", http.StatusBadRequest)
		return
	}
	statuses, sentSaved, err := s.nativeOutbound().Status(r.Context(), cmp.Or(ac.Mailbox, ac.UserID), id)
	if err != nil {
		http.Error(w, "native outbox unavailable; retain mail and repair storage before resubmitting", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outboxId": id, "deliveries": statuses, "sentSaved": sentSaved})
}
