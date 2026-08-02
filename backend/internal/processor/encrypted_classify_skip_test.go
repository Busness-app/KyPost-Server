package processor

import (
	"context"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/state"
)

// An encrypted message has no body to classify — ListUnreadInbox only sets
// PGPEncrypted because neither MIME part rendered — so sending it to the
// classifier spent an Ollama call on nothing and handed the model the sender
// and (for third-party PGP/MIME without protected headers) the real subject.
// It then fell through the "no known label returned" path and was retired
// unlabeled, which is how encrypted mail accumulated in Uncategorized.
//
// This mirrors TestHandleMessage_NonMatchingRuleStillClassifies: the Poller is
// built with a nil classifier client, so reaching classifyWithRetry panics.
// Returning normally is therefore proof the classifier was never called, not
// just that nothing went wrong.
func TestHandleMessage_EncryptedMessageSkipsTheClassifier(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	p := &Poller{log: logger} // classifier intentionally left nil
	p.cfg.Labels.Allowlist = []string{"Primary", "Bills"}

	mail := &noopMailClient{}
	uc := userCtx{id: "user-1", mail: mail, store: store, autoLabelEnabled: true}
	msg := imapadapter.Message{
		ID:           "51",
		Subject:      "[Encrypted] Email Sent by KyPost",
		Sender:       "alice@example.com",
		PGPEncrypted: true,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an encrypted message reached the classifier: %v", r)
		}
	}()

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}

	if len(mail.appliedLabels) == 0 {
		t.Fatal("the encrypted message was left unlabeled; it will strand in Uncategorized")
	}
}

// The fallback label has to be one the account actually has configured, for
// the same reason disabledLabelingFallback exists: a literal "Primary" that
// isn't in the allowlist strands mail in the Uncategorized tab, which reads as
// mail vanishing rather than being sorted.
func TestHandleMessage_EncryptedMessageTagsAConfiguredLabel(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	p := &Poller{log: logger}
	p.cfg.Labels.Allowlist = []string{"Work", "Bills"} // no "Primary"

	mail := &noopMailClient{}
	uc := userCtx{id: "user-1", mail: mail, store: store, autoLabelEnabled: true}
	msg := imapadapter.Message{ID: "52", Subject: "encrypted", Sender: "bob@example.com", PGPEncrypted: true}

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	if len(mail.appliedLabels) == 0 {
		t.Fatal("expected a label to be applied")
	}
	got := mail.appliedLabels[0]
	found := false
	for _, allowed := range p.cfg.Labels.Allowlist {
		if strings.EqualFold(allowed, got) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("applied label %q is not in the configured allowlist %v", got, p.cfg.Labels.Allowlist)
	}
}

// The label applied to an encrypted message must never be a statement that the
// message is encrypted. IMAP keywords live on the mail server in the clear, so
// an "Encrypted" keyword would hand whoever runs that server an index of which
// messages are worth attacking, while the published contract (README.md,
// SECURITY.md) says keywords are a sorting hint and never a security boundary.
func TestHandleMessage_EncryptedMessageIsNotTaggedAsEncrypted(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	p := &Poller{log: logger}
	p.cfg.Labels.Allowlist = []string{"Primary"}

	mail := &noopMailClient{}
	uc := userCtx{id: "user-1", mail: mail, store: store, autoLabelEnabled: true}
	msg := imapadapter.Message{ID: "53", Subject: "encrypted", Sender: "bob@example.com", PGPEncrypted: true}

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	for _, label := range mail.appliedLabels {
		if strings.Contains(strings.ToLower(label), "encrypt") {
			t.Fatalf("applied keyword %q advertises the message's encryption to the mail server", label)
		}
	}
}

func TestNativePushIncludesContent(t *testing.T) {
	preview := config.UserNotificationSettings{ContentPreview: true}
	noPreview := config.UserNotificationSettings{ContentPreview: false}
	plain := imapadapter.Message{Subject: "Quarterly numbers", Sender: "alice@example.com"}
	encrypted := imapadapter.Message{Subject: "Quarterly numbers", Sender: "alice@example.com", PGPEncrypted: true}

	if !nativePushIncludesContent(preview, plain) {
		t.Fatal("ContentPreview on and an ordinary message: the user asked to see sender and subject")
	}
	if nativePushIncludesContent(noPreview, plain) {
		t.Fatal("ContentPreview off must still mean off")
	}
	if nativePushIncludesContent(preview, encrypted) {
		t.Fatal("an encrypted message's sender and subject went to the relay, FCM and APNs in the clear")
	}
	if nativePushIncludesContent(noPreview, encrypted) {
		t.Fatal("ContentPreview off must still mean off")
	}
}

// The suppression is native-only on purpose. Web push payloads are encrypted
// to the browser's own subscription keys under RFC 8291, so there is no third
// party to withhold the subject from and ContentPreview stays the user's call.
// This pins that asymmetry as a decision rather than an oversight: the web
// path builds its body from buildNotificationBody with no encryption check.
func TestWebPushBodyStillHonorsContentPreviewForEncryptedMail(t *testing.T) {
	encrypted := imapadapter.Message{Subject: "Quarterly numbers", Sender: "alice@example.com", PGPEncrypted: true}
	body := buildNotificationBody(encrypted)
	if !strings.Contains(body, "Quarterly numbers") {
		t.Fatalf("web push body dropped the subject: %q", body)
	}
}
