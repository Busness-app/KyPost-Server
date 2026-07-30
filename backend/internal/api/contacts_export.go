package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	vcard "github.com/emersion/go-vcard"
)

func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// handleContactsExport exports all contacts in the caller's own address book
// as either vCard (.vcf) or CSV format.
func (s *Server) handleContactsExport(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "vcard"
	}

	list := store.List()

	switch format {
	case "vcard":
		w.Header().Set("Content-Type", "text/vcard")
		w.Header().Set("Content-Disposition", `attachment; filename="contacts.vcf"`)
		encoder := vcard.NewEncoder(w)
		for _, contact := range list {
			if contact.Deleted {
				continue
			}
			card := s.contactToVCardForUser(ac.UserID, contact)
			if err := encoder.Encode(card); err != nil {
				http.Error(w, "failed to encode vcard", http.StatusInternalServerError)
				return
			}
		}
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="contacts.csv"`)
		writer := csv.NewWriter(w)
		defer writer.Flush()

		// Header and rows are written to the response; a write error means the
		// client went away mid-download. Nothing can be sent to report it (the
		// 200 and Content-Type are already on the wire), so log and stop rather
		// than keep serialising rows into a dead socket.
		if err := writer.Write([]string{"Name", "Organization", "Title", "Email(s)", "Phone(s)", "Notes", "Birthday"}); err != nil {
			s.logger.Error("contacts csv export failed", "error", err.Error())
			return
		}

		for _, c := range list {
			if c.Deleted {
				continue
			}
			emails := ""
			if len(c.Emails) > 0 {
				emailVals := make([]string, len(c.Emails))
				for i, e := range c.Emails {
					emailVals[i] = e.Value
				}
				emails = strings.Join(emailVals, ";")
			}

			phones := ""
			if len(c.Phones) > 0 {
				phoneVals := make([]string, len(c.Phones))
				for i, p := range c.Phones {
					phoneVals[i] = p.Value
				}
				phones = strings.Join(phoneVals, ";")
			}

			if err := writer.Write([]string{
				csvSafe(c.FormattedName),
				csvSafe(c.Org),
				csvSafe(c.Title),
				csvSafe(emails),
				csvSafe(phones),
				csvSafe(c.Notes),
				csvSafe(c.Birthday),
			}); err != nil {
				http.Error(w, "failed to write csv", http.StatusInternalServerError)
				return
			}
		}
	default:
		http.Error(w, "unsupported format", http.StatusBadRequest)
	}
}

// handleContactsImport imports contacts in vCard format into the caller's own
// address book from a multipart file upload.
func (s *Server) handleContactsImport(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	// Limit to 10 MB for import file
	limitedBody := io.LimitReader(r.Body, 10<<20)

	// go-vcard unfolds continuation lines with `l += ...` inside a loop, which
	// is quadratic in the number of folds. The byte and card caps do not bound
	// folds WITHIN one card, so a single card made of continuation lines turned
	// a 10 MiB upload into minutes of memcpy on a shared, CPU-limited box.
	// Buffer and pre-scan: cheap next to what it prevents.
	raw, err := io.ReadAll(limitedBody)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to read import"})
		return
	}
	if err := checkVCardFolding(raw); err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": err.Error()})
		return
	}

	decoder := vcard.NewDecoder(bytes.NewReader(raw))

	type importResult struct {
		Imported   int      `json:"imported"`
		Skipped    int      `json:"skipped"`
		Errors     []string `json:"errors"`
		ErrorCount int      `json:"errorCount"`
	}

	result := importResult{Errors: []string{}}
	maxCards := 5000
	// maxAttempts bounds the total number of loop iterations independent of
	// cardCount: a decode error never increments cardCount, so a stream of
	// malformed (non-vCard) input would otherwise loop until the request
	// body is exhausted rather than until any cap is hit. maxCards*2 gives
	// legitimate imports plenty of room (successful decodes hit the
	// maxCards cap long before this) while still bounding pathological
	// all-malformed input.
	maxAttempts := maxCards * 2
	// maxErrors caps how many error strings we retain in the response; the
	// true count is still reported via ErrorCount so truncation is
	// communicated rather than silently dropped.
	maxErrors := 100
	cardCount := 0
	attempts := 0
	errorCount := 0

	addError := func(msg string) {
		errorCount++
		if len(result.Errors) < maxErrors {
			result.Errors = append(result.Errors, msg)
		}
	}
	// addSummary is for the one-time "why did the loop stop" message: it
	// always appears (bypassing the maxErrors cap) since it's the context
	// that explains why the Errors list may otherwise look truncated.
	addSummary := func(msg string) {
		errorCount++
		result.Errors = append(result.Errors, msg)
	}

	for {
		if cardCount >= maxCards {
			addSummary(fmt.Sprintf("stopped processing after %d contacts (limit reached)", maxCards))
			break
		}

		attempts++
		if attempts > maxAttempts {
			addSummary(fmt.Sprintf("stopped processing after %d attempts (too many errors)", maxAttempts))
			break
		}

		card, err := decoder.Decode()
		if err != nil {
			if err == io.EOF {
				break
			}
			addError(fmt.Sprintf("decode error: %v", err))
			continue
		}
		cardCount++

		contact := s.contactFromVCardForUser(ac.UserID, "", card)
		if contact.FormattedName == "" {
			result.Skipped++
			continue
		}

		_, err = store.Upsert(contact)
		if err != nil {
			addError(fmt.Sprintf("import error for %s: %v", contact.FormattedName, err))
			result.Skipped++
			continue
		}
		result.Imported++
	}

	result.ErrorCount = errorCount

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		s.logger.Error("contacts import response encode failed", "error", err.Error())
	}
}

// maxFoldedLinesPerImport bounds RFC 6350 continuation lines across one import.
// Real address books fold occasionally — a long NOTE, a base64 PHOTO — so this
// is set far above ordinary use and only refuses the pathological shape.
const maxFoldedLinesPerImport = 50_000

// checkVCardFolding refuses input whose folding would make decoding quadratic.
func checkVCardFolding(raw []byte) error {
	folded := 0
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			folded++
			if folded > maxFoldedLinesPerImport {
				return errors.New("vcard is too heavily folded to import")
			}
		}
	}
	return nil
}
