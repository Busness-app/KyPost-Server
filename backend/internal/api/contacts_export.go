package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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

	list, err := store.List()
	if err != nil {
		http.Error(w, "failed to read contacts", http.StatusInternalServerError)
		return
	}

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

// maxContactImportBytes bounds the vCard payload of one import.
const maxContactImportBytes = 10 << 20

// multipartEnvelopeAllowance is the slack added to the wire ceiling to cover a
// multipart boundary and part headers (a few hundred bytes). Without it the
// documented 10 MiB limit is a lie for the only client that exists: a 10 MiB
// .vcf wrapped in a form is over the wire limit by the size of its own framing.
const multipartEnvelopeAllowance = 8 << 10

// readContactImportBody returns the vCard bytes of an import request, along
// with the HTTP status to report if it fails.
//
// It accepts both shapes the endpoint actually receives. The browser sends
// multipart/form-data (frontend/src/api/contacts.ts builds a FormData with a
// "file" part), and reading that body directly into the vCard decoder does not
// fail loudly — the decoder skips the boundary and Content-Disposition lines,
// returning "no BEGIN field found" for each, then decodes every card
// correctly. So the contacts imported and the user was told
// "Imported N contacts. (2 errors)" every single time, on every successful
// import, with no way to tell that from a real parse failure. No test caught
// it because the tests here post raw vCard text, which is the one shape no
// browser sends.
//
// Raw bodies are still accepted: `curl --data-binary @contacts.vcf` against the
// endpoint README documents is reasonable, and it is what the bounded-loop
// tests exercise.
//
// The ceiling is http.MaxBytesReader, not io.LimitReader. LimitReader is
// indistinguishable from a body that simply ended: an oversized upload was
// truncated mid-card and imported as a partial success, so the operator was
// told the import worked while contacts went missing. MaxBytesReader makes the
// read fail instead, which is reportable as 413.
func readContactImportBody(w http.ResponseWriter, r *http.Request) ([]byte, int, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	isMultipart := err == nil && strings.HasPrefix(mediaType, "multipart/")

	ceiling := int64(maxContactImportBytes)
	if isMultipart {
		ceiling += multipartEnvelopeAllowance
	}
	r.Body = http.MaxBytesReader(w, r.Body, ceiling)

	if !isMultipart {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, contactImportReadStatus(err), errors.New("failed to read import")
		}
		return raw, http.StatusOK, nil
	}

	// maxMemory is the full ceiling, so ParseMultipartForm never spills a temp
	// file to disk: MaxBytesReader has already capped the body below it.
	if err := r.ParseMultipartForm(ceiling); err != nil {
		return nil, contactImportReadStatus(err), errors.New("import upload is too large or malformed")
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, http.StatusBadRequest, errors.New(`import upload must carry a "file" part`)
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, contactImportReadStatus(err), errors.New("failed to read import")
	}
	return raw, http.StatusOK, nil
}

// contactImportReadStatus maps a body-read failure to a status, so "you sent
// too much" is not reported as "your file is malformed".
func contactImportReadStatus(err error) int {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// handleContactsImport imports contacts in vCard format into the caller's own
// address book, from either a multipart file upload or a raw vCard body.
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

	// go-vcard unfolds continuation lines with `l += ...` inside a loop, which
	// is quadratic in the number of folds. The byte and card caps do not bound
	// folds WITHIN one card, so a single card made of continuation lines turned
	// a 10 MiB upload into minutes of memcpy on a shared, CPU-limited box.
	// Buffer and pre-scan: cheap next to what it prevents.
	raw, status, err := readContactImportBody(w, r)
	if err != nil {
		writeJSON(w, status, map[string]any{"error": err.Error()})
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
