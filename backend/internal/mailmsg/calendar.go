package mailmsg

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxCalendarReplyBytes bounds one iTIP reply object.
const MaxCalendarReplyBytes = 64 << 10

// maxCalendarDepth bounds component nesting (VCALENDAR > VEVENT > VALARM ...).
const maxCalendarDepth = 8

// ErrCalendarReply is wrapped by every CalendarReply refusal.
var ErrCalendarReply = errors.New("invalid calendar reply")

func calendarError(reason string) error {
	return fmt.Errorf("%w: %s", ErrCalendarReply, reason)
}

// CalendarReply checks that ics is one iTIP REPLY (RFC 5546): a single
// VCALENDAR whose METHOD is REPLY, holding exactly one VEVENT, in UTF-8 with
// no control characters, and returns it CRLF-normalised. It is a structural
// check, not a full iCalendar parse; the organizer's calendar validates the
// rest. Build base64-encodes the bytes, so no content can reach a header.
func CalendarReply(ics string) ([]byte, error) {
	if len(ics) > MaxCalendarReplyBytes {
		return nil, calendarError("calendar reply exceeds 64 KiB")
	}
	if !utf8.ValidString(ics) {
		return nil, calendarError("calendar reply is not UTF-8")
	}
	text := strings.ReplaceAll(strings.ReplaceAll(ics, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	var stack []string
	methods, events := 0, 0
	for i, line := range lines {
		for _, r := range line {
			if (r < 0x20 && r != '\t') || r == 0x7f {
				return nil, calendarError("calendar reply contains a control character")
			}
		}
		if line == "" {
			return nil, calendarError("calendar reply contains an empty line")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if i == 0 {
				return nil, calendarError("calendar reply starts with a continuation line")
			}
			continue // folded continuation of the previous property
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, calendarError("calendar reply has a line without a value")
		}
		name, _, _ = strings.Cut(name, ";")
		name, value = strings.ToUpper(name), strings.ToUpper(strings.TrimSpace(value))
		if i == 0 && (name != "BEGIN" || value != "VCALENDAR") {
			return nil, calendarError("calendar reply must start with BEGIN:VCALENDAR")
		}
		if len(stack) == 0 && i != 0 {
			return nil, calendarError("calendar reply has content after END:VCALENDAR")
		}
		switch name {
		case "BEGIN":
			if len(stack) >= maxCalendarDepth {
				return nil, calendarError("calendar reply is nested too deeply")
			}
			if value == "VCALENDAR" && len(stack) > 0 {
				return nil, calendarError("calendar reply holds more than one VCALENDAR")
			}
			if value == "VEVENT" {
				events++
			}
			stack = append(stack, value)
		case "END":
			if len(stack) == 0 || stack[len(stack)-1] != value {
				return nil, calendarError("calendar reply has unbalanced BEGIN/END")
			}
			stack = stack[:len(stack)-1]
		case "METHOD":
			if len(stack) != 1 || value != "REPLY" {
				return nil, calendarError("calendar reply METHOD must be REPLY")
			}
			methods++
		}
	}
	switch {
	case len(stack) != 0:
		return nil, calendarError("calendar reply must end with END:VCALENDAR")
	case methods != 1:
		return nil, calendarError("calendar reply needs exactly one METHOD:REPLY")
	case events != 1:
		return nil, calendarError("calendar reply needs exactly one VEVENT")
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n"), nil
}
