package classifier

import (
	"strings"
)

// NoAllowedLabelError reports that the model answered, but nothing in its
// answer resolved to a label on the configured allowlist. It carries the raw
// output so a caller that legitimately wants to show what the model actually
// said (the admin connectivity-test endpoint) can, without Classify having to
// return unbounded model text through its label return value.
type NoAllowedLabelError struct {
	Output string
}

func (e *NoAllowedLabelError) Error() string {
	return "classifier returned no allowed label: " + e.Output
}

func SelectLabelFromText(allowedLabels []string, output string) string {
	if len(allowedLabels) == 0 {
		return ""
	}
	lowerOut := strings.ToLower(output)
	for _, label := range allowedLabels {
		if strings.EqualFold(label, "Questionable") && strings.Contains(lowerOut, "questionable") {
			return label
		}
	}
	for _, label := range allowedLabels {
		if strings.Contains(lowerOut, strings.ToLower(label)) {
			return label
		}
	}
	if strings.Contains(lowerOut, "important") {
		for _, label := range allowedLabels {
			if strings.EqualFold(label, "Important") {
				return label
			}
		}
	}
	return ""
}
