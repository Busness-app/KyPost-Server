package classifier

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withResolver points ValidateBaseURL's name lookup at a fixed answer for the
// duration of one test, so the policy can be exercised without DNS.
func withResolver(t *testing.T, answers map[string][]net.IP) {
	t.Helper()
	original := resolveHost
	resolveHost = func(host string) ([]net.IP, error) {
		if ips, ok := answers[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { resolveHost = original })
}

func TestValidateBaseURLRequiresTLSForPublicHosts(t *testing.T) {
	withResolver(t, map[string][]net.IP{
		// A genuinely public address. The TEST-NET ranges are NOT usable
		// here: netguard classifies them as reserved, which is correct and
		// would make this case pass for the wrong reason.
		"llm.example.com": {net.ParseIP("93.184.216.34")},
		"ollama":          {net.ParseIP("172.18.0.4")},
		"localhost":       {net.ParseIP("127.0.0.1")},
	})

	for _, tc := range []struct {
		name    string
		url     string
		wantErr bool
	}{
		// The bundled Ollama and a compose sibling are the normal case, and
		// both are plaintext by design. A policy that broke either would be a
		// policy nobody could deploy.
		{"loopback literal over http", "http://127.0.0.1:11434", false},
		{"loopback name over http", "http://localhost:11434", false},
		{"compose sibling over http", "http://ollama:11434", false},
		{"private literal over http", "http://192.168.1.50:11434", false},
		// RFC 6598 shared address space — a tailnet node. netguard classifies
		// it as inside; net.IP.IsPrivate does not.
		{"tailnet address over http", "http://100.64.0.7:11434", false},

		// Every classify request carries mail and the API key. Over the public
		// internet that has to be TLS.
		{"public host over http", "http://llm.example.com/v1", true},
		{"public literal over http", "http://93.184.216.34/v1", true},
		{"public host over https", "https://llm.example.com/v1", false},

		{"missing scheme", "llm.example.com", true},
		{"wrong scheme", "ftp://llm.example.com", true},
		{"no host", "http://", true},
		{"embedded credentials", "https://user:pass@llm.example.com", true},
		{"empty", "   ", true},

		// A name that does not resolve is accepted: a compose sibling may not
		// be up when config is first saved, and refusing to configure it would
		// be worse than the risk.
		{"unresolvable name over http", "http://not-up-yet:11434", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBaseURL(tc.url)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateBaseURL(%q) = nil, want an error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateBaseURL(%q) = %v, want nil", tc.url, err)
			}
		})
	}
}

// The error an admin sees must not report what a hostname resolved to: the
// check performs a DNS lookup on request, and echoing the answer turns a
// configuration form into a resolver oracle.
func TestValidateBaseURLDoesNotDiscloseResolvedAddresses(t *testing.T) {
	withResolver(t, map[string][]net.IP{"llm.example.com": {net.ParseIP("93.184.216.34")}})
	err := ValidateBaseURL("http://llm.example.com")
	if err == nil {
		t.Fatal("expected a public plaintext host to be refused")
	}
	if strings.Contains(err.Error(), "93.184.216.34") {
		t.Fatalf("error names the resolved address: %v", err)
	}
}

// A classify request is a POST whose body is somebody's email. Go's default
// redirect policy follows up to ten hops anywhere, and a 307/308 re-sends that
// body verbatim — so the endpoint on the far end got to choose who else
// received the mail.
func TestClassifierClientRefusesCrossOriginRedirects(t *testing.T) {
	var elsewhereGotBody bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			elsewhereGotBody = true
		}
		_, _ = w.Write([]byte(`{"response":"Updates"}`))
	}))
	defer elsewhere.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := NewHTTPClient(redirector.URL, "secret-api-key", "/api/generate", "", 5*time.Second)
	req, err := http.NewRequest(http.MethodPost, redirector.URL+"/api/generate", strings.NewReader(`{"prompt":"private mail"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the cross-origin redirect to be refused")
	}
	if elsewhereGotBody {
		t.Fatal("the email body was replayed to a host the classifier endpoint chose")
	}
}
