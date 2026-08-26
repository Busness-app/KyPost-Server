package imap

// A real IMAP server over a real TLS socket, speaking just enough of the
// protocol for the adapter's folder-resolution and message-move paths.
//
// Worth the ~150 lines: the bugs in those paths are protocol behaviour, not Go
// behaviour. "Which command did we send, and what did the server do with it"
// cannot be observed through the imapadapter.Client interface, and go-imap
// takes a concrete *goimap.Dialer, so there is nothing to fake below it. This
// harness records every command line the server received, which is exactly the
// artifact the assertions need.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	goimap "github.com/BrianLeishman/go-imap"
)

type fakeFolder struct {
	name string
	// attrs is the RFC 6154 special-use attribute, if the server publishes one
	// for this folder: `\Trash`, `\Junk`, `\Sent`, `\Drafts`, `\Archive`.
	attrs string
}

type fakeIMAPServer struct {
	t     *testing.T
	ln    net.Listener
	host  string
	port  int
	delim string
	// specialUse is whether the server advertises the SPECIAL-USE capability and
	// returns the attributes in LIST. Off models the older servers the fallback
	// path exists for.
	specialUse bool
	// attrsOnlyWhenAsked models a server that follows RFC 6154 to the letter:
	// the attributes appear ONLY under the (SPECIAL-USE) selection option, never
	// in a plain LIST. This is the population the CAPABILITY probe exists for.
	attrsOnlyWhenAsked bool
	// refuseSelectionOption models a server that advertises SPECIAL-USE and then
	// rejects the selection option anyway — the case that leaves go-imap's
	// connection closed underneath us.
	refuseSelectionOption bool

	mu       sync.Mutex
	folders  []fakeFolder
	commands []string
	logins   int
	closed   bool
}

// newFakeIMAPServer starts a TLS listener on localhost and serves until the
// test ends.
func newFakeIMAPServer(t *testing.T, delim string, specialUse bool, folders []fakeFolder) *fakeIMAPServer {
	t.Helper()

	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)

	s := &fakeIMAPServer{
		t: t, ln: ln, host: "127.0.0.1", port: addr.Port,
		delim: delim, specialUse: specialUse, folders: folders,
	}

	go s.serve()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = ln.Close()
	})

	// go-imap verifies certificates by default and this one is self-signed.
	// Restored after the test so it can never leak into another one.
	previous := goimap.TLSSkipVerify
	goimap.TLSSkipVerify = true
	t.Cleanup(func() { goimap.TLSSkipVerify = previous })

	return s
}

func (s *fakeIMAPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeIMAPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := fmt.Fprint(conn, "* OK fake IMAP ready\r\n"); err != nil {
		return
	}

	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		tag, command, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		s.record(command)

		// APPEND carries its message as a literal: the server has to ask for the
		// bytes with a continuation, read exactly that many, and only then
		// answer the command.
		if strings.EqualFold(firstWord(command), "APPEND") {
			if err := s.readAppendLiteral(conn, r, tag, command); err != nil {
				return
			}
			continue
		}

		if _, err := conn.Write([]byte(s.respond(tag, command))); err != nil {
			return
		}
		if strings.EqualFold(firstWord(command), "LOGOUT") {
			return
		}
	}
}

// readAppendLiteral completes one APPEND: "+" to invite the literal, consume
// exactly the announced byte count, then answer the command.
func (s *fakeIMAPServer) readAppendLiteral(conn net.Conn, r *bufio.Reader, tag, command string) error {
	open := strings.LastIndex(command, "{")
	shut := strings.LastIndex(command, "}")
	if open < 0 || shut < open {
		_, err := conn.Write([]byte(tag + " BAD expected a literal\r\n"))
		return err
	}
	size, err := strconv.Atoi(strings.TrimSuffix(command[open+1:shut], "+"))
	if err != nil {
		_, werr := conn.Write([]byte(tag + " BAD bad literal size\r\n"))
		return werr
	}

	mailbox := unquote(strings.TrimSpace(strings.SplitN(strings.TrimSpace(strings.TrimPrefix(command, firstWord(command))), " ", 2)[0]))
	if _, err := conn.Write([]byte("+ ready for literal data\r\n")); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, make([]byte, size)); err != nil {
		return err
	}
	// The CRLF that terminates the APPEND command after the literal.
	if _, err := r.ReadString('\n'); err != nil {
		return err
	}

	if !s.hasFolder(mailbox) {
		_, err := conn.Write([]byte(tag + " NO [TRYCREATE] Mailbox doesn't exist\r\n"))
		return err
	}
	_, err = conn.Write([]byte(tag + " OK [APPENDUID 1 1] APPEND completed\r\n"))
	return err
}

func firstWord(command string) string {
	word, _, _ := strings.Cut(command, " ")
	return word
}

// unquote strips one layer of IMAP double quotes from an argument.
func unquote(arg string) string {
	return strings.Trim(strings.TrimSpace(arg), `"`)
}

func (s *fakeIMAPServer) record(command string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, command)
	if strings.EqualFold(firstWord(command), "LOGIN") {
		s.logins++
	}
}

func (s *fakeIMAPServer) hasFolder(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.folders {
		if strings.EqualFold(f.name, name) {
			return true
		}
	}
	return false
}

func (s *fakeIMAPServer) addFolder(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.folders = append(s.folders, fakeFolder{name: name})
}

func (s *fakeIMAPServer) respond(tag, command string) string {
	verb := strings.ToUpper(firstWord(command))
	rest := strings.TrimSpace(strings.TrimPrefix(command, firstWord(command)))

	switch verb {
	case "LOGIN":
		return tag + " OK LOGIN completed\r\n"
	case "LOGOUT":
		return "* BYE\r\n" + tag + " OK LOGOUT completed\r\n"
	case "CAPABILITY":
		caps := "IMAP4rev1 UIDPLUS MOVE"
		if s.specialUse {
			caps += " SPECIAL-USE LIST-EXTENDED"
		}
		return "* CAPABILITY " + caps + "\r\n" + tag + " OK CAPABILITY completed\r\n"
	case "LIST":
		return s.respondList(tag, rest)
	case "SELECT", "EXAMINE":
		if !s.hasFolder(unquote(rest)) {
			return tag + " NO Mailbox does not exist\r\n"
		}
		return "* 0 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n" +
			tag + " OK [READ-WRITE] SELECT completed\r\n"
	case "CREATE":
		name := unquote(rest)
		if s.hasFolder(name) {
			return tag + " NO Mailbox already exists\r\n"
		}
		s.addFolder(name)
		return tag + " OK CREATE completed\r\n"
	case "UID":
		return s.respondUID(tag, rest)
	default:
		return tag + " OK completed\r\n"
	}
}

// respondList answers both `LIST "" "*"` and the SPECIAL-USE selection form,
// `LIST (SPECIAL-USE) "" "*"`, which asks for only the flagged folders.
func (s *fakeIMAPServer) respondList(tag, rest string) string {
	onlySpecial := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rest)), "(SPECIAL-USE)")
	if onlySpecial && (!s.specialUse || s.refuseSelectionOption) {
		return tag + " BAD Unsupported selection option\r\n"
	}

	s.mu.Lock()
	folders := append([]fakeFolder{}, s.folders...)
	s.mu.Unlock()

	var b strings.Builder
	for _, f := range folders {
		attrs := "\\HasNoChildren"
		publishAttrs := s.specialUse && f.attrs != "" && (onlySpecial || !s.attrsOnlyWhenAsked)
		if publishAttrs {
			attrs += " " + f.attrs
		}
		if onlySpecial && f.attrs == "" {
			continue
		}
		fmt.Fprintf(&b, "* LIST (%s) \"%s\" \"%s\"\r\n", attrs, s.delim, f.name)
	}
	b.WriteString(tag + " OK LIST completed\r\n")
	return b.String()
}

func (s *fakeIMAPServer) respondUID(tag, rest string) string {
	sub := strings.ToUpper(firstWord(rest))
	args := strings.TrimSpace(strings.TrimPrefix(rest, firstWord(rest)))
	switch sub {
	case "MOVE", "COPY":
		// "<uid> <mailbox>"
		_, mailbox, _ := strings.Cut(args, " ")
		if !s.hasFolder(unquote(mailbox)) {
			return tag + " NO [TRYCREATE] Mailbox doesn't exist\r\n"
		}
		return tag + " OK MOVE completed\r\n"
	case "STORE":
		return tag + " OK STORE completed\r\n"
	default:
		return tag + " OK completed\r\n"
	}
}

// commandsMatching returns every recorded command whose first word matches verb.
func (s *fakeIMAPServer) commandsMatching(verb string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.commands {
		if strings.EqualFold(firstWord(c), verb) {
			out = append(out, c)
		}
	}
	return out
}

func (s *fakeIMAPServer) uidMoves() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.commands {
		if strings.HasPrefix(strings.ToUpper(c), "UID MOVE") {
			out = append(out, c)
		}
	}
	return out
}

func (s *fakeIMAPServer) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// client builds an APIClient pointed at this server, with credentials already
// in memory so no stored-config file is needed.
func (s *fakeIMAPServer) client(mailbox string) *APIClient {
	c := &APIClient{
		host:     s.host,
		port:     s.port,
		username: "user@example.com",
		password: "hunter2",
		mailbox:  mailbox,
	}
	s.t.Cleanup(func() { _ = c.Close() })
	return c
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-imap"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// quietRetries pins go-imap's retry count for one test. The default of 3 is
// what turns a "mailbox doesn't exist" NO into a multi-second reconnect storm,
// so tests that are not measuring the storm turn it down to keep the suite fast.
func quietRetries(t *testing.T, count int) {
	t.Helper()
	previous := goimap.RetryCount
	goimap.RetryCount = count
	t.Cleanup(func() { goimap.RetryCount = previous })
}
