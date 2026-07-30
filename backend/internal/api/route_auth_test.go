package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// authMarkers is every wrapper that constitutes a declaration of a route's
// auth model — the four real middlewares, plus the four no-op markers in
// route_auth_markers.go for the routes that authenticate some other way.
//
// Adding a name here is how you exempt a route from the check below, so adding
// one should be a deliberate act with a reason attached, not a way to make a
// failing test pass.
var authMarkers = map[string]bool{
	// Real middleware: rejects the request when the check fails.
	"withAuth":         true,
	"withMailAuth":     true,
	"withAdmin":        true,
	"withDAVBasicAuth": true,
	// Declarations that the handler is reached another way. See
	// route_auth_markers.go.
	"withPublicRoute": true,
	"withSelfAuth":    true,
	"withTokenAuth":   true,
	"withDeviceAuth":  true,
}

// TestEveryRouteDeclaresItsAuthModel reads the route table and fails on any
// route registered with a bare handler.
//
// The failure this catches is a forgotten wrapper on a new route. Across ~120
// routes and five auth mechanisms, an unwrapped registration is
// indistinguishable at a glance from the dozen routes that are unwrapped on
// purpose — /api/contacts/sync authenticates a paired device inside the
// handler, /pickup/{id} validates a signed token, /api/health is public — so
// the eye slides over a missing withAuth exactly where it matters most.
//
// Reading the source rather than the mux because http.ServeMux gives no way to
// ask what a pattern resolves to, and a handler that has lost its wrapper is
// still a perfectly valid http.HandlerFunc at runtime.
func TestEveryRouteDeclaresItsAuthModel(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	registrations := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "mux" {
			return true
		}

		pattern := "<non-literal>"
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if unquoted, err := strconv.Unquote(lit.Value); err == nil {
				pattern = unquoted
			}
		}
		registrations++

		// Any marker anywhere in the handler expression counts, so nesting
		// order does not matter: withUploadDeadline(s.withMailAuth(h)) and
		// s.withMailAuth(withUploadDeadline(h)) are both fine.
		if !mentionsAuthMarker(call.Args[1]) {
			t.Errorf("route %q is registered with no auth marker.\n"+
				"Wrap it in the middleware that gates it (withAuth/withMailAuth/withAdmin/"+
				"withDAVBasicAuth), or — if it authenticates another way — in the marker that "+
				"says so (withPublicRoute/withSelfAuth/withTokenAuth/withDeviceAuth). "+
				"See route_auth_markers.go.", pattern)
		}
		return true
	})

	// Guards against the check silently passing because it stopped finding any
	// routes at all — a refactor that moves registration out of server.go, or
	// renames the mux variable, would otherwise turn this into a no-op test
	// that reports success forever.
	if registrations < 100 {
		t.Fatalf("found only %d route registrations in server.go; the route table moved and this test is no longer looking at it", registrations)
	}
}

func mentionsAuthMarker(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && authMarkers[ident.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

// markerRequiresCall maps each inert marker to the call its handler must
// actually make.
//
// This is the check that makes the markers mean something. TestEveryRoute...
// above only asks whether one of eight names appears in the expression — so on
// its own, the fastest way to green a forgotten withAuth is to type
// withPublicRoute instead, and a marker that lies is worse than no marker at
// all: it launders "somebody forgot" into "documented decision".
//
// withPublicRoute is absent on purpose — "authenticates nothing" has no call to
// look for. It is constrained by publicRoutes below instead.
var markerRequiresCall = map[string][]string{
	// Resolves the acting user from a paired device's credentials.
	"withDeviceAuth": {"deviceAuthFromRequest"},
	// The whole credential is a signed token presented in the request — in the
	// URL for pickup/QR, in the body for native device registration.
	"withTokenAuth": {"validatePairingToken", "consumeQRToken", "decodeAndVerifyPairingToken"},
	// Inspects the session itself and answers differently when anonymous.
	"withSelfAuth": {"currentUser"},
}

// publicRoutes is every route allowed to carry withPublicRoute, with the reason
// it is reachable by an anonymous caller on the open internet.
//
// An allowlist rather than a free-for-all because withPublicRoute is the one
// marker with nothing to verify against the handler, which makes it the path of
// least resistance for a route that simply lost its withAuth. Adding an entry
// here is a deliberate second edit with a written justification attached; that
// is the cost that keeps it from being a rubber stamp.
//
// If you are adding a route here, the bar is: it returns nothing that is not
// already public, OR the caller cannot have a session yet because obtaining one
// is what the route is for.
var publicRoutes = map[string]string{
	"POST /api/auth/login":             "issues the session; by definition has none yet",
	"GET /api/auth/captcha-config":     "tells an anonymous browser which CAPTCHA widget to render",
	"GET /api/auth/login-params":       "pre-login KDF parameters; login_params.go covers why it cannot reveal account existence",
	"GET /api/auth/pow-challenge":      "issues the proof-of-work challenge required to attempt a login",
	"POST /api/auth/mfa/totp":          "second factor; the challenge id is the credential and no session exists until it passes",
	"POST /api/auth/mfa/recovery-code": "as above, for the recovery-code branch",
	"POST /api/auth/mfa/push/poll":     "as above; polls the pending push approval by challenge id",
	"POST /api/auth/mfa/push/finish":   "as above; redeems an approved push challenge for a session",
	"POST /api/mfa/push/respond":       "answered by the paired device, which authenticates with the signed push nonce, not a session",
	"/api/health":                      "liveness for orchestrators; health.Status carries no per-user data",
	"GET /api/setup":                   "pre-login hint for a fresh install with no accounts to authenticate against",
	"GET /.well-known/openpgpkey/":     "Web Key Directory is public by protocol; any sender's client must fetch published keys uncredentialed",
	"/":                                "SPA shell and static assets",
}

// TestAuthMarkersMatchTheirHandlers checks that a route's declared auth model is
// the one its handler actually implements.
//
// Without this, route_auth_markers.go is documentation that the compiler cannot
// check, sitting on the security boundary of ~120 routes.
func TestAuthMarkersMatchTheirHandlers(t *testing.T) {
	handlers := packageFuncDecls(t)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	checked := 0
	forEachRoute(file, func(pattern string, handlerExpr ast.Expr) {
		marker := inertMarkerUsed(handlerExpr)
		if marker == "" {
			return
		}
		checked++

		if marker == "withPublicRoute" {
			if _, ok := publicRoutes[pattern]; !ok {
				t.Errorf("route %q is marked withPublicRoute but is not in publicRoutes.\n"+
					"withPublicRoute means ANY anonymous caller on the internet may reach this handler. "+
					"If that is intended, add the pattern to publicRoutes with the reason. If it is not, "+
					"this route is missing its real auth wrapper.", pattern)
			}
			return
		}

		wanted := markerRequiresCall[marker]
		if len(wanted) == 0 {
			return
		}
		name := handlerFuncName(handlerExpr)
		if name == "" {
			t.Errorf("route %q: could not identify the handler behind %s", pattern, marker)
			return
		}
		decl, ok := handlers[name]
		if !ok {
			t.Errorf("route %q: handler %s not found in this package", pattern, name)
			return
		}
		if !bodyCallsAny(decl, wanted) {
			t.Errorf("route %q is marked %s, but %s never calls any of %v.\n"+
				"The marker asserts the handler authenticates the caller itself. Either it does not "+
				"(in which case this route is unauthenticated and the marker is hiding it), or the "+
				"check moved and markerRequiresCall needs updating.",
				pattern, marker, name, wanted)
		}
	})

	if checked < 15 {
		t.Fatalf("only %d marked routes found; this test is no longer reading the route table", checked)
	}
}

// TestPublicRoutesAllowlistHasNoStaleEntries keeps publicRoutes from
// accumulating permissions for routes that no longer exist — a stale entry
// silently pre-approves the next route that reuses the pattern.
func TestPublicRoutesAllowlistHasNoStaleEntries(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	live := map[string]bool{}
	forEachRoute(file, func(pattern string, handlerExpr ast.Expr) {
		if inertMarkerUsed(handlerExpr) == "withPublicRoute" {
			live[pattern] = true
		}
	})
	for pattern := range publicRoutes {
		if !live[pattern] {
			t.Errorf("publicRoutes has an entry for %q, which is no longer registered as a public route. "+
				"Remove it: a stale entry pre-approves whatever claims that pattern next.", pattern)
		}
	}
}

// forEachRoute calls fn for every mux registration in server.go.
func forEachRoute(file *ast.File, fn func(pattern string, handler ast.Expr)) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "mux" {
			return true
		}
		pattern := "<non-literal>"
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if unquoted, err := strconv.Unquote(lit.Value); err == nil {
				pattern = unquoted
			}
		}
		fn(pattern, call.Args[1])
		return true
	})
}

// inertMarkerUsed returns the no-op marker wrapping this handler, or "" if the
// route is gated by a real middleware instead.
func inertMarkerUsed(expr ast.Expr) string {
	found := ""
	ast.Inspect(expr, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		switch ident.Name {
		case "withPublicRoute", "withSelfAuth", "withTokenAuth", "withDeviceAuth":
			found = ident.Name
			return false
		}
		return true
	})
	return found
}

// handlerFuncName pulls the s.handleX method name out of a route expression,
// through any number of wrappers.
func handlerFuncName(expr ast.Expr) string {
	name := ""
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && strings.HasPrefix(sel.Sel.Name, "handle") {
			name = sel.Sel.Name
			return false
		}
		return true
	})
	return name
}

// packageFuncDecls indexes every method declared in this package's non-test
// files by name, so a route's handler body can be inspected.
func packageFuncDecls(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]*ast.FuncDecl{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				out[fn.Name.Name] = fn
			}
		}
	}
	return out
}

// bodyCallsAny reports whether fn's body mentions any of the given identifiers.
func bodyCallsAny(fn *ast.FuncDecl, names []string) bool {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if want[node.Name] {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if want[node.Sel.Name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// TestAuthMarkersAreInert pins the one property the no-op markers must keep:
// they declare, they do not gate. A marker that grew a check would be a second,
// invisible auth path that the route table claims is something else.
func TestAuthMarkersAreInert(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "route_auth_markers.go", nil, 0)
	if err != nil {
		t.Fatalf("parse route_auth_markers.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if len(fn.Body.List) != 1 {
			t.Errorf("%s has %d statements; the markers must stay no-ops that return their argument unchanged",
				fn.Name.Name, len(fn.Body.List))
			continue
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			t.Errorf("%s does not consist of a single return statement", fn.Name.Name)
			continue
		}
		ident, ok := ret.Results[0].(*ast.Ident)
		if !ok || ident.Name != "next" {
			t.Errorf("%s returns something other than its `next` argument", fn.Name.Name)
		}
	}
}
