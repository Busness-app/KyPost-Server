package api

import "net/http"

// Auth markers for routes that do not go through withAuth/withMailAuth/
// withAdmin/withDAVBasicAuth.
//
// These add no behaviour. They exist so the route table states every route's
// auth model on the route's own line, and so TestEveryRouteDeclaresItsAuthModel
// can enforce that it does.
//
// The problem they solve is not hypothetical. With ~120 routes and five auth
// mechanisms, "no wrapper" used to mean either "deliberately public", "gated by
// a signed token in the URL", "authenticates itself further down the handler",
// or "somebody forgot" — and the only way to tell was to open the handler. One
// of those four is a vulnerability and the route table could not distinguish it
// from the other three.
//
// Adding a route with no marker now fails a test rather than merging quietly.

// withPublicRoute marks a handler reachable with no credential at all, because
// it has to be: the caller has no session yet, or the response carries nothing
// that is not already public.
//
// A handler wrapped here must be safe for an anonymous caller on the open
// internet. If it returns per-user data, it is in the wrong category.
func withPublicRoute(next http.HandlerFunc) http.HandlerFunc { return next }

// withTokenAuth marks a handler whose entire credential is a signed token
// supplied in the request — in the URL for the pickup and QR routes
// (validatePairingToken, consumeQRToken), in the body for native device
// registration (decodeAndVerifyPairingToken), which is the route that MINTS a
// device and therefore cannot yet have a device secret to present.
//
// There is no session and no cookie on any of them, so there is nothing for
// CSRF to abuse — an attacker holding the token does not need a victim's
// browser.
func withTokenAuth(next http.HandlerFunc) http.HandlerFunc { return next }

// withDeviceAuth marks a handler that authenticates a paired device itself,
// via deviceAuthFromRequest, rather than through a middleware. These predate
// the middleware split and resolve the acting user from the device credentials
// as their first act; the marker records that the check exists rather than
// performing it.
func withDeviceAuth(next http.HandlerFunc) http.HandlerFunc { return next }

// withSelfAuth marks a handler that inspects the session itself and answers
// differently for an anonymous caller instead of rejecting them — handleMe
// reporting authenticated:false rather than 401. It cannot use withAuth,
// because withAuth's job is to refuse.
func withSelfAuth(next http.HandlerFunc) http.HandlerFunc { return next }
