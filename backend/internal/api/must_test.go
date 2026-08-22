package api

// The per-user store readers return an error so a failed disk re-read is never
// served as data (see contacts.Store.refreshFromDiskLocked). Tests that only
// exercise the happy path wrap the call rather than repeating the check; a
// failure panics, which fails the test with the offending line in the trace.

func must1[A any](a A, err error) A {
	if err != nil {
		panic(err)
	}
	return a
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func must4[A, B, C, D any](a A, b B, c C, d D, err error) (A, B, C, D) {
	if err != nil {
		panic(err)
	}
	return a, b, c, d
}
