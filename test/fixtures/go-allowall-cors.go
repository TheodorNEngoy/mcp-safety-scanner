package main

// This should be flagged.
func config() {
	_ = struct {
		AllowAllOrigins bool
	}{
		AllowAllOrigins: true,
	}
}

