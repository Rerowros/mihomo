//go:build !linux || android

// The ballast is for server nodes and lives in gcballast.go, built only for
// Linux other than Android. Clients (Windows, macOS, Android, iOS) get no
// ballast; this file keeps the package (imported by main) present there.
package gcballast

// Active reports whether the ballast was allocated: never on this platform.
func Active() bool { return false }
