package version

// Version is set at build time via -ldflags "-s -w -X goBastion/version.Version=..."
var Version string
