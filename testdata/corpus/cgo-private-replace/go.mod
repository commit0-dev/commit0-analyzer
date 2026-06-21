module example.com/corpus-cgo-private-replace

go 1.21

require example.com/corpusvulnlib v0.0.0

// Private replace pointing to a non-existent path — simulates a corporate
// monorepo dependency that is unavailable outside its network. The engine
// must produce UNKNOWN (load failure), never silently drop the finding.
replace example.com/corpusvulnlib => ./nonexistent-private-dep
