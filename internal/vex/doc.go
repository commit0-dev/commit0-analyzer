// Package vex builds and emits Vulnerability Exploitability eXchange (VEX)
// documents from commit0-analyzer's reachability findings.
//
// commit0-analyzer proves reachability — the exact signal VEX exists to communicate.
// Downstream scanners can consume commit0-analyzer's VEX to suppress CVEs that commit0-analyzer proved
// unreachable (status not_affected) while keeping everything commit0-analyzer could not
// prove safe under investigation.
//
// One internal model (Document/Statement, see model.go) feeds three pluggable
// Formatters: OpenVEX (the reference implementation), CycloneDX-VEX, and CSAF
// 2.0. Adding a format is a new Formatter, never a rewrite of the model.
//
// Cardinal-sin guard (MapStatus, model.go): a finding that is UNKNOWN, or whose
// producing analysis was incomplete, maps to under_investigation — NEVER
// not_affected. Only a proven NOT_REACHABLE verdict from a complete analysis may
// emit not_affected (justification vulnerable_code_not_in_execute_path).
// Emitting not_affected for an unproven case would turn commit0-analyzer into a false-clean
// generator, so it is forbidden and tested explicitly.
//
// Determinism: statements are stable-sorted (by vulnerability id, then purl) and
// the timestamp is injected by the caller (never time.Now() inside a formatter),
// so the same scan produces byte-identical VEX for golden stability.
package vex
