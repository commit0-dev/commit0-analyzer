module example.com/corpus-not-reachable-cve

go 1.21

require example.com/corpusvulnlib v0.0.0

replace example.com/corpusvulnlib => ../vulnlib
