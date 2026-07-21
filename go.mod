module github.com/exclavenetwork/sing-shadowquic

go 1.24.0

require (
	github.com/metacubex/jls-quic-go v0.0.0-20260727080412-732f2fc9a34d
	github.com/metacubex/jls-tls v0.0.0-20260723084315-67adc0e2f796
	github.com/sagernet/sing v0.8.11
)

// Do not downgrade github.com/metacubex/randv2 to v0.2.0. It is licensed under GPL v3
// only, which is incompatible with the MIT License (github.com/metacubex/jls-quic-go)
// or GPL v3 or later (this project).

require (
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/randv2 v0.2.1-0.20260726125100-81aa96a9b1a5 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
