# Security Policy

## Supported Versions

This repository is a fork of `cloudflare/odoh-go` that uses
`github.com/jedisct1/go-hpke-compact` instead of `github.com/cisco/go-hpke`.
Only the latest `master` (and tagged releases `v0.0.x`) are supported.

| Version | Supported          |
| ------- | ------------------ |
| master  | :white_check_mark: |
| v0.0.x  | :white_check_mark: |
| < v0.0.1| :x:                |

## Reporting a Vulnerability

If you discover a security issue in this fork, please report it **privately**:

- Open a [GitHub Security Advisory](https://github.com/nam348tnh3gp/odoh-go/security/advisories/new)
  (preferred), or
- Email the maintainer at the address listed on the GitHub profile
  [@nam348tnh3gp](https://github.com/nam348tnh3gp).

Please include:
- A description of the issue and its impact.
- Steps to reproduce (minimal PoC if possible).
- Affected versions/commits.
- Any suggested fix.

**Do not** open a public issue for security vulnerabilities.

## Scope

This fork changes the HPKE backend and hardens several parsers. The following
are **in scope**:

- `odoh.go`, `messages.go`, `codec.go` — parsing, length checks, nil guards,
  slice aliasing, padding validation, key-ID handling.
- `examples/` — only if the issue affects the library API.

The following are **out of scope**:

- Vulnerabilities in `github.com/jedisct1/go-hpke-compact` (report upstream).
- Vulnerabilities in `github.com/miekg/dns` (report upstream).
- Issues that require a compromised build environment or leaked seed.
- Denial-of-service via resource exhaustion without a concrete, practical
  attack (we still welcome reports, but they are lower priority).

## Disclosure Policy

- We aim to acknowledge reports within 72 hours.
- We aim to provide a fix or mitigation within 14 days for confirmed issues.
- We will credit reporters in the release notes unless you prefer to remain
  anonymous.

## Notes

- The original `cloudflare/odoh-go` is archived. This fork is maintained
  independently and is **not** affiliated with Cloudflare or Apple.
- If the issue also affects the upstream project, please report it there as
  well.
