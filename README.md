# SSL Certificate Checker

[![GoDoc](https://godoc.org/github.com/guessi/ssl-certs-checker?status.svg)](https://godoc.org/github.com/guessi/ssl-certs-checker)
[![Go Report Card](https://goreportcard.com/badge/github.com/guessi/ssl-certs-checker)](https://goreportcard.com/report/github.com/guessi/ssl-certs-checker)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/guessi/ssl-certs-checker)](https://github.com/guessi/ssl-certs-checker/blob/master/go.mod)
[![Docker Stars](https://img.shields.io/docker/stars/guessi/ssl-certs-checker.svg)](https://hub.docker.com/r/guessi/ssl-certs-checker/)
[![Docker Pulls](https://img.shields.io/docker/pulls/guessi/ssl-certs-checker.svg)](https://hub.docker.com/r/guessi/ssl-certs-checker/)

Concurrent CLI tool to inspect TLS/SSL certificates for one or many hosts.

It connects to each target, performs a TLS handshake, extracts the leaf certificate, and prints certificate metadata in `table`, `json`, or `yaml` format.

## Features

- Concurrent certificate checks (up to 10 hosts in parallel)
- Multiple input modes: CLI string, plain text file, or YAML config
- Host syntax support:
  - `hostname`
  - `hostname:port`
  - `IPv4`
  - `IPv6` with and without brackets
- Configurable timeout per connection
- Optional insecure mode to skip certificate verification
- Multiple output formats (`table`, `json`, `yaml`)
- Graceful shutdown on `SIGINT`/`SIGTERM`

## Requirements

- Go `1.24+` (see `go.mod`)
- Network access to target hosts/ports
- Docker (optional, if using container image)

## Quick Start

### With Docker

```bash
docker run --rm -it guessi/ssl-certs-checker --domains "github.com"
```

### With Go (without installing)

```bash
go run . --domains "github.com"
```

### Build local binary

```bash
go build -o ssl-certs-checker .
./ssl-certs-checker --domains "github.com"
```

### Install via `go install`

```bash
go install github.com/guessi/ssl-certs-checker@latest
ssl-certs-checker --domains "github.com"
```

## CLI Reference

```bash
ssl-certs-checker --help
```

```text
NAME:
   ssl-certs-checker - check SSL certificates at once

USAGE:
   ssl-certs-checker [global options]

GLOBAL OPTIONS:
   --config string, -C string        config file
   --domains string, -d string       comma-separated list of domains to check (e.g., example.com,google.com:443)
   --domains-file string, -f string  file containing newline-separated domains to check
   --timeout int, -t int             dialer timeout in second(s) (default: 5)
   --insecure, -k                    skip the verification of certificates (default: false)
   --output string, -o string        output format (table, json, yaml) (default: "table")
   --help, -h                        show help
```

## Input Modes

Exactly one input source must be provided:

- `--domains`
- `--domains-file`
- `--config`

Using more than one input source at the same time is treated as an error.

### 1) `--domains` (comma-separated)

```bash
ssl-certs-checker --domains "github.com,google.com:443,1.1.1.1,[2606:4700:4700::1111]:443"
```

Behavior:
- Empty entries are ignored (for example: `a.com,,b.com`)
- Values are trimmed
- Host/port syntax is validated before execution

### 2) `--domains-file` (newline-separated)

Example file:

```text
github.com
google.com:443
[2606:4700:4700::1111]:443
```

Run:

```bash
ssl-certs-checker --domains-file ./hosts.txt
```

Docker run with file mount:

```bash
docker run --rm -it \
  -v "$PWD:/work" \
  -w /work \
  guessi/ssl-certs-checker \
  --domains-file ./hosts.txt
```

### 3) `--config` (YAML)

Config file format:

```yaml
hosts:
  - github.com
  - google.com:443
  - [2606:4700:4700::1111]:443
```

Run:

```bash
ssl-certs-checker --config ./hosts.yaml
```

Docker run with config mount:

```bash
docker run --rm -it \
  -v "$PWD:/work" \
  -w /work \
  guessi/ssl-certs-checker \
  --config ./hosts.yaml
```

## Host Format Rules

Accepted examples:

- `example.com`
- `example.com:8443`
- `192.168.1.10`
- `2001:db8::1`
- `[2001:db8::1]`
- `[2001:db8::1]:8443`

Port behavior:

- Default port is `443` when omitted
- Port must be numeric and in range `1-65535`

## Runtime Behavior

### Concurrency

- The checker processes hosts concurrently
- Maximum parallel checks: `10` hosts at a time

### Timeout

- `--timeout` is in seconds
- Default timeout: `5`
- Timeout applies to connection and handshake workflow

### Certificate verification

- By default, certificate verification is enabled
- `--insecure` disables TLS certificate verification (`InsecureSkipVerify`)
- Use `--insecure` only for debugging/internal environments

### Signal handling

- `SIGINT` and `SIGTERM` cancel ongoing checks gracefully via context cancellation

## Output

Use `--output` with:

- `table` (default)
- `json`
- `yaml`

### Table output

- Prints certificate rows to `stdout`
- Columns:
  - `Host`
  - `Common Name`
  - `DNS Names`
  - `Not Before`
  - `Not After`
  - `PublicKeyAlgorithm`
  - `Issuer`
- If individual host checks fail, error messages are printed to `stderr`

Example:

```bash
ssl-certs-checker --domains "github.com" --output table
```

```text
+----------------+-------------+----------------+-------------------------------+-------------------------------+--------------------+------------------------------------------------+
| Host           | Common Name | DNS Names      | Not Before                    | Not After                     | PublicKeyAlgorithm | Issuer                                         |
+----------------+-------------+----------------+-------------------------------+-------------------------------+--------------------+------------------------------------------------+
| github.com:443 | github.com  | github.com     | 2025-02-05 00:00:00 +0000 UTC | 2026-02-05 23:59:59 +0000 UTC | ECDSA              | Sectigo ECC Domain Validation Secure Server CA |
|                |             | www.github.com |                               |                               |                    |                                                |
+----------------+-------------+----------------+-------------------------------+-------------------------------+--------------------+------------------------------------------------+
```

### JSON output

```bash
ssl-certs-checker --domains "github.com,invalid-host:443" --output json
```

Schema:

```json
{
  "certificates": [
    {
      "host": "string",
      "common_name": "string",
      "dns_names": ["string"],
      "not_before": "RFC3339 timestamp",
      "not_after": "RFC3339 timestamp",
      "public_key_algorithm": "string",
      "issuer": "string"
    }
  ],
  "errors": [
    {
      "host": "string",
      "error": "string"
    }
  ]
}
```

Notes:
- `errors` is omitted when empty
- Failed hosts do not stop successful hosts from being reported

### YAML output

```bash
ssl-certs-checker --domains "github.com,invalid-host:443" --output yaml
```

Example structure:

```yaml
certificates:
  - host: github.com:443
    common_name: github.com
    dns_names:
      - github.com
      - www.github.com
    not_before: 2025-02-05T00:00:00Z
    not_after: 2026-02-05T23:59:59Z
    public_key_algorithm: ECDSA
    issuer: Sectigo ECC Domain Validation Secure Server CA
errors:
  - host: invalid-host:443
    error: failed to connect to invalid-host:443: ...
```

## Exit Behavior

- Exit code `0`:
  - command ran successfully, even if some hosts failed and appear in `errors`
- Exit code `1`:
  - invalid configuration/arguments
  - failed input parsing/loading
  - unsupported output format
  - context cancellation or unrecoverable runtime failure

## Examples

### Check a single host

```bash
ssl-certs-checker --domains "github.com"
```

### Check custom ports

```bash
ssl-certs-checker --domains "example.com:443,example.com:8443"
```

### Check from domains file with JSON output

```bash
ssl-certs-checker --domains-file ./hosts.txt --output json
```

### Check from YAML config with longer timeout

```bash
ssl-certs-checker --config ./hosts.yaml --timeout 15 --output table
```

### Skip certificate verification (debug only)

```bash
ssl-certs-checker --domains "self-signed.internal:443" --insecure
```

## Troubleshooting

### `one of --config, --domains, or --domains-file must be specified`

You did not provide an input source. Add exactly one of these flags.

### `--config, --domains, and --domains-file are mutually exclusive`

More than one input source was provided. Keep only one.

### `invalid port number` or `port number out of range`

Check host format and ensure port is numeric and between `1` and `65535`.

### `failed to connect` / timeout errors

- Verify DNS resolution and network path
- Verify target port is open
- Increase timeout with `--timeout`

### TLS handshake / certificate validation errors

- Certificate may be expired, mismatched, or untrusted
- For debugging only, retry with `--insecure` to bypass verification

## Development

### Run tests

Unit-focused (skips integration tests):

```bash
go test ./... -short
```

Full test suite (includes network-dependent integration tests):

```bash
go test ./...
```

### Project structure

```text
.
├── main.go                  # CLI entrypoint and signal handling
├── pkg/app                  # App orchestration
├── pkg/config               # Input parsing/validation and config loading
├── pkg/cert                 # TLS connection and certificate extraction
├── pkg/output               # Table/JSON/YAML formatting
├── hosts.yaml               # Example config
└── Dockerfile               # Multi-stage container build
```

## Docker Image

The provided `Dockerfile` builds a static binary and packages it into a minimal `scratch` image with CA certificates.

Local build:

```bash
docker build -t ssl-certs-checker:local .
docker run --rm -it ssl-certs-checker:local --domains "github.com"
```

## License

[MIT LICENSE](LICENSE)
