# zonefile-rs

A DNS zone file generator written in Rust. Reads TOML configuration and generates zone files for Unbound or NSD DNS servers.

## Features

- Generate DNS zone files from TOML configuration
- Support for multiple DNS record types (A, PTR, NS, MX, CNAME, SRV)
- Two output formats: Unbound and NSD
- Automatic reverse zone generation
- Serial number management with date-based increments
- Flexible input/output: stdin, stdout, files, or directories
- DNS name and email validation (RFC compliant)

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/zonefile-rs`.

## Usage

```bash
# Read from file, output to stdout (Unbound format)
zonefile-rs -i zones.toml

# Read from stdin, write to file
cat zones.toml | zonefile-rs -o output.conf

# Generate NSD zone files in a directory
zonefile-rs -i zones.toml -o /etc/nsd/zones -f nsd

# Specify custom serial file
zonefile-rs -i zones.toml -s .my-serial
```

### Command-line Options

- `-i, --input <FILE>`: Input TOML file (default: stdin)
- `-o, --output <PATH>`: Output file or directory (default: stdout)
- `-s, --serial <FILE>`: Serial number file (default: `.serial`)
- `-f, --format <FORMAT>`: Output format: `unbound` or `nsd` (default: `unbound`)

## TOML Configuration Format

### Forward Zone Example

```toml
[zone."example.com"]
ns = "ns1.example.com."
email = "admin.example.com."

[zone."example.com".hosts]
"@" = "192.168.1.1"
www = "192.168.1.2"
mail = "192.168.1.3"

[[zone."example.com".mx]]
host = "mail.example.com."
priority = 10

[[zone."example.com".cname]]
alias = "webmail.example.com."
host = "mail.example.com."

[[zone."example.com".srv]]
service = "_imap._tcp"
host = "mail.example.com."
priority = 0
weight = 1
port = 143
```

### Reverse Zone Example

```toml
[reverse."192.168.1.0/24"]
ns = "ns1.example.com."
email = "admin.example.com."
```

Reverse zones automatically include PTR records from forward zone hosts.

### Supported Record Types

- **A records**: IPv4 address mapping
- **PTR records**: Reverse DNS lookup (auto-generated)
- **NS records**: Nameserver records
- **MX records**: Mail exchanger records
- **CNAME records**: Canonical name aliases
- **SRV records**: Service location records

### Optional Fields

All zones support these optional fields:

- `ttl`: Time to live (default: 3600)
- `refresh`: SOA refresh interval (default: 10800)
- `retry`: SOA retry interval (default: 3600)
- `expire`: SOA expire time (default: 604800)
- `nrc_ttl`: Negative response caching TTL (default: 86400)

## Output Formats

### Unbound

Generates a single configuration file suitable for inclusion in Unbound's configuration:

```
local-zone:  example.com. static
local-data: "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2025102501 10800 3600 604800 86400"
local-data: "example.com. IN A 192.168.1.1"
local-data: "www.example.com. IN A 192.168.1.2"
```

### NSD

Creates separate zone files in the specified directory:

```
example.com.zone
1.168.192.in-addr.arpa.zone
```

Each file contains standard zone file format:

```
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. (
    2025102501  ; serial
    10800       ; refresh
    3600        ; retry
    604800      ; expire
    86400       ; negative cache ttl
)
```

## Serial Number Management

Serial numbers are automatically managed:

1. Previous serial is read from the serial file (default: `.serial`)
2. New serial is calculated as `YYYYMMDD##` (year, month, day, sequence)
3. If multiple generations occur on the same day, sequence is incremented
4. Serial file is updated only after successful zone generation

## DNS Name Validation

The tool validates DNS names according to RFC standards:

- Maximum length: 253 characters
- Labels separated by dots
- Each label: 1-63 characters
- Labels start with alphanumeric, end with alphanumeric
- Labels may contain hyphens (not at start/end)
- Wildcards (`*`) allowed only as first character of first label
- All hostnames must be fully qualified (end with `.`)

## Project Structure

```
src/
├── main.rs          # CLI entry point
├── parser.rs        # TOML parsing and deserialization
├── transform.rs     # TOML to DNS record transformation
├── validation.rs    # DNS name and email validation
├── record.rs        # DNS record type definitions
├── constants.rs     # Default values and constants
├── serial.rs        # Serial number management
└── output/
    ├── mod.rs       # Output module declarations
    ├── unbound.rs   # Unbound format generator
    └── nsd.rs       # NSD format generator
```

## Dependencies

- `toml` - TOML parsing
- `serde` - Serialization framework
- `clap` - Command-line argument parsing
- `anyhow` - Error handling
- `thiserror` - Custom error types
- `chrono` - Date/time handling for serial numbers
- `ipnetwork` - IP network handling

## License

See LICENSE file for details.

## Author

Written as a Rust learning project, porting functionality from the original Python zonefile generator.
