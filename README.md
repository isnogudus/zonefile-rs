# zonefile-rs

A DNS zone file generator written in Rust. Reads YAML or TOML configuration and generates zone files for Unbound or NSD DNS servers with precise error reporting.

## Features

- **Flexible Input Formats**: YAML or TOML configuration files
- **Multiple DNS Record Types**: A, AAAA, PTR, NS, MX, CNAME, SRV
- **Two Output Formats**: Unbound and NSD
- **Automatic Reverse Zones**: Generate PTR records automatically from forward zones
- **Serial Number Management**: Date-based increments with automatic persistence
- **Precise Error Messages**: Line and column numbers for all validation errors
- **RFC Compliant Validation**: DNS names and email addresses validated according to RFCs
- **Flexible I/O**: stdin, stdout, files, or directories
- **IPv4 and IPv6 Support**: Full dual-stack support

## Installation

### From Source

```bash
# Build with all features (default: YAML + TOML + Unbound + NSD)
cargo build --release

# Build with only YAML input and Unbound output (smaller binary: ~833KB)
cargo build --release --no-default-features --features yaml,unbound

# Build with only TOML input and NSD output (smaller binary: ~946KB)
cargo build --release --no-default-features --features toml,nsd
```

The binary will be available at `target/release/zonefile-rs`.

**Binary Sizes:**
- All features: ~1.1MB
- YAML + Unbound only: ~833KB
- TOML + NSD only: ~946KB

### Cargo Features

- **`yaml`** - YAML input format support (via `serde_yml`)
- **`toml`** - TOML input format support
- **`unbound`** - Unbound output format
- **`nsd`** - NSD output format
- **Default**: All features enabled

## Usage

```bash
# Read YAML from file, output to stdout (Unbound format)
zonefile-rs -i zones.yaml

# Explicitly specify input and output formats
zonefile-rs -i zones.yaml -I yaml -O unbound

# Read TOML from stdin, write to file
cat zones.toml | zonefile-rs -I toml -o output.conf

# Generate NSD zone files in a directory
zonefile-rs -i zones.yaml -O nsd -o /etc/nsd/zones

# Specify custom serial file
zonefile-rs -i zones.yaml -s .my-serial
```

### Command-line Options

```
  -i, --input <FILE>            Input file (default: stdin)
  -I, --input-format <FORMAT>   Input format: yaml or toml [default: yaml]
  -o, --output <PATH>           Output file or directory
  -O, --output-format <FORMAT>  Output format: unbound or nsd [default: unbound]
  -s, --serial <FILE>           Serial number file [default: .serial]
  -h, --help                    Print help
  -V, --version                 Print version
```

**Note**: The flags follow a consistent pattern:
- Lowercase (`-i`, `-o`) = file/path
- Uppercase (`-I`, `-O`) = format

## Configuration Format

Both YAML and TOML formats are supported. The structure is identical, but YAML allows for more flexible syntax (e.g., zones as maps or arrays).

### YAML Configuration Example

```yaml
defaults:
  email: admin@example.com
  nameserver: ns1.example.com.
  ttl: 10800

zone:
  example.com:  # Zone name from map key
    hosts:
      "@": 192.168.1.1
      www: 192.168.1.2
      mail:
        ip: [192.168.1.3, "2001:db8::3"]  # IPv4 + IPv6
        ttl: 3600

    mx:
      - name: mail.example.com.
        prio: 10

    cname:
      webmail: mail.example.com.

    srv:
      _http._tcp:
        target: www.example.com.
        port: 80
        prio: 0
        weight: 5

reverse:
  - 192.168.1.0/24
  - "2001:db8::/64"
```

### TOML Configuration Example

```toml
[defaults]
email = "admin@example.com"
nameserver = "ns1.example.com."
ttl = 10800

[[zone]]
name = "example.com"

[[zone.hosts]]
name = "@"
ip = "192.168.1.1"

[[zone.hosts]]
name = "www"
ip = "192.168.1.2"

[[zone.hosts]]
name = "mail"
ip = ["192.168.1.3", "2001:db8::3"]
ttl = 3600

[[zone.mx]]
name = "mail.example.com."
prio = 10

[[zone.cname]]
name = "webmail"
target = "mail.example.com."

[zone.srv]
"_http._tcp" = { target = "www.example.com.", port = 80, prio = 0, weight = 5 }

[reverse]
networks = ["192.168.1.0/24", "2001:db8::/64"]
```

### Flexible Syntax

**YAML** supports both map and array formats:

```yaml
# Map format (name from key, no 'name' field needed)
zone:
  example.com:
    hosts: { ... }

# Array format (requires 'name' field)
zone:
  - name: example.com
    hosts: { ... }
```

**Host entries** can be simplified:

```yaml
hosts:
  www: 192.168.1.2              # Just an IP
  mail: [192.168.1.3, "::1"]    # Multiple IPs
  server:                        # Full object with options
    ip: 192.168.1.4
    alias: ["ftp", "ssh"]
    ttl: 7200
    with-ptr: false
```

### Supported Record Types

- **A/AAAA records**: IPv4/IPv6 address mapping
- **PTR records**: Reverse DNS lookup (auto-generated from hosts with `with-ptr: true`)
- **NS records**: Nameserver records
- **MX records**: Mail exchanger records with priority
- **CNAME records**: Canonical name aliases
- **SRV records**: Service location records (requires `_service._protocol` format)

### Global Defaults

Set defaults for all zones in the `defaults` section:

```yaml
defaults:
  email: admin@example.com       # Required: contact email
  nameserver: ns1.example.com.   # Default nameserver (can be overridden per zone)
  ttl: 10800                     # Default TTL (1-2147483647)
  refresh: 7200                  # SOA refresh interval
  retry: 3600                    # SOA retry interval
  expire: 1209600                # SOA expire time
  nrc-ttl: 3600                  # Negative response caching TTL
  mx-prio: 0                     # Default MX priority
  srv-prio: 5                    # Default SRV priority
  srv-weight: 10                 # Default SRV weight
  with-ptr: true                 # Auto-generate PTR records
```

Each zone can override these defaults by specifying the same fields.

## Validation and Error Messages

The tool provides **precise error messages** with line and column numbers:

```
Error: YAML parse error:
  Path:  'defaults.ttl'
  Location: at line 4 column 8
  Error: TTL cannot be zero
```

**Validation includes:**

- **TTL values**: Must be 1-2147483647 (RFC compliant)
- **Email addresses**: Validated as `user@domain.com` (RFC 5322)
  - Local part: max 64 chars, no leading/trailing dots
  - Domain: must have dots, valid labels, no all-numeric TLD
- **DNS names**: RFC compliant (max 253 chars, valid labels)
- **SRV records**: Service and protocol must start with `_`
- **IP addresses**: Valid IPv4 or IPv6 addresses
- **Networks**: Valid CIDR notation for reverse zones

## Output Formats

### Unbound

Generates a single configuration file suitable for inclusion in Unbound:

```
server:
local-zone:  example.com. static
local-data: "example.com.                            10800 IN SOA  ns1.example.com. admin.example.com. 2025102701 7200 3600 1209600 3600"
local-data: "example.com.                                  IN NS   ns1.example.com."
local-data: "example.com.                                  IN MX   10 mail.example.com."
local-data: "example.com.                                  IN A    192.168.1.1"
local-data: "www.example.com.                              IN A    192.168.1.2"
local-data: "mail.example.com.                             IN A    192.168.1.3"
local-data: "mail.example.com.                             IN AAAA 2001:db8::3"
```

### NSD

Creates separate zone files in the specified directory:

```
/etc/nsd/zones/
├── zones.conf              # Zone declarations
└── master/
    ├── example.com.zone
    └── 1.168.192.in-addr.arpa.zone
```

Each zone file contains standard BIND format:

```
$ORIGIN example.com.
$TTL 10800

@                            IN SOA     ns1.example.com. admin.example.com. (
                                       2025102701   ; serial number
                                       7200         ; refresh
                                       3600         ; retry
                                       1209600      ; expire
                                       3600         ; min ttl
                             )
                                IN NS      ns1.example.com.
                                IN MX   10 mail.example.com.
@                               IN A       192.168.1.1
www                             IN A       192.168.1.2
mail                            IN A       192.168.1.3
mail                            IN AAAA    2001:db8::3
```

## Serial Number Management

Serial numbers follow the **YYYYMMDD##** format:

1. Previous serial is read from the serial file (default: `.serial`)
2. New serial is calculated based on current date
3. If multiple runs occur on the same day, sequence number is incremented
4. Serial file is **only updated after successful zone generation** (transactional)

Example progression:
- First run on 2025-10-27: `2025102700`
- Second run same day: `2025102701`
- Next day: `2025102800`

## Testing

```bash
# Run all tests (64 tests: 58 unit + 6 integration)
cargo test

# Run specific test module
cargo test parser::tests
cargo test validation::tests

# Run with Clippy linting
cargo clippy --all-targets
```

The test suite includes:
- **Unit tests** for all validation functions
- **Deserializer tests** for TTL and Email types
- **Integration tests** for complete zone file generation
- **Edge case tests** for error handling

## Project Structure

```
src/
├── main.rs          # CLI entry point with clap argument parsing
├── parser.rs        # YAML/TOML parsing with custom deserializers
├── transform.rs     # Configuration to DNS record transformation
├── validation.rs    # DNS name and email validation (RFC compliant)
├── record.rs        # DNS record type definitions
├── constants.rs     # Default values (TTL, refresh, retry, etc.)
├── serial.rs        # Serial number management
└── output/
    ├── mod.rs       # Output module declarations
    ├── unbound.rs   # Unbound format generator
    └── nsd.rs       # NSD format generator

tests/
└── integration_test.rs  # End-to-end zone generation tests
```

## Dependencies

- `serde` + `serde_yml` + `toml` - Configuration parsing (optional)
- `serde_path_to_error` - Enhanced error reporting with paths
- `clap` - Command-line argument parsing
- `anyhow` + `thiserror` - Error handling
- `chrono` - Date/time for serial numbers
- `ipnetwork` - IP network CIDR handling
- `hex` - Utilities

All format dependencies (`serde_yml`, `toml`) are optional and can be disabled via Cargo features.

## Technical Highlights

### Custom Serde Deserializers

The project uses **Visitor Pattern** for custom deserialization to provide precise error messages:

- **TTL**: Validates range (1-2147483647) during deserialization
- **Email**: Validates RFC 5322 format during deserialization
- **SRV records**: Validates service/protocol naming (`_service._protocol`)
- **IP addresses**: Custom error messages for invalid addresses
- **Flexible types**: `SingleOrVec<T>` accepts both single values and arrays

This approach ensures that validation errors include **exact line and column numbers** from the input file.

### Error Message Quality

**Before** (generic Serde errors):
```
Error: data did not match any variant of untagged enum Zones
```

**After** (precise custom errors):
```
Error: YAML parse error at 'zone.example.com.srv._http._tcp' (at line 74 column 7)
SRV entry #3 'mqtt.tcp': service name 'mqtt' must start with '_'
```

## License

See LICENSE file for details.

## Version History

- **v0.2.1** (2025-10-30): Version Flag
  - Added `--version` / `-V` flag to display version information

- **v0.2.0** (2025-10-28): Optional Features Release
  - **Breaking**: Changed CLI from `--yaml`/`--toml` flags to `-I`/`--input-format` and `-O`/`--output-format`
  - Added Cargo features for optional format support (yaml, toml, unbound, nsd)
  - Reduced binary size: ~833KB for minimal builds (was 1.1MB)
  - Conditional compilation for unused formats
  - Updated to `serde_yml` (from deprecated `serde_yaml`)
  - Improved CLI consistency with uppercase/lowercase flag pattern

- **v0.1.0** (2025-10-27): Initial release
  - YAML and TOML support
  - Unbound and NSD output formats
  - Comprehensive validation with precise error messages
  - IPv4/IPv6 dual-stack support
  - Custom Serde deserializers for better UX

## Author

Written as a Rust learning project, porting and enhancing functionality from the original Python zonefile generator.
