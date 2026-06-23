# adblock-rust-compat-checker-cli

A CLI that finds the rules in a filter list that relate to a given set of domains, and
reports which ones [adblock-rust](https://github.com/brave/adblock-rust) supports.

## What "supported" means

A rule is reported as **supported** only if adblock-rust both:

1. **parses** it (the syntax and options are recognised), and
2. when the rule injects a **scriptlet** (`##+js(...)`) or uses a **redirect**
   (`$redirect=`), the referenced resource actually resolves in
   adblock-rust's resource set.

Otherwise it is **unsupported**, with a single reason: a parse error (e.g.
`UnrecognisedOption` for `$replace=`/`$denyallow=`) or a resource one
(`resource missing` / `resource requires permission`).

This matters because a rule can parse cleanly and still do nothing, e.g. a
`##+js(some-scriptlet)` whose scriptlet adblock-rust doesn't ship. Resource resolution
uses adblock-rust's own `ResourceStorage` loaded from Brave's vendored
`brave-resources.json`, so `.js` suffixing, aliases, dependencies, and permissions match
the engine.

## What counts as a "match"

A rule relates to the domain set in one of two ways (a rule can be both):

- **target** - the rule blocks a request *to* one of the domains
  (e.g. `||www.youtube.com/...`, `||r3.googlevideo.com^`).
- **scope** - the rule runs *while browsing* one of the domains
  (e.g. `youtube.com##.ad`, `||ads.example.com^$domain=youtube.com`).

Matching inspects each rule's parsed structure when possible, and falls back to a
role-aware text scan for rules adblock-rust rejects. Incidental mentions don't count: a
domain that appears only in a `denyallow=` allowlist or a negated `domain=~...` is
ignored.

## Install

```sh
cargo build --release --locked
# binary at target/release/adblock-rust-compat-checker
```

## Usage

Both a domain set (`--domains`) and a filter list (`--url` or `--file`) are required.

```sh
adblock-rust-compat-checker \
  --url https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt \
  --domains "youtube.com,youtu.be,googlevideo.com"
```

See `examples/`.

| Flag | Description |
|---|---|
| `--domains LIST` | Comma-separated domains to match (required) |
| `--url URL` | Fetch the filter list from a URL |
| `--file PATH` | Read the filter list from a local file (alternative to `--url`) |
| `--markdown` | Emit a markdown report to stdout |
| `--json` | Emit the full report as JSON to stdout |
| `--show-supported` | Also list supported rules (text output only) |
| `-h`, `--help` | Show help |

Progress goes to stderr and the report to stdout, so
`... --markdown > report.md` produces a clean file.

When listing domains, include the registrable domain (e.g. `example.com`, which covers
all subdomains for request targets) plus any specific subdomains used in cosmetic or
`$domain=` scopes (those are matched by hash, so they must be listed exactly).

## Output

The default is a text summary plus the unsupported rules. `--markdown` adds a provenance
header (source, domain set, adblock-rust version, tool version) and Unsupported/Supported
tables; its output is deterministic, so a committed report only changes when the rules or
their support actually change. `--json` emits one object per matched rule with its
relations, support status, and reason.

## Development

```sh
cargo test          # unit tests for matching, support, and resource resolution
cargo run -- --help
```

Source layout:

- `src/main.rs` - CLI, pipeline, and text/markdown/JSON reporting
- `src/domains.rs` - `DomainMatcher`: target/scope matching against a domain set
- `src/resources.rs` - scriptlet/redirect resource resolution
- `data/brave-resources.json` - vendored Brave resource set (embedded at build time)

The pinned adblock-rust version is set in `Cargo.toml`; `ADBLOCK_RUST_VERSION` in
`src/main.rs` mirrors it for the markdown provenance header. The vendored
`brave-resources.json` is a manual snapshot from
`brave/adblock-rust:data/brave/brave-resources.json`.
