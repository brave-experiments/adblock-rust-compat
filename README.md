# adblock-rust-compat

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
cargo install --locked --path .
# installs `adblock-rust-compat` to ~/.cargo/bin (on your PATH)
```

Or just build it (binary at `target/release/adblock-rust-compat`):

```sh
cargo build --release --locked
```

## Usage

At least one source is required (`--list`, `--url`, or `--file`); multiple are combined
and de-duplicated. `--domains` is optional; omit it to check every rule.

```sh
# uBO's list, only YouTube-related rules:
adblock-rust-compat --list ubo --domains "youtube.com,youtu.be,googlevideo.com"

# uBO + EasyList combined, every rule:
adblock-rust-compat --list ubo,easylist

# Mix presets, raw URLs, and local files:
adblock-rust-compat --list ubo --url https://example.com/custom.txt --file ./local.txt
```

See `examples/`.

| Flag | Description |
|---|---|
| `--list NAMES\|URLS` | Sources: `ubo`, `easylist`, `easyprivacy`, or http(s) URLs; comma-separated and/or repeated |
| `--url URL` | Raw URL (repeatable) |
| `--file PATH` | Local file (repeatable) |
| `--domains LIST` | Comma-separated domains to match; omit to check every rule |
| `--option NAME` | Keep only rules using this option/type (see below) |
| `--rule '<rule>'` | Explain a single rule (type, support, options) and exit |
| `--probe` | With `--rule`, label each network option ok/unsupported; with a `--json` scan, add `unsupported_options` to each unsupported rule |
| `--markdown` | Emit a markdown report to stdout |
| `--json` | Emit the full report as JSON to stdout |
| `--show-supported` | Also list supported rules (text output only) |
| `-h`, `--help` | Show help |

The `--list`/`--url`/`--file` sources are combined; at least one is required.

### Exploring by option

Every rule has option/type tokens: a network rule's `$` modifiers (`script`,
`third-party`, `domain`, `replace`, `redirect`, ...) or a cosmetic rule's type
(`elemhide`, `scriptlet`, `style`, `remove`, `procedural`, `js`, `exception`). The
`style`/`remove` actions cover both the uBO `:style()`/`:remove()` forms and the ABP
`{css}`/`{remove: true;}` forms ([brave/adblock-rust#415][415]). Discover a rule's
options, then find every rule that uses one across the lists:

```sh
# What options does this rule use? (--probe labels each as ok/unsupported)
adblock-rust-compat --rule '||www.youtube.com/watch?$xhr,1p,replace=/"adPlacements"/"x"/' --probe
#   Type: network / Supported: no (UnrecognisedOption)
#   Options: xhr (ok), 1p (ok), replace (unsupported)

# Every rule using $replace across uBO + EasyList + EasyPrivacy, with compat + source:
adblock-rust-compat --list ubo,easylist,easyprivacy --option replace
```

`--option` composes with `--domains` (a rule must satisfy both). Option matching is on
the name as written (e.g. `third-party`, not its `3p` alias). `--probe` exists because
adblock-rust's `UnrecognisedOption` error doesn't say *which* option failed, so each
network option is re-parsed in isolation to attribute the failure.

[415]: https://github.com/brave/adblock-rust/issues/415

Progress goes to stderr and the report to stdout, so
`... --markdown > report.md` produces a clean file.

When listing domains, include the registrable domain (e.g. `example.com`, which covers
all subdomains for request targets) plus any specific subdomains used in cosmetic or
`$domain=` scopes (those are matched by hash, so they must be listed exactly).

## Output

The default is a text summary plus the unsupported rules. `--markdown` adds a provenance
header (source, domain set, adblock-rust version, tool version) and Unsupported/Supported
tables; its output is deterministic, so a committed report only changes when the rules or
their support actually change. `--json` emits a single object with the same provenance
(`adblock_version`, `tool`, `tool_version`, `source`, `domains`, `option`) plus a `rules`
array, each entry carrying its rule text, `sources`, relations, support status, and reason.

Adding `--probe` to a `--json` scan attaches an `unsupported_options` array to each
**unsupported** rule: for a network rule, the option(s) that fail in isolation (e.g.
`["replace"]`); for a cosmetic rule, its type(s) (e.g. `["procedural"]`). Supported rules
omit it, and without `--probe` it's absent entirely (so the default scan is unchanged).
Only unsupported rules are probed, and per-option results are memoized, so the cost is small.

When more than one source is combined, each rule records which list(s) it came from: a
`sources` array in `--json` (always present), and a `Source` column (markdown) / `<src>`
prefix (text) shown only in multi-source runs. A rule found in several lists lists them all.

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

## License

[MPL-2.0](LICENSE). The vendored `data/brave-resources.json` is from
[brave/adblock-rust](https://github.com/brave/adblock-rust), also MPL-2.0.
