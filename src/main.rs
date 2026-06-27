//! Find filter-list rules that have to do with a set of domains and report which ones
//! adblock-rust supports.
//!
//! A rule is "supported" only if adblock-rust both parses it and, when it depends on
//! a scriptlet or redirect resource, can resolve that resource. Otherwise it is
//! "unsupported" with a single reason (a parse error, or a missing/restricted resource).
//!
//! Run `adblock-rust-compat --help` for usage. A filter list (`--url`/`--file`)
//! is required; `--domains` is optional (omit to check every rule in the list).

mod domains;
mod options;
mod resources;

use std::collections::{HashMap, HashSet};
use std::io::Read;

use adblock::filters::network::NetworkFilterError;
use adblock::lists::{
    parse_filter, FilterFormat, FilterParseError, ParseOptions, ParsedFilter, RuleTypes,
};
use adblock::resources::PermissionMask;

use domains::{DomainMatcher, Relation};
use options::rule_options;
use resources::{ResourceChecker, ResourceStatus};

/// adblock-rust version this tool is built against (keep in sync with Cargo.toml).
const ADBLOCK_RUST_VERSION: &str = "0.12.x";

const UBO_URL: &str =
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt";
const EASYLIST_URL: &str = "https://easylist.to/easylist/easylist.txt";
const EASYPRIVACY_URL: &str = "https://easylist.to/easylist/easyprivacy.txt";

/// Resolve a `--list` value (a preset name or an http(s) URL) to a URL.
fn resolve_list(value: &str) -> Result<String, String> {
    match value {
        "ubo" => Ok(UBO_URL.to_string()),
        "easylist" => Ok(EASYLIST_URL.to_string()),
        "easyprivacy" => Ok(EASYPRIVACY_URL.to_string()),
        v if v.starts_with("http://") || v.starts_with("https://") => Ok(v.to_string()),
        other => Err(format!(
            "unknown list '{other}': use ubo, easylist, easyprivacy, or an http(s) URL"
        )),
    }
}

/// Expand `--list` values (comma-separated and/or repeated) into individual tokens,
/// trimmed, with empties dropped.
fn list_tokens(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(serde::Serialize)]
struct RuleReport {
    rule: String,
    /// Which source list(s) the rule came from (a rule can appear in more than one).
    sources: Vec<String>,
    relations: Vec<Relation>,
    supported: bool,
    filter_type: Option<&'static str>,
    reason: Option<String>,
    /// With `--probe`, what's unsupported about an unsupported rule: for a network rule,
    /// the option(s) that fail in isolation; for a cosmetic rule, its type(s). Empty
    /// (and omitted) without `--probe` or for supported rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unsupported_options: Vec<String>,
}

/// Top-level `--json` output: provenance (so downstream consumers don't have to restate
/// the adblock-rust version) plus the per-rule reports. Field order is stable for
/// deterministic, diff-friendly output.
#[derive(serde::Serialize)]
struct Report<'a> {
    adblock_version: &'static str,
    tool: &'static str,
    tool_version: &'static str,
    source: String,
    domains: Option<Vec<String>>,
    /// The `--option` filter, if any (only rules with this option are included).
    option: Option<String>,
    rules: &'a [RuleReport],
}

fn parse_options() -> ParseOptions {
    ParseOptions {
        rule_types: RuleTypes::All,
        format: FilterFormat::Standard,
        permissions: PermissionMask::from_bits(0),
    }
}

fn parse(rule: &str) -> (Option<ParsedFilter>, Option<&'static str>, Option<String>) {
    match parse_filter(rule, true, parse_options()) {
        Ok(p @ ParsedFilter::Network(_)) => (Some(p), Some("network"), None),
        Ok(p @ ParsedFilter::Cosmetic(_)) => (Some(p), Some("cosmetic"), None),
        Err(FilterParseError::Network(e)) => (None, Some("network"), Some(format!("{e:?}"))),
        Err(FilterParseError::Cosmetic(e)) => (None, Some("cosmetic"), Some(format!("{e:?}"))),
        Err(FilterParseError::Unsupported) => (None, None, Some("unsupported".into())),
        Err(FilterParseError::Empty) => (None, None, Some("empty".into())),
    }
}

fn support(
    rule: &str,
    parsed: &Option<ParsedFilter>,
    parse_error: Option<String>,
    resources: &ResourceChecker,
) -> (bool, Option<String>) {
    let Some(parsed) = parsed else {
        return (false, parse_error);
    };
    match resources.check_rule(parsed, rule) {
        ResourceStatus::NotApplicable | ResourceStatus::Ok => (true, None),
        ResourceStatus::Missing => (false, Some("resource missing".into())),
        ResourceStatus::RequiresPermission => (false, Some("resource requires permission".into())),
    }
}

fn is_filter_line(line: &str) -> bool {
    !line.is_empty() && !line.starts_with('!') && !line.starts_with('[')
}

/// A filter-list source: `name` is the short label shown per-rule (e.g. `ubo`), `label`
/// is the resolved URL/path shown in the report provenance, and `text` is its contents.
struct Source {
    name: String,
    label: String,
    text: String,
}

/// Merge all sources into per-rule reports. Identical rule lines are de-duplicated across
/// sources; a rule's `sources` accumulates every list it appeared in (in source order).
/// With a `matcher`, only rules related to the domain set are kept; without, all are kept.
fn collect_reports(
    sources: &[Source],
    matcher: Option<&DomainMatcher>,
    option_filter: Option<&str>,
    probe: bool,
    resources: &ResourceChecker,
) -> Vec<RuleReport> {
    let mut reports: Vec<RuleReport> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut seen_nonmatch: HashSet<String> = HashSet::new();
    // Memoize per-option probe results so a shared option (e.g. `popup`) is tested once.
    let mut option_cache: HashMap<String, bool> = HashMap::new();

    for src in sources {
        for line in src.text.lines() {
            let rule = line.trim();
            if !is_filter_line(rule) {
                continue;
            }
            // Already kept: just record this additional source.
            if let Some(&i) = index.get(rule) {
                if !reports[i].sources.contains(&src.name) {
                    reports[i].sources.push(src.name.clone());
                }
                continue;
            }
            // Already seen and rejected: skip re-checking.
            if seen_nonmatch.contains(rule) {
                continue;
            }
            // Option filter is rule-intrinsic (textual), so check it before parsing.
            if let Some(opt) = option_filter {
                if !rule_options(rule).iter().any(|o| o == opt) {
                    seen_nonmatch.insert(rule.to_string());
                    continue;
                }
            }

            let (parsed, filter_type, parse_error) = parse(rule);
            let relations = match matcher {
                Some(m) => {
                    let rels = match &parsed {
                        Some(p) => m.relations_parsed(p),
                        None => m.relations_raw(rule),
                    };
                    if rels.is_empty() {
                        seen_nonmatch.insert(rule.to_string());
                        continue;
                    }
                    rels
                }
                None => Vec::new(),
            };

            let (supported, reason) = support(rule, &parsed, parse_error, resources);

            // With --probe, attribute what's unsupported: network -> the option(s) that
            // fail in isolation; cosmetic -> its type(s). Empty for supported rules.
            let unsupported_options = if probe && !supported {
                if filter_type == Some("network") {
                    rule_options(rule)
                        .into_iter()
                        .filter(|o| {
                            !*option_cache
                                .entry(o.clone())
                                .or_insert_with(|| option_supported(o))
                        })
                        .collect()
                } else {
                    rule_options(rule)
                }
            } else {
                Vec::new()
            };

            index.insert(rule.to_string(), reports.len());
            reports.push(RuleReport {
                rule: rule.to_string(),
                sources: vec![src.name.clone()],
                relations,
                supported,
                filter_type,
                reason,
                unsupported_options,
            });
        }
    }
    reports
}

fn fetch_list(url: &str) -> Result<String, String> {
    // Cap the response so a hostile or runaway URL can't exhaust memory, and time out
    // so it can't hang the run.
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let resp = ureq::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .get(url)
        .call()
        .map_err(|e| format!("fetch failed: {e}"))?;
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BYTES)
        .read_to_string(&mut body)
        .map_err(|e| format!("read failed: {e}"))?;
    Ok(body)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }
    let output_json = args.iter().any(|a| a == "--json");
    let output_markdown = args.iter().any(|a| a == "--markdown");
    let show_supported = args.iter().any(|a| a == "--show-supported");
    let probe = args.iter().any(|a| a == "--probe");
    let value_of = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };
    // All values passed to a repeatable flag (the arg following each occurrence).
    let values_of = |flag: &str| -> Vec<String> {
        args.iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == flag)
            .filter_map(|(i, _)| args.get(i + 1).cloned())
            .collect()
    };

    // `--rule '<rule>'`: explain a single rule (type, support, options) and exit.
    // `--probe` additionally tests each network option in isolation.
    if let Some(rule) = value_of("--rule") {
        explain_rule(&rule, probe, &ResourceChecker::from_embedded());
        return;
    }

    // `--option <name>`: keep only rules that use this option/type.
    let option_filter = value_of("--option").map(|s| s.trim().to_ascii_lowercase());

    // Sources can be combined: any mix of --file, --list (preset/URL; comma-separated
    // and/or repeated), and --url (repeatable). Each keeps a short `name` (shown per-rule)
    // and a resolved `label` (shown in the report provenance).
    let mut sources: Vec<Source> = Vec::new();

    for path in values_of("--file") {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| fatal(&format!("could not read {path}: {e}")));
        sources.push(Source {
            name: path.clone(),
            label: format!("file {path}"),
            text,
        });
    }
    for token in list_tokens(&values_of("--list")) {
        let url = resolve_list(&token).unwrap_or_else(|e| fatal(&e));
        eprintln!("Fetching {url} ...");
        let text = fetch_list(&url).unwrap_or_else(|e| fatal(&e));
        sources.push(Source {
            name: token,
            label: url,
            text,
        });
    }
    for url in values_of("--url") {
        eprintln!("Fetching {url} ...");
        let text = fetch_list(&url).unwrap_or_else(|e| fatal(&e));
        sources.push(Source {
            name: url.clone(),
            label: url,
            text,
        });
    }

    if sources.is_empty() {
        fatal("a filter list is required: --list <ubo|easylist|easyprivacy|URL ...>, --url URL, or --file PATH");
    }

    let source_label = sources
        .iter()
        .map(|s| s.label.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let multi_source = sources.len() > 1;

    // No --domains means "check every rule" (no domain filtering).
    let domains: Option<Vec<String>> = match value_of("--domains") {
        Some(list) => {
            let v: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if v.is_empty() {
                fatal("--domains was empty");
            }
            Some(v)
        }
        None => None,
    };
    match &domains {
        Some(d) => eprintln!("Matching domains: {}", d.join(", ")),
        None => eprintln!("No --domains given: checking all rules."),
    }
    if let Some(opt) = &option_filter {
        eprintln!("Filtering to rules with option: {opt}");
    }
    let matcher = domains.as_ref().map(|d| DomainMatcher::new(d));
    let resource_checker = ResourceChecker::from_embedded();

    let reports = collect_reports(
        &sources,
        matcher.as_ref(),
        option_filter.as_deref(),
        probe,
        &resource_checker,
    );

    if output_json {
        let report = Report {
            adblock_version: ADBLOCK_RUST_VERSION,
            tool: env!("CARGO_PKG_NAME"),
            tool_version: env!("CARGO_PKG_VERSION"),
            source: source_label.clone(),
            domains: domains.clone(),
            option: option_filter.clone(),
            rules: &reports,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    if output_markdown {
        print_markdown(
            &reports,
            domains.as_deref(),
            &source_label,
            multi_source,
            option_filter.as_deref(),
        );
        return;
    }

    print_report(&reports, show_supported, domains.is_some(), multi_source);
}

/// Explain a single rule: its parsed type, whether adblock-rust supports it, and the
/// option/type tokens it uses. With `probe`, each network option is tested in isolation
/// and labelled `ok`/`unsupported` (adblock-rust's error doesn't say which option failed).
fn explain_rule(rule: &str, probe: bool, resources: &ResourceChecker) {
    let rule = rule.trim();
    let (parsed, filter_type, parse_error) = parse(rule);
    let (supported, reason) = support(rule, &parsed, parse_error, resources);
    let opts = rule_options(rule);

    println!("Rule:      {rule}");
    println!("Type:      {}", filter_type.unwrap_or("unknown"));
    if supported {
        println!("Supported: yes");
    } else {
        println!("Supported: no ({})", reason.as_deref().unwrap_or("?"));
    }

    let options_line = if opts.is_empty() {
        "(none)".to_string()
    } else if probe && filter_type == Some("network") {
        opts.iter()
            .map(|o| {
                let mark = if option_supported(o) {
                    "ok"
                } else {
                    "unsupported"
                };
                format!("{o} ({mark})")
            })
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        opts.join(", ")
    };
    println!("Options:   {options_line}");

    if probe && filter_type != Some("network") {
        println!("Note:      --probe applies to network $options; cosmetic types aren't probed.");
    }
}

/// Is a network option recognised by adblock-rust? Probe it in isolation on a canonical
/// rule. `UnrecognisedOption` (for both valueless and valued forms) means unsupported;
/// any other outcome means the option is recognised (it may just need a valid value).
fn option_supported(name: &str) -> bool {
    let probes = [
        format!("||example.com^${name}"),
        format!("||example.com^${name}=example.com"),
    ];
    for probe in probes {
        match parse_filter(&probe, false, parse_options()) {
            Ok(_) => return true,
            Err(FilterParseError::Network(NetworkFilterError::UnrecognisedOption)) => continue,
            Err(_) => return true,
        }
    }
    false
}

fn print_report(
    reports: &[RuleReport],
    show_supported: bool,
    domain_filtered: bool,
    multi_source: bool,
) {
    let supported = reports.iter().filter(|r| r.supported).count();
    let unsupported = reports.len() - supported;

    if domain_filtered {
        let targets = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Target))
            .count();
        let scopes = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Scope))
            .count();
        println!(
            "Matching rules: {}  (target: {targets}, scope: {scopes})",
            reports.len()
        );
    } else {
        println!("Rules checked:  {}", reports.len());
    }
    println!("Supported:      {supported}");
    println!("Unsupported:    {unsupported}");

    let mut unsupported_rules: Vec<&RuleReport> = reports.iter().filter(|r| !r.supported).collect();
    unsupported_rules
        .sort_by(|a, b| (a.reason.as_deref(), &a.rule).cmp(&(b.reason.as_deref(), &b.rule)));
    if !unsupported_rules.is_empty() {
        println!("\n=== UNSUPPORTED RULES ===");
        for r in unsupported_rules {
            println!(
                "{}{}({}) {}",
                source_prefix(r, multi_source),
                tag_prefix(r),
                r.reason.as_deref().unwrap_or("?"),
                r.rule
            );
        }
    }

    if show_supported {
        println!("\n=== SUPPORTED RULES ===");
        for r in reports.iter().filter(|r| r.supported) {
            println!(
                "{}{}[{}] {}",
                source_prefix(r, multi_source),
                tag_prefix(r),
                r.filter_type.unwrap_or("?"),
                r.rule
            );
        }
    }
}

fn tags(r: &RuleReport) -> String {
    r.relations
        .iter()
        .map(|rel| match rel {
            Relation::Target => "target",
            Relation::Scope => "scope",
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// A `[tag+tag] ` prefix, or empty when the rule has no domain relations (match-all mode).
fn tag_prefix(r: &RuleReport) -> String {
    if r.relations.is_empty() {
        String::new()
    } else {
        format!("[{}] ", tags(r))
    }
}

/// A `<src+src> ` prefix shown only when multiple sources were combined.
fn source_prefix(r: &RuleReport, multi_source: bool) -> String {
    if multi_source {
        format!("<{}> ", r.sources.join("+"))
    } else {
        String::new()
    }
}

/// Render a deterministic markdown report. Output depends only on the inputs (rules,
/// domains, source) so re-running on the same data yields identical bytes - safe to
/// commit and diff.
fn print_markdown(
    reports: &[RuleReport],
    domains: Option<&[String]>,
    source: &str,
    multi_source: bool,
    option_filter: Option<&str>,
) {
    let supported = reports.iter().filter(|r| r.supported).count();
    let unsupported = reports.len() - supported;
    let domain_filtered = domains.is_some();

    println!("# adblock-rust filter compatibility\n");

    println!("| | |");
    println!("|---|---|");
    println!("| Source | {} |", md_text(source));
    let domains_label = match domains {
        Some(d) => d.join(", "),
        None => "all (no domain filter)".to_string(),
    };
    println!("| Domains | {} |", md_text(&domains_label));
    if let Some(opt) = option_filter {
        println!("| Option | {} |", md_text(opt));
    }
    println!("| adblock-rust | {ADBLOCK_RUST_VERSION} |");
    println!(
        "| Tool | {} v{} |",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    println!();

    if domain_filtered {
        let targets = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Target))
            .count();
        let scopes = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Scope))
            .count();
        println!(
            "**{} matching rules** - {supported} supported, {unsupported} unsupported \
             (target: {targets}, scope: {scopes}).\n",
            reports.len()
        );
    } else {
        println!(
            "**{} rules checked** - {supported} supported, {unsupported} unsupported.\n",
            reports.len()
        );
    }

    let mut unsupported_rules: Vec<&RuleReport> = reports.iter().filter(|r| !r.supported).collect();
    unsupported_rules
        .sort_by(|a, b| (a.reason.as_deref(), &a.rule).cmp(&(b.reason.as_deref(), &b.rule)));
    println!("## Unsupported ({unsupported})\n");
    if unsupported_rules.is_empty() {
        println!("_None._\n");
    } else {
        let mut headers: Vec<&str> = Vec::new();
        if multi_source {
            headers.push("Source");
        }
        if domain_filtered {
            headers.push("Tags");
        }
        headers.push("Reason");
        headers.push("Rule");
        let rows: Vec<Vec<String>> = unsupported_rules
            .iter()
            .map(|r| {
                let mut row = Vec::new();
                if multi_source {
                    row.push(md_text(&r.sources.join("+")));
                }
                if domain_filtered {
                    row.push(tags(r));
                }
                row.push(md_text(r.reason.as_deref().unwrap_or("?")));
                row.push(md_code(&r.rule));
                row
            })
            .collect();
        print_table(&headers, &rows);
        println!();
    }

    let mut supported_rules: Vec<&RuleReport> = reports.iter().filter(|r| r.supported).collect();
    supported_rules.sort_by(|a, b| (a.filter_type, &a.rule).cmp(&(b.filter_type, &b.rule)));
    println!("## Supported ({supported})\n");
    if supported_rules.is_empty() {
        println!("_None._");
    } else {
        let mut headers: Vec<&str> = Vec::new();
        if multi_source {
            headers.push("Source");
        }
        if domain_filtered {
            headers.push("Tags");
        }
        headers.push("Type");
        headers.push("Rule");
        let rows: Vec<Vec<String>> = supported_rules
            .iter()
            .map(|r| {
                let mut row = Vec::new();
                if multi_source {
                    row.push(md_text(&r.sources.join("+")));
                }
                if domain_filtered {
                    row.push(tags(r));
                }
                row.push(r.filter_type.unwrap_or("?").to_string());
                row.push(md_code(&r.rule));
                row
            })
            .collect();
        print_table(&headers, &rows);
    }
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    println!("| {} |", headers.join(" | "));
    println!("|{}|", vec!["---"; headers.len()].join("|"));
    for row in rows {
        println!("| {} |", row.join(" | "));
    }
}

fn md_text(s: &str) -> String {
    s.replace('|', "\\|")
}

fn md_code(s: &str) -> String {
    format!("`{}`", s.replace('|', "\\|"))
}

fn print_usage() {
    println!(
        "{name} v{version} - check which filter-list rules adblock-rust supports

USAGE:
    adblock-rust-compat <SOURCE>... [--domains LIST] [--option NAME] [OPTIONS]
    adblock-rust-compat --rule '<rule>'

SOURCE (one or more; their rules are combined and de-duplicated):
    --list NAMES|URLS    ubo, easylist, easyprivacy, or http(s) URLs; comma-separated
                         and/or repeated (e.g. --list ubo,easylist)
    --url URL            Raw URL (repeatable)
    --file PATH          Local file (repeatable)

OPTIONS:
    --domains LIST       Comma-separated domains to match (e.g. youtube.com,youtu.be);
                         omit to check every rule in the list
    --option NAME        Keep only rules using this option/type (network $modifier like
                         replace, redirect, third-party; or cosmetic type like scriptlet,
                         elemhide, procedural, style)
    --rule '<rule>'      Explain a single rule (type, support, options) and exit
    --probe              Attribute what's unsupported. With --rule, label each network
                         option ok/unsupported. With a --json scan, add an
                         `unsupported_options` array to each unsupported rule.
    --markdown           Emit a markdown report to stdout
    --json               Emit the full report as JSON to stdout
    --show-supported     Also list supported rules (text output only)
    -h, --help           Show this help

When --domains is given, list registrable domains (e.g. example.com) for broad subdomain
coverage, plus any specific subdomains used in cosmetic/$domain= scopes.
Discover a rule's options with --rule, then search for them with --option, e.g.
    adblock-rust-compat --list ubo,easylist,easyprivacy --option replace
See examples/check-youtube.sh for the YouTube domain set.",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn fatal(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_list_presets_and_urls() {
        assert_eq!(resolve_list("ubo").unwrap(), UBO_URL);
        assert_eq!(resolve_list("easylist").unwrap(), EASYLIST_URL);
        assert_eq!(resolve_list("easyprivacy").unwrap(), EASYPRIVACY_URL);
        assert_eq!(
            resolve_list("https://example.com/list.txt").unwrap(),
            "https://example.com/list.txt"
        );
        assert!(resolve_list("nonsense").is_err());
        // A stray flag captured as a value (e.g. `--list --json`) is rejected.
        assert!(resolve_list("--json").is_err());
    }

    #[test]
    fn sources_recorded_and_deduped_across_lists() {
        let resources = ResourceChecker::from_embedded();
        let sources = vec![
            Source {
                name: "a".into(),
                label: "a".into(),
                text: "||x.com^\n||shared.com^\n".into(),
            },
            Source {
                name: "b".into(),
                label: "b".into(),
                text: "||shared.com^\n||y.com^\n".into(),
            },
        ];
        // No domain filter, no option filter: every unique rule is kept.
        let reports = collect_reports(&sources, None, None, false, &resources);
        assert_eq!(reports.len(), 3);

        let shared = reports.iter().find(|r| r.rule == "||shared.com^").unwrap();
        assert_eq!(shared.sources, vec!["a", "b"]); // present in both, in source order
        let x = reports.iter().find(|r| r.rule == "||x.com^").unwrap();
        assert_eq!(x.sources, vec!["a"]);
        let y = reports.iter().find(|r| r.rule == "||y.com^").unwrap();
        assert_eq!(y.sources, vec!["b"]);
    }

    #[test]
    fn option_supported_classifies_network_options() {
        // recognised options (valueless and value-taking)
        assert!(option_supported("script"));
        assert!(option_supported("third-party"));
        assert!(option_supported("1p"));
        assert!(option_supported("domain"));
        assert!(option_supported("redirect"));
        // unrecognised by adblock-rust
        assert!(!option_supported("popup"));
        assert!(!option_supported("replace"));
        assert!(!option_supported("rewrite"));
    }

    #[test]
    fn option_filter_keeps_only_matching_rules() {
        let resources = ResourceChecker::from_embedded();
        let sources = vec![Source {
            name: "a".into(),
            label: "a".into(),
            text: "||a.com^$replace=/x/y/\n||b.com^$script\n||c.com^\nd.com##.ad\n".into(),
        }];
        let reports = collect_reports(&sources, None, Some("replace"), false, &resources);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].rule, "||a.com^$replace=/x/y/");
    }

    #[test]
    fn probe_populates_unsupported_options() {
        let resources = ResourceChecker::from_embedded();
        let sources = vec![Source {
            name: "a".into(),
            label: "a".into(),
            text: "||a.com^$popup,domain=x.com\n||b.com^$script\nc.com##.x {color:red}\n".into(),
        }];
        let reports = collect_reports(&sources, None, None, true, &resources);

        // unsupported network -> only the failing option (not `domain`)
        let popup = reports.iter().find(|r| r.rule.contains("popup")).unwrap();
        assert_eq!(popup.unsupported_options, vec!["popup"]);
        // supported network -> empty
        let script = reports
            .iter()
            .find(|r| r.rule == "||b.com^$script")
            .unwrap();
        assert!(script.unsupported_options.is_empty());
        // unsupported cosmetic -> its type
        let cosmetic = reports.iter().find(|r| r.rule.contains("##")).unwrap();
        assert_eq!(cosmetic.unsupported_options, vec!["style"]);
    }

    #[test]
    fn no_probe_leaves_unsupported_options_empty() {
        let resources = ResourceChecker::from_embedded();
        let sources = vec![Source {
            name: "a".into(),
            label: "a".into(),
            text: "||a.com^$popup\n".into(),
        }];
        let reports = collect_reports(&sources, None, None, false, &resources);
        assert!(reports[0].unsupported_options.is_empty());
    }

    #[test]
    fn list_tokens_split_and_repeat() {
        // comma-separated, repeated, and a mix all expand to individual tokens
        assert_eq!(
            list_tokens(&["ubo,easylist".to_string()]),
            vec!["ubo", "easylist"]
        );
        assert_eq!(
            list_tokens(&["ubo".to_string(), "easylist".to_string()]),
            vec!["ubo", "easylist"]
        );
        assert_eq!(
            list_tokens(&[" ubo , easyprivacy ".to_string(), "easylist".to_string()]),
            vec!["ubo", "easyprivacy", "easylist"]
        );
        // empties and stray commas are dropped
        assert_eq!(list_tokens(&["ubo,,".to_string()]), vec!["ubo"]);
        assert!(list_tokens(&[]).is_empty());
    }

    #[test]
    fn supported_network_rule() {
        let (parsed, ty, err) = parse("||ads.youtube.com^");
        assert!(parsed.is_some());
        assert_eq!(ty, Some("network"));
        assert!(err.is_none());
    }

    #[test]
    fn supported_cosmetic_rule() {
        let (parsed, ty, err) = parse("youtube.com##.ytp-ad-module");
        assert!(parsed.is_some());
        assert_eq!(ty, Some("cosmetic"));
        assert!(err.is_none());
    }

    #[test]
    fn rejected_replace_rule_reports_reason() {
        let rule = r#"||www.youtube.com/watch?$xhr,1p,replace=/"adPlacements"/"no_ads"/"#;
        let (parsed, ty, err) = parse(rule);
        assert!(parsed.is_none());
        assert_eq!(ty, Some("network"));
        assert!(
            err.as_deref().unwrap_or("").contains("Unrecognised"),
            "expected an UnrecognisedOption error, got {err:?}"
        );
    }

    #[test]
    fn unsupported_when_scriptlet_resource_missing() {
        let resources = ResourceChecker::from_embedded();
        let rule = "youtube.com##+js(this-scriptlet-does-not-exist-xyz)";
        let (parsed, _ty, parse_error) = parse(rule);
        assert!(parsed.is_some(), "rule should parse");
        let (supported, reason) = support(rule, &parsed, parse_error, &resources);
        assert!(!supported);
        assert_eq!(reason.as_deref(), Some("resource missing"));
    }

    #[test]
    fn supported_when_parses_and_resource_resolves() {
        let resources = ResourceChecker::from_embedded();
        let rule = "youtube.com##+js(set, foo, 1)";
        let (parsed, _ty, parse_error) = parse(rule);
        let (supported, reason) = support(rule, &parsed, parse_error, &resources);
        assert!(supported);
        assert!(reason.is_none());
    }

    #[test]
    fn comment_and_header_lines_are_not_filters() {
        assert!(!is_filter_line("! a comment"));
        assert!(!is_filter_line("[Adblock Plus 2.0]"));
        assert!(!is_filter_line(""));
        assert!(is_filter_line("||youtube.com^"));
    }
}
