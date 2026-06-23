//! Find filter-list rules that have to do with a set of domains and report which ones
//! adblock-rust supports.
//!
//! A rule is "supported" only if adblock-rust both parses it and, when it depends on
//! a scriptlet or redirect resource, can resolve that resource. Otherwise it is
//! "unsupported" with a single reason (a parse error, or a missing/restricted resource).
//!
//! Run `adblock-rust-compat-checker --help` for usage. A filter list (`--url`/`--file`)
//! and `--domains` are required.

mod domains;
mod resources;

use std::io::Read;

use adblock::lists::{
    parse_filter, FilterFormat, FilterParseError, ParseOptions, ParsedFilter, RuleTypes,
};
use adblock::resources::PermissionMask;

use domains::{DomainMatcher, Relation};
use resources::{ResourceChecker, ResourceStatus};

/// adblock-rust version this tool is built against (keep in sync with Cargo.toml).
const ADBLOCK_RUST_VERSION: &str = "0.12.x";

#[derive(serde::Serialize)]
struct RuleReport {
    rule: String,
    relations: Vec<Relation>,
    supported: bool,
    filter_type: Option<&'static str>,
    reason: Option<String>,
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
    let value_of = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let file = value_of("--file");
    let url = value_of("--url");

    let (source_label, text) = match (&file, &url) {
        (Some(_), Some(_)) => fatal("pass only one of --file or --url"),
        (Some(path), None) => (
            format!("file {path}"),
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| fatal(&format!("could not read {path}: {e}"))),
        ),
        (None, Some(url)) => {
            eprintln!("Fetching {url} ...");
            (url.clone(), fetch_list(url).unwrap_or_else(|e| fatal(&e)))
        }
        (None, None) => fatal("a filter list is required: pass --url URL or --file PATH"),
    };

    let domains: Vec<String> = match value_of("--domains") {
        Some(list) => {
            let v: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if v.is_empty() {
                fatal("--domains was empty");
            }
            v
        }
        None => fatal("--domains is required (comma-separated, e.g. youtube.com,youtu.be)"),
    };
    eprintln!("Matching domains: {}", domains.join(", "));
    let matcher = DomainMatcher::new(&domains);
    let resource_checker = ResourceChecker::from_embedded();
    let mut reports: Vec<RuleReport> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let rule = line.trim();
        if !is_filter_line(rule) || !seen.insert(rule.to_string()) {
            continue;
        }

        let (parsed, filter_type, parse_error) = parse(rule);

        let relations = match &parsed {
            Some(p) => matcher.relations_parsed(p),
            None => matcher.relations_raw(rule),
        };
        if relations.is_empty() {
            continue;
        }

        let (supported, reason) = support(rule, &parsed, parse_error, &resource_checker);

        reports.push(RuleReport {
            rule: rule.to_string(),
            relations,
            supported,
            filter_type,
            reason,
        });
    }

    if output_json {
        println!("{}", serde_json::to_string_pretty(&reports).unwrap());
        return;
    }

    if output_markdown {
        print_markdown(&reports, &domains, &source_label);
        return;
    }

    print_report(&reports, show_supported);
}

fn print_report(reports: &[RuleReport], show_supported: bool) {
    let supported = reports.iter().filter(|r| r.supported).count();
    let unsupported = reports.len() - supported;
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
    println!("Supported:      {supported}");
    println!("Unsupported:    {unsupported}");

    let mut unsupported_rules: Vec<&RuleReport> = reports.iter().filter(|r| !r.supported).collect();
    unsupported_rules.sort_by(|a, b| a.reason.cmp(&b.reason));
    if !unsupported_rules.is_empty() {
        println!("\n=== UNSUPPORTED RULES ===");
        for r in unsupported_rules {
            println!(
                "[{}] ({}) {}",
                tags(r),
                r.reason.as_deref().unwrap_or("?"),
                r.rule
            );
        }
    }

    if show_supported {
        println!("\n=== SUPPORTED RULES ===");
        for r in reports.iter().filter(|r| r.supported) {
            println!(
                "[{}] [{}] {}",
                tags(r),
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

/// Render a deterministic markdown report. Output depends only on the inputs (rules,
/// domains, source) so re-running on the same data yields identical bytes - safe to
/// commit and diff.
fn print_markdown(reports: &[RuleReport], domains: &[String], source: &str) {
    let supported = reports.iter().filter(|r| r.supported).count();
    let unsupported = reports.len() - supported;
    let targets = reports
        .iter()
        .filter(|r| r.relations.contains(&Relation::Target))
        .count();
    let scopes = reports
        .iter()
        .filter(|r| r.relations.contains(&Relation::Scope))
        .count();

    println!("# adblock-rust filter compatibility\n");

    println!("| | |");
    println!("|---|---|");
    println!("| Source | {} |", md_text(source));
    println!("| Domains | {} |", md_text(&domains.join(", ")));
    println!("| adblock-rust | {ADBLOCK_RUST_VERSION} |");
    println!(
        "| Tool | {} v{} |",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    println!();

    println!(
        "**{} matching rules** - {supported} supported, {unsupported} unsupported \
         (target: {targets}, scope: {scopes}).\n",
        reports.len()
    );

    let mut unsupported_rules: Vec<&RuleReport> = reports.iter().filter(|r| !r.supported).collect();
    unsupported_rules
        .sort_by(|a, b| (a.reason.as_deref(), &a.rule).cmp(&(b.reason.as_deref(), &b.rule)));
    println!("## Unsupported ({unsupported})\n");
    if unsupported_rules.is_empty() {
        println!("_None._\n");
    } else {
        println!("| Tags | Reason | Rule |");
        println!("|---|---|---|");
        for r in unsupported_rules {
            println!(
                "| {} | {} | {} |",
                tags(r),
                md_text(r.reason.as_deref().unwrap_or("?")),
                md_code(&r.rule)
            );
        }
        println!();
    }

    let mut supported_rules: Vec<&RuleReport> = reports.iter().filter(|r| r.supported).collect();
    supported_rules.sort_by(|a, b| (a.filter_type, &a.rule).cmp(&(b.filter_type, &b.rule)));
    println!("## Supported ({supported})\n");
    if supported_rules.is_empty() {
        println!("_None._");
    } else {
        println!("| Tags | Type | Rule |");
        println!("|---|---|---|");
        for r in supported_rules {
            println!(
                "| {} | {} | {} |",
                tags(r),
                r.filter_type.unwrap_or("?"),
                md_code(&r.rule)
            );
        }
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
        "{name} v{version} - check which filter-list rules for a set of domains are \
supported by adblock-rust

USAGE:
    adblock-rust-compat-checker --domains LIST (--url URL | --file PATH) [OPTIONS]

REQUIRED:
    --domains LIST       Comma-separated domains to match (e.g. youtube.com,youtu.be)
    --url URL            Fetch the filter list from URL
    --file PATH          Read the filter list from a local file (alternative to --url)

OPTIONS:
    --markdown           Emit a markdown report to stdout
    --json               Emit the full report as JSON to stdout
    --show-supported     Also list supported rules (text output only)
    -h, --help           Show this help

--file and --url are mutually exclusive. List registrable domains (e.g. example.com)
for broad subdomain coverage, plus any specific subdomains used in cosmetic/$domain=
scopes. See examples/youtube-defaults.txt for the YouTube/uBO values.",
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
